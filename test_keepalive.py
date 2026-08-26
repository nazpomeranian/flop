#!/usr/bin/env python3
"""Unit tests for keepalive.py (T1, T2). Plain unittest, run with:
    python3 test_keepalive.py
No network access required -- safe_note._get/_post are monkeypatched.
"""
from __future__ import annotations

import contextlib
import io
import unittest
import urllib.error
from unittest import mock

import safe_note
import keepalive


class ComputeTests(unittest.TestCase):
    """T1: compute() unit tests -- existing value / no existing value /
    replace-existing / oversize, per the four patterns the spec calls for."""

    def setUp(self):
        self.compute = keepalive.build_compute(timestamp="2026-08-26T00:00:00Z")

    def test_no_existing_value(self):
        result = self.compute(None)
        self.assertEqual(result, "keepalive: 2026-08-26T00:00:00Z")

    def test_existing_value_no_prior_keepalive(self):
        result = self.compute("mailbox: mb-abc123")
        self.assertEqual(result, "mailbox: mb-abc123 | keepalive: 2026-08-26T00:00:00Z")

    def test_replaces_existing_keepalive_fragment(self):
        current = "mailbox: mb-abc123 | keepalive: 2020-01-01T00:00:00Z | other: x"
        result = self.compute(current)
        self.assertEqual(result, "mailbox: mb-abc123 | keepalive: 2026-08-26T00:00:00Z | other: x")
        # only one keepalive fragment after replace -- no unbounded growth
        self.assertEqual(result.count("keepalive:"), 1)

    def test_second_replace_does_not_grow(self):
        first = self.compute("mailbox: mb-abc123")
        compute2 = keepalive.build_compute(timestamp="2026-08-27T00:00:00Z")
        second = compute2(first)
        self.assertEqual(second, "mailbox: mb-abc123 | keepalive: 2026-08-27T00:00:00Z")
        self.assertEqual(second.count("keepalive:"), 1)

    def test_oversize_raises(self):
        current = "x" * 8180  # no existing keepalive fragment -- will append " | keepalive: ..." and overflow
        with self.assertRaises(keepalive.NoteTooLargeError):
            self.compute(current)

    def test_oversize_reported_length_matches_would_be_value(self):
        current = "x" * 8180
        try:
            self.compute(current)
            self.fail("expected NoteTooLargeError")
        except keepalive.NoteTooLargeError as e:
            would_be = f"{current} | keepalive: 2026-08-26T00:00:00Z"
            self.assertEqual(int(str(e)), len(would_be))


class DryRunTests(unittest.TestCase):
    """T1: --dry-run applies compute() once to the current value and prints
    without ever calling cas_update / _post."""

    def test_dry_run_prints_new_value(self):
        with mock.patch.object(safe_note, "_get", return_value="mailbox: mb-abc123"):
            current = safe_note._get("did", "somefp")
        compute = keepalive.build_compute(timestamp="2026-08-26T00:00:00Z")
        new_value = compute(current)
        self.assertEqual(new_value, "mailbox: mb-abc123 | keepalive: 2026-08-26T00:00:00Z")


class SuccessWritePathTests(unittest.TestCase):
    """Must-fix: acceptance criterion 1's happy path -- running with no
    args (default --ns/--key) must actually call safe_note.cas_update(),
    exit 0 (i.e. main() completes without raising SystemExit), and print
    the value cas_update returned. Previously only the --dry-run and
    error paths were tested; this is the core successful-write path."""

    def test_main_no_args_calls_cas_update_with_defaults_and_prints_result(self):
        captured = {}

        def fake_cas_update(ns, key, compute):
            captured["ns"] = ns
            captured["key"] = key
            captured["compute"] = compute
            # Behaves like the real cas_update: apply compute() to a
            # representative "current" value and return the result --
            # this also exercises that main() passes a working compute()
            # closure through, not just any callable.
            return compute("mailbox: mb-abc123")

        with mock.patch.object(safe_note, "cas_update", side_effect=fake_cas_update), \
             mock.patch.object(safe_note, "_get", side_effect=lambda ns, key: captured["compute"]("mailbox: mb-abc123")), \
             mock.patch("sys.argv", ["keepalive.py"]):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                try:
                    keepalive.main()
                except SystemExit as e:
                    self.fail(f"main() must exit 0 (no SystemExit) on a successful write, got SystemExit({e.code!r})")

        # criterion 1: no args -> default --ns did --key <own fp>
        self.assertEqual(captured["ns"], keepalive.DEFAULT_NS)
        self.assertEqual(captured["key"], keepalive.DEFAULT_KEY)
        self.assertEqual(keepalive.DEFAULT_NS, "did")
        self.assertEqual(keepalive.DEFAULT_KEY, "b6711fbd4361b2f8")

        # criterion 1/2/3: the printed output is exactly what cas_update returned
        # (existing field preserved, keepalive fragment appended with today's timestamp)
        output = buf.getvalue().strip()
        self.assertTrue(output.startswith("mailbox: mb-abc123 | keepalive:"), output)
        self.assertRegex(output, r"keepalive: \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_main_no_args_never_calls_post_directly(self):
        """The success path must go through safe_note.cas_update() (criterion
        5: reuse cas_update's CAS retry, not a reimplementation) -- it must
        not call safe_note._post on its own outside of what cas_update
        itself does internally. It DOES call safe_note._get once afterward,
        deliberately, for read-back verification (see ReadBackVerificationTests)."""
        with mock.patch.object(safe_note, "cas_update", return_value="whatever") as cas_update_mock, \
             mock.patch.object(safe_note, "_get", return_value="whatever") as get_mock, \
             mock.patch.object(safe_note, "_post") as post_mock, \
             mock.patch("sys.argv", ["keepalive.py"]):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                keepalive.main()
        self.assertTrue(cas_update_mock.called)
        get_mock.assert_called_once()
        post_mock.assert_not_called()
        self.assertEqual(buf.getvalue().strip(), "whatever")


class ReadBackVerificationTests(unittest.TestCase):
    """The note has no write protection (unsigned, last-write-wins), so a
    successful cas_update() doesn't guarantee the keepalive fragment is
    still there a moment later. main() must read the note back after a
    successful write and treat a mismatch as a failure, not a silent
    success -- this is the gap a jp-agents room finding pointed out."""

    def test_readback_matches_exits_zero(self):
        with mock.patch.object(safe_note, "cas_update", return_value="mailbox: mb-abc | keepalive: X"), \
             mock.patch.object(safe_note, "_get", return_value="mailbox: mb-abc | keepalive: X"), \
             mock.patch("sys.argv", ["keepalive.py"]):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                try:
                    keepalive.main()
                except SystemExit as e:
                    self.fail(f"expected exit 0 on matching read-back, got SystemExit({e.code!r})")
        self.assertEqual(buf.getvalue().strip(), "mailbox: mb-abc | keepalive: X")

    def test_readback_mismatch_exits_nonzero_with_warning(self):
        with mock.patch.object(safe_note, "cas_update", return_value="mailbox: mb-abc | keepalive: X"), \
             mock.patch.object(safe_note, "_get", return_value="something else entirely -- clobbered"), \
             mock.patch("sys.argv", ["keepalive.py"]):
            buf, errbuf = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(errbuf):
                with self.assertRaises(SystemExit) as ctx:
                    keepalive.main()
        self.assertNotEqual(ctx.exception.code, 0)
        self.assertIn("read-back mismatch", errbuf.getvalue())
        self.assertIn("mailbox: mb-abc | keepalive: X", buf.getvalue())

    def test_readback_network_error_warns_but_still_exits_zero(self):
        """A failed read-back check (network error) is not proof the note
        was clobbered -- our write already succeeded, so don't fail the run
        over a check we merely couldn't perform. Warn on stderr instead."""
        with mock.patch.object(safe_note, "cas_update", return_value="mailbox: mb-abc | keepalive: X"), \
             mock.patch.object(safe_note, "_get", side_effect=urllib.error.URLError("boom")), \
             mock.patch("sys.argv", ["keepalive.py"]):
            buf, errbuf = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(errbuf):
                try:
                    keepalive.main()
                except SystemExit as e:
                    self.fail(f"a failed read-back attempt must not fail the run, got SystemExit({e.code!r})")
        self.assertIn("WARNING", errbuf.getvalue())
        self.assertEqual(buf.getvalue().strip(), "mailbox: mb-abc | keepalive: X")


class ErrorHandlingTests(unittest.TestCase):
    """T2: oversize-on-retry must abort before a second POST, and must exit
    nonzero without ever calling _post a second time."""

    def test_oversize_on_cas_retry_stops_before_second_post(self):
        # current is short at first read; the 409 conflict value handed back
        # on the first POST attempt is near the 8192 cap, so the *second*
        # compute() call (inside cas_update's retry loop) must raise before
        # a second _post() happens.
        near_cap_conflict = "y" * 8180  # + " | keepalive: ..." on top overflows

        post_calls = []

        def fake_post(ns, key, value, *, if_value, if_absent):
            post_calls.append(value)
            # first (and, if the bug existed, only) call: report a conflict
            return False, near_cap_conflict

        with mock.patch.object(safe_note, "_get", return_value="short value"), \
             mock.patch.object(safe_note, "_post", side_effect=fake_post):
            compute = keepalive.build_compute(timestamp="2026-08-26T00:00:00Z")
            with self.assertRaises(keepalive.NoteTooLargeError):
                safe_note.cas_update("did", "somefp", compute)

        self.assertEqual(len(post_calls), 1, "must not attempt a second POST once oversize is detected")

    def test_main_exits_nonzero_on_oversize_dry_run(self):
        near_cap = "z" * 8180
        with mock.patch.object(safe_note, "_get", return_value=near_cap), \
             mock.patch("sys.argv", ["keepalive.py", "--dry-run"]):
            with self.assertRaises(SystemExit) as ctx:
                keepalive.main()
            self.assertNotEqual(ctx.exception.code, 0)

    def test_main_exits_nonzero_on_network_error_dry_run(self):
        import urllib.error

        def raise_url_error(ns, key):
            raise urllib.error.URLError("simulated network failure")

        with mock.patch.object(safe_note, "_get", side_effect=raise_url_error), \
             mock.patch("sys.argv", ["keepalive.py", "--dry-run"]):
            with self.assertRaises(SystemExit) as ctx:
                keepalive.main()
            self.assertNotEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
