#!/usr/bin/env python3
"""Unit tests for signer_service.py (T3, T4, T5). Plain unittest, run with:
    python3 test_signer_service.py
No network access -- signer_service.py never makes an HTTP call itself, it
only signs. Uses a throwaway generated seed (never the real
.agent_identity.secret) written to a temp dir for every test. STATE_PATH and
LOCK_PATH are both patched to per-test tmpdir locations so nothing ever
touches this repo's real .signer_nonce_state.json / .signer_nonce_state.lock.
"""
from __future__ import annotations

import contextlib
import fcntl
import io
import json
import os
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import signer_service
# NOTE: sign_compat.py is invoked only via subprocess (see _run_sign_compat
# below), never imported directly -- importing it as a module runs sign.py's
# main() immediately against *this* process's sys.argv (its trailer calls
# runpy.run_path("sign.py", run_name="__main__") unconditionally, not behind
# an `if __name__ == "__main__"` guard), which would blow up this test file.

_HERE = os.path.dirname(os.path.abspath(__file__))


def _make_seed_file(tmpdir: str, seed_hex: str | None = None) -> tuple[str, str]:
    seed_hex = seed_hex or secrets.token_hex(32)
    path = os.path.join(tmpdir, ".test_identity.secret")
    with open(path, "w") as f:
        f.write(f"seed: {seed_hex}\n")
    os.chmod(path, 0o600)
    return path, seed_hex


class HelpTests(unittest.TestCase):
    """T3: --help must not expose a raw --seed / $SIGN_SEED-equivalent, and
    must not have a positional nonce."""

    def test_no_seed_flag_top_level(self):
        out = subprocess.run(
            [sys.executable, os.path.join(_HERE, "signer_service.py"), "--help"],
            capture_output=True, text=True, check=True,
        )
        self.assertNotIn("--seed ", out.stdout)
        self.assertNotRegex(out.stdout, r"--seed\b(?!-file)")
        self.assertIn("--seed-file", out.stdout)

    def test_say_help_has_no_positional_nonce(self):
        out = subprocess.run(
            [sys.executable, os.path.join(_HERE, "signer_service.py"), "say", "--help"],
            capture_output=True, text=True, check=True,
        )
        self.assertIn("--nonce", out.stdout)
        self.assertNotIn("room text nonce", out.stdout)
        # positional usage line should be exactly "room text", not include nonce
        usage_line = [l for l in out.stdout.splitlines() if l.strip().startswith("room")]
        # room/text listed as separate positional args section, nonce must be a flag
        self.assertNotIn("nonce\n", out.stdout.split("optional")[0] if "optional" in out.stdout else out.stdout)


class SeedFlagAndEnvRejectionTests(unittest.TestCase):
    """Must-fix: --help text alone doesn't prove --seed is rejected (argparse's
    default allow_abbrev=True would silently treat "--seed VALUE" as an
    abbreviation of "--seed-file VALUE" -- see build_parser()'s comment).
    These actually invoke the CLI with --seed and with $SIGN_SEED set, to
    prove the rejection/non-use is real behavior, not just missing --help
    text. All values used below are placeholder markers, never real key
    material -- if a bug ever printed one, that alone tells us the bug
    exists, without leaking anything sensitive."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.seed_file, self.seed_hex = _make_seed_file(self.tmpdir)
        self.state_path = os.path.join(self.tmpdir, ".signer_nonce_state.json")
        self.lock_path = os.path.join(self.tmpdir, ".signer_nonce_state.lock")

    def _run(self, argv, env_overrides=None):
        env_patch = mock.patch.dict(os.environ, env_overrides or {})
        with mock.patch.object(signer_service, "STATE_PATH", self.state_path), \
             mock.patch.object(signer_service, "LOCK_PATH", self.lock_path), \
             env_patch:
            with mock.patch("sys.argv", ["signer_service.py"] + argv):
                signer_service.main()

    def test_seed_flag_on_say_subcommand_rejected(self):
        with self.assertRaises(SystemExit) as ctx:
            self._run(["say", "room", "text", "--seed", "MARKER-NOT-A-REAL-SEED-abc123"])
        self.assertNotEqual(ctx.exception.code, 0)
        self.assertFalse(os.path.exists(self.state_path), "a rejected CLI parse must not reach the point of touching state")

    def test_seed_flag_on_set_subcommand_rejected(self):
        with self.assertRaises(SystemExit) as ctx:
            self._run(["set", "ns", "key", "value", "--seed", "MARKER-NOT-A-REAL-SEED-abc123"])
        self.assertNotEqual(ctx.exception.code, 0)
        self.assertFalse(os.path.exists(self.state_path))

    def test_seed_flag_before_subcommand_rejected(self):
        with self.assertRaises(SystemExit) as ctx:
            self._run(["--seed", "MARKER-NOT-A-REAL-SEED-abc123", "say", "room", "text"])
        self.assertNotEqual(ctx.exception.code, 0)

    def test_seed_flag_is_not_silently_accepted_as_seed_file_abbreviation(self):
        """The specific failure mode this guards against: argparse's default
        allow_abbrev=True would treat an unmatched "--seed" as an
        abbreviation of "--seed-file" (the only option here starting with
        "--seed"), silently parsing "--seed VALUE" as "--seed-file VALUE"
        instead of rejecting it outright. Confirmed directly against the
        real parser object, independent of any exit-code/state-file
        side-effect assertion above."""
        parser = signer_service.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["say", "room", "text", "--seed", "MARKER-NOT-A-REAL-SEED-abc123"])

    def test_sign_seed_env_var_is_never_consulted(self):
        """Setting $SIGN_SEED (the exact env var name sign.py itself
        supports) must have zero effect: signer_service.py must keep
        reading from --seed-file regardless. Proven by running the same
        say command twice -- once with $SIGN_SEED unset, once with it set
        to a DIFFERENT throwaway seed -- and asserting identical output
        both times (same did/sig for the same --seed-file + --nonce)."""
        other_seed_file, other_seed_hex = _make_seed_file(self.tmpdir, seed_hex=secrets.token_hex(32))
        self.assertNotEqual(self.seed_hex, other_seed_hex)  # sanity: genuinely different seeds

        buf1 = io.StringIO()
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SIGN_SEED", None)
            with mock.patch.object(signer_service, "STATE_PATH", self.state_path), \
                 mock.patch.object(signer_service, "LOCK_PATH", self.lock_path), \
                 mock.patch("sys.argv", ["signer_service.py", "say", "room1", "text1", "--nonce", "1", "--seed-file", self.seed_file]):
                with contextlib.redirect_stdout(buf1):
                    signer_service.main()

        # second state file so nonce reuse across the two runs doesn't interfere
        state_path_2 = os.path.join(self.tmpdir, ".signer_nonce_state_2.json")
        buf2 = io.StringIO()
        with mock.patch.dict(os.environ, {"SIGN_SEED": other_seed_hex}):
            with mock.patch.object(signer_service, "STATE_PATH", state_path_2), \
                 mock.patch.object(signer_service, "LOCK_PATH", self.lock_path), \
                 mock.patch("sys.argv", ["signer_service.py", "say", "room1", "text1", "--nonce", "1", "--seed-file", self.seed_file]):
                with contextlib.redirect_stdout(buf2):
                    signer_service.main()

        self.assertEqual(
            buf1.getvalue(), buf2.getvalue(),
            "$SIGN_SEED being set (to a DIFFERENT seed) must not change the output -- "
            "if it did, signer_service.py would be reading it instead of --seed-file",
        )

    def test_sign_seed_name_never_referenced_in_source(self):
        """Belt-and-suspenders static check alongside the behavioral test
        above: the string "SIGN_SEED" must not appear anywhere in
        signer_service.py's source at all -- there is no code path that
        could consult it, not even one gated by a flag that happens to be
        off by default."""
        src_path = os.path.join(_HERE, "signer_service.py")
        with open(src_path) as f:
            source = f.read()
        self.assertNotIn("SIGN_SEED", source)


class SeedFilePermissionTests(unittest.TestCase):
    """Must-fix: acceptance criterion 6's "0600 permission of
    .agent_identity.secret must not change" -- verified with a throwaway
    0600 seed file (never the real secret), running signer_service.py
    against it and confirming the mode bits are identical before/after."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.seed_file, self.seed_hex = _make_seed_file(self.tmpdir)
        self.state_path = os.path.join(self.tmpdir, ".signer_nonce_state.json")
        self.lock_path = os.path.join(self.tmpdir, ".signer_nonce_state.lock")

    def _mode(self, path):
        return stat.S_IMODE(os.stat(path).st_mode)

    def test_permission_unchanged_after_successful_say(self):
        before = self._mode(self.seed_file)
        self.assertEqual(before, 0o600)

        with mock.patch.object(signer_service, "STATE_PATH", self.state_path), \
             mock.patch.object(signer_service, "LOCK_PATH", self.lock_path), \
             mock.patch("sys.argv", ["signer_service.py", "say", "room", "text", "--nonce", "1", "--seed-file", self.seed_file]):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                signer_service.main()

        after = self._mode(self.seed_file)
        self.assertEqual(after, before, "seed file permission must be unchanged after a successful run")
        self.assertEqual(after, 0o600)

    def test_permission_unchanged_after_rejected_format(self):
        # even an error path (seed file exists but fails hex validation)
        # must not touch the file's permissions.
        bad_path = os.path.join(self.tmpdir, "bad_perm.secret")
        with open(bad_path, "w") as f:
            f.write("seed: not-valid-hex\n")
        os.chmod(bad_path, 0o600)
        before = self._mode(bad_path)

        with mock.patch.object(signer_service, "STATE_PATH", self.state_path), \
             mock.patch.object(signer_service, "LOCK_PATH", self.lock_path), \
             mock.patch("sys.argv", ["signer_service.py", "say", "room", "text", "--seed-file", bad_path]):
            with self.assertRaises(SystemExit):
                signer_service.main()

        after = self._mode(bad_path)
        self.assertEqual(after, before)
        self.assertEqual(after, 0o600)


class _IsolatedPathsMixin:
    """Common per-test isolation: fresh tmpdir, fresh STATE_PATH/LOCK_PATH
    (both patched on the module so nothing touches the real repo files),
    fresh throwaway seed file."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.seed_file, self.seed_hex = _make_seed_file(self.tmpdir)
        self.state_path = os.path.join(self.tmpdir, ".signer_nonce_state.json")
        self.lock_path = os.path.join(self.tmpdir, ".signer_nonce_state.lock")

    def _run_signer(self, argv):
        with mock.patch.object(signer_service, "STATE_PATH", self.state_path), \
             mock.patch.object(signer_service, "LOCK_PATH", self.lock_path):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                with mock.patch("sys.argv", ["signer_service.py"] + argv):
                    signer_service.main()
            return buf.getvalue().strip().splitlines()

    def _run_signer_expect_exit(self, argv):
        with mock.patch.object(signer_service, "STATE_PATH", self.state_path), \
             mock.patch.object(signer_service, "LOCK_PATH", self.lock_path):
            with mock.patch("sys.argv", ["signer_service.py"] + argv):
                with self.assertRaises(SystemExit) as ctx:
                    signer_service.main()
                return ctx.exception


class CanonicalMatchTests(_IsolatedPathsMixin, unittest.TestCase):
    """T3: same (room|text|nonce) or (ns|key|value|nonce) must produce the
    same did/sig as sign_compat.py --seed <seed> ..."""

    def _run_sign_compat(self, cmd_args):
        out = subprocess.run(
            [sys.executable, os.path.join(_HERE, "sign_compat.py"), "--seed", self.seed_hex] + cmd_args,
            capture_output=True, text=True, check=True,
        )
        return out.stdout.strip().splitlines()

    def test_say_matches_sign_compat(self):
        lines = self._run_signer(["say", "testroom", "hello there", "--nonce", "42", "--seed-file", self.seed_file])
        did, sig, nonce = lines
        expected = self._run_sign_compat(["say", "testroom", "42", "hello there"])
        self.assertEqual([did, sig], expected)
        self.assertEqual(nonce, "42")

    def test_set_matches_sign_compat(self):
        lines = self._run_signer(["set", "myns", "mykey", "myvalue", "--nonce", "99", "--seed-file", self.seed_file])
        did, sig, nonce = lines
        expected = self._run_sign_compat(["set", "myns", "mykey", "99", "myvalue"])
        self.assertEqual([did, sig], expected)
        self.assertEqual(nonce, "99")

    def test_output_never_contains_seed(self):
        lines = self._run_signer(["say", "testroom", "hello there", "--nonce", "43", "--seed-file", self.seed_file])
        for line in lines:
            self.assertNotIn(self.seed_hex, line)

    def test_say_matches_sign_compat_with_leading_zero_nonce(self):
        """Must-fix: an explicit nonce with leading zeros (e.g. "00042") is a
        different canonical-string BYTE sequence than its int form ("42") --
        sign.py/sign_compat.py sign whatever digit string they were given,
        verbatim. int()-normalizing the nonce before signing would produce a
        signature over "...|42|..." while the caller (and any independent
        verifier replaying their original "00042" input) expects
        "...|00042|...". Both must match sign_compat.py exactly."""
        lines = self._run_signer(["say", "testroom", "hello there", "--nonce", "00042", "--seed-file", self.seed_file])
        did, sig, nonce = lines
        expected = self._run_sign_compat(["say", "testroom", "00042", "hello there"])
        self.assertEqual([did, sig], expected)
        self.assertEqual(nonce, "00042", "printed nonce must preserve the caller's original digit string")

    def test_set_matches_sign_compat_with_leading_zero_nonce(self):
        lines = self._run_signer(["set", "myns", "mykey", "myvalue", "--nonce", "007", "--seed-file", self.seed_file])
        did, sig, nonce = lines
        expected = self._run_sign_compat(["set", "myns", "mykey", "007", "myvalue"])
        self.assertEqual([did, sig], expected)
        self.assertEqual(nonce, "007")

    def test_leading_zero_nonce_and_its_int_form_are_state_equivalent(self):
        """The state comparison itself must stay numeric: having used "007"
        once, a subsequent explicit "7" (or lower) must be rejected as
        non-increasing -- leading zeros must not make two representations
        of the same integer look like different nonces to the ratchet."""
        self._run_signer(["say", "zroom", "text-a", "--nonce", "007", "--seed-file", self.seed_file])
        exc = self._run_signer_expect_exit(["say", "zroom", "text-b", "--nonce", "7", "--seed-file", self.seed_file])
        self.assertNotEqual(exc.code, 0)


class NonceStateTests(_IsolatedPathsMixin, unittest.TestCase):
    """T4: state file creation, monotonic enforcement, auto-issue after an
    explicit high nonce, lock filename convention."""

    def test_a_first_issue_creates_state_file(self):
        self.assertFalse(os.path.exists(self.state_path))
        did, sig, nonce = self._run_signer(["say", "room1", "text1", "--seed-file", self.seed_file])
        self.assertTrue(os.path.exists(self.state_path))
        with open(self.state_path) as f:
            state = json.load(f)
        self.assertEqual(state[did]["say"]["room1"], int(nonce))

    def test_lock_file_uses_exact_spec_name_not_json_lock(self):
        self._run_signer(["say", "room1", "text1", "--seed-file", self.seed_file])
        self.assertTrue(os.path.exists(self.lock_path), ".signer_nonce_state.lock must be created")
        self.assertFalse(self.lock_path.endswith(".json.lock"))
        self.assertTrue(self.lock_path.endswith(".signer_nonce_state.lock"))
        # and it must be a file distinct from the state file, not state_path + ".lock"
        self.assertNotEqual(self.lock_path, self.state_path + ".lock")

    def test_b_nonce_at_or_below_last_rejected_and_state_unchanged(self):
        self._run_signer(["say", "room1", "text1", "--nonce", "1000", "--seed-file", self.seed_file])
        with open(self.state_path) as f:
            before = json.load(f)

        exc = self._run_signer_expect_exit(["say", "room1", "text1", "--nonce", "1000", "--seed-file", self.seed_file])
        self.assertNotEqual(exc.code, 0)

        with open(self.state_path) as f:
            after = json.load(f)
        self.assertEqual(before, after, "state must be unchanged after a rejected (non-increasing) nonce")

    def test_c_explicit_high_nonce_then_auto_issue_exceeds_it(self):
        did1, sig1, nonce1 = self._run_signer(["say", "room2", "text-a", "--nonce", "99999999999999", "--seed-file", self.seed_file])
        self.assertEqual(nonce1, "99999999999999")
        did2, sig2, nonce2 = self._run_signer(["say", "room2", "text-b", "--seed-file", self.seed_file])
        self.assertGreater(int(nonce2), int(nonce1))

    def test_d_lock_serializes_concurrent_commits(self):
        """Race-condition smoke test: A validates candidate=100, is paused
        inside commit() via _test_hook right before persisting. While paused,
        B (a separate thread) must block on flock trying to acquire the same
        lock. Once A resumes and commits, B must proceed and see last=100,
        issuing something > 100."""
        did, _, _ = self._run_signer(["say", "raceroom", "warmup", "--nonce", "1", "--seed-file", self.seed_file])

        a_in_commit = threading.Event()
        a_may_finish = threading.Event()
        b_acquired = threading.Event()
        results = {}

        def a_hook():
            a_in_commit.set()
            a_may_finish.wait(timeout=5)

        def run_a():
            with signer_service.locked_nonce_state(
                self.state_path, did, "say", "raceroom", 5, _test_hook=a_hook, lock_path=self.lock_path
            ) as txn:
                txn.validate("100")
                txn.commit()
            results["a_done"] = True

        thread_a = threading.Thread(target=run_a)
        thread_a.start()
        self.assertTrue(a_in_commit.wait(timeout=5), "A should have entered commit()")

        def run_b():
            with signer_service.locked_nonce_state(
                self.state_path, did, "say", "raceroom", 5, lock_path=self.lock_path
            ) as txn:
                b_acquired.set()
                nonce = txn.validate(None)
                txn.commit()
                results["b_nonce"] = nonce

        thread_b = threading.Thread(target=run_b)
        thread_b.start()
        # B must NOT be able to acquire the lock while A is paused in commit()
        time.sleep(0.3)
        self.assertFalse(b_acquired.is_set(), "B must be blocked while A holds the lock")

        a_may_finish.set()
        thread_a.join(timeout=5)
        thread_b.join(timeout=5)

        self.assertTrue(results.get("a_done"))
        self.assertGreater(int(results["b_nonce"]), 100)  # validate() now returns the display string

    def test_e_atomic_write_crash_safety_leaves_existing_state_intact(self):
        # establish a known-good state file first
        self._run_signer(["say", "safe-room", "text", "--nonce", "10", "--seed-file", self.seed_file])
        with open(self.state_path) as f:
            good_state_bytes = f.read()

        def boom(*a, **kw):
            raise OSError("simulated crash right before os.replace")

        with mock.patch("os.replace", side_effect=boom):
            with self.assertRaises(OSError):
                signer_service._atomic_write_json(self.state_path, {"corrupted": True})

        with open(self.state_path) as f:
            after = f.read()
        self.assertEqual(after, good_state_bytes, "existing state file must be untouched by a failed replace")
        # tmp file must have been cleaned up
        leftover_tmp = [f for f in os.listdir(self.tmpdir) if f.startswith(".tmp-")]
        self.assertEqual(leftover_tmp, [])


class NonceOverflowTests(_IsolatedPathsMixin, unittest.TestCase):
    """Must-fix: auto-issue must never walk last_nonce past the 19-digit
    ceiling sign.py's NONCE_RE allows -- doing so would persist a last_nonce
    for which no future signature could ever be legal again (permanently
    bricking that target). The cap must be enforced BEFORE any state
    mutation, for both the auto-issue path and an explicit candidate that
    would (in principle) exceed it."""

    def _seed_last_nonce(self, did, kind, target, last_nonce):
        state = {did: {kind: {target: last_nonce}}}
        signer_service._atomic_write_json(self.state_path, state)

    def _get_did(self):
        seed = signer_service._load_seed(self.seed_file)
        key, _ = signer_service.sign.load_key(seed)
        return signer_service.sign.did_of(key)

    def test_auto_issue_at_max_nonce_refuses_and_leaves_state_untouched(self):
        did = self._get_did()
        self._seed_last_nonce(did, "say", "overflow-room", signer_service.MAX_NONCE)
        with open(self.state_path) as f:
            before = f.read()

        with self.assertRaises(SystemExit) as ctx:
            with signer_service.locked_nonce_state(
                self.state_path, did, "say", "overflow-room", 5, lock_path=self.lock_path
            ) as txn:
                txn.validate(None)  # auto-issue: max(now_ms(), MAX_NONCE + 1) > MAX_NONCE
        self.assertNotEqual(ctx.exception.code, 0)

        with open(self.state_path) as f:
            after = f.read()
        self.assertEqual(before, after, "an over-limit auto-issued nonce must never be persisted")

    def test_auto_issue_at_max_nonce_via_cli_exits_nonzero(self):
        did = self._get_did()
        self._seed_last_nonce(did, "say", "overflow-room-cli", signer_service.MAX_NONCE)
        with open(self.state_path) as f:
            before = f.read()

        exc = self._run_signer_expect_exit(["say", "overflow-room-cli", "text", "--seed-file", self.seed_file])
        self.assertNotEqual(exc.code, 0)

        with open(self.state_path) as f:
            after = f.read()
        self.assertEqual(before, after)

    def test_explicit_nonce_exceeding_19_digits_rejected_by_format_and_state_unchanged(self):
        # 20 ASCII digits -- already invalid per sign.py's NONCE_RE, must fail
        # before validate() even reaches the MAX_NONCE comparison, and must
        # not touch state.
        did = self._get_did()
        self.assertFalse(os.path.exists(self.state_path))
        exc = self._run_signer_expect_exit(
            ["say", "some-room", "text", "--nonce", "1" + "0" * 20, "--seed-file", self.seed_file]
        )
        self.assertNotEqual(exc.code, 0)
        self.assertFalse(os.path.exists(self.state_path), "state file must not be created on a malformed nonce")

    def test_max_nonce_itself_is_a_legal_candidate(self):
        # MAX_NONCE (19 nines) is still a legal, signable nonce -- only
        # exceeding it must be refused.
        did = self._get_did()
        did_out, sig, nonce = self._run_signer(
            ["say", "boundary-room", "text", "--nonce", str(signer_service.MAX_NONCE), "--seed-file", self.seed_file]
        )
        self.assertEqual(int(nonce), signer_service.MAX_NONCE)


class SeedFormatValidationTests(_IsolatedPathsMixin, unittest.TestCase):
    """Must-fix (T5): the `seed:` value must be validated as 64 hex chars;
    a non-hex value (which sign.load_key would otherwise silently treat as
    a passphrase to SHA-256) must be rejected with a nonzero exit, and the
    error must never echo the seed value itself."""

    def _write_seed_line(self, raw_value: str) -> str:
        path = os.path.join(self.tmpdir, ".bad_identity.secret")
        with open(path, "w") as f:
            f.write(f"seed: {raw_value}\n")
        return path

    def test_passphrase_style_value_rejected(self):
        bad_path = self._write_seed_line("this is not hex at all, it is a passphrase")
        exc = self._run_signer_expect_exit(["say", "room", "text", "--seed-file", bad_path])
        self.assertNotEqual(exc.code, 0)

    def test_error_message_never_contains_seed_value(self):
        secret_looking_value = "this-is-a-secret-passphrase-do-not-leak-me"
        bad_path = self._write_seed_line(secret_looking_value)
        with mock.patch.object(signer_service, "STATE_PATH", self.state_path), \
             mock.patch.object(signer_service, "LOCK_PATH", self.lock_path):
            with mock.patch("sys.argv", ["signer_service.py", "say", "room", "text", "--seed-file", bad_path]):
                try:
                    signer_service.main()
                    self.fail("expected SystemExit")
                except SystemExit as e:
                    self.assertNotIn(secret_looking_value, str(e))

    def test_63_char_hex_rejected(self):
        bad_path = self._write_seed_line(secrets.token_hex(31) + "a")  # 63 hex chars, one short
        exc = self._run_signer_expect_exit(["say", "room", "text", "--seed-file", bad_path])
        self.assertNotEqual(exc.code, 0)

    def test_65_char_hex_rejected(self):
        bad_path = self._write_seed_line(secrets.token_hex(32) + "a")  # 65 hex chars, one too many
        exc = self._run_signer_expect_exit(["say", "room", "text", "--seed-file", bad_path])
        self.assertNotEqual(exc.code, 0)

    def test_non_hex_characters_rejected(self):
        bad_path = self._write_seed_line("g" * 64)  # right length, but 'g' is not a hex digit
        exc = self._run_signer_expect_exit(["say", "room", "text", "--seed-file", bad_path])
        self.assertNotEqual(exc.code, 0)

    def test_valid_64_hex_accepted(self):
        good_path = self._write_seed_line(secrets.token_hex(32))
        # must NOT raise
        lines = self._run_signer(["say", "room", "text", "--nonce", "5", "--seed-file", good_path])
        self.assertEqual(len(lines), 3)


class ErrorHandlingTests(_IsolatedPathsMixin, unittest.TestCase):
    """T5: missing/invalid seed file and lock timeout must fail loudly
    without leaking any file content."""

    def test_missing_seed_file_exits_nonzero_no_leak(self):
        missing_path = "/nonexistent/path/does-not-exist.secret"
        exc = self._run_signer_expect_exit(["say", "room", "text", "--seed-file", missing_path])
        self.assertNotEqual(exc.code, 0)

    def test_seed_file_without_seed_line_rejected(self):
        bad_path = os.path.join(self.tmpdir, "bad.secret")
        with open(bad_path, "w") as f:
            f.write("not-a-seed-line: xyz\n")
        exc = self._run_signer_expect_exit(["say", "room", "text", "--seed-file", bad_path])
        self.assertNotEqual(exc.code, 0)

    def test_lock_timeout_raises_and_does_not_hang(self):
        # hold the lock externally, in-process, on a separate fd -- same
        # LOCK_PATH signer_service will try to acquire once patched
        blocker_fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(blocker_fd, fcntl.LOCK_EX)
        try:
            start = time.monotonic()
            exc = self._run_signer_expect_exit(
                ["say", "room", "text", "--seed-file", self.seed_file, "--lock-timeout", "0.3"]
            )
            elapsed = time.monotonic() - start
            self.assertNotEqual(exc.code, 0)
            self.assertLess(elapsed, 3.0, "must respect --lock-timeout rather than hang")
        finally:
            fcntl.flock(blocker_fd, fcntl.LOCK_UN)
            os.close(blocker_fd)

    # ---- must-fix: NaN/inf/negative --lock-timeout must be rejected, not
    # accepted into an infinite (NaN never satisfies ">=deadline") or
    # effectively-infinite (inf) wait loop. The validation in
    # _flock_with_timeout() runs BEFORE the flock loop, so these are fast
    # and deterministic even with no lock contention at all. ----

    def test_flock_with_timeout_rejects_nan_directly(self):
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            with self.assertRaises(SystemExit):
                signer_service._flock_with_timeout(fd, float("nan"))
        finally:
            os.close(fd)

    def test_flock_with_timeout_rejects_inf_directly(self):
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            with self.assertRaises(SystemExit):
                signer_service._flock_with_timeout(fd, float("inf"))
        finally:
            os.close(fd)

    def test_flock_with_timeout_rejects_negative_directly(self):
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            with self.assertRaises(SystemExit):
                signer_service._flock_with_timeout(fd, -1.0)
        finally:
            os.close(fd)

    def test_flock_with_timeout_accepts_zero_directly(self):
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            signer_service._flock_with_timeout(fd, 0.0)  # lock is free -- must succeed immediately
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _run_signer_in_thread(self, argv, join_timeout=2.0):
        """Runs signer_service.main() on a background thread with a bounded
        join, so a regression that reintroduces the NaN infinite-wait bug
        fails this test instead of hanging the whole suite."""
        result = {}

        def run():
            with mock.patch.object(signer_service, "STATE_PATH", self.state_path), \
                 mock.patch.object(signer_service, "LOCK_PATH", self.lock_path):
                with mock.patch("sys.argv", ["signer_service.py"] + argv):
                    try:
                        signer_service.main()
                        result["exit_code"] = 0
                    except SystemExit as e:
                        result["exit_code"] = e.code
                    except Exception as e:  # noqa: BLE001 -- surface any unexpected error to the assertion below
                        result["exception"] = e

        t = threading.Thread(target=run, daemon=True)
        t.start()
        t.join(timeout=join_timeout)
        result["alive"] = t.is_alive()
        return result

    def test_lock_timeout_nan_via_cli_rejected_without_hanging(self):
        result = self._run_signer_in_thread(["say", "room", "text", "--seed-file", self.seed_file, "--lock-timeout", "nan"])
        self.assertFalse(result["alive"], "must not hang on --lock-timeout nan")
        self.assertNotIn("exception", result, result.get("exception"))
        self.assertNotEqual(result.get("exit_code"), 0)

    def test_lock_timeout_inf_via_cli_rejected_without_hanging(self):
        result = self._run_signer_in_thread(["say", "room", "text", "--seed-file", self.seed_file, "--lock-timeout", "inf"])
        self.assertFalse(result["alive"], "must not hang on --lock-timeout inf")
        self.assertNotIn("exception", result, result.get("exception"))
        self.assertNotEqual(result.get("exit_code"), 0)

    def test_lock_timeout_negative_via_cli_rejected(self):
        result = self._run_signer_in_thread(["say", "room", "text", "--seed-file", self.seed_file, "--lock-timeout", "-1"])
        self.assertFalse(result["alive"])
        self.assertNotIn("exception", result, result.get("exception"))
        self.assertNotEqual(result.get("exit_code"), 0)

    def test_lock_timeout_zero_is_accepted(self):
        # 0 is a valid (if extreme) finite, non-negative timeout -- must not
        # be rejected by the validation itself; with no contention it just
        # succeeds normally.
        lines = self._run_signer(["say", "room", "text", "--nonce", "1", "--seed-file", self.seed_file, "--lock-timeout", "0"])
        self.assertEqual(len(lines), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
