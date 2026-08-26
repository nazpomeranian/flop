#!/usr/bin/env python3
"""Unit/integration tests for room_radar.py (T1-T5 of
specs/2026-08-26_room-radar/00_mini_spec.md). Plain unittest, run with:
    python3 test_room_radar.py
    python3 -m pytest test_room_radar.py -v

No real network access and no real signing: `_http_get`/`_http_get_once` are
monkeypatched to canned responses, `subprocess.run` (signer_service.py) is
monkeypatched except in the one deliberate real-subprocess integration test
(SignViaServiceRealSubprocessTests), which uses a throwaway generated seed --
never .agent_identity.secret -- and never touches the network either
(signing has no network component). `LOCK_PATH`/`DEFAULT_STATE_PATH` are
patched to per-test tmpdir locations so nothing here ever touches this
repo's real room_radar_state.json / .room_radar.lock.
"""
from __future__ import annotations

import copy
import json
import os
import secrets
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

import room_radar as rr
from ratelimit_tracker import RateLimiter

_HERE = os.path.dirname(os.path.abspath(__file__))


# ---------- shared fixtures/helpers ----------

def fast_rl() -> RateLimiter:
    """A RateLimiter with a huge budget so wait_if_needed never sleeps."""
    return RateLimiter(fetch_limits=False, reads_per_minute=600000, writes_per_minute=600000)


def rooms_body(entries: list[dict]) -> str:
    return json.dumps({"rooms": entries, "total": len(entries), "capacity": 10240})


def room_entry(room: str, last_seq: int, nbytes: int = 100, idle_seconds=0) -> dict:
    return {"room": room, "last_seq": last_seq, "bytes": nbytes, "idle_seconds": idle_seconds}


def pulse_body(text: str | None) -> str:
    messages = [] if text is None else [{"seq": 1, "ts": "2026-08-26T00:00:00Z", "from": "did:key:z6x", "text": text, "nonce": 1}]
    return json.dumps({"room": "d-technocore-pulse", "count": len(messages), "first_seq": 1, "last_seq": 1, "messages": messages})


PULSE_TEXT_SAMPLE = (
    "Technocore Network Pulse — 2026-08-26 15:15 JST | Window: 14:45–15:15 JST | "
    "Network: public rooms 8,125 (-1), stored 94.4 MiB (+9.4 MiB), notes 190,547 (+3,410) | "
    "Activity (comparable top-200 sample): observed seq advances 46,945 | Coverage: listed 200/8,125"
)


def valid_state_text(rooms: dict, scanned_at: str = "2026-08-26T00:00:00Z") -> str:
    return json.dumps({"scanned_at": scanned_at, "rooms": rooms})


class TmpDirTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmpdir = Path(self._tmp.name)
        self.state_path = self.tmpdir / "state.json"
        self.lock_path = str(self.tmpdir / ".test.lock")
        self.default_state_path = str(self.tmpdir / "default_state.json")

        patches = [
            mock.patch.object(rr, "LOCK_PATH", self.lock_path),
            mock.patch.object(rr, "DEFAULT_STATE_PATH", self.default_state_path),
            mock.patch.object(rr, "_make_rate_limiter", side_effect=fast_rl),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)


# ================= T1 =================

class ParseArgsTests(unittest.TestCase):
    def test_defaults(self):
        args = rr.parse_args([])
        self.assertEqual(args.limit, 200)
        self.assertEqual(args.top_n, 8)
        self.assertIsNone(args.config)
        self.assertFalse(args.dry_run)

    def test_limit_boundaries_ok(self):
        self.assertEqual(rr.parse_args(["--limit", "1"]).limit, 1)
        self.assertEqual(rr.parse_args(["--limit", "1000"]).limit, 1000)

    def test_top_n_boundaries_ok(self):
        self.assertEqual(rr.parse_args(["--top-n", "1"]).top_n, 1)
        self.assertEqual(rr.parse_args(["--top-n", "10"]).top_n, 10)

    def test_limit_out_of_range_rejected(self):
        for bad in ("0", "-1", "1001"):
            with self.subTest(bad=bad), self.assertRaises(SystemExit):
                rr.parse_args(["--limit", bad])

    def test_limit_non_integer_rejected(self):
        with self.assertRaises(SystemExit):
            rr.parse_args(["--limit", "abc"])

    def test_top_n_out_of_range_rejected(self):
        for bad in ("0", "11"):
            with self.subTest(bad=bad), self.assertRaises(SystemExit):
                rr.parse_args(["--top-n", bad])


class LoadConfigTests(TmpDirTestCase):
    def test_no_config_returns_default_denylist_only(self):
        cfg = rr.load_config(None)
        self.assertEqual(cfg["noise_denylist"], {"gpu-miners"})

    def test_valid_config_merges(self):
        p = self.tmpdir / "config.json"
        p.write_text(json.dumps({"noise_denylist": ["extra-room"]}))
        cfg = rr.load_config(p)
        self.assertEqual(cfg["noise_denylist"], {"gpu-miners", "extra-room"})

    def test_noise_denylist_not_a_list_raises(self):
        p = self.tmpdir / "config.json"
        p.write_text(json.dumps({"noise_denylist": "not-a-list"}))
        with self.assertRaises(rr.ConfigError):
            rr.load_config(p)

    def test_noise_denylist_non_string_element_raises(self):
        p = self.tmpdir / "config.json"
        p.write_text(json.dumps({"noise_denylist": ["ok", 5]}))
        with self.assertRaises(rr.ConfigError):
            rr.load_config(p)

    def test_duplicate_json_key_raises(self):
        p = self.tmpdir / "config.json"
        p.write_text('{"noise_denylist": ["a"], "noise_denylist": ["b"]}')
        with self.assertRaises(rr.ConfigError):
            rr.load_config(p)

    def test_missing_file_raises(self):
        with self.assertRaises(rr.ConfigError):
            rr.load_config(self.tmpdir / "does-not-exist.json")

    def test_default_denylist_survives_config_without_key(self):
        p = self.tmpdir / "config.json"
        p.write_text(json.dumps({}))
        cfg = rr.load_config(p)
        self.assertIn("gpu-miners", cfg["noise_denylist"])

    def test_default_denylist_survives_config_with_other_values_only(self):
        p = self.tmpdir / "config.json"
        p.write_text(json.dumps({"noise_denylist": ["some-other-room"]}))
        cfg = rr.load_config(p)
        self.assertIn("gpu-miners", cfg["noise_denylist"])
        self.assertIn("some-other-room", cfg["noise_denylist"])

    def test_gpu_miners_excluded_in_all_three_scenarios(self):
        no_config = rr.load_config(None)
        p_missing_key = self.tmpdir / "a.json"
        p_missing_key.write_text(json.dumps({}))
        p_other_value = self.tmpdir / "b.json"
        p_other_value.write_text(json.dumps({"noise_denylist": ["some-other-room"]}))
        for cfg in (no_config, rr.load_config(p_missing_key), rr.load_config(p_other_value)):
            self.assertTrue(rr.is_noise("gpu-miners", cfg["noise_denylist"]))


class InstanceLockTests(TmpDirTestCase):
    def test_acquire_and_second_acquire_fails(self):
        fd1 = rr.try_acquire_instance_lock(self.lock_path)
        self.assertIsNotNone(fd1)
        fd2 = rr.try_acquire_instance_lock(self.lock_path)
        self.assertIsNone(fd2)
        rr.release_instance_lock(fd1)

    def test_reacquire_after_release(self):
        fd1 = rr.try_acquire_instance_lock(self.lock_path)
        rr.release_instance_lock(fd1)
        fd2 = rr.try_acquire_instance_lock(self.lock_path)
        self.assertIsNotNone(fd2)
        rr.release_instance_lock(fd2)


class ConfigInvalidOrderingTests(TmpDirTestCase):
    """T1: if --config is invalid, the lock function must never be called."""

    def test_lock_not_called_when_config_invalid(self):
        bad_config = self.tmpdir / "bad.json"
        bad_config.write_text("not valid json {{{")
        with mock.patch.object(rr, "try_acquire_instance_lock") as lock_mock:
            rc = rr.main(["--config", str(bad_config), "--state", str(self.state_path)])
        self.assertNotEqual(rc, 0)
        lock_mock.assert_not_called()


class LockContentionIntegrationTests(TmpDirTestCase):
    """T1: lock already held -> zero HTTP, zero state change, load_state called once."""

    def test_lock_held_blocks_everything(self):
        self.state_path.write_text(valid_state_text({"lobby": {"last_seq": 1, "bytes": 1, "idle_seconds": 0}}))
        holder_fd = rr.try_acquire_instance_lock(self.lock_path)
        self.addCleanup(rr.release_instance_lock, holder_fd)

        with mock.patch.object(rr, "load_state", side_effect=rr.load_state) as load_state_spy, \
             mock.patch.object(rr, "_http_get") as http_get_mock, \
             mock.patch.object(rr, "_http_get_once") as http_get_once_mock, \
             mock.patch.object(rr, "sign_via_service") as sign_mock:
            rc = rr.main(["--state", str(self.state_path)])

        self.assertNotEqual(rc, 0)
        http_get_mock.assert_not_called()
        http_get_once_mock.assert_not_called()
        sign_mock.assert_not_called()
        self.assertEqual(load_state_spy.call_count, 1)
        self.assertEqual(
            self.state_path.read_text(),
            valid_state_text({"lobby": {"last_seq": 1, "bytes": 1, "idle_seconds": 0}}),
        )


# ================= T2 =================

class SweepDisplayTextTests(unittest.TestCase):
    def test_control_chars_become_space_and_trimmed(self):
        self.assertEqual(rr.sweep_display_text("foo\nbar"), "foo bar")
        self.assertEqual(rr.sweep_display_text("\x00\x01hello\x02"), "hello")

    def test_pure_control_chars_become_empty(self):
        self.assertEqual(rr.sweep_display_text("\n\t\x00"), "")

    def test_full_width_space_is_not_swept(self):
        # U+3000 IDEOGRAPHIC SPACE is category Zs, not in the swept set.
        self.assertIn("　", rr.sweep_display_text("a　b"))

    def test_clean_string_unchanged(self):
        self.assertEqual(rr.sweep_display_text("lobby"), "lobby")


class TruncateForDisplayTests(unittest.TestCase):
    def test_short_untouched(self):
        self.assertEqual(rr.truncate_for_display("short"), "short")

    def test_long_truncated_with_ellipsis(self):
        s = "x" * 100
        out = rr.truncate_for_display(s)
        self.assertEqual(len(out), 80)
        self.assertTrue(out.endswith("…"))


class ParseRoomsResponseTests(unittest.TestCase):
    def test_valid_response(self):
        body = rooms_body([room_entry("lobby", 100), room_entry("hyperliquid", 50, idle_seconds=None)])
        snap = rr.parse_rooms_response(body)
        self.assertEqual(snap["lobby"], {"last_seq": 100, "bytes": 100, "idle_seconds": 0})
        self.assertIsNone(snap["hyperliquid"]["idle_seconds"])

    def test_rooms_not_a_list_raises(self):
        with self.assertRaises(rr.RoomsResponseError):
            rr.parse_rooms_response(json.dumps({"rooms": "nope"}))

    def test_empty_rooms_list_raises(self):
        with self.assertRaises(rr.RoomsResponseError):
            rr.parse_rooms_response(rooms_body([]))

    def test_negative_last_seq_raises(self):
        with self.assertRaises(rr.RoomsResponseError):
            rr.parse_rooms_response(rooms_body([room_entry("lobby", -1)]))

    def test_negative_bytes_raises(self):
        with self.assertRaises(rr.RoomsResponseError):
            rr.parse_rooms_response(rooms_body([room_entry("lobby", 1, nbytes=-5)]))

    def test_bool_last_seq_raises(self):
        entry = room_entry("lobby", 1)
        entry["last_seq"] = True
        with self.assertRaises(rr.RoomsResponseError):
            rr.parse_rooms_response(rooms_body([entry]))

    def test_duplicate_room_name_raises(self):
        with self.assertRaises(rr.RoomsResponseError):
            rr.parse_rooms_response(rooms_body([room_entry("lobby", 1), room_entry("lobby", 2)]))

    def test_type_error_on_bad_entry_shape(self):
        with self.assertRaises(rr.RoomsResponseError):
            rr.parse_rooms_response(json.dumps({"rooms": ["not-an-object"]}))

    def test_partial_validity_still_invalidates_whole_response(self):
        good = room_entry("lobby", 1)
        bad = room_entry("broken", -1)
        with self.assertRaises(rr.RoomsResponseError):
            rr.parse_rooms_response(rooms_body([good, bad]))

    def test_room_name_with_newline_sanitized_and_may_collide(self):
        body = rooms_body([room_entry("lo\nbby", 1), room_entry("lo bby", 2)])
        with self.assertRaises(rr.RoomsResponseError):
            rr.parse_rooms_response(body)

    def test_room_name_all_control_chars_raises(self):
        with self.assertRaises(rr.RoomsResponseError):
            rr.parse_rooms_response(rooms_body([room_entry("\x00\x01\x02", 1)]))

    def test_idle_seconds_null_is_valid(self):
        entry = room_entry("lobby", 1, idle_seconds=None)
        snap = rr.parse_rooms_response(rooms_body([entry]))
        self.assertIsNone(snap["lobby"]["idle_seconds"])

    def test_idle_seconds_negative_raises(self):
        with self.assertRaises(rr.RoomsResponseError):
            rr.parse_rooms_response(rooms_body([room_entry("lobby", 1, idle_seconds=-1)]))


class NowIsoTests(unittest.TestCase):
    def test_matches_own_regex(self):
        self.assertTrue(rr._SCANNED_AT_RE.fullmatch(rr.now_iso()))


class LoadStateTests(TmpDirTestCase):
    def test_missing_file_returns_none(self):
        self.assertIsNone(rr.load_state(self.state_path))

    def test_valid_state_returns_dict(self):
        self.state_path.write_text(valid_state_text({"lobby": {"last_seq": 1, "bytes": 1, "idle_seconds": 0}}))
        data = rr.load_state(self.state_path)
        self.assertEqual(data["rooms"]["lobby"]["last_seq"], 1)

    def test_invalid_json_raises(self):
        self.state_path.write_text("not json {{{")
        with self.assertRaises(rr.StateFileError):
            rr.load_state(self.state_path)

    def test_missing_scanned_at_raises(self):
        self.state_path.write_text(json.dumps({"rooms": {}}))
        with self.assertRaises(rr.StateFileError):
            rr.load_state(self.state_path)

    def test_scanned_at_with_newline_raises(self):
        self.state_path.write_text(json.dumps({"scanned_at": "2026-08-26T00:00:00Z\ninjected", "rooms": {}}))
        with self.assertRaises(rr.StateFileError):
            rr.load_state(self.state_path)

    def test_scanned_at_too_long_raises(self):
        self.state_path.write_text(json.dumps({"scanned_at": "2026-08-26T00:00:00Z" + "x" * 5000, "rooms": {}}))
        with self.assertRaises(rr.StateFileError):
            rr.load_state(self.state_path)

    def test_scanned_at_wrong_format_raises(self):
        for bad in ("2026-08-26T00:00:00.000Z", "2026-08-26T00:00:00+09:00", "2026-08-26"):
            with self.subTest(bad=bad):
                self.state_path.write_text(json.dumps({"scanned_at": bad, "rooms": {}}))
                with self.assertRaises(rr.StateFileError):
                    rr.load_state(self.state_path)

    def test_now_iso_output_passes_validation(self):
        self.state_path.write_text(valid_state_text({}, scanned_at=rr.now_iso()))
        rr.load_state(self.state_path)  # must not raise

    def test_rooms_not_dict_raises(self):
        self.state_path.write_text(json.dumps({"scanned_at": rr.now_iso(), "rooms": []}))
        with self.assertRaises(rr.StateFileError):
            rr.load_state(self.state_path)

    def test_negative_last_seq_in_state_raises(self):
        self.state_path.write_text(valid_state_text({"lobby": {"last_seq": -1, "bytes": 1, "idle_seconds": 0}}))
        with self.assertRaises(rr.StateFileError):
            rr.load_state(self.state_path)

    def test_empty_room_key_raises(self):
        self.state_path.write_text(valid_state_text({"": {"last_seq": 1, "bytes": 1, "idle_seconds": 0}}))
        with self.assertRaises(rr.StateFileError):
            rr.load_state(self.state_path)

    def test_unsanitized_room_key_raises(self):
        self.state_path.write_text(valid_state_text({"lo\nbby": {"last_seq": 1, "bytes": 1, "idle_seconds": 0}}))
        with self.assertRaises(rr.StateFileError):
            rr.load_state(self.state_path)

    def test_duplicate_json_key_in_rooms_raises_and_file_untouched(self):
        raw = (
            '{"scanned_at": "2026-08-26T00:00:00Z", "rooms": '
            '{"lobby": {"last_seq": 1, "bytes": 1, "idle_seconds": 0}, '
            '"lobby": {"last_seq": 2, "bytes": 2, "idle_seconds": 0}}}'
        )
        self.state_path.write_text(raw)
        with self.assertRaises(rr.StateFileError):
            rr.load_state(self.state_path)
        self.assertEqual(self.state_path.read_text(), raw)


class MainOrderIntegrationTests(TmpDirTestCase):
    """T2: a corrupt state file must be rejected before the lock and before
    any HTTP call -- load_state called exactly once, in main(), not in _run()."""

    def test_corrupt_state_blocks_lock_and_http(self):
        self.state_path.write_text("not json {{{")
        with mock.patch.object(rr, "load_state", side_effect=rr.load_state) as load_state_spy, \
             mock.patch.object(rr, "try_acquire_instance_lock") as lock_mock, \
             mock.patch.object(rr, "_http_get") as http_get_mock, \
             mock.patch.object(rr, "_http_get_once") as http_get_once_mock, \
             mock.patch.object(rr, "sign_via_service") as sign_mock:
            rc = rr.main(["--state", str(self.state_path)])

        self.assertNotEqual(rc, 0)
        lock_mock.assert_not_called()
        http_get_mock.assert_not_called()
        http_get_once_mock.assert_not_called()
        sign_mock.assert_not_called()
        self.assertEqual(load_state_spy.call_count, 1)
        self.assertEqual(self.state_path.read_text(), "not json {{{")


class BaselineAndDiffIntegrationTests(TmpDirTestCase):
    def test_first_run_records_baseline_no_post(self):
        body = rooms_body([room_entry("lobby", 100)])
        with mock.patch.object(rr, "_http_get", return_value=(200, body)), \
             mock.patch.object(rr, "sign_via_service") as sign_mock:
            rc = rr.main(["--state", str(self.state_path)])
        self.assertEqual(rc, 0)
        sign_mock.assert_not_called()
        data = json.loads(self.state_path.read_text())
        self.assertEqual(data["rooms"]["lobby"]["last_seq"], 100)

    def test_second_run_computes_delta_and_posts(self):
        self.state_path.write_text(valid_state_text({"lobby": {"last_seq": 100, "bytes": 100, "idle_seconds": 0}}))

        def http_get_stub(url, *a, **kw):
            if "/rooms" in url:
                return 200, rooms_body([room_entry("lobby", 150, nbytes=150)])
            if "d-technocore-pulse" in url:
                return 200, pulse_body(None)
            if rr.ROOM in url:
                return 200, json.dumps({"messages": []})
            raise AssertionError(f"unexpected _http_get url: {url}")

        with mock.patch.object(rr, "_http_get", side_effect=http_get_stub), \
             mock.patch.object(rr, "sign_via_service", return_value=("did:key:zme", "sig123", "1")), \
             mock.patch.object(rr, "_http_get_once", return_value=(200, "ok")) as post_mock:
            rc = rr.main(["--state", str(self.state_path)])

        self.assertEqual(rc, 0)
        post_mock.assert_called_once()
        posted_url = post_mock.call_args[0][0]
        self.assertIn("say-signed", posted_url)
        data = json.loads(self.state_path.read_text())
        self.assertEqual(data["rooms"]["lobby"]["last_seq"], 150)

    def test_invalid_rooms_response_leaves_state_untouched(self):
        original = valid_state_text({"lobby": {"last_seq": 100, "bytes": 100, "idle_seconds": 0}})
        self.state_path.write_text(original)
        with mock.patch.object(rr, "_http_get", return_value=(200, rooms_body([]))):
            rc = rr.main(["--state", str(self.state_path)])
        self.assertNotEqual(rc, 0)
        self.assertEqual(self.state_path.read_text(), original)


class RaceConditionIntegrationTests(TmpDirTestCase):
    """T2 (round8 core, tightened in round12): within a SINGLE main() call,
    load_state must be called exactly twice, and _run() must use the SECOND
    (in-lock) read's value, not the first (pre-lock) one -- even when the
    state file changes to a NEW value strictly between the two calls (which
    is what a concurrent process winning the lock in between would look
    like). A single-read implementation, or one that reuses its first read's
    result instead of the second, must fail this test."""

    def test_second_load_state_call_sees_update_made_between_the_two_reads(self):
        self.state_path.write_text(valid_state_text({"lobby": {"last_seq": 100, "bytes": 100, "idle_seconds": 0}}))

        real_load_state = rr.load_state
        real_compute_ranking = rr.compute_ranking
        call_log: list[int] = []
        captured: dict = {}

        def load_state_spy(path):
            call_log.append(len(call_log) + 1)
            if len(call_log) == 1:
                result = real_load_state(path)
                self.assertEqual(
                    result["rooms"]["lobby"]["last_seq"], 100,
                    "first (pre-lock) read must see the original v1 state",
                )
                # Simulate a concurrent process winning the lock strictly
                # BETWEEN this call and the next one, updating state to v2.
                self.state_path.write_text(
                    valid_state_text({"lobby": {"last_seq": 150, "bytes": 150, "idle_seconds": 0}})
                )
                return result
            result = real_load_state(path)
            self.assertEqual(
                result["rooms"]["lobby"]["last_seq"], 150,
                "second (in-lock) read must see the value written between the two reads",
            )
            return result

        def spying_compute_ranking(current_snapshot, state, config, top_n):
            captured["state"] = state
            return real_compute_ranking(current_snapshot, state, config, top_n=top_n)

        def http_get_stub(url, *a, **kw):
            if "/rooms" in url:
                return 200, rooms_body([room_entry("lobby", 220, nbytes=220)])
            if "d-technocore-pulse" in url:
                return 200, pulse_body(None)
            return 200, json.dumps({"messages": []})

        with mock.patch.object(rr, "load_state", side_effect=load_state_spy) as load_state_mock, \
             mock.patch.object(rr, "compute_ranking", side_effect=spying_compute_ranking), \
             mock.patch.object(rr, "_http_get", side_effect=http_get_stub), \
             mock.patch.object(rr, "sign_via_service", return_value=("did:key:zB", "sigB", "1")), \
             mock.patch.object(rr, "_http_get_once", return_value=(200, "ok")):
            rc = rr.main(["--state", str(self.state_path)])

        self.assertEqual(rc, 0)
        self.assertEqual(load_state_mock.call_count, 2, "load_state must be called exactly twice per run")
        self.assertEqual(
            captured["state"]["rooms"]["lobby"]["last_seq"], 150,
            "_run() must use the SECOND (in-lock) load_state result, not the first",
        )


class LockScopeThroughMainTests(TmpDirTestCase):
    """round12 must-fix: the state-save-guarantee tests (see StateSaveGuaranteeTests
    below) call _run() directly, which never exercises main()'s own lock
    acquire/release -- so a bug that dropped the outer try/finally, or that
    released the lock too early (e.g. right after the /rooms fetch instead of
    after the finally-save), would still pass every one of those. These go
    through main() itself and prove the lock is (a) still held immediately
    before release_instance_lock actually releases it, and (b) free again
    after main() returns, even when processing raised partway through."""

    def test_lock_held_through_save_state_and_released_only_after(self):
        # round13 must-fix: probing only "immediately before release_instance_lock
        # is called" doesn't rule out a regression that releases the lock right
        # after acquiring it and runs _run()/save_state entirely unlocked (that
        # regression would still show "locked" at the probe point, since nothing
        # else re-acquires it in a single-threaded test -- there'd be no OTHER
        # holder for the probe to collide with). This probes from INSIDE
        # save_state's own side effects (not from a callback release() happens
        # to invoke), and asserts the exact event order save_state(full
        # execution, probe-fails-while-held included) -> release.
        self.state_path.write_text(valid_state_text({"lobby": {"last_seq": 100, "bytes": 100, "idle_seconds": 0}}))
        body = rooms_body([room_entry("lobby", 150, nbytes=150)])

        events: list[tuple[str, object]] = []
        real_save_state = rr.save_state
        real_release = rr.release_instance_lock  # captured BEFORE patching -- calling
        # rr.release_instance_lock/rr.save_state from inside their own
        # side_effect below would recurse into the mock itself instead of
        # actually doing anything.

        def save_state_spy(path, data):
            # Independent, non-blocking acquire attempt on the SAME lock path,
            # taken from WITHIN save_state's own execution -- must fail here,
            # proving the lock is held not merely "at some point before
            # release" but continuously through save_state's real work
            # (_atomic_write_json's open/fsync/os.replace).
            probe_fd = rr.try_acquire_instance_lock(self.lock_path)
            events.append(("save_state.probe_while_running", probe_fd))
            if probe_fd is not None:
                real_release(probe_fd)
            events.append(("save_state.start", None))
            result = real_save_state(path, data)
            events.append(("save_state.end", None))
            return result

        def release_spy(fd):
            events.append(("release", None))
            real_release(fd)

        with mock.patch.object(rr, "_http_get", return_value=(200, body)), \
             mock.patch.object(rr, "compute_ranking", side_effect=RuntimeError("boom")), \
             mock.patch.object(rr, "save_state", side_effect=save_state_spy) as save_state_mock, \
             mock.patch.object(rr, "release_instance_lock", side_effect=release_spy) as release_mock:
            rc = rr.main(["--state", str(self.state_path)])

        self.assertNotEqual(rc, 0)
        self.assertEqual(save_state_mock.call_count, 1)
        self.assertEqual(release_mock.call_count, 1)

        # Event order: save_state must fully complete (probe, then its own
        # write) BEFORE release is ever called -- not interleaved, not after.
        self.assertEqual(
            [name for name, _ in events],
            ["save_state.probe_while_running", "save_state.start", "save_state.end", "release"],
        )
        probe_value = dict(events)["save_state.probe_while_running"]
        self.assertIsNone(probe_value, "lock must still be held while save_state is actually running")

        # main() returned -- the lock must be free again now, and only now.
        fd = rr.try_acquire_instance_lock(self.lock_path)
        self.assertIsNotNone(fd, "lock must be released after main() returns, even on exception")
        rr.release_instance_lock(fd)

        # And save_state's write (proven above to have happened while locked,
        # strictly before release) actually persisted the snapshot.
        data = json.loads(self.state_path.read_text())
        self.assertEqual(data["rooms"]["lobby"]["last_seq"], 150)

    def test_lock_released_after_successful_run_too(self):
        with mock.patch.object(rr, "_http_get", return_value=(200, rooms_body([room_entry("lobby", 100)]))):
            rc = rr.main(["--state", str(self.state_path)])
        self.assertEqual(rc, 0)
        fd = rr.try_acquire_instance_lock(self.lock_path)
        self.assertIsNotNone(fd, "lock must be released after a normal successful run")
        rr.release_instance_lock(fd)


class TopNWiringThroughMainTests(TmpDirTestCase):
    """round12 must-fix: compute_ranking()'s own top_n slicing was tested in
    isolation, but nothing proved _run() actually forwards args.top_n to it --
    a bug that dropped `top_n=args.top_n` from the call site (falling back to
    some hardcoded value) would still pass every prior test. This goes
    through main() with --top-n on the command line and checks both the
    value compute_ranking() actually received and the number of entries in
    the posted body."""

    def _stub_five_growing_rooms(self, url, *a, **kw):
        if "/rooms" in url:
            entries = [room_entry(f"room{i}", 100 + (i + 1) * 10) for i in range(5)]
            return 200, rooms_body(entries)
        if "d-technocore-pulse" in url:
            return 200, pulse_body(None)
        return 200, json.dumps({"messages": []})

    def _run_with_top_n(self, top_n: int):
        self.state_path.write_text(valid_state_text({
            f"room{i}": {"last_seq": 100, "bytes": 100, "idle_seconds": 0} for i in range(5)
        }))
        real_compute_ranking = rr.compute_ranking
        captured = {}

        def spying_compute_ranking(current_snapshot, state, config, top_n):
            captured["top_n"] = top_n
            return real_compute_ranking(current_snapshot, state, config, top_n=top_n)

        posted = {}

        def once_stub(url):
            posted["url"] = url
            return 200, "ok"

        with mock.patch.object(rr, "_http_get", side_effect=self._stub_five_growing_rooms), \
             mock.patch.object(rr, "compute_ranking", side_effect=spying_compute_ranking), \
             mock.patch.object(rr, "sign_via_service", return_value=("did:key:zt", "sigt", "1")), \
             mock.patch.object(rr, "_http_get_once", side_effect=once_stub):
            rc = rr.main(["--state", str(self.state_path), "--top-n", str(top_n)])
        self.assertEqual(rc, 0)
        return captured["top_n"], posted["url"]

    def test_top_n_1_flows_through_to_compute_ranking_and_posted_body(self):
        received_top_n, url = self._run_with_top_n(1)
        self.assertEqual(received_top_n, 1)
        text = urllib.parse.unquote(_say_signed_enc(url))
        self.assertEqual(text.count(") room"), 1)

    def test_top_n_3_flows_through_to_compute_ranking_and_posted_body(self):
        received_top_n, url = self._run_with_top_n(3)
        self.assertEqual(received_top_n, 3)
        text = urllib.parse.unquote(_say_signed_enc(url))
        self.assertEqual(text.count(") room"), 3)


class DenylistUnionAppliedInRankingTests(unittest.TestCase):
    """round12 must-fix: load_config()'s union-with-default and is_noise()'s
    denylist membership check were each tested alone, but nothing proved
    compute_ranking() actually applies that denylist to real candidates -- a
    bug that dropped the `is_noise(room, denylist)` check (or passed the
    wrong denylist) from compute_ranking() would still pass every prior
    test. These build a real ranking candidate set including gpu-miners
    (with a deliberately huge delta, so it would dominate the ranking if not
    filtered) and check it never appears in compute_ranking()'s output,
    across all three config scenarios."""

    def _current_and_prev(self):
        prev = {"rooms": {
            "gpu-miners": {"last_seq": 100, "bytes": 100, "idle_seconds": 0},
            "lobby": {"last_seq": 100, "bytes": 100, "idle_seconds": 0},
        }}
        current = {
            "gpu-miners": {"last_seq": 5000, "bytes": 5000, "idle_seconds": 0},
            "lobby": {"last_seq": 110, "bytes": 110, "idle_seconds": 0},
        }
        return current, prev

    def _assert_gpu_miners_excluded(self, config):
        current, prev = self._current_and_prev()
        ranked = rr.compute_ranking(current, prev, config, top_n=8)
        rooms_in_ranking = {r[0] for r in ranked}
        self.assertNotIn("gpu-miners", rooms_in_ranking)
        self.assertIn("lobby", rooms_in_ranking)

    def test_excluded_with_no_config(self):
        self._assert_gpu_miners_excluded(rr.load_config(None))

    def test_excluded_with_config_missing_denylist_key(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "config.json"
            p.write_text(json.dumps({}))
            self._assert_gpu_miners_excluded(rr.load_config(p))

    def test_excluded_with_config_specifying_only_other_values(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "config.json"
            p.write_text(json.dumps({"noise_denylist": ["some-other-room"]}))
            config = rr.load_config(p)
            self._assert_gpu_miners_excluded(config)
            # and the other, non-default value must ALSO still work (union, not replace)
            current, prev = self._current_and_prev()
            current["some-other-room"] = {"last_seq": 999, "bytes": 999, "idle_seconds": 0}
            prev["rooms"]["some-other-room"] = {"last_seq": 1, "bytes": 1, "idle_seconds": 0}
            ranked = rr.compute_ranking(current, prev, config, top_n=8)
            self.assertNotIn("some-other-room", {r[0] for r in ranked})


class StateConsistentPathTests(TmpDirTestCase):
    """round5: --state must be the only path ever touched; the default path
    must never be created."""

    def test_custom_state_path_isolated_across_three_runs(self):
        custom = self.tmpdir / "custom_state.json"
        default_path = Path(self.default_state_path)

        body1 = rooms_body([room_entry("lobby", 100)])
        with mock.patch.object(rr, "_http_get", return_value=(200, body1)):
            rc1 = rr.main(["--state", str(custom)])
        self.assertEqual(rc1, 0)
        self.assertTrue(custom.exists())
        self.assertFalse(default_path.exists())

        def http_get_stub(url, *a, **kw):
            if "/rooms" in url:
                return 200, rooms_body([room_entry("lobby", 120, nbytes=120)])
            return 200, json.dumps({"messages": []})

        with mock.patch.object(rr, "_http_get", side_effect=http_get_stub), \
             mock.patch.object(rr, "sign_via_service", return_value=("did:key:zc", "sigc", "1")), \
             mock.patch.object(rr, "_http_get_once", return_value=(200, "ok")):
            rc2 = rr.main(["--state", str(custom)])
        self.assertEqual(rc2, 0)
        self.assertFalse(default_path.exists())

        with mock.patch.object(rr, "_http_get", side_effect=http_get_stub), \
             mock.patch.object(rr, "sign_via_service", side_effect=RuntimeError("boom")):
            rc3 = rr.main(["--state", str(custom)])
        self.assertNotEqual(rc3, 0)
        self.assertFalse(default_path.exists())
        data = json.loads(custom.read_text())
        self.assertEqual(data["rooms"]["lobby"]["last_seq"], 120)


# ================= T3 =================

class IsNoiseTests(unittest.TestCase):
    def test_floppy_pattern(self):
        self.assertTrue(rr.is_noise("floppy-3525e4ec", set()))

    def test_ca_pattern(self):
        self.assertTrue(rr.is_noise("ca-" + "a" * 40, set()))

    def test_mailbox_prefix(self):
        self.assertTrue(rr.is_noise("mb-malesfahie", set()))

    def test_denylist(self):
        self.assertTrue(rr.is_noise("gpu-miners", {"gpu-miners"}))

    def test_legit_room_not_noise(self):
        self.assertFalse(rr.is_noise("d-techno-hub", set()))
        self.assertFalse(rr.is_noise("lobby", set()))


class ComputeRankingTests(unittest.TestCase):
    def setUp(self):
        self.prev = {"rooms": {}}
        self.current = {}
        for i in range(12):
            room = f"room{i}"
            self.prev["rooms"][room] = {"last_seq": 100, "bytes": 100, "idle_seconds": 0}
            self.current[room] = {"last_seq": 100 + (i + 1) * 10, "bytes": 100, "idle_seconds": 0}
        self.config = {"noise_denylist": set()}

    def test_sort_order_and_top_n(self):
        ranked = rr.compute_ranking(self.current, self.prev, self.config, top_n=5)
        self.assertEqual(len(ranked), 5)
        deltas = [r[1] for r in ranked]
        self.assertEqual(deltas, sorted(deltas, reverse=True))
        self.assertEqual(ranked[0][0], "room11")  # biggest delta

    def test_top_n_wiring_various_values(self):
        for n in (1, 5, 8, 10):
            with self.subTest(n=n):
                ranked = rr.compute_ranking(self.current, self.prev, self.config, top_n=n)
                self.assertEqual(len(ranked), n)

    def test_top_n_required_typeerror_if_omitted(self):
        with self.assertRaises(TypeError):
            rr.compute_ranking(self.current, self.prev, self.config)

    def test_always_excluded_rooms(self):
        current = dict(self.current)
        prev = copy.deepcopy(self.prev)
        current[rr.ROOM] = {"last_seq": 999, "bytes": 1, "idle_seconds": 0}
        prev["rooms"][rr.ROOM] = {"last_seq": 1, "bytes": 1, "idle_seconds": 0}
        current["d-technocore-pulse"] = {"last_seq": 999, "bytes": 1, "idle_seconds": 0}
        prev["rooms"]["d-technocore-pulse"] = {"last_seq": 1, "bytes": 1, "idle_seconds": 0}
        ranked = rr.compute_ranking(current, prev, self.config, top_n=20)
        rooms_in_ranking = {r[0] for r in ranked}
        self.assertNotIn(rr.ROOM, rooms_in_ranking)
        self.assertNotIn("d-technocore-pulse", rooms_in_ranking)

    def test_zero_positive_delta_returns_empty(self):
        prev = {"rooms": {"lobby": {"last_seq": 100, "bytes": 100, "idle_seconds": 0}}}
        current = {"lobby": {"last_seq": 100, "bytes": 100, "idle_seconds": 0}}
        ranked = rr.compute_ranking(current, prev, self.config, top_n=8)
        self.assertEqual(ranked, [])

    def test_tie_break_by_bytes_then_name(self):
        prev = {"rooms": {
            "b-room": {"last_seq": 100, "bytes": 100, "idle_seconds": 0},
            "a-room": {"last_seq": 100, "bytes": 100, "idle_seconds": 0},
        }}
        current = {
            "b-room": {"last_seq": 110, "bytes": 200, "idle_seconds": 0},
            "a-room": {"last_seq": 110, "bytes": 200, "idle_seconds": 0},
        }
        ranked = rr.compute_ranking(current, prev, self.config, top_n=8)
        self.assertEqual([r[0] for r in ranked], ["a-room", "b-room"])


class ExtractPulseSummaryTests(unittest.TestCase):
    def test_live_sample_extracts(self):
        summary = rr.extract_pulse_summary(PULSE_TEXT_SAMPLE)
        self.assertIsNotNone(summary)
        self.assertIn("public rooms 8,125", summary)

    def test_none_input(self):
        self.assertIsNone(rr.extract_pulse_summary(None))

    def test_no_network_field(self):
        self.assertIsNone(rr.extract_pulse_summary("nothing relevant here"))

    def test_no_trailing_pipe(self):
        self.assertIsNone(rr.extract_pulse_summary("Network: public rooms 100 no pipe here"))

    def test_control_chars_in_quoted_segment_are_swept(self):
        # round12 must-fix: sweep_display_text is unit-tested on its own, and
        # room-name collisions are covered separately, but nothing proved
        # extract_pulse_summary() itself actually calls sweep_display_text --
        # a bug that dropped that call would still pass every prior pulse
        # test (none of them fed it a raw control character). Tab/NUL (not a
        # literal "\n") are used deliberately: regex "." doesn't match "\n"
        # without re.DOTALL, so a raw newline INSIDE the captured group would
        # make the whole regex fail to match (extract_pulse_summary returns
        # None) regardless of whether the sweep call is present or not --
        # that would prove nothing about the sweep. Tab/NUL stay on one
        # "line" for "." purposes, so the match succeeds either way, and only
        # the sweep call determines whether they survive into the result.
        raw = "Technocore Network Pulse | Network: a\tb\x00c |  more stuff"
        summary = rr.extract_pulse_summary(raw)
        self.assertIsNotNone(summary)
        self.assertNotIn("\t", summary)
        self.assertNotIn("\x00", summary)
        self.assertEqual(summary, "a b c")

    def test_control_chars_absent_from_rendered_message(self):
        raw = "Technocore Network Pulse | Network: a\tb\x00c |  more"
        summary = rr.extract_pulse_summary(raw)
        text = rr.render_message(summary, [], "2026-08-26T00:00:00Z", "2026-08-26T01:00:00Z")
        self.assertNotIn("\t", text)
        self.assertNotIn("\x00", text)

    def test_embedded_newline_inside_segment_fails_closed_to_none(self):
        # A raw newline INSIDE the "Network: ... |" segment can't be matched
        # by the current (non-DOTALL) regex at all, so extraction fails
        # closed to None (the pulse-quote line is simply omitted from the
        # post) rather than partially matching or crashing -- a different,
        # complementary safety property from the sweep itself.
        raw = "Technocore Network Pulse | Network: a\nb |  more stuff"
        self.assertIsNone(rr.extract_pulse_summary(raw))


class PulseSweepEndToEndTests(TmpDirTestCase):
    """round12 must-fix, integration variant: proves a control character in
    the LIVE d-technocore-pulse quote never survives into the actual posted
    say-signed URL, going all the way through main()."""

    def test_posted_text_has_no_raw_control_chars_from_malicious_pulse_quote(self):
        self.state_path.write_text(valid_state_text({"lobby": {"last_seq": 100, "bytes": 100, "idle_seconds": 0}}))
        # Tab/NUL, not a literal "\n" -- see ExtractPulseSummaryTests for why
        # an embedded newline inside the segment can't be matched at all
        # (fails closed to None) and so wouldn't prove the sweep is applied.
        malicious_pulse = "Technocore Network Pulse | Network: a\tb\x00c |  more"

        def http_get_stub(url, *a, **kw):
            if "/rooms" in url:
                return 200, rooms_body([room_entry("lobby", 150, nbytes=150)])
            if "d-technocore-pulse" in url:
                return 200, pulse_body(malicious_pulse)
            return 200, json.dumps({"messages": []})

        posted = {}

        def once_stub(url):
            posted["url"] = url
            return 200, "ok"

        with mock.patch.object(rr, "_http_get", side_effect=http_get_stub), \
             mock.patch.object(rr, "sign_via_service", return_value=("did:key:zp", "sigp", "1")), \
             mock.patch.object(rr, "_http_get_once", side_effect=once_stub):
            rc = rr.main(["--state", str(self.state_path)])

        self.assertEqual(rc, 0)
        text = urllib.parse.unquote(_say_signed_enc(posted["url"]))
        self.assertNotIn("\t", text)
        self.assertNotIn("\x00", text)
        self.assertIn("a b c", text)
        self.assertIn("a b c", text)


class FetchPulseSummarySafeTests(unittest.TestCase):
    def test_success(self):
        with mock.patch.object(rr, "_http_get", return_value=(200, pulse_body(PULSE_TEXT_SAMPLE))):
            summary = rr.fetch_pulse_summary_safe(fast_rl())
        self.assertIsNotNone(summary)

    def test_http_exception_returns_none(self):
        with mock.patch.object(rr, "_http_get", side_effect=RuntimeError("boom")):
            self.assertIsNone(rr.fetch_pulse_summary_safe(fast_rl()))

    def test_non_200_returns_none(self):
        with mock.patch.object(rr, "_http_get", return_value=(500, "err")):
            self.assertIsNone(rr.fetch_pulse_summary_safe(fast_rl()))

    def test_bad_json_returns_none(self):
        with mock.patch.object(rr, "_http_get", return_value=(200, "not json")):
            self.assertIsNone(rr.fetch_pulse_summary_safe(fast_rl()))

    def test_empty_messages_returns_none(self):
        with mock.patch.object(rr, "_http_get", return_value=(200, pulse_body(None))):
            self.assertIsNone(rr.fetch_pulse_summary_safe(fast_rl()))

    def test_no_network_pattern_returns_none(self):
        with mock.patch.object(rr, "_http_get", return_value=(200, pulse_body("no relevant field"))):
            self.assertIsNone(rr.fetch_pulse_summary_safe(fast_rl()))


class FormatIdleAndRenderMessageTests(unittest.TestCase):
    def test_format_idle_none(self):
        self.assertEqual(rr._format_idle(None), "idle unknown")

    def test_format_idle_values(self):
        self.assertEqual(rr._format_idle(0), "idle 0s")
        self.assertEqual(rr._format_idle(340), "idle 340s")

    def test_render_message_with_none_idle_no_exception(self):
        ranked = [("lobby", 42, 100, None)]
        text = rr.render_message(None, ranked, "2026-08-26T00:00:00Z", "2026-08-26T01:00:00Z")
        self.assertIn("idle unknown", text)

    def test_render_message_no_ranked(self):
        text = rr.render_message(None, [], "2026-08-26T00:00:00Z", "2026-08-26T01:00:00Z")
        self.assertIn("none this scan", text)


class FitTo4096Tests(unittest.TestCase):
    def test_fits_under_limit_unchanged_count(self):
        ranked = [(f"room{i}", 10, 10, 0) for i in range(8)]
        text = rr.fit_to_4096(None, ranked, "2026-08-26T00:00:00Z", "2026-08-26T01:00:00Z")
        self.assertLessEqual(len(text), rr.MAX_TEXT_CHARS)
        self.assertEqual(text.count(") room"), 8)

    def test_oversized_shrinks_from_tail(self):
        # round12 should-fix: with the default 4096 cap, 20 entries (each
        # capped at 80 display chars by truncate_for_display) never actually
        # exceeded the limit, so the shrink loop was never exercised. Force it
        # with a small max_len (and no pulse quote, to isolate the entry-
        # shrinking behavior from the separate pulse-shrinking fallback) and
        # assert entries were actually dropped from the tail (lowest-ranked
        # first), not just that the output happens to be short.
        ranked = [(f"room{i}", 100 - i, 10, 0) for i in range(20)]
        text = rr.fit_to_4096(None, ranked, "2026-08-26T00:00:00Z", "2026-08-26T01:00:00Z", max_len=200)
        self.assertLessEqual(len(text), 200)
        surviving = text.count(") room")
        self.assertGreater(surviving, 0, "should not shrink all the way to zero at this max_len")
        self.assertLess(surviving, 20, "the shrink loop must have actually dropped entries")
        self.assertIn("room0", text, "highest-ranked entry must be kept, not an arbitrary one")
        self.assertNotIn("room19", text, "lowest-ranked entry must be dropped first")


class IdleSecondsNullEndToEndTests(TmpDirTestCase):
    def test_full_pipeline_with_null_idle_succeeds(self):
        self.state_path.write_text(valid_state_text({"lobby": {"last_seq": 100, "bytes": 100, "idle_seconds": 0}}))

        def http_get_stub(url, *a, **kw):
            if "/rooms" in url:
                return 200, rooms_body([room_entry("lobby", 150, nbytes=150, idle_seconds=None)])
            if "d-technocore-pulse" in url:
                return 200, pulse_body(None)
            return 200, json.dumps({"messages": []})

        captured = {}
        original_render = rr.render_message

        def spying_render(pulse_line, ranked, scanned_at, now):
            text = original_render(pulse_line, ranked, scanned_at, now)
            captured["text"] = text
            return text

        with mock.patch.object(rr, "_http_get", side_effect=http_get_stub), \
             mock.patch.object(rr, "render_message", side_effect=spying_render), \
             mock.patch.object(rr, "sign_via_service", return_value=("did:key:zi", "sigi", "1")), \
             mock.patch.object(rr, "_http_get_once", return_value=(200, "ok")):
            rc = rr.main(["--state", str(self.state_path)])

        self.assertEqual(rc, 0)
        self.assertIn("idle unknown", captured["text"])


# ================= T4 =================

class SignViaServiceMockedSubprocessTests(unittest.TestCase):
    def test_argv_shape_no_shell(self):
        fake = mock.Mock(returncode=0, stdout="did:key:zme\nsig123\n42\n", stderr="")
        with mock.patch.object(rr.subprocess, "run", return_value=fake) as run_mock:
            did, sig, nonce = rr.sign_via_service("d-room-radar", "hello")
        self.assertEqual((did, sig, nonce), ("did:key:zme", "sig123", "42"))
        args, kwargs = run_mock.call_args
        cmd = args[0]
        self.assertEqual(cmd[0], sys.executable)
        self.assertEqual(cmd[1], rr.SIGNER_SERVICE_PATH)
        self.assertEqual(cmd[2:5], ["say", "d-room-radar", "hello"])
        self.assertNotIn("shell", kwargs)

    def test_nonzero_returncode_raises(self):
        fake = mock.Mock(returncode=1, stdout="", stderr="boom")
        with mock.patch.object(rr.subprocess, "run", return_value=fake):
            with self.assertRaises(RuntimeError):
                rr.sign_via_service("d-room-radar", "hello")


class SignViaServiceRealSubprocessTests(unittest.TestCase):
    """One deliberate real-subprocess test (no network -- signing is local):
    a throwaway generated seed, never .agent_identity.secret."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        seed_hex = secrets.token_hex(32)
        self.seed_file = os.path.join(self._tmp.name, ".test_identity.secret")
        with open(self.seed_file, "w") as f:
            f.write(f"seed: {seed_hex}\n")
        os.chmod(self.seed_file, 0o600)

    def test_real_signer_service_subprocess_returns_valid_triple(self):
        did, sig, nonce = rr.sign_via_service("d-room-radar", "hello from a test", seed_file=self.seed_file)
        self.assertTrue(did.startswith("did:key:"))
        self.assertTrue(sig)
        self.assertTrue(nonce.isdigit())


class AlreadyPostedTests(unittest.TestCase):
    def test_found_returns_true(self):
        body = json.dumps({"messages": [{"from": "did:key:zme", "text": "hello", "seq": 1}]})
        with mock.patch.object(rr, "_http_get", return_value=(200, body)):
            self.assertTrue(rr.already_posted("d-room-radar", "hello", "did:key:zme", fast_rl()))

    def test_not_found_returns_false(self):
        body = json.dumps({"messages": [{"from": "did:key:zother", "text": "hello", "seq": 1}]})
        with mock.patch.object(rr, "_http_get", return_value=(200, body)):
            self.assertFalse(rr.already_posted("d-room-radar", "hello", "did:key:zme", fast_rl()))

    def test_http_failure_returns_false_not_raise(self):
        with mock.patch.object(rr, "_http_get", side_effect=RuntimeError("boom")):
            self.assertFalse(rr.already_posted("d-room-radar", "hello", "did:key:zme", fast_rl()))


def _incrementing_sign():
    """Returns a sign_via_service side_effect that returns a DIFFERENT
    (sig, nonce) pair on every call -- a fixed return_value would let a
    same-nonce/sig reuse bug pass unnoticed (round12 must-fix)."""
    counter = {"n": 0}

    def _sign(room, text, seed_file=None):
        counter["n"] += 1
        return "did:key:zme", f"sig{counter['n']}", str(counter["n"])

    return _sign


def _say_signed_segments(url: str) -> tuple[str, str, str]:
    # .../say-signed/{did}/{sig}/{nonce}/{enc}
    tail = url.split("/say-signed/", 1)[1]
    did, sig, nonce, _enc = tail.split("/", 3)
    return did, sig, nonce


def _say_signed_enc(url: str) -> str:
    """Returns just the (still url-encoded) posted-text segment of a
    say-signed URL -- the caller decodes it with urllib.parse.unquote."""
    tail = url.split("/say-signed/", 1)[1]
    _did, _sig, _nonce, enc = tail.split("/", 3)
    return enc


class PostWithRetryTests(unittest.TestCase):
    def test_5xx_then_success_resigns_with_fresh_nonce_and_sig(self):
        sign_spy = _incrementing_sign()
        sign_calls = []

        def fake_sign(room, text, seed_file=None):
            result = sign_spy(room, text, seed_file)
            sign_calls.append(result)
            return result

        responses = iter([(500, "err"), (200, "ok")])
        urls = []

        def fake_once(url):
            urls.append(url)
            return next(responses)

        with mock.patch.object(rr, "sign_via_service", side_effect=fake_sign), \
             mock.patch.object(rr, "_http_get_once", side_effect=fake_once), \
             mock.patch.object(rr, "already_posted", return_value=False):
            ok = rr.post_with_retry("d-room-radar", "hi", fast_rl(), backoff=0.001)
        self.assertTrue(ok)
        self.assertEqual(len(sign_calls), 2)
        seg1, seg2 = _say_signed_segments(urls[0]), _say_signed_segments(urls[1])
        self.assertNotEqual(seg1[1], seg2[1], "sig must differ between the two attempts")
        self.assertNotEqual(seg1[2], seg2[2], "nonce must differ between the two attempts")

    def test_connection_error_then_success_resigns_with_fresh_nonce_and_sig(self):
        import urllib.error

        sign_spy = _incrementing_sign()
        sign_calls = []

        def fake_sign(room, text, seed_file=None):
            result = sign_spy(room, text, seed_file)
            sign_calls.append(result)
            return result

        urls = []
        state = {"n": 0}

        def fake_once(url):
            urls.append(url)
            state["n"] += 1
            if state["n"] == 1:
                raise urllib.error.URLError("conn refused")
            return 200, "ok"

        with mock.patch.object(rr, "sign_via_service", side_effect=fake_sign), \
             mock.patch.object(rr, "_http_get_once", side_effect=fake_once), \
             mock.patch.object(rr, "already_posted", return_value=False):
            ok = rr.post_with_retry("d-room-radar", "hi", fast_rl(), backoff=0.001)
        self.assertTrue(ok)
        self.assertEqual(len(sign_calls), 2)
        seg1, seg2 = _say_signed_segments(urls[0]), _say_signed_segments(urls[1])
        self.assertNotEqual(seg1[1], seg2[1], "sig must differ between the two attempts")
        self.assertNotEqual(seg1[2], seg2[2], "nonce must differ between the two attempts")

    def test_non_retryable_4xx_fails_without_resigning(self):
        sign_mock_calls = []

        def fake_sign(room, text, seed_file=None):
            sign_mock_calls.append(1)
            return "did:key:zme", "sig", "1"

        with mock.patch.object(rr, "sign_via_service", side_effect=fake_sign), \
             mock.patch.object(rr, "_http_get_once", return_value=(400, "bad request")), \
             mock.patch.object(rr, "already_posted", return_value=False):
            ok = rr.post_with_retry("d-room-radar", "hi", fast_rl(), backoff=0.001)
        self.assertFalse(ok)
        self.assertEqual(len(sign_mock_calls), 1)

    def test_429_is_retried_with_fresh_nonce_and_sig(self):
        sign_spy = _incrementing_sign()
        sign_calls = []

        def fake_sign(room, text, seed_file=None):
            result = sign_spy(room, text, seed_file)
            sign_calls.append(result)
            return result

        responses = iter([(429, "slow down"), (200, "ok")])
        urls = []

        def fake_once(url):
            urls.append(url)
            return next(responses)

        with mock.patch.object(rr, "sign_via_service", side_effect=fake_sign), \
             mock.patch.object(rr, "_http_get_once", side_effect=fake_once), \
             mock.patch.object(rr, "already_posted", return_value=False):
            ok = rr.post_with_retry("d-room-radar", "hi", fast_rl(), backoff=0.001)
        self.assertTrue(ok)
        self.assertEqual(len(sign_calls), 2)
        seg1, seg2 = _say_signed_segments(urls[0]), _say_signed_segments(urls[1])
        self.assertNotEqual(seg1[1], seg2[1], "sig must differ between the two attempts")
        self.assertNotEqual(seg1[2], seg2[2], "nonce must differ between the two attempts")

    def test_duplicate_detected_skips_resign(self):
        calls = {"n": 0}

        def fake_sign(room, text, seed_file=None):
            calls["n"] += 1
            return "did:key:zme", "sig", str(calls["n"])

        with mock.patch.object(rr, "sign_via_service", side_effect=fake_sign), \
             mock.patch.object(rr, "_http_get_once", side_effect=[(500, "err")]), \
             mock.patch.object(rr, "already_posted", return_value=True):
            ok = rr.post_with_retry("d-room-radar", "hi", fast_rl(), backoff=0.001)
        self.assertTrue(ok)
        self.assertEqual(calls["n"], 1)  # only the first attempt signed; dedup found it after that

    def test_quote_safe_empty_encodes_slash(self):
        captured_urls = []

        def fake_once(url):
            captured_urls.append(url)
            return 200, "ok"

        with mock.patch.object(rr, "sign_via_service", return_value=("did:key:zme", "sig", "1")), \
             mock.patch.object(rr, "_http_get_once", side_effect=fake_once), \
             mock.patch.object(rr, "already_posted", return_value=False):
            rr.post_with_retry("d-room-radar", "a/b/c", fast_rl(), backoff=0.001)
        url = captured_urls[0]
        tail = url.split("/say-signed/", 1)[1]
        segments = tail.split("/")
        self.assertEqual(len(segments), 4, f"say-signed URL should have exactly 4 segments after it, got: {segments}")


class WriteUrlSingleLocationTests(unittest.TestCase):
    def test_say_signed_or_set_signed_url_built_in_exactly_one_place(self):
        # Comments/docstrings/log messages may mention "say-signed" freely (and do,
        # to explain the convention) -- what must be singular is the actual URL
        # f-string construction, i.e. a line that both builds an f-string off BASE
        # and contains "say-signed"/"set-signed" as a literal path segment.
        src = Path(rr.__file__).read_text()
        construction_lines = [
            line for line in src.splitlines()
            if ("say-signed" in line or "set-signed" in line) and 'f"{BASE}' in line
        ]
        self.assertEqual(
            len(construction_lines), 1,
            f"expected exactly one write-URL construction line, found: {construction_lines}",
        )


# ================= T5 =================

class StateSaveGuaranteeTests(TmpDirTestCase):
    def _prep_state_and_snapshot(self):
        self.state_path.write_text(valid_state_text({"lobby": {"last_seq": 100, "bytes": 100, "idle_seconds": 0}}))
        state = rr.load_state(self.state_path)
        args = rr.parse_args(["--state", str(self.state_path)])
        config = rr.load_config(None)
        return args, config, state

    def _current_snapshot_patch(self):
        body = rooms_body([room_entry("lobby", 150, nbytes=150)])
        return mock.patch.object(rr, "fetch_rooms", return_value=body)

    def test_compute_ranking_exception_still_saves_state(self):
        args, config, state = self._prep_state_and_snapshot()
        with self._current_snapshot_patch(), \
             mock.patch.object(rr, "compute_ranking", side_effect=RuntimeError("boom")):
            rc = rr._run(args, config, state)
        self.assertNotEqual(rc, 0)
        data = json.loads(self.state_path.read_text())
        self.assertEqual(data["rooms"]["lobby"]["last_seq"], 150)

    def test_fetch_pulse_exception_still_saves_state(self):
        args, config, state = self._prep_state_and_snapshot()
        with self._current_snapshot_patch(), \
             mock.patch.object(rr, "fetch_pulse_summary_safe", side_effect=RuntimeError("boom")):
            rc = rr._run(args, config, state)
        self.assertNotEqual(rc, 0)
        data = json.loads(self.state_path.read_text())
        self.assertEqual(data["rooms"]["lobby"]["last_seq"], 150)

    def test_render_message_exception_still_saves_state(self):
        # round13 must-fix: render_message() runs AFTER fetch_pulse_summary_safe()
        # in _run() -- leaving fetch_pulse_summary_safe unmocked here meant it
        # ran for real and reached real _http_get/urlopen against production
        # technocore.chat. Mock it explicitly (its own behavior is already
        # covered by FetchPulseSummarySafeTests).
        args, config, state = self._prep_state_and_snapshot()
        with self._current_snapshot_patch(), \
             mock.patch.object(rr, "fetch_pulse_summary_safe", return_value=None), \
             mock.patch.object(rr, "render_message", side_effect=RuntimeError("boom")):
            rc = rr._run(args, config, state)
        self.assertNotEqual(rc, 0)
        data = json.loads(self.state_path.read_text())
        self.assertEqual(data["rooms"]["lobby"]["last_seq"], 150)

    def test_post_with_retry_exception_still_saves_state(self):
        args, config, state = self._prep_state_and_snapshot()
        with self._current_snapshot_patch(), \
             mock.patch.object(rr, "fetch_pulse_summary_safe", return_value=None), \
             mock.patch.object(rr, "post_with_retry", side_effect=RuntimeError("boom")):
            rc = rr._run(args, config, state)
        self.assertNotEqual(rc, 0)
        data = json.loads(self.state_path.read_text())
        self.assertEqual(data["rooms"]["lobby"]["last_seq"], 150)

    def test_post_with_retry_false_still_saves_state_nonzero_exit(self):
        args, config, state = self._prep_state_and_snapshot()
        with self._current_snapshot_patch(), \
             mock.patch.object(rr, "fetch_pulse_summary_safe", return_value=None), \
             mock.patch.object(rr, "post_with_retry", return_value=False):
            rc = rr._run(args, config, state)
        self.assertEqual(rc, 1)
        data = json.loads(self.state_path.read_text())
        self.assertEqual(data["rooms"]["lobby"]["last_seq"], 150)

    def test_post_with_retry_true_saves_state_zero_exit(self):
        args, config, state = self._prep_state_and_snapshot()
        with self._current_snapshot_patch(), \
             mock.patch.object(rr, "fetch_pulse_summary_safe", return_value=None), \
             mock.patch.object(rr, "post_with_retry", return_value=True):
            rc = rr._run(args, config, state)
        self.assertEqual(rc, 0)
        data = json.loads(self.state_path.read_text())
        self.assertEqual(data["rooms"]["lobby"]["last_seq"], 150)


class DryRunTests(TmpDirTestCase):
    def test_case_a_new_state_no_file_created_no_signing(self):
        # round12 must-fix: this dry-run path still calls fetch_rooms()/_http_get
        # BEFORE the "state is None" early-return (see _run()), so leaving
        # _http_get unmocked meant this test silently depended on a real
        # network call to production technocore.chat. Mock it explicitly.
        custom = self.tmpdir / "brand_new_state.json"
        self.assertFalse(custom.exists())
        body = rooms_body([room_entry("lobby", 100)])
        with mock.patch.object(rr, "_http_get", return_value=(200, body)) as http_get_mock, \
             mock.patch.object(rr, "sign_via_service") as sign_mock, \
             mock.patch.object(rr, "post_with_retry") as post_mock, \
             mock.patch.object(rr, "_http_get_once") as once_mock, \
             mock.patch.object(rr, "try_acquire_instance_lock", side_effect=rr.try_acquire_instance_lock) as lock_mock, \
             mock.patch.object(rr, "release_instance_lock", side_effect=rr.release_instance_lock) as unlock_mock:
            rc = rr.main(["--state", str(custom), "--dry-run"])
        self.assertEqual(rc, 0)
        http_get_mock.assert_called_once()
        self.assertFalse(custom.exists())
        sign_mock.assert_not_called()
        post_mock.assert_not_called()
        once_mock.assert_not_called()
        self.assertEqual(lock_mock.call_count, 1)
        self.assertEqual(unlock_mock.call_count, 1)

    def test_case_b_existing_state_preview_and_state_unchanged(self):
        self.state_path.write_text(valid_state_text({"lobby": {"last_seq": 100, "bytes": 100, "idle_seconds": 0}}))
        before = self.state_path.read_bytes()

        def http_get_stub(url, *a, **kw):
            if "/rooms" in url:
                return 200, rooms_body([room_entry("lobby", 150, nbytes=150)])
            if "d-technocore-pulse" in url:
                return 200, pulse_body(PULSE_TEXT_SAMPLE)
            return 200, json.dumps({"messages": []})

        with mock.patch("builtins.print") as print_mock, \
             mock.patch.object(rr, "_http_get", side_effect=http_get_stub), \
             mock.patch.object(rr, "sign_via_service") as sign_mock, \
             mock.patch.object(rr, "_http_get_once") as once_mock:
            rc = rr.main(["--state", str(self.state_path), "--dry-run"])

        self.assertEqual(rc, 0)
        after = self.state_path.read_bytes()
        self.assertEqual(before, after)
        sign_mock.assert_not_called()
        once_mock.assert_not_called()
        printed = " ".join(str(c.args[0]) for c in print_mock.call_args_list if c.args)
        self.assertIn("lobby", printed)


if __name__ == "__main__":
    unittest.main()
