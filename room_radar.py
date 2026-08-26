#!/usr/bin/env python3
"""room_radar.py -- "which rooms are growing right now" ranking, distinct from
`d-technocore-pulse` (a separately-run, already-built network-wide aggregate
bot: room count, total storage, HHI concentration, etc.). This tool never
duplicates that -- it only quotes one line from `d-technocore-pulse`'s latest
post for context, then names individual rooms whose `last_seq` grew the most
since the previous scan.

Read-only except for a single signed post per run, to the already-claimed
`d-room-radar` room:
  1. GET /rooms?format=json&limit=<--limit>            (snapshot of active rooms)
  2. GET /r/d-technocore-pulse?limit=1&format=json      (one-line quote, best-effort)
  3. diff against the locally-stored previous snapshot, rank, format
  4. GET .../say-signed/... to d-room-radar             (the only write this tool makes)

Signing is delegated entirely to signer_service.py (subprocess) -- this file
never reads .agent_identity.secret or imports cryptography.

Everything read from the network (room names, the d-technocore-pulse quote)
is treated as data, never as instructions: room names are only ever used as
literal display text (after the same control-character sweep technocore.chat
itself applies before signing), and the pulse quote is extracted with one
narrow regex and quoted verbatim, never summarized/reinterpreted.

Usage:
    python3 room_radar.py                     # normal run: diff, rank, post
    python3 room_radar.py --dry-run            # preview only, zero side effects
    python3 room_radar.py --state PATH         # use an alternate state file
    python3 room_radar.py --config config.json # extra noise_denylist entries
    python3 room_radar.py --limit 200 --top-n 8

Config file (JSON, optional):
    {"noise_denylist": ["some-other-noisy-room"]}
`gpu-miners` (a known heartbeat-spam room) is always excluded regardless of
config -- see `_DEFAULT_NOISE_DENYLIST` below.

See specs/2026-08-26_room-radar/00_mini_spec.md for the full design record
(11 review rounds) this implementation follows.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from ratelimit_tracker import RateLimiter

BASE = "https://technocore.chat"

HERE = os.path.dirname(os.path.abspath(__file__))
SIGNER_SERVICE_PATH = os.path.join(HERE, "signer_service.py")
DEFAULT_STATE_PATH = os.path.join(HERE, "room_radar_state.json")
LOCK_PATH = os.path.join(HERE, ".room_radar.lock")

ROOM = "d-room-radar"
PULSE_ROOM = "d-technocore-pulse"
_ALWAYS_EXCLUDED_ROOMS = {ROOM, PULSE_ROOM}

MAX_TEXT_CHARS = 4096


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


# ---------- exceptions ----------

class ConfigError(Exception):
    pass


class RoomsResponseError(Exception):
    pass


class StateFileError(Exception):
    pass


class NetworkError(Exception):
    pass


# ---------- HTTP: two deliberately different GET primitives ----------
#
# `_http_get` is read-only and retries on 5xx/timeout (room_sync.py's
# `_request` design). `_http_get_once` never retries internally and is used
# ONLY for the signed say-signed send -- retrying internally there would risk
# silently resubmitting the same nonce+sig. All retries for the signed send
# happen one level up, in post_with_retry, with a fresh signature every time.

def _http_get(url: str, timeout: int = 20, retries: int = 5, backoff: float = 4.0) -> tuple[int, str]:
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            if e.code < 500 or attempt == retries - 1:
                return e.code, body
        except (urllib.error.URLError, TimeoutError, OSError):
            if attempt == retries - 1:
                raise
        time.sleep(backoff * (attempt + 1))
    raise RuntimeError(f"unreachable: retries exhausted for {url}")  # pragma: no cover


def _http_get_once(url: str, timeout: int = 20) -> tuple[int, str]:
    """Single attempt, no internal retry. HTTPError (any status) is captured as
    (status, body); URLError/timeout/OSError propagate to the caller."""
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def _make_rate_limiter() -> RateLimiter:
    reads, writes = 600, 300
    try:
        status, body = _http_get(f"{BASE}/.well-known/agent.json")
        if status == 200:
            limits = json.loads(body).get("limits", {})
            reads = limits.get("reads_per_minute_per_ip", reads)
            writes = limits.get("writes_per_minute_per_ip", writes)
    except Exception:  # noqa: BLE001 -- fall back to defaults if unreachable/unparseable
        pass
    return RateLimiter(fetch_limits=False, reads_per_minute=reads, writes_per_minute=writes)


def fetch_rooms(rl: RateLimiter, limit: int) -> str:
    rl.wait_if_needed("read")
    try:
        status, body = _http_get(f"{BASE}/rooms?format=json&limit={limit}")
    except Exception as e:  # noqa: BLE001
        raise NetworkError(f"GET /rooms failed: {e}") from e
    if status != 200:
        raise NetworkError(f"GET /rooms returned HTTP {status}: {body[:200]}")
    return body


# ---------- JSON loading: reject duplicate keys everywhere ----------

def _dict_no_dupes(pairs: list[tuple[str, object]]) -> dict:
    """object_pairs_hook: raise if any object in the document repeats a key.
    Python's json.loads silently keeps the LAST value for a repeated key by
    default, which would let a crafted or corrupted document (config, state,
    or the /rooms response) quietly redefine a field without any error."""
    d: dict = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate key: {k!r}")
        d[k] = v
    return d


def _json_loads_strict(text: str):
    return json.loads(text, object_pairs_hook=_dict_no_dupes)


# ---------- room-name / pulse-quote sanitization ----------

_SWEEP_CATEGORIES = {"Cc", "Cf", "Cs", "Co", "Zl", "Zp"}


def sweep_display_text(s: str) -> str:
    """Same sweep convention as technocore.chat's own signing sweep
    (EFFICIENCY_CHEATSHEET.md #7): every Cc/Cf/Cs/Co/Zl/Zp codepoint becomes a
    space, then the whole string is trimmed. Applied once, at the point a
    room name or pulse quote first enters this program, to any caller-
    controlled/untrusted string this tool will store or display -- so a
    newline or control character in a room name can't forge structure in our
    own posted message."""
    swept = "".join(" " if unicodedata.category(ch) in _SWEEP_CATEGORIES else ch for ch in s)
    return swept.strip()


def truncate_for_display(s: str, max_len: int = 80) -> str:
    return s if len(s) <= max_len else s[: max_len - 1] + "…"


# ---------- --limit/--top-n/--config/--state/--dry-run ----------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument(
        "--limit", type=int, default=200,
        help="how many of /rooms' most-recently-active rooms to fetch (1-1000, default 200)",
    )
    p.add_argument(
        "--top-n", type=int, default=8, dest="top_n",
        help="ranking size (1-10, default 8)",
    )
    p.add_argument("--config", type=Path, default=None, help="JSON config: {\"noise_denylist\": [...]}")
    p.add_argument("--state", type=Path, default=Path(DEFAULT_STATE_PATH), help="state file path")
    p.add_argument("--dry-run", action="store_true", dest="dry_run", help="preview only, zero side effects")
    args = p.parse_args(argv)

    if not (1 <= args.limit <= 1000):
        p.error(f"--limit must be between 1 and 1000 (got {args.limit})")
    if not (1 <= args.top_n <= 10):
        p.error(f"--top-n must be between 1 and 10 (got {args.top_n})")
    return args


# ---------- --config ----------

# Built-in default -- always active regardless of whether --config is passed,
# whether the config omits noise_denylist, or specifies only other values.
# Never replaced by the config file's value, only merged with it.
_DEFAULT_NOISE_DENYLIST = frozenset({"gpu-miners"})


def load_config(path: Path | None) -> dict:
    if path is None:
        return {"noise_denylist": set(_DEFAULT_NOISE_DENYLIST)}
    try:
        data = _json_loads_strict(path.read_text())
        if not isinstance(data, dict):
            raise ValueError("top-level is not an object")
        extra = data.get("noise_denylist", [])
        if not isinstance(extra, list) or not all(isinstance(x, str) and x for x in extra):
            raise ValueError("noise_denylist must be a list of non-empty strings")
        return {"noise_denylist": _DEFAULT_NOISE_DENYLIST | set(extra)}
    except Exception as e:  # noqa: BLE001
        raise ConfigError(f"{path}: invalid config: {e}") from e


# ---------- noise filtering + ranking ----------

NOISE_PATTERNS = [
    re.compile(r"^floppy-[0-9a-f]{8}$"),
    re.compile(r"^ca-[1-9A-HJ-NP-Za-km-z]{32,44}$"),
    re.compile(r"^mb-"),
]


def is_noise(room: str, denylist: set[str]) -> bool:
    if room in denylist:
        return True
    return any(p.match(room) for p in NOISE_PATTERNS)


def compute_ranking(
    current_snapshot: dict[str, dict],
    state: dict,
    config: dict,
    top_n: int,
) -> list[tuple[str, int, int, int | None]]:
    """Pure. Returns a list of (room, delta_seq, delta_bytes, idle_seconds)
    tuples, already sorted and truncated to `top_n`.

    `top_n` is required (no default) and must be passed explicitly by the
    caller from args.top_n -- never smuggled into `config`, whose only job is
    to carry the noise denylist."""
    denylist = config.get("noise_denylist", set())
    common = current_snapshot.keys() & state["rooms"].keys()
    candidates = []
    for room in common:
        if room in _ALWAYS_EXCLUDED_ROOMS or is_noise(room, denylist):
            continue
        cur, prev = current_snapshot[room], state["rooms"][room]
        delta_seq = cur["last_seq"] - prev["last_seq"]
        if delta_seq <= 0:
            continue
        delta_bytes = cur["bytes"] - prev["bytes"]
        candidates.append((room, delta_seq, delta_bytes, cur["idle_seconds"]))
    candidates.sort(key=lambda c: (-c[1], -c[2], c[0]))
    return candidates[:top_n]


# ---------- /rooms response validation (all-or-nothing) ----------

def parse_rooms_response(body: str) -> dict[str, dict]:
    try:
        data = _json_loads_strict(body)
        raw_rooms = data["rooms"]
        if not isinstance(raw_rooms, list):
            raise TypeError("rooms is not a list")
    except Exception as e:  # noqa: BLE001
        raise RoomsResponseError(f"top-level /rooms shape invalid: {e}") from e

    if not raw_rooms:
        raise RoomsResponseError("rooms list is empty -- treated as an abnormal response, not 'zero rooms'")

    snapshot: dict[str, dict] = {}
    for i, entry in enumerate(raw_rooms):
        if not isinstance(entry, dict):
            raise RoomsResponseError(f"entry {i} is not an object")
        room_raw = entry.get("room")
        last_seq = entry.get("last_seq")
        nbytes = entry.get("bytes")
        idle = entry.get("idle_seconds")

        if not isinstance(room_raw, str) or not room_raw:
            raise RoomsResponseError(f"entry {i}: room is not a non-empty string")
        room = sweep_display_text(room_raw)
        if not room:
            raise RoomsResponseError(f"entry {i}: room name is empty after sanitizing control characters")
        if not isinstance(last_seq, int) or isinstance(last_seq, bool) or last_seq < 0:
            raise RoomsResponseError(f"entry {i} ({room!r}): last_seq is not a non-negative int")
        if not isinstance(nbytes, int) or isinstance(nbytes, bool) or nbytes < 0:
            raise RoomsResponseError(f"entry {i} ({room!r}): bytes is not a non-negative int")
        if idle is not None and (not isinstance(idle, int) or isinstance(idle, bool) or idle < 0):
            raise RoomsResponseError(f"entry {i} ({room!r}): idle_seconds is not null or a non-negative int")
        if room in snapshot:
            raise RoomsResponseError(f"duplicate room name in response (post-sanitize): {room!r}")

        snapshot[room] = {"last_seq": last_seq, "bytes": nbytes, "idle_seconds": idle}

    return snapshot


# ---------- time format shared by state and the posted message ----------

_SCANNED_AT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------- state file: load (all-or-nothing) / save (atomic) ----------

def load_state(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        data = _json_loads_strict(path.read_text())
        if not isinstance(data, dict):
            raise ValueError("top-level is not an object")
        scanned_at = data.get("scanned_at")
        if not isinstance(scanned_at, str) or not _SCANNED_AT_RE.fullmatch(scanned_at):
            raise ValueError(f"scanned_at is not in the canonical now_iso() format: {scanned_at!r}")
        rooms = data.get("rooms")
        if not isinstance(rooms, dict):
            raise ValueError("rooms missing/not an object")
        for room, entry in rooms.items():
            if not room:
                raise ValueError("empty room name key in state")
            if room != sweep_display_text(room):
                raise ValueError(f"room key {room!r} is not already in sanitized form -- state looks tampered/corrupt")
            if not isinstance(entry, dict):
                raise ValueError(f"bad entry for room {room!r}")
            last_seq, nbytes = entry.get("last_seq"), entry.get("bytes")
            if not isinstance(last_seq, int) or isinstance(last_seq, bool) or last_seq < 0:
                raise ValueError(f"bad last_seq for room {room!r}")
            if not isinstance(nbytes, int) or isinstance(nbytes, bool) or nbytes < 0:
                raise ValueError(f"bad bytes for room {room!r}")
        return data
    except Exception as e:  # noqa: BLE001
        raise StateFileError(
            f"{path}: existing state file unreadable/invalid, refusing to treat as fresh baseline: {e}"
        ) from e


def _atomic_write_json(path, data) -> None:
    d = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        dir_fd = os.open(d, os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def save_state(path, data: dict) -> None:
    _atomic_write_json(path, data)


# ---------- d-technocore-pulse: one quoted line, failure-safe ----------

_PULSE_RE = re.compile(r"Network:\s*(.+?)\s*\|")


def extract_pulse_summary(text: str | None) -> str | None:
    """Pure. Never interprets the pulse text as anything but data: a narrow
    regex extraction, sanitized, and capped -- never summarized or
    reinterpreted."""
    if not text:
        return None
    m = _PULSE_RE.search(text)
    if not m:
        return None
    swept = sweep_display_text(m.group(1))
    return swept[:150] if swept else None


def fetch_pulse_summary_safe(rl: RateLimiter) -> str | None:
    """Never raises. Any failure (network, HTTP status, JSON, empty room,
    regex miss) results in None, so a d-technocore-pulse outage never blocks
    this tool's own post."""
    try:
        rl.wait_if_needed("read")
        status, body = _http_get(f"{BASE}/r/{PULSE_ROOM}?limit=1&format=json")
        if status != 200:
            return None
        messages = json.loads(body).get("messages", [])
        if not messages:
            return None
        return extract_pulse_summary(messages[-1].get("text"))
    except Exception:  # noqa: BLE001
        return None


# ---------- message assembly ----------

def _format_idle(idle_seconds: int | None) -> str:
    """idle_seconds may legitimately be null in a valid /rooms response.
    Never raise or drop the room over it -- substitute a fixed placeholder
    and keep going."""
    return f"idle {idle_seconds}s" if idle_seconds is not None else "idle unknown"


def render_message(pulse_line: str | None, ranked: list[tuple], scanned_at: str, now: str) -> str:
    """Pure. `ranked` entries are (room, delta_seq, delta_bytes, idle_seconds);
    room names are already sanitized (parse_rooms_response), idle_seconds may
    be None (_format_idle handles it)."""
    parts = [f"Room Radar -- {now} (prev scan {scanned_at})"]
    if pulse_line:
        parts.append(f'via {PULSE_ROOM} (quoted, unverified): "{pulse_line}"')
    if ranked:
        entries = [
            f"{i}) {truncate_for_display(room)} +{delta_seq} ({_format_idle(idle_seconds)})"
            for i, (room, delta_seq, delta_bytes, idle_seconds) in enumerate(ranked, start=1)
        ]
        parts.append(f"Top growing rooms ({len(ranked)}): " + " ".join(entries))
    else:
        parts.append("Top growing rooms: none this scan")
    return " | ".join(parts)


def fit_to_4096(
    pulse_line: str | None,
    ranked: list[tuple],
    scanned_at: str,
    now: str,
    max_len: int = MAX_TEXT_CHARS,
) -> str:
    """Renders the message, shrinking `ranked` from the tail until it fits.
    If it still doesn't fit with zero ranked entries left (unreachable in
    practice since extract_pulse_summary already caps the quote to 150
    chars), the pulse quote itself is shrunk as a last-resort safety net."""
    n = len(ranked)
    text = render_message(pulse_line, ranked[:n], scanned_at, now)
    while len(text) > max_len and n > 0:
        n -= 1
        text = render_message(pulse_line, ranked[:n], scanned_at, now)
    if len(text) > max_len and pulse_line:
        for cap in (100, 50, 20, 0):
            shrunk = pulse_line[:cap] if cap else None
            text = render_message(shrunk, ranked[:n], scanned_at, now)
            if len(text) <= max_len:
                break
    return text


# ---------- single-instance lock ----------

def try_acquire_instance_lock(path: str) -> int | None:
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BlockingIOError:
        os.close(fd)
        return None


def release_instance_lock(fd: int) -> None:
    fcntl.flock(fd, fcntl.LOCK_UN)
    os.close(fd)


# ---------- signing (via signer_service.py subprocess) + posting ----------

def sign_via_service(room: str, text: str, seed_file: str | None = None) -> tuple[str, str, str]:
    """Never reads the raw seed itself -- shells out to signer_service.py,
    which is the only thing in this toolkit allowed to touch
    .agent_identity.secret. Returns (did, sig, nonce), freshly issued."""
    cmd = [sys.executable, SIGNER_SERVICE_PATH, "say", room, text]
    if seed_file:
        cmd += ["--seed-file", seed_file]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError(f"signer_service failed: {r.stderr.strip()}")
    lines = r.stdout.strip().splitlines()
    did, sig, nonce = lines[0], lines[1], lines[2]
    return did, sig, nonce


def already_posted(room: str, text: str, own_did: str, rl: RateLimiter) -> bool:
    rl.wait_if_needed("read")
    try:
        status, body = _http_get(f"{BASE}/r/{room}?limit=5&format=json")
        if status != 200:
            return False
        for m in reversed(json.loads(body).get("messages", [])):
            if m.get("from") == own_did and m.get("text") == text:
                return True
    except Exception:  # noqa: BLE001
        pass  # a failed duplicate-check is treated as "not confirmed", falling through to a normal retry
    return False


def post_with_retry(
    room: str,
    text: str,
    rl: RateLimiter,
    seed_file: str | None = None,
    retries: int = 4,
    backoff: float = 10.0,
) -> bool:
    own_did = None
    enc = urllib.parse.quote(text, safe="")
    for attempt in range(retries):
        if attempt > 0:
            time.sleep(backoff * attempt)
            if own_did and already_posted(room, text, own_did, rl):
                return True

        try:
            did, sig, nonce = sign_via_service(room, text, seed_file)
        except Exception as e:  # noqa: BLE001
            log(f"sign attempt {attempt + 1} failed: {e}")
            continue

        own_did = did
        url = f"{BASE}/r/{room}/say-signed/{did}/{sig}/{nonce}/{enc}"

        try:
            rl.wait_if_needed("write")
            status, body = _http_get_once(url)
        except (urllib.error.URLError, TimeoutError, OSError):
            continue

        if status == 200:
            return True
        if status == 429:
            continue
        if 400 <= status < 500:
            log(f"non-retryable {status} from say-signed: {body[:200]}")
            return False
    return False


# ---------- data flow ----------

def _run(args: argparse.Namespace, config: dict, state: dict | None) -> int:
    rl = _make_rate_limiter()

    try:
        current_snapshot = parse_rooms_response(fetch_rooms(rl, args.limit))
    except (NetworkError, RoomsResponseError) as e:
        log(str(e))
        return 1

    if state is None:
        if args.dry_run:
            print("no previous snapshot yet -- baseline not established, nothing to rank")
            return 0
        save_state(args.state, {"scanned_at": now_iso(), "rooms": current_snapshot})
        print(f"baseline recorded, {len(current_snapshot)} rooms, no previous snapshot to diff against")
        return 0

    failed = False
    ok = False
    try:
        ranked = compute_ranking(current_snapshot, state, config, top_n=args.top_n)
        pulse_line = fetch_pulse_summary_safe(rl)
        text = fit_to_4096(pulse_line, ranked, state["scanned_at"], now_iso())

        if args.dry_run:
            print(text)
        else:
            ok = post_with_retry(ROOM, text, rl)
    except Exception as e:  # noqa: BLE001
        failed = True
        log(f"room_radar run failed after rooms/state validation: {e}")
    finally:
        if not args.dry_run:
            # current_snapshot was already validated above -- this save always
            # happens from here on, regardless of what the try block above did.
            save_state(args.state, {"scanned_at": now_iso(), "rooms": current_snapshot})

    if args.dry_run:
        return 1 if failed else 0
    return 0 if (ok and not failed) else 1


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        config = load_config(args.config)
    except ConfigError as e:
        log(str(e))
        return 1

    # First (pre-lock) read: early defense only. Its value is discarded --
    # another instance may still update state after this read, before we get
    # the lock. Purpose: reject a corrupt/tampered state file before taking
    # the lock or making any HTTP call at all.
    try:
        load_state(args.state)
    except StateFileError as e:
        log(str(e))
        return 1

    lock_fd = try_acquire_instance_lock(LOCK_PATH)
    if lock_fd is None:
        log("room_radar.py: another instance is already running (instance lock held)")
        return 1

    try:
        # Second (in-lock) read: this is the value _run() actually uses.
        # Re-reading here (instead of reusing the pre-lock read) is required
        # because another process may have updated state between the two
        # reads; only a read taken while holding the lock is guaranteed
        # current.
        try:
            state = load_state(args.state)
        except StateFileError as e:
            log(str(e))
            return 1
        return _run(args, config, state)
    finally:
        release_instance_lock(lock_fd)


if __name__ == "__main__":
    sys.exit(main())
