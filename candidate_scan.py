#!/usr/bin/env python3
"""candidate_scan.py -- read-only room/KV monitor that queues write
*candidates* for a human (or a later, separate approval step) to review.
It never writes anything to technocore-chat itself: every HTTP call in this
file goes through GET, via a single `_http_get`, and nothing in here ever
touches sign.py, signer_service.py or any secret file.

Detection rules (single dispatcher, fixed priority):
  room side  (dispatch_room_message):
    1. exclude own messages (msg["from"] == own_did)
    2. R2 -- self_mailbox_room: any message is a candidate
    3. R1 -- room in config["rooms"] AND own_did/own_fp mentioned in the text
    4. R3 -- room in config["keyword_rooms"] AND any keyword substring-matches
  KV side    (dispatch_kv_note):
    - (ns, key) in watched_notes -> R4 only (hash changed since last observed)
    - else ns in kv_namespaces and is_new_key -> R5 (namespace has a new key)

All candidates carry draft: null -- this tool never drafts a reply, it only
flags. Candidates are appended to candidates_queue.jsonl (deduped by id) and
never removed here.

Usage:
    python3 candidate_scan.py --config config.json               # scan + queue + persist state
    python3 candidate_scan.py --config config.json --dry-run      # scan + print candidates only

Config file (JSON):
    {
      "own_did": "did:key:...",
      "own_fp": "b6711fbd4361b2f8",
      "self_mailbox_room": "mb-b6711fbd4361b2f8",
      "rooms": ["lobby", "hyperliquid"],
      "keyword_rooms": ["lobby"],
      "keywords": ["technocore-agent"],
      "kv_namespaces": ["guides"],
      "watched_notes": ["did/b6711fbd4361b2f8"],
      "max_messages_per_room": 200
    }
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

from ratelimit_tracker import RateLimiter

BASE = "https://technocore.chat"

_HERE = os.path.dirname(os.path.abspath(__file__))
STATE_PATH = os.path.join(_HERE, "candidate_scan_state.json")
QUEUE_PATH = os.path.join(_HERE, "candidates_queue.jsonl")
QUEUE_LOCK_PATH = QUEUE_PATH + ".lock"
INSTANCE_LOCK_PATH = os.path.join(_HERE, ".candidate_scan.lock")

DEFAULT_MAX_MESSAGES_PER_ROOM = 200


# ---------- HTTP: the one and only place urlopen is called ----------

def _http_get(url: str, max_retries: int = 3, backoff: float = 2.0) -> tuple[int, str]:
    """Single GET call site (see module docstring). Retries on 5xx and on
    network/timeout errors -- a transient server hiccup must not take down
    an otherwise-healthy scan. 4xx (e.g. 404 for baseline detection) is
    returned immediately, never retried, since it's an expected outcome
    the callers already handle."""
    last_exc: Exception | None = None
    for attempt in range(max_retries):
        req = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            if e.code < 500 or attempt == max_retries - 1:
                return e.code, e.read().decode()
            last_exc = e
        except urllib.error.URLError as e:
            last_exc = e
            if attempt == max_retries - 1:
                raise
        time.sleep(backoff * (attempt + 1))
    raise last_exc  # pragma: no cover -- loop above always returns or raises first


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


def _strip_banner(body: str) -> str:
    if body.startswith("!!") and "\n\n" in body:
        body = body.split("\n\n", 1)[1]
    return body[:-1] if body.endswith("\n") else body


def _parse_kv_listing(body: str) -> set[str]:
    keys: set[str] = set()
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("!!"):
            continue
        keys.add(line.rsplit("/", 1)[-1])
    return keys


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hash_value(value: str | None) -> str | None:
    if value is None:
        return None
    return hashlib.sha256(value.encode()).hexdigest()


# ---------- id / record construction ----------

def kv_id(ns: str, key: str, new_value: str | None) -> str:
    marker = "D" if new_value is None else "V"
    payload = f"{ns}|{key}|{marker}|{new_value if new_value is not None else ''}"
    return "kv:" + hashlib.sha256(payload.encode()).hexdigest()


def _room_record(room: str, msg: dict, rule: str, reason: str) -> dict:
    seq = msg.get("seq")
    text = msg.get("text", "") or ""
    return {
        "id": f"room:{room}:{seq}",
        "detected_at": _now_iso(),
        "rule": rule,
        "target": {"room": room, "seq": seq, "from": msg.get("from"), "ts": msg.get("ts")},
        "reason": reason,
        "excerpt": text[:200],
        "draft": None,
        "status": "pending",
    }


def _kv_record(ns: str, key: str, new_value: str | None, old_hash, new_hash, rule: str, reason: str) -> dict:
    excerpt = "(deleted)" if new_value is None else new_value[:200]
    return {
        "id": kv_id(ns, key, new_value),
        "detected_at": _now_iso(),
        "rule": rule,
        "target": {"ns": ns, "key": key, "old_hash": old_hash, "new_hash": new_hash},
        "reason": reason,
        "excerpt": excerpt,
        "draft": None,
        "status": "pending",
    }


# ---------- dispatchers ----------

def dispatch_room_message(room: str, msg: dict, config: dict) -> dict | None:
    if msg.get("from") == config.get("own_did"):
        return None
    if room == config.get("self_mailbox_room"):
        return _room_record(room, msg, "R2", "message in own mailbox")
    if room in config.get("rooms", []):
        text = msg.get("text", "") or ""
        own_did = config.get("own_did") or ""
        own_fp = config.get("own_fp") or ""
        if (own_did and own_did in text) or (own_fp and own_fp in text):
            return _room_record(room, msg, "R1", "own DID/fingerprint mentioned")
    if room in config.get("keyword_rooms", []):
        text = msg.get("text", "") or ""
        for kw in config.get("keywords", []):
            if kw and kw in text:
                return _room_record(room, msg, "R3", f"keyword match: {kw!r}")
    return None


def dispatch_kv_note(
    ns: str,
    key: str,
    old_hash,
    new_value: str | None,
    is_new_key: bool,
    config: dict,
    watched_keys_set: set[str],
) -> dict | None:
    new_hash = _hash_value(new_value)
    note_id = f"{ns}/{key}"
    if note_id in watched_keys_set:
        if new_hash != old_hash:
            return _kv_record(ns, key, new_value, old_hash, new_hash, "R4", "watched note changed")
        return None
    if ns in config.get("kv_namespaces", []) and is_new_key:
        return _kv_record(ns, key, new_value, old_hash, new_hash, "R5", "new key in namespace")
    return None


# ---------- baseline ----------

def _is_baseline(state_section: dict, name: str) -> bool:
    return name not in state_section


def _target_rooms(config: dict) -> list[str]:
    rooms: set[str] = set(config.get("rooms", []))
    if config.get("self_mailbox_room"):
        rooms.add(config["self_mailbox_room"])
    rooms.update(config.get("keyword_rooms", []))
    return sorted(rooms)


# ---------- scanning ----------

def scan_room(room: str, state: dict, config: dict, rl: RateLimiter, max_messages: int = DEFAULT_MAX_MESSAGES_PER_ROOM):
    rooms_state = state.get("rooms", {})

    if _is_baseline(rooms_state, room):
        rl.wait_if_needed("read")
        status, body = _http_get(f"{BASE}/r/{room}?limit=1&format=json")
        rl.observe(body)
        if status != 200:
            raise RuntimeError(f"baseline read of room {room!r} failed: HTTP {status}")
        last_seq = json.loads(body).get("last_seq") or 0
        return [], last_seq

    since = rooms_state[room].get("last_processed_seq", 0)
    candidates: list[dict] = []
    evaluated_last_seq = since
    cursor = since
    remaining = max_messages

    while remaining > 0:
        page_limit = min(200, remaining)
        rl.wait_if_needed("read")
        status, body = _http_get(f"{BASE}/r/{room}?since={cursor}&limit={page_limit}&format=json")
        rl.observe(body)
        if status != 200:
            raise RuntimeError(f"read of room {room!r} failed: HTTP {status}")
        data = json.loads(body)
        msgs = data.get("messages", [])
        if not msgs:
            break
        for msg in msgs:
            if remaining <= 0:
                break
            rec = dispatch_room_message(room, msg, config)
            if rec is not None:
                candidates.append(rec)
            evaluated_last_seq = msg.get("seq", evaluated_last_seq)
            remaining -= 1
        cursor = msgs[-1].get("seq", cursor)
        if len(msgs) < page_limit:
            break

    return candidates, evaluated_last_seq


def scan_kv(config: dict, state: dict, rl: RateLimiter):
    candidates: list[dict] = []

    watched_notes = config.get("watched_notes", [])
    kv_namespaces = config.get("kv_namespaces", [])
    watched_keys_set = set(watched_notes)

    watched_state = state.get("watched_notes", {})
    updated_hashes = dict(watched_state)

    for note_id in watched_notes:
        ns, key = note_id.split("/", 1)
        rl.wait_if_needed("read")
        status, body = _http_get(f"{BASE}/kv/{ns}/{key}")
        rl.observe(body)
        if status == 404:
            new_value = None
        elif status == 200:
            new_value = _strip_banner(body)
        else:
            raise RuntimeError(f"watched note read {note_id!r} failed: HTTP {status}")

        if _is_baseline(watched_state, note_id):
            updated_hashes[note_id] = _hash_value(new_value)
            continue

        old_hash = watched_state[note_id]
        rec = dispatch_kv_note(ns, key, old_hash, new_value, False, config, watched_keys_set)
        if rec is not None:
            candidates.append(rec)
        updated_hashes[note_id] = _hash_value(new_value)

    kv_ns_state = state.get("kv_namespaces", {})
    updated_known_keys = {ns_name: dict(entry) for ns_name, entry in kv_ns_state.items()}

    for ns in kv_namespaces:
        rl.wait_if_needed("read")
        status, body = _http_get(f"{BASE}/kv/{ns}")
        rl.observe(body)
        if status == 404:
            listed_keys: set[str] = set()
        elif status == 200:
            listed_keys = _parse_kv_listing(body)
        else:
            raise RuntimeError(f"list of kv namespace {ns!r} failed: HTTP {status}")

        if _is_baseline(kv_ns_state, ns):
            updated_known_keys[ns] = {"known_keys": sorted(listed_keys)}
            continue

        known_keys = set(kv_ns_state[ns].get("known_keys", []))
        result_keys = set(known_keys)

        for key in sorted(listed_keys):
            if f"{ns}/{key}" in watched_keys_set:
                continue  # watched_notes owns this key permanently -- excluded from the R5 pool
            if key in known_keys:
                continue

            rl.wait_if_needed("read")
            kstatus, kbody = _http_get(f"{BASE}/kv/{ns}/{key}")
            rl.observe(kbody)
            if kstatus == 404:
                # round7: do NOT record into known_keys -- keep retrying next scan
                continue
            elif kstatus == 200:
                new_value = _strip_banner(kbody)
            else:
                raise RuntimeError(f"read of kv/{ns}/{key} failed: HTTP {kstatus}")

            rec = dispatch_kv_note(ns, key, None, new_value, True, config, watched_keys_set)
            if rec is not None:
                candidates.append(rec)
            result_keys.add(key)  # only recorded on a successful 200

        updated_known_keys[ns] = {"known_keys": sorted(result_keys)}

    return candidates, updated_known_keys, updated_hashes


# ---------- queue (JSONL, append-only, lock + dedup + fsync) ----------

def _read_queue_ids(path: str) -> set[str]:
    """Reads every line of the queue file and returns the set of ids.
    Raises ValueError on the first unparseable line -- including a
    genuinely blank one, position doesn't matter (spec 8.2) -- same rule
    _validate_complete_lines() enforces.

    Opened and split in binary mode on b"\\n" ONLY, matching
    _complete_lines_boundary()'s exact notion of "line" -- deliberately
    NOT `open(path)` text-mode iteration, whose default universal-newlines
    handling (newline=None) also treats a bare \\r as a line boundary. That
    would make this function's idea of "one line" diverge from the
    LF-only boundary the rest of this file (truncation/append) uses, the
    same class of mismatch str.splitlines() caused in
    _validate_complete_lines() (see that function's docstring)."""
    if not os.path.exists(path):
        return set()
    with open(path, "rb") as f:
        data = f.read()
    if not data:
        return set()
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines = lines[:-1]  # a lone trailing terminator, not a genuine blank final line
    ids: set[str] = set()
    for lineno, raw_line in enumerate(lines, 1):
        try:
            rec = json.loads(raw_line.decode())
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ValueError(f"{path}:{lineno}: invalid JSON in queue file: {e}")
        ids.add(rec["id"])
    return ids


def _complete_lines_boundary(data: bytes) -> int:
    """Pure computation (no file I/O, no mutation): the byte offset within
    `data` up to which the content is complete (newline-terminated) lines.
    Empty data, or data already ending in a newline, is entirely
    "complete" (boundary == len(data)). Otherwise the final, newline-less
    line (a prior crash mid-write) is excluded from the boundary."""
    if not data or data.endswith(b"\n"):
        return len(data)
    idx = data.rfind(b"\n")
    return idx + 1 if idx != -1 else 0


def _validate_complete_lines(data: bytes, path: str) -> set[str]:
    """Parses every line in `data` (expected to already be limited to a
    _complete_lines_boundary()-computed slice, so each line here is
    newline-terminated in the original file) as JSON, returning the set of
    ids. Raises ValueError on the first unparseable line -- including a
    genuinely blank one, same rule _read_queue_ids enforces -- and, being a
    pure in-memory computation over bytes the caller already read, never
    touches the file itself. The caller MUST NOT mutate the file until
    after this returns successfully (spec 8.2: an existing malformed line
    aborts with neither queue nor state changed).

    Line boundaries here MUST be LF-only (b"\\n"), matching
    _complete_lines_boundary()'s own notion of "line" exactly. Splitting
    via str.splitlines() instead (the previous implementation) is NOT
    equivalent: it additionally breaks on \\v, \\f, \\x1c-\\x1e, \\x85,
    \\u2028/\\u2029 -- so a single LF-delimited physical line containing an
    embedded \\x0b, e.g. b'{"id":"a"}\\x0b{"id":"b"}\\n', would be split
    into two individually-valid-looking JSON fragments and pass validation,
    even though the real line (LF-delimited, the only boundary the rest of
    this file's truncation/append logic recognizes) is not valid JSON at
    all (a JSON value followed by trailing "extra data" is a parse error)."""
    ids: set[str] = set()
    if not data:
        return ids
    lines = data.split(b"\n")
    # data is either empty (handled above) or ends with b"\n" -- guaranteed
    # by _complete_lines_boundary()'s contract -- so split(b"\n") always
    # yields exactly one trailing empty bytes-string for that final
    # terminator. Drop only that one; any OTHER empty entry is a
    # genuinely blank line and must still fail json.loads() below like any
    # other malformed line, not be silently treated as "no more lines".
    if lines and lines[-1] == b"":
        lines = lines[:-1]
    for lineno, raw_line in enumerate(lines, 1):
        try:
            rec = json.loads(raw_line.decode())
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ValueError(f"{path}:{lineno}: invalid JSON in queue file: {e}")
        ids.add(rec["id"])
    return ids


def queue_append(record: dict) -> bool:
    """Returns True if the record was newly appended, False if it was
    already present (dedup by id)."""
    lock_fd = os.open(QUEUE_LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        fd = os.open(QUEUE_PATH, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            # Read-only pass first: compute where a prior crash's incomplete
            # tail line (if any) begins, and validate every COMPLETE line
            # ahead of it as JSON -- all purely in memory, the file itself
            # is not touched yet. If any existing line fails to parse, this
            # raises here and queue_append returns having mutated nothing
            # at all (no ftruncate, no write). Only once validation has
            # fully succeeded do we proceed to actually mutate the file:
            # doing ftruncate() before validation (the previous, buggy
            # order) could drop the incomplete tail and only THEN discover
            # an unrelated pre-existing bad line, leaving the queue
            # mutated despite the abort.
            os.lseek(fd, 0, os.SEEK_SET)
            data = os.read(fd, os.fstat(fd).st_size)
            boundary = _complete_lines_boundary(data)
            existing_ids = _validate_complete_lines(data[:boundary], QUEUE_PATH)

            # Truncation and appending are two SEPARATE mutations from here on,
            # not one bundled behind the dedup check. Spec's queue_append order
            # is truncate -> dedup -> append: normalizing the incomplete tail
            # is unconditional once validation has passed, regardless of
            # whether this particular record turns out to be a duplicate.
            # (A prior version returned early on a dedup hit BEFORE
            # truncating, so a scan that only rediscovered an already-queued
            # id -- leaving state to advance normally -- would never clean up
            # a leftover corrupt/incomplete tail from an earlier crash;
            # nothing would ever call queue_append again for that same file
            # with a genuinely new id to trigger the cleanup.)
            if boundary != len(data):
                # Now safe to drop the incomplete tail -- validation above
                # already passed for everything ahead of it.
                os.ftruncate(fd, boundary)

            if record["id"] in existing_ids:
                return False  # truncation above still applies; just no new line

            line = (json.dumps(record) + "\n").encode()
            os.lseek(fd, boundary, os.SEEK_SET)
            written = os.write(fd, line)
            if written != len(line):
                # os.write() is permitted to write fewer bytes than asked (e.g. a
                # signal-interrupted write) -- treat that as a failure rather than
                # fsync + report success, or a truncated record would sit in the
                # queue looking like a real (but corrupt/partial) candidate. The
                # file is left with an incomplete trailing line, which the next
                # queue_append call's validate-then-truncate pass will clean up.
                raise OSError(
                    f"short write appending to {QUEUE_PATH}: wrote {written} of {len(line)} bytes"
                )
            os.fsync(fd)
            return True
        finally:
            os.close(fd)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


# ---------- state persistence ----------

def _atomic_write_json(path, data):
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


def _load_state(path: str) -> dict:
    if not os.path.exists(path):
        return {"rooms": {}, "kv_namespaces": {}, "watched_notes": {}}
    with open(path) as f:
        data = json.load(f)
    data.setdefault("rooms", {})
    data.setdefault("kv_namespaces", {})
    data.setdefault("watched_notes", {})
    return data


# ---------- single-instance lock ----------

def _acquire_instance_lock(path: str) -> int:
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise SystemExit("candidate_scan.py: another instance is already running (instance lock held)")
    return fd


def _release_instance_lock(fd: int) -> None:
    fcntl.flock(fd, fcntl.LOCK_UN)
    os.close(fd)


# ---------- main ----------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", required=True, help="path to the JSON config (see module docstring)")
    parser.add_argument("--dry-run", action="store_true", help="scan and print candidates, do not touch queue/state")
    parser.add_argument("--state", default=STATE_PATH, help="state file path (default: %(default)s)")
    parser.add_argument("--lock", default=INSTANCE_LOCK_PATH, help="single-instance lock file path")
    args = parser.parse_args()

    lock_fd = _acquire_instance_lock(args.lock)
    try:
        with open(args.config) as f:
            config = json.load(f)

        max_messages = config.get("max_messages_per_room", DEFAULT_MAX_MESSAGES_PER_ROOM)
        state = _load_state(args.state)
        rl = _make_rate_limiter()

        all_candidates: list[dict] = []
        room_new_seqs: dict[str, int] = {}

        for room in _target_rooms(config):
            candidates, new_seq = scan_room(room, state, config, rl, max_messages=max_messages)
            all_candidates.extend(candidates)
            room_new_seqs[room] = new_seq

        kv_candidates, updated_known_keys, updated_hashes = scan_kv(config, state, rl)
        all_candidates.extend(kv_candidates)

        if args.dry_run:
            for c in all_candidates:
                print(json.dumps(c))
            print(
                f"dry-run: {len(all_candidates)} candidate(s) detected, queue/state not modified",
                file=sys.stderr,
            )
            return

        appended = 0
        for c in all_candidates:
            if queue_append(c):
                appended += 1

        new_state = {
            "rooms": dict(state.get("rooms", {})),
            "kv_namespaces": updated_known_keys,
            "watched_notes": updated_hashes,
        }
        for room, seq in room_new_seqs.items():
            new_state["rooms"][room] = {"last_processed_seq": seq}

        _atomic_write_json(args.state, new_state)

        print(f"scan complete: {len(all_candidates)} candidate(s) detected, {appended} newly queued")
    finally:
        _release_instance_lock(lock_fd)


if __name__ == "__main__":
    main()
