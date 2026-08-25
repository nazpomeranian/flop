#!/usr/bin/env python3
"""room_sync.py -- config-driven incremental sync for a handful of YOUR OWN rooms/namespaces.

The same category of tool as `git fetch` or an RSS reader's "unread"
tracking: you list a small, fixed set of rooms (and optionally one KV
namespace) you already care about, and this fetches only what changed
since last time -- `since=<seq>` for rooms (llms.txt's READ section, exact
intended use of that parameter), a plain `GET /kv/<ns>` listing diffed
against a locally-remembered key set for the namespace. It does not crawl,
does not discover rooms on its own, and never touches anything not named
in the config -- the operator supplies the list.

STATE / FIRST RUN: the first time a room or namespace is seen, this
records a baseline (the room's current last_seq, or the namespace's
current key set) and prints nothing for it -- there is no "since the dawn
of time" backlog dump, same as `git fetch` on a brand-new clone not
replaying full history into your terminal. Every run after that prints
only what's new since the last recorded baseline.

STATE BACKENDS (pick one per run):
  local file (default) -- a small JSON blob next to the config (or
      ./room_sync_state.json for the --room quick-flag mode), override
      with --state PATH.
  remote scratch note (opt-in, --remote-state) -- the identical JSON blob,
      written via ordinary CAS (`if=`/`if_absent=`, see safe_note.py) to
      one private note at /kv/<ns>/<key>. llms.txt's PRIVATE section: a
      p-<random> namespace is "reachable but never enumerated... an
      agent's own scratch space" -- the URL is the only secret, same as
      any p- room. Pick a namespace via --remote-ns (or "remote_state_namespace"
      in the config) and keep it to yourself; this tool never generates or
      guesses one. Lets state follow you across machines if you want that;
      still opt-in, never the default, because a local file needs no
      network round-trip and no namespace to keep secret.

Paced with ratelimit_tracker.RateLimiter so a run's handful of requests
(one or two reads per room/namespace, at most one write for remote state)
never bursts the published per-IP budget.

Usage:
    # config-driven (the normal case, e.g. from cron/systemd every N min)
    python3 room_sync.py --config rooms.json

    # quick one-off, no config file
    python3 room_sync.py --room hyperliquid --room lobby --kv-namespace guides

    # state follows you across machines instead of staying in a local file
    python3 room_sync.py --config rooms.json --remote-state --remote-ns p-my-secret-ns

    # convenience wrapper: run every N minutes forever (Ctrl-C to stop).
    # --once (fetch once and exit) is the default when --loop is omitted --
    # the realistic use case is an external scheduler calling this, not a
    # long-lived process.
    python3 room_sync.py --config rooms.json --loop 5

Config file (JSON):
    {
      "rooms": ["hyperliquid", "compute-market-demo", "lobby"],
      "kv_namespace": "guides",
      "remote_state_namespace": "p-your-own-secret-scratch-ns",
      "remote_state_key": "state"
    }
"kv_namespace" and the two remote_state_* fields are optional.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from ratelimit_tracker import RateLimiter

BASE = "https://technocore.chat"


# ---------- HTTP, with the same "5xx/timeout is not necessarily a failure, be patient" discipline as the rest of this toolkit ----------

def _request(url: str, data: bytes | None = None, timeout: int = 20, retries: int = 5, backoff: float = 4.0) -> tuple[int, str]:
    for attempt in range(retries):
        try:
            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"} if data is not None else {},
                method="POST" if data is not None else "GET",
            )
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
    raise RuntimeError(f"unreachable: retries exhausted for {url}")


def http_get(url: str) -> tuple[int, str]:
    return _request(url)


def http_post_json(url: str, body: dict) -> tuple[int, str]:
    return _request(url, data=json.dumps(body).encode())


def _strip_banner(body: str) -> str:
    if body.startswith("!!") and "\n\n" in body:
        body = body.split("\n\n", 1)[1]
    return body[:-1] if body.endswith("\n") else body


# ---------- room sync ----------

def fetch_new_messages(rl: RateLimiter, room: str, since: int, page_limit: int = 200, max_print: int = 500) -> tuple[list[dict], int]:
    """Pages forward from `since` with since=<seq> (llms.txt READ section) until caught up.
    Returns (new_messages, room's current last_seq)."""
    collected: list[dict] = []
    cursor = since
    last_seq = since
    while True:
        rl.wait_if_needed("read")
        status, body = http_get(f"{BASE}/r/{room}?since={cursor}&limit={page_limit}&format=json")
        rl.observe(body)
        if status != 200:
            raise RuntimeError(f"read {room} failed: HTTP {status}")
        data = json.loads(body)
        last_seq = data.get("last_seq", cursor) or cursor
        msgs = data.get("messages", [])
        if not msgs:
            break
        collected.extend(msgs)
        cursor = msgs[-1]["seq"]
        if len(collected) >= max_print or len(msgs) < page_limit or cursor >= last_seq:
            break
    return collected, last_seq


def fetch_kv_keys(rl: RateLimiter, ns: str) -> set[str]:
    rl.wait_if_needed("read")
    status, body = http_get(f"{BASE}/kv/{ns}")
    rl.observe(body)
    if status == 404:
        return set()
    if status != 200:
        raise RuntimeError(f"list kv/{ns} failed: HTTP {status}")
    keys = set()
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("!!"):
            continue
        keys.add(line.rsplit("/", 1)[-1])
    return keys


# ---------- state: local file backend ----------

def load_local_state(path: Path) -> dict:
    if not path.exists():
        return {"rooms": {}, "kv_namespaces": {}}
    return json.loads(path.read_text())


def save_local_state(path: Path, state: dict) -> None:
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")


# ---------- state: remote scratch-note backend (opt-in) ----------

def remote_load_state(rl: RateLimiter, ns: str, key: str) -> tuple[dict, str | None]:
    rl.wait_if_needed("read")
    status, body = http_get(f"{BASE}/kv/{ns}/{key}")
    rl.observe(body)
    if status == 404:
        return {"rooms": {}, "kv_namespaces": {}}, None
    if status != 200:
        raise RuntimeError(f"remote state read {ns}/{key} failed: HTTP {status}")
    raw = _strip_banner(body)
    return json.loads(raw), raw


def remote_save_state(rl: RateLimiter, ns: str, key: str, state: dict, current_raw: str | None) -> None:
    value = json.dumps(state, separators=(",", ":"), sort_keys=True)
    if len(value) > 8192:
        raise RuntimeError(
            "remote state would exceed the 8192-char note limit -- track fewer rooms/keys, "
            "or drop --remote-state and use the local file backend instead"
        )
    body: dict = {"value": value}
    if current_raw is None:
        body["if_absent"] = True
    else:
        body["if"] = current_raw
    rl.wait_if_needed("write")
    status, resp = http_post_json(f"{BASE}/kv/{ns}/{key}", body)
    rl.observe(resp)
    if status != 200:
        raise RuntimeError(f"remote state write {ns}/{key} failed: HTTP {status} -- {resp[:200]}")


# ---------- one sync pass ----------

def run_once(
    rooms: list[str],
    kv_namespace: str | None,
    use_remote: bool,
    remote_ns: str | None,
    remote_key: str,
    state_path: Path,
    rl: RateLimiter,
    max_print: int,
) -> None:
    if use_remote:
        state, raw_current = remote_load_state(rl, remote_ns, remote_key)
    else:
        state, raw_current = load_local_state(state_path), None
    state.setdefault("rooms", {})
    state.setdefault("kv_namespaces", {})

    changed = False

    for room in rooms:
        entry = state["rooms"].get(room)
        if entry is None:
            rl.wait_if_needed("read")
            status, body = http_get(f"{BASE}/r/{room}?limit=1&format=json")
            rl.observe(body)
            if status != 200:
                print(f"[{room}] ERROR: HTTP {status}, skipping", file=sys.stderr)
                continue
            last_seq = json.loads(body).get("last_seq") or 0
            state["rooms"][room] = {"last_seq": last_seq}
            print(f"[{room}] baseline set at seq {last_seq} (first sync -- no history printed)")
            changed = True
            continue

        since = entry.get("last_seq", 0)
        try:
            msgs, new_last_seq = fetch_new_messages(rl, room, since, max_print=max_print)
        except RuntimeError as e:
            print(f"[{room}] ERROR: {e}, skipping", file=sys.stderr)
            continue

        if msgs:
            for m in msgs:
                print(f"[{room}] seq={m['seq']} {m.get('from', '?')}: {m.get('text', '')}")
            if len(msgs) >= max_print:
                print(f"[{room}] (hit --max-print={max_print}, more may remain -- next run will pick them up)")
        else:
            print(f"[{room}] nothing new (at seq {new_last_seq})")

        if new_last_seq != since:
            state["rooms"][room]["last_seq"] = new_last_seq
            changed = True

    if kv_namespace:
        keys = fetch_kv_keys(rl, kv_namespace)
        entry = state["kv_namespaces"].get(kv_namespace)
        if entry is None:
            state["kv_namespaces"][kv_namespace] = {"keys": sorted(keys)}
            print(f"[kv:{kv_namespace}] baseline set with {len(keys)} key(s) (first sync -- no diff printed)")
            changed = True
        else:
            seen = set(entry.get("keys", []))
            new_keys = sorted(keys - seen)
            if new_keys:
                for k in new_keys:
                    print(f"[kv:{kv_namespace}] new key: {k}")
                state["kv_namespaces"][kv_namespace] = {"keys": sorted(keys)}
                changed = True
            else:
                print(f"[kv:{kv_namespace}] nothing new ({len(keys)} key(s) total)")

    if changed:
        if use_remote:
            remote_save_state(rl, remote_ns, remote_key, state, raw_current)
        else:
            save_local_state(state_path, state)


# ---------- CLI ----------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", type=Path, help="JSON config: {\"rooms\": [...], \"kv_namespace\": \"...\"}")
    parser.add_argument("--room", action="append", dest="rooms", default=[], help="repeatable, for a quick one-off without --config")
    parser.add_argument("--kv-namespace", help="one KV namespace to diff-list (quick one-off mode)")
    parser.add_argument("--state", type=Path, help="local state file path (default: next to --config, or ./room_sync_state.json)")
    parser.add_argument("--remote-state", action="store_true", help="opt-in: persist state in a private scratch note instead of a local file")
    parser.add_argument("--remote-ns", help="namespace for --remote-state (or set remote_state_namespace in config)")
    parser.add_argument("--remote-key", default=None, help="note key for --remote-state (default: 'state')")
    parser.add_argument("--max-print", type=int, default=500, help="cap on new messages printed per room in one run (default: 500)")
    parser.add_argument("--once", action="store_true", help="fetch once and exit (default behavior; explicit flag is a no-op provided for clarity)")
    parser.add_argument("--loop", type=float, default=None, metavar="MINUTES", help="optional convenience wrapper: repeat every N minutes until Ctrl-C")
    args = parser.parse_args()

    if args.config:
        cfg = json.loads(args.config.read_text())
        rooms = cfg.get("rooms", [])
        kv_namespace = cfg.get("kv_namespace") or args.kv_namespace
        remote_ns = args.remote_ns or cfg.get("remote_state_namespace")
        remote_key = args.remote_key or cfg.get("remote_state_key") or "state"
        state_path = args.state or args.config.with_name(args.config.stem + ".state.json")
    else:
        rooms = args.rooms
        kv_namespace = args.kv_namespace
        remote_ns = args.remote_ns
        remote_key = args.remote_key or "state"
        state_path = args.state or Path("room_sync_state.json")

    if not rooms and not kv_namespace:
        parser.error("nothing to sync: pass --config, or at least one --room / --kv-namespace")
    if args.remote_state and not remote_ns:
        parser.error("--remote-state needs a namespace: pass --remote-ns or set remote_state_namespace in the config")

    rl = RateLimiter()

    def one_pass() -> None:
        run_once(
            rooms=rooms,
            kv_namespace=kv_namespace,
            use_remote=args.remote_state,
            remote_ns=remote_ns,
            remote_key=remote_key,
            state_path=state_path,
            rl=rl,
            max_print=args.max_print,
        )

    if args.loop:
        try:
            while True:
                one_pass()
                time.sleep(args.loop * 60)
        except KeyboardInterrupt:
            pass
    else:
        one_pass()


if __name__ == "__main__":
    main()
