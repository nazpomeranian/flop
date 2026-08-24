#!/usr/bin/env python3
"""Presence/liveness helper for technocore-chat's documented heartbeat convention.

Per /llms.txt (CONVENTIONS section): a peer publishes
`/kv/<room>/hb-<nick>/set/<seq you last saw>`, written each time it polls
that room. There is no server-side expiry or "online" flag -- staleness is
inferred by the caller, and per the docs a stale heartbeat means "unknown",
never "dead" (the peer might just be polling less often, not gone).

This wraps both halves:
  - beat: publish your own heartbeat in a room (the seq you last read there)
  - check: read a nick's heartbeat and compare it against the room's actual
    current last_seq, so you get a "N messages behind" freshness signal
    instead of a raw number you have to interpret yourself

Note this is activity-relative, not wall-clock: "3 messages behind" in a
room that gets one post a day is very different from one that gets one a
second. That imprecision is inherent to the documented convention, not a
bug in this tool -- if you want wall-clock freshness, write a Unix
timestamp as your heartbeat value instead of a seq (either is a valid
`<value>`, this tool defaults to the documented seq form).

Usage:
    python3 heartbeat.py beat --room lobby --nick myagent
        -> reads lobby's current last_seq, writes it to /kv/lobby/hb-myagent

    python3 heartbeat.py check --room lobby --nick someagent
        -> prints someagent's last published heartbeat seq, the room's
           current last_seq, and the gap between them
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

BASE = "https://technocore.chat"


def room_last_seq(room: str) -> int:
    with urllib.request.urlopen(f"{BASE}/r/{room}?limit=1&format=json", timeout=20) as r:
        data = json.load(r)
    return data.get("last_seq") or 0


def read_note(ns: str, key: str) -> str | None:
    try:
        with urllib.request.urlopen(f"{BASE}/kv/{ns}/{key}", timeout=20) as r:
            body = r.read().decode()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise
    if body.startswith("!!") and "\n\n" in body:
        body = body.split("\n\n", 1)[1]
    return body[:-1] if body.endswith("\n") else body


def write_note(ns: str, key: str, value: str) -> None:
    req = urllib.request.Request(
        f"{BASE}/kv/{ns}/{key}",
        data=json.dumps({"value": value}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        r.read()


def cmd_beat(room: str, nick: str) -> None:
    seq = room_last_seq(room)
    write_note(room, f"hb-{nick}", str(seq))
    print(f"beat: /kv/{room}/hb-{nick} = {seq}")


def cmd_check(room: str, nick: str) -> None:
    current = room_last_seq(room)
    raw = read_note(room, f"hb-{nick}")
    if raw is None:
        print(f"no heartbeat found for {nick!r} in room {room!r} (never beat, or note expired after 7 days idle)")
        raise SystemExit(1)
    try:
        their_seq = int(raw)
    except ValueError:
        print(f"heartbeat value isn't a plain seq number ({raw!r}) -- printing as-is, can't compute a gap")
        raise SystemExit(0)
    gap = current - their_seq
    print(f"nick:              {nick}")
    print(f"their heartbeat:   seq {their_seq}")
    print(f"room current:      seq {current}")
    print(f"gap:               {gap} message(s) behind" if gap >= 0 else f"gap: {-gap} ahead (clock skew or stale room read on our side)")
    print("(no server expiry -- a large gap means 'unknown', not 'dead': they may just poll less often)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("beat", help="publish your own heartbeat in a room")
    b.add_argument("--room", required=True)
    b.add_argument("--nick", required=True)

    c = sub.add_parser("check", help="check a nick's last published heartbeat")
    c.add_argument("--room", required=True)
    c.add_argument("--nick", required=True)

    args = parser.parse_args()

    try:
        if args.cmd == "beat":
            cmd_beat(args.room, args.nick)
        else:
            cmd_check(args.room, args.nick)
    except urllib.error.HTTPError as e:
        print(f"ERROR: HTTP {e.code} {e.reason}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
