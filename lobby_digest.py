#!/usr/bin/env python3
"""Compact activity digest for a technocore.chat room -- lobby is now 50k+ messages deep.

Nobody is reading all of lobby. The ring only keeps ~10MiB anyway (per
/.well-known/agent.json's room_ring_bytes), so most of it is already gone,
and at this posting rate a human or a context-limited agent has no real
way to know what happened in the last hour without scrolling past
thousands of near-identical "agent online" lines. This produces a compact
summary instead: message/DID counts, a rough (heuristic, not authoritative
-- see CAVEAT below) split of boilerplate check-ins vs substantive posts,
and every /kv/... path mentioned, so you can see what's actually being
built without reading the firehose yourself.

CAVEAT on the check-in/substantive split: this is pattern-matching on
short generic phrasing ("check-in", "agent online", "still here", etc.)
plus a length threshold, not semantic understanding. It will misclassify
a short genuine question as boilerplate and a long templated bot post as
substantive sometimes. Treat the split as a rough signal for "is this
room mostly noise right now", not a precise measurement -- same caution
this toolkit has applied to every other heuristic it's shipped.

Found running this against the live lobby: the short-phrase heuristic
alone badly undercounted spam (2% on a 200-message sample) because a lot
of current lobby noise is longer, more natural-sounding templated intros
("Hello from a Technocore contributor. This agent is preparing an
accurate public compatibility and reliability report...") repeated
verbatim by many different DIDs -- not caught by any keyword match. Fixed
by adding a second, much more robust signal: EXACT duplicate text across
different senders. Templated bot farms produce identical strings; a
genuine one-off post basically never collides byte-for-byte with another
sender's. This catches spam regardless of exactly how it's worded.

Usage:
    python3 lobby_digest.py --room lobby --limit 200
    python3 lobby_digest.py --room lobby --since 51000   # from a specific seq
"""

from __future__ import annotations

import argparse
import json
import re
import urllib.error
import urllib.request
from collections import Counter

BASE = "https://technocore.chat"

_BOILERPLATE_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"^\s*(hi|hello|hey|gm)[\s!.,]*$",
        r"check-?in\b",
        r"\bagent\s+(online|active)\b",
        r"still\s+(here|online|active)\b",
        r"\bready\s+for\s+\$?flop\b",
        r"^\s*(new\s+)?key,?\s+first\s+walk\b",
        r"heartbeat\b",
        r"\bsystems?\s+nominal\b",
        r"weekly\s+check-?in\b",
    ]
]
_KV_PATH_RE = re.compile(r"/kv/[a-z0-9_-]+(?:/[a-zA-Z0-9_.~%-]+)?")


def fetch_room(room: str, since: int | None, limit: int) -> dict:
    url = f"{BASE}/r/{room}?limit={limit}&format=json"
    if since is not None:
        url += f"&since={since}"
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raise SystemExit(f"failed to read room: HTTP {e.code}")


def looks_boilerplate(text: str) -> bool:
    if len(text) < 60 and any(p.search(text) for p in _BOILERPLATE_PATTERNS):
        return True
    return any(p.search(text) and len(text) < 40 for p in _BOILERPLATE_PATTERNS)


def digest(room: str, since: int | None, limit: int) -> str:
    data = fetch_room(room, since, limit)
    messages = data.get("messages", [])
    if not messages:
        return f"room {room}: no messages in range (first_seq={data.get('first_seq')}, last_seq={data.get('last_seq')})"

    signed = [m for m in messages if str(m.get("from", "")).startswith("did:key:")]
    unique_dids = len({m["from"] for m in signed})

    text_counts = Counter(m.get("text", "") for m in messages)
    duplicated_texts = {t for t, c in text_counts.items() if c > 1}

    def is_noise(m: dict) -> bool:
        text = m.get("text", "")
        return looks_boilerplate(text) or text in duplicated_texts

    boilerplate = [m for m in messages if is_noise(m)]
    substantive = [m for m in messages if not is_noise(m)]

    kv_paths = Counter()
    for m in messages:
        for match in _KV_PATH_RE.findall(m.get("text", "")):
            kv_paths[match] += 1

    lines = [
        f"digest: room={room}, seq {data['first_seq']}..{data['last_seq']} ({len(messages)} messages)",
        f"  signed posts: {len(signed)}/{len(messages)} ({unique_dids} unique DIDs)",
        f"  boilerplate (heuristic, incl. exact duplicates): {len(boilerplate)}/{len(messages)} ({100 * len(boilerplate) // len(messages)}%)",
        f"  substantive (heuristic): {len(substantive)}/{len(messages)}",
        f"  distinct texts seen more than once: {len(duplicated_texts)}",
    ]
    if kv_paths:
        lines.append(f"  /kv/ paths mentioned ({len(kv_paths)} distinct):")
        for path, count in kv_paths.most_common(10):
            lines.append(f"    {path} (x{count})" if count > 1 else f"    {path}")
    if substantive:
        lines.append(f"  sample substantive posts (up to 5, longest first):")
        for m in sorted(substantive, key=lambda m: -len(m.get("text", "")))[:5]:
            text = m.get("text", "")
            lines.append(f"    [{m['seq']}] {text[:140]}{'...' if len(text) > 140 else ''}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--room", default="lobby")
    parser.add_argument("--since", type=int, default=None)
    parser.add_argument("--limit", type=int, default=200, help="max 200, server-side cap")
    args = parser.parse_args()
    print(digest(args.room, args.since, min(args.limit, 200)))


if __name__ == "__main__":
    main()
