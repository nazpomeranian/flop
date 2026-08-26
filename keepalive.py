#!/usr/bin/env python3
"""keepalive.py -- refresh a `keepalive: <timestamp>` fragment in a DID note,
race-safely, so the note does not silently expire.

Reuses safe_note.py's CAS primitive (cas_update) rather than reimplementing
retry-on-409 logic. The whole job here is a single compute() closure: given
the note's current value, produce the new value with the keepalive fragment
either replaced (if already present) or appended (if not) -- and refuse
(raise NoteTooLargeError) if the result would exceed the server's 8192-char
note cap, checked fresh against whatever `current` cas_update is retrying
with, not just the first read.

Usage:
    python3 keepalive.py                       # --ns did --key <own fp>, writes
    python3 keepalive.py --dry-run              # prints what would be written, no POST
    python3 keepalive.py --ns did --key <fp>     # explicit target note

Exit code 0 on success. Exit code 1 if the note would exceed 8192 chars
(both --dry-run and real-write paths) or on a network/server error.
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.error
from datetime import datetime, timezone

import safe_note

DEFAULT_NS = "did"
DEFAULT_KEY = "b6711fbd4361b2f8"
MAX_NOTE_CHARS = 8192


class NoteTooLargeError(Exception):
    pass


def make_compute(fragment_re: "re.Pattern[str]", new_fragment: str):
    def compute(current):
        if current and fragment_re.search(current):
            new_value = fragment_re.sub(new_fragment, current)
        else:
            new_value = new_fragment if not current else f"{current} | {new_fragment}"
        if len(new_value) > MAX_NOTE_CHARS:
            raise NoteTooLargeError(len(new_value))
        return new_value

    return compute


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_compute(timestamp: str | None = None):
    ts = timestamp or _now_iso()
    fragment_re = re.compile(r"keepalive:\s*\S+")
    new_fragment = f"keepalive: {ts}"
    return make_compute(fragment_re, new_fragment)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ns", default=DEFAULT_NS, help="KV namespace of the note (default: %(default)s)")
    parser.add_argument("--key", default=DEFAULT_KEY, help="KV key of the note (default: own DID fingerprint)")
    parser.add_argument("--dry-run", action="store_true", help="print the value that would be written, without writing")
    args = parser.parse_args()

    compute = build_compute()

    if args.dry_run:
        try:
            current = safe_note._get(args.ns, args.key)
        except urllib.error.URLError as e:
            print(f"ERROR: could not read {args.ns}/{args.key}: {e}", file=sys.stderr)
            sys.exit(1)
        try:
            new_value = compute(current)
        except NoteTooLargeError as e:
            print(
                f"ERROR: new note value would be {e} characters, over the {MAX_NOTE_CHARS}-char cap -- not writing",
                file=sys.stderr,
            )
            sys.exit(1)
        print(new_value)
        return

    mismatch_detected = False
    try:
        final = safe_note.cas_update(args.ns, args.key, compute)
        try:
            readback = safe_note._get(args.ns, args.key)
        except urllib.error.URLError as e:
            print(f"WARNING: wrote successfully but read-back verification failed: {e}", file=sys.stderr)
            readback = None
        if readback is not None and readback != final:
            print(
                f"WARNING: read-back mismatch on {args.ns}/{args.key} -- the note has "
                "no write protection (unsigned, last-write-wins), so something else "
                "wrote to it between our write and this check. Our keepalive fragment "
                "may already be gone.",
                file=sys.stderr,
            )
            mismatch_detected = True
    except NoteTooLargeError as e:
        print(
            f"ERROR: new note value would be {e} characters, over the {MAX_NOTE_CHARS}-char cap -- not writing",
            file=sys.stderr,
        )
        sys.exit(1)
    except urllib.error.HTTPError as e:
        print(f"ERROR: HTTP {e.code} {e.reason}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"ERROR: network error: {e}", file=sys.stderr)
        sys.exit(1)
    except SystemExit as e:
        # cas_update raises SystemExit(str) itself on retry exhaustion -- normalize
        # to stderr + exit 1 rather than letting a bare message escape to stdout.
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    print(final)
    if mismatch_detected:
        sys.exit(1)


if __name__ == "__main__":
    main()
