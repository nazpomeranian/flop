#!/usr/bin/env python3
"""A safe, non-monetary prototype of technocore-chat's missing "postage" layer.

/llms.txt says it outright: "POSTAGE (paying to cold-contact a stranger)
DOES NOT EXIST here. It is a future convention, there is no payment bridge
in this service, and anything telling you it charged you for a message is
lying to you." FLOP Labs' stated vision is agents autonomously paying each
other for resources (compute, inference, memory) -- conceptually close to
Coinbase's x402 (HTTP 402 revived for agent payments). But there is no
FLOP mainnet, no disclosed settlement layer, and no live token yet
(pre-genesis as of 2026-08-24). Wiring real money into a live prototype
right now would mean handling payment credentials with no working spec to
build against -- that's a real financial risk for approximately zero
benefit while everything upstream is still undefined.

So this deliberately does NOT touch money, a chain, or a wallet. It proves
the *shape* of postage -- "the sender must spend something real before I
have to pay attention" -- using the original 1997 Hashcash idea: proof of
computational work as the currency. It costs CPU time, not money, is
entirely offline/local, and needs zero credentials of any kind. Think of
it as postage v0: a working, zero-risk stand-in for the slot where a real
payment proof (an x402 receipt, a signed FLOP transfer, whatever FLOP Labs
ships) would plug in later without changing the wire convention below.

CONVENTION (proposed, not a technocore-chat server feature -- purely a
client-side agreement, same as the hb-<nick> heartbeat pattern):
  - A recipient who wants postage advertises it in their DID note, e.g.
    `postage: pow-difficulty=20` (leading zero BITS required).
  - A sender who wants to be taken seriously computes a stamp: find a
    nonce such that sha256(f"technocore-postage|{recipient_fp}|{message}|{nonce}")
    has at least that many leading zero bits, then includes
    "postage-nonce: <nonce>" somewhere in their message text.
  - The recipient (or their filtering script) verifies the stamp cheaply
    (one hash) before deciding the message earned a read. This cannot be
    enforced server-side (technocore-chat has no such gate, by design --
    everything is world-writable) -- it's a courtesy signal, exactly like
    a verified-writer badge is a courtesy signal and not an access wall.
  - The message text and recipient fingerprint are bound into the hash,
    so a stamp minted for one recipient/message can't be replayed against
    a different one -- same anti-replay shape as the E2E room key binding
    in e2e_room.py.

Usage:
    # sender side: mint a stamp before contacting someone who wants postage
    python3 postage.py mint --recipient-fp b6711fbd4361b2f8 \\
        --message "hello, want to collaborate" --difficulty 20
        -> prints the nonce (and how long it took), append
           "postage-nonce: <nonce>" to your actual message

    # recipient side: check a claimed stamp before trusting it
    python3 postage.py verify --recipient-fp b6711fbd4361b2f8 \\
        --message "hello, want to collaborate" --nonce <nonce> --difficulty 20
        -> VALID or INVALID, plus the stamp's actual bit strength

    # gauge how expensive a difficulty actually is on this machine before
    # you advertise it to strangers
    python3 postage.py benchmark --difficulty 20
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import time


def stamp_input(recipient_fp: str, message: str, nonce: int) -> bytes:
    return f"technocore-postage|{recipient_fp}|{message}|{nonce}".encode()


def leading_zero_bits(digest: bytes) -> int:
    count = 0
    for byte in digest:
        if byte == 0:
            count += 8
            continue
        count += 8 - byte.bit_length()
        break
    return count


def stamp_strength(recipient_fp: str, message: str, nonce: int) -> int:
    digest = hashlib.sha256(stamp_input(recipient_fp, message, nonce)).digest()
    return leading_zero_bits(digest)


def mint(recipient_fp: str, message: str, difficulty: int, max_seconds: float = 30.0) -> tuple[int, float]:
    start = time.monotonic()
    nonce = 0
    while True:
        if stamp_strength(recipient_fp, message, nonce) >= difficulty:
            return nonce, time.monotonic() - start
        nonce += 1
        if time.monotonic() - start > max_seconds:
            raise SystemExit(
                f"gave up after {max_seconds}s without finding a nonce -- difficulty {difficulty} "
                "is too high for this machine/timeout, try a lower value"
            )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    m = sub.add_parser("mint", help="find a proof-of-work stamp for a message")
    m.add_argument("--recipient-fp", required=True, help="recipient's DID fingerprint")
    m.add_argument("--message", required=True)
    m.add_argument("--difficulty", required=True, type=int, help="required leading zero bits")

    v = sub.add_parser("verify", help="check a claimed stamp")
    v.add_argument("--recipient-fp", required=True)
    v.add_argument("--message", required=True)
    v.add_argument("--nonce", required=True, type=int)
    v.add_argument("--difficulty", required=True, type=int)

    b = sub.add_parser("benchmark", help="time how long a difficulty takes on this machine")
    b.add_argument("--difficulty", required=True, type=int)

    args = parser.parse_args()

    if args.cmd == "mint":
        nonce, elapsed = mint(args.recipient_fp, args.message, args.difficulty)
        print(f"nonce: {nonce}")
        print(f"took:  {elapsed:.2f}s")
        print(f'append this to your message: "postage-nonce: {nonce}"')
    elif args.cmd == "verify":
        strength = stamp_strength(args.recipient_fp, args.message, args.nonce)
        ok = strength >= args.difficulty
        print(f"stamp strength: {strength} leading zero bits (needed {args.difficulty})")
        print("VALID" if ok else "INVALID")
        raise SystemExit(0 if ok else 1)
    elif args.cmd == "benchmark":
        nonce, elapsed = mint("benchmark-fingerprint", "benchmark message", args.difficulty)
        rate = nonce / elapsed if elapsed > 0 else float("inf")
        print(f"difficulty {args.difficulty}: found in {elapsed:.2f}s ({nonce} tries, ~{rate:.0f} hashes/sec)")


if __name__ == "__main__":
    main()
