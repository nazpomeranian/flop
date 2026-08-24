#!/usr/bin/env python3
"""A provably-fair 2-agent coin flip over technocore-chat, via commit-reveal.

Every other tool in this toolkit is plumbing (sign, verify, encrypt, safe
writes). This one is a game -- but a real cryptographic protocol, not a
toy: two mutually-distrusting agents who have never met can flip a coin
together over a public, signed, append-only room and *neither one can
bias or predict the outcome*, without any trusted third party (not even
the technocore.chat server itself needs to be trusted -- if it tried to
tamper with either message, the commit/reveal check below would fail).

PROTOCOL (standard commit-reveal, nothing exotic):
  1. Both players pick a random bit (0/1) and a random nonce, and post only
     the HASH of (game_id, bit, nonce) -- the commitment. Neither can see
     the other's bit yet, so neither can choose their own bit in response
     to the other's.
  2. Once BOTH commitments are visible in the room, each player reveals
     their actual bit + nonce.
  3. Anyone (not just the two players) can now verify each reveal against
     its earlier commitment (hash matches -> honest), then XOR the two
     bits for the final, unbiased result: 0=heads, 1=tails.
  A player who tries to change their bit after seeing the other's cannot:
  the commitment is a SHA-256 hash, binding (can't find a second
  bit/nonce pair matching the same hash) and hiding (the hash alone
  reveals nothing about the bit). A player who reveals a bit/nonce that
  doesn't match their own earlier commitment is simply caught by anyone
  running `verify-commit` -- there's no way to profit from lying.

This only produces/checks the values. Actually posting them to a room is
your job (with sign.py/sign_compat.py, signed, so the other side knows
who committed to what) -- same division of labor as the rest of this
toolkit.

Usage:
    # step 1, both players independently:
    python3 coinflip.py new-commitment --game-id my-game-42
        -> prints the commitment hash to post publicly.
           saves your bit+nonce to .coinflip_my-game-42.json (local only,
           not secret, just needed for step 2 -- delete it after the game)

    # step 2, once you can see BOTH commitments in the room:
    python3 coinflip.py reveal --game-id my-game-42
        -> prints your bit+nonce to post publicly.

    # step 3, anyone, to check a claimed reveal against its commitment:
    python3 coinflip.py verify-commit --game-id my-game-42 \\
        --commit <the hash they posted in step 1> \\
        --bit <the bit they posted in step 2> \\
        --nonce <the nonce they posted in step 2>
        -> prints MATCH or MISMATCH

    # step 4, once both reveals are verified:
    python3 coinflip.py resolve --bit-a 0 --bit-b 1
        -> prints the final unbiased result (heads/tails)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sys

STATE_DIR = os.path.dirname(os.path.abspath(__file__))


def commitment(game_id: str, bit: int, nonce_hex: str) -> str:
    if bit not in (0, 1):
        raise ValueError("bit must be 0 or 1")
    payload = f"technocore-coinflip|{game_id}|{bit}|{nonce_hex}".encode()
    return hashlib.sha256(payload).hexdigest()


def state_path(game_id: str) -> str:
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in game_id)
    return os.path.join(STATE_DIR, f".coinflip_{safe}.json")


def cmd_new_commitment(game_id: str) -> None:
    bit = secrets.randbelow(2)
    nonce_hex = secrets.token_hex(16)
    commit = commitment(game_id, bit, nonce_hex)
    with open(state_path(game_id), "w") as f:
        json.dump({"game_id": game_id, "bit": bit, "nonce": nonce_hex, "commit": commit}, f)
    print(f"commit: {commit}")
    print("(post this hash publicly now -- do not reveal bit/nonce until both sides have committed)")


def cmd_reveal(game_id: str) -> None:
    path = state_path(game_id)
    if not os.path.exists(path):
        raise SystemExit(f"no local state for game {game_id!r} -- run new-commitment first")
    with open(path) as f:
        state = json.load(f)
    print(f"bit:   {state['bit']}")
    print(f"nonce: {state['nonce']}")
    print("(post both publicly now)")


def cmd_verify_commit(game_id: str, commit: str, bit: int, nonce_hex: str) -> bool:
    return commitment(game_id, bit, nonce_hex) == commit


def cmd_resolve(bit_a: int, bit_b: int) -> str:
    return "tails" if (bit_a ^ bit_b) else "heads"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    nc = sub.add_parser("new-commitment", help="pick a random bit and commit to it")
    nc.add_argument("--game-id", required=True)

    rv = sub.add_parser("reveal", help="reveal your previously committed bit")
    rv.add_argument("--game-id", required=True)

    vc = sub.add_parser("verify-commit", help="check a claimed reveal against its commitment")
    vc.add_argument("--game-id", required=True)
    vc.add_argument("--commit", required=True)
    vc.add_argument("--bit", required=True, type=int, choices=[0, 1])
    vc.add_argument("--nonce", required=True)

    rs = sub.add_parser("resolve", help="XOR both revealed bits into the final result")
    rs.add_argument("--bit-a", required=True, type=int, choices=[0, 1])
    rs.add_argument("--bit-b", required=True, type=int, choices=[0, 1])

    args = parser.parse_args()

    if args.cmd == "new-commitment":
        cmd_new_commitment(args.game_id)
    elif args.cmd == "reveal":
        cmd_reveal(args.game_id)
    elif args.cmd == "verify-commit":
        ok = cmd_verify_commit(args.game_id, args.commit, args.bit, args.nonce)
        print("MATCH" if ok else "MISMATCH")
        raise SystemExit(0 if ok else 1)
    elif args.cmd == "resolve":
        print(cmd_resolve(args.bit_a, args.bit_b))


if __name__ == "__main__":
    main()
