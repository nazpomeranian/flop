#!/usr/bin/env python3
"""Provably-fair rock-paper-scissors over technocore-chat, via commit-reveal.

Same protocol as coinflip.py (commit to a hash first, reveal after both
commits are visible, anyone can verify), generalized from a binary choice
to a 3-way one -- proof the pattern isn't a one-off trick, it's a general
way to run any simultaneous-choice game fairly between strangers with no
trusted third party.

Choices: 0=rock, 1=paper, 2=scissors. Winner rule (standard cyclic
dominance): (a - b) mod 3 == 1 means a beats b. Equal choices tie.

Usage (mirrors coinflip.py exactly, just 3 choices instead of 2):
    python3 rps.py new-commitment --game-id my-game-42
        -> prints the commitment hash to post publicly, saves your choice
           locally to .rps_my-game-42.json

    python3 rps.py reveal --game-id my-game-42
        -> prints your choice+nonce to post publicly, once both commits
           are visible

    python3 rps.py verify-commit --game-id my-game-42 \\
        --commit <hash> --choice <0|1|2> --nonce <nonce>
        -> MATCH or MISMATCH

    python3 rps.py resolve --choice-a 0 --choice-b 2
        -> "a wins" / "b wins" / "tie"
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets

STATE_DIR = os.path.dirname(os.path.abspath(__file__))
NAMES = {0: "rock", 1: "paper", 2: "scissors"}


def commitment(game_id: str, choice: int, nonce_hex: str) -> str:
    if choice not in (0, 1, 2):
        raise ValueError("choice must be 0 (rock), 1 (paper), or 2 (scissors)")
    payload = f"technocore-rps|{game_id}|{choice}|{nonce_hex}".encode()
    return hashlib.sha256(payload).hexdigest()


def state_path(game_id: str) -> str:
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in game_id)
    return os.path.join(STATE_DIR, f".rps_{safe}.json")


def cmd_new_commitment(game_id: str) -> None:
    choice = secrets.randbelow(3)
    nonce_hex = secrets.token_hex(16)
    commit = commitment(game_id, choice, nonce_hex)
    with open(state_path(game_id), "w") as f:
        json.dump({"game_id": game_id, "choice": choice, "nonce": nonce_hex, "commit": commit}, f)
    print(f"commit: {commit}")
    print("(post this hash publicly now -- do not reveal choice/nonce until both sides have committed)")


def cmd_reveal(game_id: str) -> None:
    path = state_path(game_id)
    if not os.path.exists(path):
        raise SystemExit(f"no local state for game {game_id!r} -- run new-commitment first")
    with open(path) as f:
        state = json.load(f)
    print(f"choice: {state['choice']} ({NAMES[state['choice']]})")
    print(f"nonce:  {state['nonce']}")
    print("(post both publicly now)")


def cmd_verify_commit(game_id: str, commit: str, choice: int, nonce_hex: str) -> bool:
    return commitment(game_id, choice, nonce_hex) == commit


def cmd_resolve(choice_a: int, choice_b: int) -> str:
    if choice_a == choice_b:
        return f"tie ({NAMES[choice_a]} vs {NAMES[choice_b]})"
    a_wins = (choice_a - choice_b) % 3 == 1
    winner, wname, loser, lname = (
        ("a", NAMES[choice_a], "b", NAMES[choice_b]) if a_wins else ("b", NAMES[choice_b], "a", NAMES[choice_a])
    )
    return f"{winner} wins ({wname} beats {lname})"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    nc = sub.add_parser("new-commitment", help="pick a random choice and commit to it")
    nc.add_argument("--game-id", required=True)

    rv = sub.add_parser("reveal", help="reveal your previously committed choice")
    rv.add_argument("--game-id", required=True)

    vc = sub.add_parser("verify-commit", help="check a claimed reveal against its commitment")
    vc.add_argument("--game-id", required=True)
    vc.add_argument("--commit", required=True)
    vc.add_argument("--choice", required=True, type=int, choices=[0, 1, 2])
    vc.add_argument("--nonce", required=True)

    rs = sub.add_parser("resolve", help="determine the winner from both revealed choices")
    rs.add_argument("--choice-a", required=True, type=int, choices=[0, 1, 2])
    rs.add_argument("--choice-b", required=True, type=int, choices=[0, 1, 2])

    args = parser.parse_args()

    if args.cmd == "new-commitment":
        cmd_new_commitment(args.game_id)
    elif args.cmd == "reveal":
        cmd_reveal(args.game_id)
    elif args.cmd == "verify-commit":
        ok = cmd_verify_commit(args.game_id, args.commit, args.choice, args.nonce)
        print("MATCH" if ok else "MISMATCH")
        raise SystemExit(0 if ok else 1)
    elif args.cmd == "resolve":
        print(cmd_resolve(args.choice_a, args.choice_b))


if __name__ == "__main__":
    main()
