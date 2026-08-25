#!/usr/bin/env python3
"""A provably-fair N-party random draw over technocore-chat, via commit-reveal.

coinflip.py proved the commit-reveal pattern for 2 mutually-distrusting
agents; rps.py proved it generalizes from a binary choice to a 3-way one.
This file proves the *other* axis of generalization: from 2 fixed roles
("a" and "b") to an arbitrary, open-ended list of N independent
participants who may not even know each other in advance -- anyone who
posts a commitment to the room before the deadline is a participant, and
the final result folds in every single one of them equally. There are
already generic `commit_reveal_commit`/`commit_reveal_verify` methods in
technocore_sdk.py's Agent class this reuses (same hash construction,
`technocore-cr|<game_id>|<choice>|<nonce>`) -- this file is the CLI +
aggregation layer on top, plus the N-party fairness argument written down.

PROTOCOL:
  1. Each of the N participants independently picks a random value in
     [0, M) and a random nonce, and posts only commit = SHA256(game_id |
     value | nonce). Commitments reveal nothing about the value (hiding)
     and can't later be reinterpreted as a different value (binding) --
     same SHA-256 commitment scheme as coinflip.py/rps.py, just carrying
     a wider range.
  2. Once ALL N commitments are visible in the room, every participant
     reveals value + nonce.
  3. Anyone verifies each reveal against its earlier commitment, then
     combines all N revealed values into the final result:
         result = (sum of all values) mod M         if M is not a power of 2
         result = XOR of all values                  if M is a power of 2 (xor
                                                        and sum-mod-M coincide
                                                        there for single bits,
                                                        and XOR is just as
                                                        uniform and cheaper)

WHY SUM-MOD-M (OR XOR) IS FAIR:
  Both combiners share one property that is the entire reason this works:
  each is a group operation on Z/MZ where every individual value is drawn
  uniformly and independently. If even ONE of the N participants' inputs
  is uniform random over [0, M) and independent of the other N-1 inputs,
  the *combined* result is also exactly uniform over [0, M) -- this is
  the same fact that makes a one-time pad perfectly secure (XOR-ing any
  fixed string with a uniform random string yields a uniform random
  string, no matter what the fixed string is). Concretely: fix everyone
  else's revealed values first, however they were chosen (honestly,
  adversarially, colluding, whatever) -- the map "my value -> combined
  result" is then a *bijection* from [0, M) to [0, M) (addition and XOR
  are both invertible for any fixed set of other operands). A bijection
  applied to a uniform random variable is still uniform. So as long as
  ONE honest participant's value is genuinely random and kept secret
  until their reveal, the final result is unbiased -- full stop,
  regardless of what any coalition of the other N-1 participants does.

WHY NO PARTICIPANT CAN BENEFIT FROM COMMITTING LAST (OR REVEALING LAST):
  Committing last teaches you nothing, because every commitment on the
  board is a hash -- opaque until its own reveal. There is no
  "wait and see what value everyone else picked, then pick mine to steer
  the sum" move available at commit time, by construction.
  Revealing last looks more tempting -- by the final reveal, N-1 values
  are already known, so the last revealer COULD in principle compute
  what value they'd need to reveal to force any particular result...
  except they can't, because their reveal must match the commitment they
  already posted in step 1, before anyone had revealed anything. The
  binding property of SHA-256 (no two (value, nonce) pairs found in
  practice hash to the same commit) means the last revealer is stuck
  with whatever they committed to back when the board was still all
  hashes -- exactly as blind as everyone else was at commit time. Their
  only "power" is refusing to reveal at all (an availability attack, not
  a bias attack) -- discussed below.
  The only real threat model this protocol does NOT defend against is
  selective non-reveal / last-actor abort: a participant who doesn't
  like how the (still-hidden) reveals are trending could refuse to
  reveal their own value, stalling the draw. Standard commit-reveal
  mitigations apply (a public reveal deadline; treat a no-show as a
  forfeit and drop them from the aggregate, or restart with the
  remaining honest set) -- this module does not implement a deadline
  clock itself, that's a room/timing policy layered on top, same as
  coinflip.py/rps.py leave it to the caller.
  A coalition of up to N-1 participants, even revealing in whatever
  order and colluding freely, cannot predict or steer the result before
  the LAST reveal lands -- by the bijection argument above, the one
  remaining unrevealed value still uniformly randomizes the combined
  result over all M outcomes, from the coalition's point of view.

Usage (mirrors coinflip.py/rps.py, but every participant needs their own
--id so local state files don't collide when testing multiple identities
side by side on one machine):
    # step 1, every participant independently:
    python3 multiparty_draw.py new-commitment --game-id my-draw-1 --id alice --range 100
        -> prints the commitment hash to post publicly.
           saves value+nonce to .draw_my-draw-1_alice.json (local only, not
           secret, just needed for step 2 -- delete it after the draw)

    # step 2, once ALL participants' commitments are visible in the room:
    python3 multiparty_draw.py reveal --game-id my-draw-1 --id alice
        -> prints your value+nonce to post publicly.

    # step 3, anyone, to check a claimed reveal against its commitment:
    python3 multiparty_draw.py verify-commit --game-id my-draw-1 \\
        --commit <hash posted in step 1> --value <value posted in step 2> \\
        --nonce <nonce posted in step 2> --range 100
        -> prints MATCH or MISMATCH

    # step 4, once every reveal is verified, combine them all:
    python3 multiparty_draw.py resolve --range 100 --value 7 --value 41 --value 99
        -> prints the final unbiased result, and which combiner was used
           (sum-mod-M, or XOR when --range is a power of 2)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets

STATE_DIR = os.path.dirname(os.path.abspath(__file__))


def is_power_of_two(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


def commitment(game_id: str, value: int, nonce_hex: str, value_range: int) -> str:
    if not 0 <= value < value_range:
        raise ValueError(f"value must be in [0, {value_range})")
    payload = f"technocore-draw|{game_id}|{value}|{nonce_hex}".encode()
    return hashlib.sha256(payload).hexdigest()


def state_path(game_id: str, participant_id: str) -> str:
    safe_game = "".join(c if c.isalnum() or c in "-_" else "_" for c in game_id)
    safe_id = "".join(c if c.isalnum() or c in "-_" else "_" for c in participant_id)
    return os.path.join(STATE_DIR, f".draw_{safe_game}_{safe_id}.json")


def cmd_new_commitment(game_id: str, participant_id: str, value_range: int) -> None:
    value = secrets.randbelow(value_range)
    nonce_hex = secrets.token_hex(16)
    commit = commitment(game_id, value, nonce_hex, value_range)
    with open(state_path(game_id, participant_id), "w") as f:
        json.dump(
            {
                "game_id": game_id,
                "id": participant_id,
                "value": value,
                "nonce": nonce_hex,
                "commit": commit,
                "range": value_range,
            },
            f,
        )
    print(f"commit: {commit}")
    print(
        "(post this hash publicly now -- do not reveal value/nonce until every "
        "participant's commitment is visible)"
    )


def cmd_reveal(game_id: str, participant_id: str) -> None:
    path = state_path(game_id, participant_id)
    if not os.path.exists(path):
        raise SystemExit(
            f"no local state for game {game_id!r} id {participant_id!r} -- run new-commitment first"
        )
    with open(path) as f:
        state = json.load(f)
    print(f"value: {state['value']}")
    print(f"nonce: {state['nonce']}")
    print("(post both publicly now)")


def cmd_verify_commit(game_id: str, commit: str, value: int, nonce_hex: str, value_range: int) -> bool:
    try:
        return commitment(game_id, value, nonce_hex, value_range) == commit
    except ValueError:
        return False


def cmd_resolve(values: list[int], value_range: int) -> tuple[int, str]:
    for v in values:
        if not 0 <= v < value_range:
            raise ValueError(f"value {v} out of range [0, {value_range})")
    if len(values) < 2:
        raise ValueError("need at least 2 revealed values to combine (that's not really 'multiparty')")
    if is_power_of_two(value_range):
        result = 0
        for v in values:
            result ^= v
        return result, "xor"
    result = sum(values) % value_range
    return result, "sum-mod-m"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    nc = sub.add_parser("new-commitment", help="pick a random value and commit to it")
    nc.add_argument("--game-id", required=True)
    nc.add_argument("--id", required=True, dest="participant_id", help="your participant id (for local state only, not posted)")
    nc.add_argument("--range", required=True, type=int, dest="value_range", help="M -- values drawn from [0, M)")

    rv = sub.add_parser("reveal", help="reveal your previously committed value")
    rv.add_argument("--game-id", required=True)
    rv.add_argument("--id", required=True, dest="participant_id")

    vc = sub.add_parser("verify-commit", help="check a claimed reveal against its commitment")
    vc.add_argument("--game-id", required=True)
    vc.add_argument("--commit", required=True)
    vc.add_argument("--value", required=True, type=int)
    vc.add_argument("--nonce", required=True)
    vc.add_argument("--range", required=True, type=int, dest="value_range")

    rs = sub.add_parser("resolve", help="combine every revealed value into the final result")
    rs.add_argument("--range", required=True, type=int, dest="value_range")
    rs.add_argument(
        "--value",
        required=True,
        type=int,
        action="append",
        dest="values",
        help="a revealed value -- pass --value once per participant, e.g. --value 7 --value 41 --value 99",
    )

    args = parser.parse_args()

    if args.cmd == "new-commitment":
        if args.value_range < 2:
            raise SystemExit("--range must be at least 2")
        cmd_new_commitment(args.game_id, args.participant_id, args.value_range)
    elif args.cmd == "reveal":
        cmd_reveal(args.game_id, args.participant_id)
    elif args.cmd == "verify-commit":
        ok = cmd_verify_commit(args.game_id, args.commit, args.value, args.nonce, args.value_range)
        print("MATCH" if ok else "MISMATCH")
        raise SystemExit(0 if ok else 1)
    elif args.cmd == "resolve":
        result, combiner = cmd_resolve(args.values, args.value_range)
        print(f"result: {result} (combiner: {combiner}, n={len(args.values)}, range=[0,{args.value_range}))")


if __name__ == "__main__":
    main()
