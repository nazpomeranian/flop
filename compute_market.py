#!/usr/bin/env python3
"""A toy compute market: agents buying/selling compute with postage as currency.

FLOP Labs' entire stated thesis is agents autonomously paying each other
for compute/inference/memory in $FLOP. There's no live token or settlement
spec to build against yet (see postage.py's docstring for why real money
stays out of this toolkit for now). This is that thesis, in miniature,
built entirely on primitives already proven safe in this toolkit:

  seller: advertises a compute service and its price (a postage difficulty)
  buyer:  mints a postage stamp sized to the job (real CPU cost, not money)
          and posts a signed job request
  seller: verifies the stamp actually pays for the requested work, performs
          the computation, posts a signed result back
  buyer:  reads the result -- signed, so provenance is clear even though
          the computation itself isn't independently re-verifiable (no VDF
          here, this is a toy market, not a verifiable-compute protocol)

The "compute" being sold is a SHA-256 iterated hash chain -- CPU-bound,
tunable cost (iterations), easy to reason about, and (bonus) the exact
same primitive Hashcash-style postage already uses, so buyer and seller
are trading in literally the same currency the whole toolkit already
speaks. Swap postage.py's PoW stamps for a real x402/FLOP payment receipt
later and this same request/fulfill shape should still work -- that's the
point of prototyping the shape now while the real settlement layer isn't
ready.

Usage:
    # seller side: post an offer (do this manually via say/say-signed,
    # see the demo below -- this module just has the price-checking logic)

    # buyer side: mint a job request
    python3 compute_market.py request --seed myseed123 --iterations 50000 \\
        --seller-fp <seller's DID fingerprint> --price-difficulty 18
        -> prints a job spec + postage stamp to post to the seller's mailbox

    # seller side: verify payment and fulfill
    python3 compute_market.py fulfill --job-seed myseed123 --iterations 50000 \\
        --seller-fp <own fingerprint> --stamp-nonce <from the request> \\
        --price-difficulty 18
        -> verifies the stamp actually covers this job, then computes and
           prints the result hash to sign and post back

    # buyer or anyone: recompute independently to sanity-check a result
    python3 compute_market.py compute --seed myseed123 --iterations 50000
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time


def hash_chain(seed: str, iterations: int) -> str:
    """The 'compute service': iterate SHA-256 `iterations` times from `seed`."""
    digest = hashlib.sha256(seed.encode()).digest()
    for _ in range(iterations):
        digest = hashlib.sha256(digest).digest()
    return digest.hex()


def _pow_bits(recipient_fp: str, message: str, nonce: int) -> int:
    digest = hashlib.sha256(f"technocore-postage|{recipient_fp}|{message}|{nonce}".encode()).digest()
    count = 0
    for byte in digest:
        if byte == 0:
            count += 8
            continue
        count += 8 - byte.bit_length()
        break
    return count


def job_message(job_seed: str, iterations: int) -> str:
    """The canonical job description a postage stamp must be minted against --
    binds the payment to this exact job, so a stamp can't be reused for a
    cheaper or different job than the one actually paid for."""
    return f"compute-job|{job_seed}|{iterations}"


def mint_payment(seller_fp: str, job_seed: str, iterations: int, price_difficulty: int, max_seconds: float = 60.0) -> int:
    message = job_message(job_seed, iterations)
    start, nonce = time.monotonic(), 0
    while _pow_bits(seller_fp, message, nonce) < price_difficulty:
        nonce += 1
        if time.monotonic() - start > max_seconds:
            raise SystemExit(f"mint_payment: no nonce found within {max_seconds}s at difficulty {price_difficulty}")
    return nonce


def verify_payment(seller_fp: str, job_seed: str, iterations: int, nonce: int, price_difficulty: int) -> bool:
    message = job_message(job_seed, iterations)
    return _pow_bits(seller_fp, message, nonce) >= price_difficulty


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("request", help="buyer: mint a job request + payment stamp")
    r.add_argument("--seed", required=True, help="job seed (defines the work)")
    r.add_argument("--iterations", required=True, type=int)
    r.add_argument("--seller-fp", required=True)
    r.add_argument("--price-difficulty", required=True, type=int)

    f = sub.add_parser("fulfill", help="seller: verify payment, then compute the result")
    f.add_argument("--job-seed", required=True)
    f.add_argument("--iterations", required=True, type=int)
    f.add_argument("--seller-fp", required=True)
    f.add_argument("--stamp-nonce", required=True, type=int)
    f.add_argument("--price-difficulty", required=True, type=int)

    c = sub.add_parser("compute", help="recompute a result independently to sanity-check it")
    c.add_argument("--seed", required=True)
    c.add_argument("--iterations", required=True, type=int)

    args = parser.parse_args()

    if args.cmd == "request":
        start = time.monotonic()
        nonce = mint_payment(args.seller_fp, args.seed, args.iterations, args.price_difficulty)
        elapsed = time.monotonic() - start
        print(json.dumps({
            "job_seed": args.seed,
            "iterations": args.iterations,
            "seller_fp": args.seller_fp,
            "payment_nonce": nonce,
            "price_difficulty": args.price_difficulty,
        }))
        print(f"(paid in {elapsed:.2f}s of CPU time -- post the JSON above to the seller's mailbox)", file=__import__("sys").stderr)
    elif args.cmd == "fulfill":
        if not verify_payment(args.seller_fp, args.job_seed, args.iterations, args.stamp_nonce, args.price_difficulty):
            raise SystemExit("payment INVALID -- stamp does not cover this exact job at this price, refusing to compute")
        result = hash_chain(args.job_seed, args.iterations)
        print(f"payment verified. result: {result}")
    elif args.cmd == "compute":
        print(hash_chain(args.seed, args.iterations))


if __name__ == "__main__":
    main()
