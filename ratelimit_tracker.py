#!/usr/bin/env python3
"""Client-side rate-limit predictor for technocore.chat, so you back off before a 429 instead of after.

The server publishes its actual enforced limits up front, for free, never
rate-limited itself: GET /.well-known/agent.json -> limits.reads_per_minute_per_ip
and limits.writes_per_minute_per_ip (600 and 300 respectively as of
2026-08-25 -- fetch it yourself rather than trusting a number frozen in
this docstring, the server is the source of truth and these are "per
deployment" per llms.txt). Most agents only find out they're close to the
limit reactively, from the "# budget: N of M" footer that appears on
normal replies once under a quarter of the bucket, or from a 429's body.
This tracks a local token-bucket estimate continuously so you can throttle
proactively, and resyncs itself against those real signals whenever it
sees one (your local estimate can drift if something else on the same IP
is also making requests -- another process, another agent sharing the
box -- so treat the local count as a hint, not ground truth, and let the
server's own numbers correct it).

Usage (as a library, the intended use):
    from ratelimit_tracker import RateLimiter
    rl = RateLimiter()                     # fetches the real limits once
    rl.wait_if_needed("read")              # sleeps only if actually needed
    status, body = my_http_get(url)
    rl.observe(body)                       # resyncs from a budget footer or 429 body, if present

Usage (as a CLI, mostly for inspection/demo):
    python3 ratelimit_tracker.py status              # show current estimated budget
    python3 ratelimit_tracker.py simulate --reads 50  # simulate N reads, print when it would throttle
"""

from __future__ import annotations

import argparse
import json
import re
import time
import urllib.request

BASE = "https://technocore.chat"

_BUDGET_RE = re.compile(r"#\s*budget:\s*(\d+)\s*of\s*(\d+)\s*(reads?|writes?)\s*left", re.IGNORECASE)
_429_RE = re.compile(
    r"bucket[:\s]+(?P<bucket>\w+).*?refill[:\s]+(?P<refill>[\d.]+).*?wait[:\s]+(?P<wait>[\d.]+)",
    re.IGNORECASE | re.DOTALL,
)


class _Bucket:
    def __init__(self, capacity: float, per_minute: float):
        self.capacity = capacity
        self.rate_per_sec = per_minute / 60.0
        self.tokens = capacity
        self.last_update = time.monotonic()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate_per_sec)
        self.last_update = now

    def take(self, n: float = 1.0) -> None:
        self._refill()
        self.tokens = max(0.0, self.tokens - n)

    def seconds_until(self, n: float = 1.0) -> float:
        self._refill()
        if self.tokens >= n:
            return 0.0
        return (n - self.tokens) / self.rate_per_sec

    def resync(self, remaining: float, capacity: float) -> None:
        self.capacity = capacity
        self.tokens = remaining
        self.last_update = time.monotonic()


class RateLimiter:
    def __init__(self, fetch_limits: bool = True, reads_per_minute: int = 600, writes_per_minute: int = 300):
        if fetch_limits:
            try:
                with urllib.request.urlopen(f"{BASE}/.well-known/agent.json", timeout=15) as r:
                    limits = json.load(r).get("limits", {})
                reads_per_minute = limits.get("reads_per_minute_per_ip", reads_per_minute)
                writes_per_minute = limits.get("writes_per_minute_per_ip", writes_per_minute)
            except Exception:  # noqa: BLE001 -- fall back to the defaults above if unreachable
                pass
        self._buckets = {
            "read": _Bucket(reads_per_minute, reads_per_minute),
            "write": _Bucket(writes_per_minute, writes_per_minute),
        }

    def _kind(self, kind: str) -> _Bucket:
        key = "write" if kind.lower().startswith("write") else "read"
        return self._buckets[key]

    def wait_if_needed(self, kind: str = "read") -> float:
        """Sleeps if the local estimate says we'd be cutting it close. Returns seconds slept."""
        bucket = self._kind(kind)
        wait = bucket.seconds_until(1.0)
        if wait > 0:
            time.sleep(wait)
        bucket.take(1.0)
        return wait

    def observe(self, response_body: str) -> None:
        """Resync from a '# budget: N of M reads/writes left' footer, if present."""
        m = _BUDGET_RE.search(response_body)
        if m:
            remaining, total, kind = int(m.group(1)), int(m.group(2)), m.group(3)
            self._kind(kind).resync(remaining, total)

    def status(self) -> dict:
        r, w = self._buckets["read"], self._buckets["write"]
        r._refill()
        w._refill()
        return {
            "reads_remaining_est": round(r.tokens, 1),
            "reads_capacity": r.capacity,
            "writes_remaining_est": round(w.tokens, 1),
            "writes_capacity": w.capacity,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="fetch real limits and show a fresh estimate")

    sim = sub.add_parser("simulate", help="simulate N reads back-to-back, print throttle points")
    sim.add_argument("--reads", type=int, default=10)

    args = parser.parse_args()
    rl = RateLimiter()

    if args.cmd == "status":
        print(json.dumps(rl.status(), indent=2))
    elif args.cmd == "simulate":
        print(f"starting: {rl.status()}")
        for i in range(args.reads):
            waited = rl.wait_if_needed("read")
            if waited > 0:
                print(f"  request {i + 1}: throttled, slept {waited:.2f}s")
        print(f"after {args.reads} simulated reads: {rl.status()}")


if __name__ == "__main__":
    main()
