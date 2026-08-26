#!/usr/bin/env python3
"""signer_service.py -- sign technocore-chat writes without ever putting the
raw Ed25519 seed on a command line or in an environment variable (both of
which end up in Claude Code's shell history / tool-call log).

Reads the seed internally from a seed file (default: .agent_identity.secret
next to this script, same format private_mailbox.py uses), signs, and
prints did/sig/nonce -- it does not perform the HTTP write itself; pipe the
output into the say-signed/set-signed URL the same way sign.py's output is
meant to be used.

Nonce handling is a transaction: for a given (identity, kind, target) --
kind is "say" or "set", target is the room name or "<ns>/<key>" -- the
candidate nonce is validated against the last nonce used for that exact
target while holding an flock, and the new last-nonce is persisted
(atomically) before the lock is released. This is deliberately NOT split
into "issue a nonce" then separately "sign" then separately "record it" --
a crash or a lost race between those steps is exactly the kind of double
spend a nonce is supposed to prevent.

CLI:
    signer_service.py say <room> <text> [--nonce N] [--seed-file PATH] [--lock-timeout SEC]
    signer_service.py set <ns> <key> <value> [--nonce N] [--seed-file PATH] [--lock-timeout SEC]

--nonce is optional; omitted, one is auto-issued as max(now_ms(), last+1).
Passing a --nonce at or below the last recorded nonce for that target fails
loudly (nonzero exit, state and lock untouched beyond the read).

Prints exactly three lines on success: did:key, base64url signature, nonce.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import math
import os
import re
import sys
import tempfile
import time

# ---- same cryptography<40 compat shim as sign_compat.py, applied BEFORE
# ---- importing sign.py, so this runs on the same cryptography version the
# ---- rest of the toolkit does without ever touching sign.py itself.
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

if not hasattr(Ed25519PublicKey, "public_bytes_raw"):
    Ed25519PublicKey.public_bytes_raw = lambda self: self.public_bytes(Encoding.Raw, PublicFormat.Raw)
if not hasattr(Ed25519PrivateKey, "private_bytes_raw"):
    Ed25519PrivateKey.private_bytes_raw = lambda self: self.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )

import sign  # noqa: E402 -- must follow the shim above

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SEED_FILE = os.path.join(_HERE, ".agent_identity.secret")
STATE_PATH = os.path.join(_HERE, ".signer_nonce_state.json")
# Deliberately NOT state_path + ".lock" (that would be ".signer_nonce_state.json.lock").
# The spec names this exact, stable filename so every caller/lock holder agrees on it
# regardless of what state path they were given.
LOCK_PATH = os.path.join(_HERE, ".signer_nonce_state.lock")

_SEED_HEX_RE = re.compile(r"[0-9a-fA-F]{64}")


# ---------- seed loading (never printed, never logged) ----------

def _load_seed(path: str) -> str:
    """Parses the `seed: <64-hex-chars>` line -- same format as
    private_mailbox.py's _load_ed25519_seed. Error messages never include
    file contents (including the seed value itself), only the path."""
    try:
        with open(path) as f:
            for line in f:
                if line.startswith("seed:"):
                    seed = line.split(":", 1)[1].strip()
                    if not _SEED_HEX_RE.fullmatch(seed):
                        raise SystemExit(
                            f"{path}: 'seed:' line is not a 64-character hex value "
                            "(expected the .agent_identity.secret format)"
                        )
                    return seed
    except FileNotFoundError:
        raise SystemExit(f"seed file not found: {path}")
    except OSError as e:
        raise SystemExit(f"cannot read seed file {path}: {e.strerror or e}")
    raise SystemExit(f"{path}: no 'seed:' line found (expected the .agent_identity.secret format)")


# ---------- atomic JSON persistence (shared design with candidate_scan.py) ----------

def _atomic_write_json(path, data):
    d = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        dir_fd = os.open(d, os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _read_json_file(path):
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


# ---------- nonce transaction ----------

def _flock_with_timeout(fd: int, timeout: float) -> None:
    # A NaN timeout makes every "have we timed out yet?" comparison below
    # false (NaN compares unequal/false against everything, including
    # itself), so a contended lock would spin forever instead of ever
    # raising. inf and negative values are also refused: inf is the same
    # "wait forever" trap by a different route, and a negative duration has
    # no sensible meaning here. Only finite, non-negative timeouts pass.
    if not math.isfinite(timeout) or timeout < 0:
        raise SystemExit(f"invalid --lock-timeout {timeout!r}: must be a finite number >= 0")
    deadline = time.monotonic() + timeout
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise SystemExit(f"timed out after {timeout}s waiting for the nonce-state lock")
            time.sleep(0.05)


_NONCE_RE = re.compile(r"[0-9]{1,19}")
MAX_NONCE = 10**19 - 1  # sign.py's NONCE_RE requires 1-19 ASCII digits: this is the largest legal value


def _parse_or_auto(explicit_nonce, last_nonce: int) -> tuple[int, str]:
    """Returns (candidate_as_int, candidate_display_string). The int is for
    numeric comparison against last_nonce and for state persistence; the
    display string is what actually gets signed and printed -- for an
    explicit --nonce this is the caller's original digit string verbatim
    (e.g. "00042"), because sign.py/sign_compat.py sign the raw nonce
    string, not its integer value, and "00042" != "42" as canonical-string
    bytes even though they're the same nonce numerically."""
    if explicit_nonce is None:
        n = max(int(time.time() * 1000), last_nonce + 1)
        return n, str(n)
    s = str(explicit_nonce)
    if not _NONCE_RE.fullmatch(s):
        raise SystemExit(f"nonce must be 1-19 ASCII digits, got {explicit_nonce!r}")
    return int(s), s


@contextlib.contextmanager
def locked_nonce_state(state_path, identity_did, kind, target, lock_timeout=5, _test_hook=None, lock_path=None):
    # The lock file is a fixed, stable name -- deliberately NOT state_path + ".lock"
    # (state_path may vary by --state, but every caller must still flock the same
    # file to actually serialize with each other). Defaults to the module-level
    # LOCK_PATH; tests pass their own isolated lock_path.
    if lock_path is None:
        lock_path = LOCK_PATH
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        _flock_with_timeout(lock_fd, lock_timeout)
        state = _read_json_file(state_path) or {}
        last_nonce = state.get(identity_did, {}).get(kind, {}).get(target, 0)

        class Txn:
            def validate(self, explicit_nonce):
                candidate, display = _parse_or_auto(explicit_nonce, last_nonce)
                # Applies uniformly to BOTH the explicit path (which _parse_or_auto's
                # regex already bounds to <=19 digits) and the auto-issue path (which
                # has no such bound -- max(now_ms(), last_nonce + 1) can walk last_nonce
                # past the 19-digit ceiling one increment at a time). Checked here,
                # before any state mutation, so an overflow never gets persisted --
                # persisting an unsignable nonce would brick this target permanently
                # (every future auto-issue would inherit the same over-limit last_nonce).
                if candidate > MAX_NONCE:
                    raise SystemExit(
                        f"nonce {candidate} exceeds the 19-digit maximum ({MAX_NONCE}) -- "
                        "refusing to sign or persist it"
                    )
                if candidate <= last_nonce:
                    raise SystemExit(f"nonce not increasing: candidate={candidate} last={last_nonce}")
                # candidate (int) is what gets persisted -- state only ever needs the
                # numeric last-nonce for future comparisons, never the display form.
                # display (str, leading zeros intact) is what the caller must sign
                # and print, returned here for exactly that purpose.
                self.candidate = candidate
                self.candidate_display = display
                return display

            def commit(self):
                if _test_hook:
                    _test_hook()
                state.setdefault(identity_did, {}).setdefault(kind, {})[target] = self.candidate
                _atomic_write_json(state_path, state)

        yield Txn()
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


# ---------- canonical strings / signing ----------

def _canonical_say(room: str, nonce: str, text: str) -> str:
    # nonce is the display string (leading zeros intact, if the caller gave any) --
    # sign.py/sign_compat.py sign the raw nonce string as given, never its int value.
    return f"{room}|{nonce}|{sign.swept(text, sign.MAX_TEXT_CHARS)}"


def _canonical_set(ns: str, key: str, nonce: str, value: str) -> str:
    return f"{ns}|{key}|{nonce}|{sign.swept(value, sign.MAX_VALUE_CHARS)}"


# ---------- CLI ----------

def build_parser() -> argparse.ArgumentParser:
    # --seed-file / --lock-timeout live on a parent parser with SUPPRESS
    # defaults, mirroring sign.py's --seed handling: this lets either flag
    # appear on either side of the subcommand without one copy's default
    # silently clobbering a value the other copy already parsed.
    #
    # allow_abbrev=False on EVERY parser below is load-bearing, not
    # cosmetic: argparse's default (allow_abbrev=True) treats an unmatched
    # long option as an abbreviation of any option it's an unambiguous
    # prefix of. Since "--seed" is an unambiguous prefix of "--seed-file"
    # (no other option here starts with "--seed"), a caller passing
    # "--seed VALUE" -- believing they're using sign.py's raw-seed flag --
    # would otherwise be silently parsed as "--seed-file VALUE" instead of
    # being rejected. That defeats acceptance criterion 1 (no raw-seed
    # argument or environment-variable equivalent) without a single line
    # looking wrong: `argparse.ArgumentParser(add_help=False)` with no
    # allow_abbrev looks identical in a diff to one that's actually safe.
    common = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    common.add_argument("--seed-file", default=argparse.SUPPRESS, help=f"seed file (default: {DEFAULT_SEED_FILE})")
    common.add_argument(
        "--lock-timeout", type=float, default=argparse.SUPPRESS, dest="lock_timeout", help="seconds to wait for the nonce-state lock (default: 5)"
    )

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0], parents=[common], allow_abbrev=False)
    sub = parser.add_subparsers(dest="cmd", required=True)

    say = sub.add_parser("say", parents=[common], help="sign a room post", allow_abbrev=False)
    say.add_argument("room")
    say.add_argument("text")
    say.add_argument("--nonce", default=None, help="explicit nonce (1-19 digits); omitted = auto-issued")

    setp = sub.add_parser("set", parents=[common], help="sign a KV note write", allow_abbrev=False)
    setp.add_argument("ns")
    setp.add_argument("key")
    setp.add_argument("value")
    setp.add_argument("--nonce", default=None, help="explicit nonce (1-19 digits); omitted = auto-issued")

    return parser


def main() -> None:
    args = build_parser().parse_args()
    seed_file = getattr(args, "seed_file", DEFAULT_SEED_FILE)
    lock_timeout = float(getattr(args, "lock_timeout", 5.0))

    seed = _load_seed(seed_file)
    key, _provenance = sign.load_key(seed)
    did = sign.did_of(key)
    del seed  # not needed past key construction; never printed regardless

    if args.cmd == "say":
        kind, target = "say", args.room
    else:
        kind, target = "set", f"{args.ns}/{args.key}"

    with locked_nonce_state(STATE_PATH, did, kind, target, lock_timeout) as txn:
        nonce = txn.validate(args.nonce)
        if args.cmd == "say":
            canonical = _canonical_say(args.room, nonce, args.text)
        else:
            canonical = _canonical_set(args.ns, args.key, nonce, args.value)
        sig = sign.signature(key, canonical)
        txn.commit()

    print(did)
    print(sig)
    print(nonce)


if __name__ == "__main__":
    main()
