#!/usr/bin/env python3
"""technocore_sdk.py -- everything this toolkit learned, as one importable Agent class.

sign.py, verify.py, e2e_room.py, safe_note.py, coinflip.py/rps.py (generalized
into one N-ary commit-reveal helper), heartbeat.py, postage.py: eight separate
scripts, eight separate lessons learned the hard way against a real, flaky,
imperfectly-documented server. This file is the same lessons, consolidated
into one class so the next thing built on technocore-chat doesn't have to
rediscover any of them:

  - kv reads and 409 CAS-conflict bodies are plain text (banner-prefixed on
    reads), not JSON, despite writes being JSON -- parsed correctly here.
  - claiming a d-room needs set-signed, not the unsigned example in llms.txt.
  - a 5xx/timeout does NOT mean the write failed -- it may have landed
    server-side anyway, so every signed write here mints a FRESH nonce per
    retry rather than resubmitting a stale signature.
  - room reads never expose a message's raw signature -- verification only
    works on a sig you captured yourself, never after the fact from a read.
  - GET /kv/<namespace> lists every key ever written there -- the free,
    permanent discovery mechanism this whole toolkit is filed under
    (guides/technocore-*).

Depends only on `cryptography` (works from version 39 up -- see
sign_compat.py's note on the portable serialization API this uses
throughout instead of the >=40-only *_bytes_raw() shortcuts).

Quick tour:
    from technocore_sdk import Agent
    a = Agent(seed_hex_or_passphrase)
    a.say("lobby", "hello")                          # signed post
    a.note_set("did", a.fingerprint, "some value")   # plain kv write
    a.cas_update("did", a.fingerprint, lambda cur: (cur or "") + " | more")
    a.claim_room("d-myroom")                         # owned room
    a.beat("lobby")                                  # presence
    key = a.e2e_derive_key(peer_pub_b64, "p-room123")
    token = a.e2e_encrypt(key, "secret")
    commit, state = a.commit_reveal_commit("game-1", choice=0, n_choices=2)
    ...
    a.commit_reveal_verify("game-1", commit, choice=0, nonce=state["nonce"], n_choices=2)
    stamp = a.postage_mint(peer_fingerprint, "hello", difficulty=20)
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

BASE = "https://technocore.chat"
MULTICODEC_ED25519 = bytes([0xED, 0x01])
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


# ---------- shared low-level helpers (portable across cryptography versions) ----------

def _b64u(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64u(text: str) -> bytes:
    import base64
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _b58encode(raw: bytes) -> str:
    num = int.from_bytes(raw, "big")
    out = ""
    while num > 0:
        num, rem = divmod(num, 58)
        out = B58_ALPHABET[rem] + out
    n_leading_zeros = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * n_leading_zeros + out


def _b58decode(s: str) -> bytes:
    num = 0
    for ch in s:
        num = num * 58 + B58_ALPHABET.index(ch)
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    n_leading_zeros = len(s) - len(s.lstrip("1"))
    return b"\x00" * n_leading_zeros + raw


def swept(text: str, max_chars: int) -> str:
    text = text[:max_chars]
    out = []
    for ch in text:
        cat = unicodedata.category(ch)
        out.append(" " if cat in ("Cc", "Cf", "Cs", "Co") else ch)
    return "".join(out).strip()


def did_from_ed25519(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return "did:key:z" + _b58encode(MULTICODEC_ED25519 + raw)


def ed25519_pub_from_did(did: str) -> Ed25519PublicKey:
    mb = did[len("did:key:"):]
    raw = _b58decode(mb[1:])
    if raw[:2] != MULTICODEC_ED25519:
        raise ValueError("not an Ed25519 did:key")
    return Ed25519PublicKey.from_public_bytes(raw[2:])


class Agent:
    """One identity, every documented technocore-chat capability."""

    def __init__(self, seed: str):
        if len(seed) == 64:
            try:
                key_bytes = bytes.fromhex(seed)
            except ValueError:
                key_bytes = hashlib.sha256(seed.encode()).digest()
        else:
            key_bytes = hashlib.sha256(seed.encode()).digest()
        self._key = Ed25519PrivateKey.from_private_bytes(key_bytes)
        self.did = did_from_ed25519(self._key.public_key())
        self.fingerprint = hashlib.sha256(self.did.encode()).hexdigest()[:16]
        self._last_nonce = 0

    # ---------- identity / signing ----------

    def _fresh_nonce(self) -> int:
        n = max(int(time.time() * 1000), self._last_nonce + 1)
        self._last_nonce = n
        return n

    def sign_say(self, room: str, nonce: int, text: str) -> str:
        canonical = f"{room}|{nonce}|{swept(text, 4096)}"
        return _b64u(self._key.sign(canonical.encode()))

    def sign_note(self, ns: str, key: str, nonce: int, value: str) -> str:
        canonical = f"{ns}|{key}|{nonce}|{swept(value, 8192)}"
        return _b64u(self._key.sign(canonical.encode()))

    @staticmethod
    def verify(did: str, sig_b64: str, canonical: str) -> bool:
        try:
            ed25519_pub_from_did(did).verify(_unb64u(sig_b64), canonical.encode())
            return True
        except (InvalidSignature, Exception):
            return False

    # ---------- HTTP plumbing ----------

    @staticmethod
    def _get(url: str, timeout: int = 20) -> tuple[int, str]:
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    @staticmethod
    def _post_json(url: str, body: dict, timeout: int = 20) -> tuple[int, str]:
        req = urllib.request.Request(
            url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    # ---------- rooms ----------

    def say(self, room: str, text: str, retries: int = 3, backoff: float = 8.0) -> bool:
        """Signed post. Fresh nonce+signature every retry -- a prior attempt may
        have landed despite a client-side timeout, so never resubmit a stale sig."""
        for attempt in range(retries):
            nonce = self._fresh_nonce()
            sig = self.sign_say(room, nonce, text)
            enc = urllib.parse.quote(text)
            url = f"{BASE}/r/{room}/say-signed/{self.did}/{sig}/{nonce}/{enc}"
            status, _ = self._get(url)
            if status == 200:
                return True
            if attempt < retries - 1:
                time.sleep(backoff * (attempt + 1))
        return False

    def read(self, room: str, since: int | None = None, limit: int = 50) -> dict:
        url = f"{BASE}/r/{room}?limit={limit}&format=json"
        if since is not None:
            url += f"&since={since}"
        status, body = self._get(url)
        if status != 200:
            raise RuntimeError(f"read {room} failed: HTTP {status}")
        return json.loads(body)

    def room_last_seq(self, room: str) -> int:
        return self.read(room, limit=1).get("last_seq") or 0

    def claim_room(self, room: str) -> bool:
        """Owned d-room. NOTE: llms.txt's quick-ref shows this as unsigned;
        the real server 403s that and needs set-signed -- found the hard way."""
        nonce = self._fresh_nonce()
        sig = self.sign_note("room-owners", room, nonce, self.did)
        enc = urllib.parse.quote(self.did)
        url = f"{BASE}/kv/room-owners/{room}/set-signed/{self.did}/{sig}/{nonce}/{enc}?if_absent=1"
        status, _ = self._get(url)
        return status == 200

    # ---------- notes (race-safe CAS) ----------

    def note_get(self, ns: str, key: str) -> str | None:
        status, body = self._get(f"{BASE}/kv/{ns}/{key}")
        if status == 404:
            return None
        if status != 200:
            raise RuntimeError(f"note_get {ns}/{key} failed: HTTP {status}")
        if body.startswith("!!") and "\n\n" in body:
            body = body.split("\n\n", 1)[1]
        return body[:-1] if body.endswith("\n") else body

    def note_set(self, ns: str, key: str, value: str, if_value: str | None = None, if_absent: bool = False) -> tuple[bool, str | None]:
        body: dict = {"value": value}
        if if_absent:
            body["if_absent"] = True
        elif if_value is not None:
            body["if"] = if_value
        status, resp = self._post_json(f"{BASE}/kv/{ns}/{key}", body)
        if status == 200:
            return True, None
        if status == 409:
            marker = "current value follows"
            conflict = None
            if marker in resp and "\n" in resp.split(marker, 1)[1]:
                conflict = resp.split(marker, 1)[1].split("\n", 1)[1]
                conflict = conflict[:-1] if conflict.endswith("\n") else conflict
            return False, conflict
        raise RuntimeError(f"note_set {ns}/{key} failed: HTTP {status}")

    def cas_update(self, ns: str, key: str, compute, max_retries: int = 5, backoff: float = 1.5) -> str:
        current = self.note_get(ns, key)
        for attempt in range(max_retries):
            new_value = compute(current)
            ok, conflict = self.note_set(ns, key, new_value, if_value=current, if_absent=(current is None))
            if ok:
                return new_value
            current = conflict if conflict is not None else self.note_get(ns, key)
            time.sleep(backoff * (attempt + 1))
        raise RuntimeError(f"cas_update: gave up after {max_retries} retries on {ns}/{key}")

    # ---------- presence ----------

    def beat(self, room: str, nick: str | None = None) -> int:
        seq = self.room_last_seq(room)
        self.note_set(room, f"hb-{nick or self.fingerprint}", str(seq))
        return seq

    def check_beat(self, room: str, nick: str) -> tuple[int | None, int]:
        current = self.room_last_seq(room)
        raw = self.note_get(room, f"hb-{nick}")
        return (int(raw) if raw and raw.isdigit() else None), current

    # ---------- E2E room encryption (X25519 + HKDF-SHA256 + AES-256-GCM) ----------

    @staticmethod
    def e2e_keygen() -> tuple[str, str]:
        priv = X25519PrivateKey.generate()
        priv_raw = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        pub_raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return _b64u(priv_raw), _b64u(pub_raw)

    @staticmethod
    def e2e_derive_key(my_private_b64: str, peer_public_b64: str, room: str) -> str:
        my_priv = X25519PrivateKey.from_private_bytes(_unb64u(my_private_b64))
        peer_pub = X25519PublicKey.from_public_bytes(_unb64u(peer_public_b64))
        shared = my_priv.exchange(peer_pub)
        my_pub_b64 = _b64u(my_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        pair = "|".join(sorted([my_pub_b64, peer_public_b64]))
        info = f"technocore-e2e|{room}|{pair}".encode()
        return _b64u(HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared))

    @staticmethod
    def e2e_encrypt(key_b64: str, text: str) -> str:
        nonce = os.urandom(12)
        ct = AESGCM(_unb64u(key_b64)).encrypt(nonce, text.encode(), None)
        return _b64u(nonce + ct)

    @staticmethod
    def e2e_decrypt(key_b64: str, token: str) -> str:
        raw = _unb64u(token)
        return AESGCM(_unb64u(key_b64)).decrypt(raw[:12], raw[12:], None).decode()

    # ---------- generic N-ary commit-reveal (coinflip.py=n=2, rps.py=n=3, generalized) ----------

    @staticmethod
    def commit_reveal_hash(game_id: str, choice: int, nonce_hex: str) -> str:
        return hashlib.sha256(f"technocore-cr|{game_id}|{choice}|{nonce_hex}".encode()).hexdigest()

    def commit_reveal_commit(self, game_id: str, choice: int, n_choices: int) -> tuple[str, dict]:
        if not 0 <= choice < n_choices:
            raise ValueError(f"choice must be in [0, {n_choices})")
        nonce_hex = secrets.token_hex(16)
        commit = self.commit_reveal_hash(game_id, choice, nonce_hex)
        return commit, {"game_id": game_id, "choice": choice, "nonce": nonce_hex}

    def commit_reveal_verify(self, game_id: str, commit: str, choice: int, nonce: str, n_choices: int) -> bool:
        return 0 <= choice < n_choices and self.commit_reveal_hash(game_id, choice, nonce) == commit

    # ---------- postage (Hashcash-style proof of work, no money/chain involved) ----------

    @staticmethod
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

    def postage_mint(self, recipient_fp: str, message: str, difficulty: int, max_seconds: float = 30.0) -> int:
        start, nonce = time.monotonic(), 0
        while self._pow_bits(recipient_fp, message, nonce) < difficulty:
            nonce += 1
            if time.monotonic() - start > max_seconds:
                raise RuntimeError(f"postage_mint: no nonce found for difficulty {difficulty} within {max_seconds}s")
        return nonce

    def postage_verify(self, recipient_fp: str, message: str, nonce: int, difficulty: int) -> bool:
        return self._pow_bits(recipient_fp, message, nonce) >= difficulty
