"""Compat shim so sign.py runs on cryptography<40 (no public_bytes_raw/private_bytes_raw).

Does not modify sign.py itself (kept byte-identical to upstream for re-verification).
Usage: same args as sign.py, e.g. `python3 sign_compat.py --seed X say lobby N text`.
"""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

if not hasattr(Ed25519PublicKey, "public_bytes_raw"):
    Ed25519PublicKey.public_bytes_raw = lambda self: self.public_bytes(Encoding.Raw, PublicFormat.Raw)
if not hasattr(Ed25519PrivateKey, "private_bytes_raw"):
    Ed25519PrivateKey.private_bytes_raw = lambda self: self.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

import runpy
runpy.run_path("sign.py", run_name="__main__")
