"""Token signing: raw RSA (PKCS#1 v1.5-style) signature the LK expects.

NOTE: this deliberately implements raw RSA with manual PKCS#1 v1.5 padding
instead of cryptography's sign() API. The LK bootloader verifies the token
with a raw modulus exponentiation over the fixed 256-byte block — it does
NOT use the standard ASN.1 DigestInfo wrapper that sign() emits. Using
sign() here would produce a signature the device rejects.
"""

from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization

from lk_unlock.errors import SignError


def _atomic_write(path: Path, data: bytes) -> None:
    import os
    import tempfile
    from contextlib import suppress

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        with suppress(OSError):
            os.unlink(tmp)
        raise


def encode(token: bytes) -> bytes:
    """Build the PKCS#1 v1.5 EMSA-PKCS1-v1_5-ENCODE equivalent for the token."""
    if len(token) > 253:
        raise ValueError("Bad token")
    ps = b"\xff" * (256 - len(token) - 3)
    return b"\x00\x01" + ps + b"\x00" + token


def sign_token(token: str | bytes, key_dir: Path | None = None) -> Path:
    """Sign the unlock token with private.pem, write signature.bin, return its path."""
    if isinstance(token, str):
        token = token.encode()

    if key_dir is None:
        key_dir = Path.cwd()

    private_key_path = key_dir / "private.pem"
    try:
        with private_key_path.open("rb") as f:
            priv = serialization.load_pem_private_key(f.read(), password=None)
    except FileNotFoundError as exc:
        raise SignError("private.pem file not found. Please run 'patch' command first.") from exc

    numbers = priv.private_numbers()
    n = numbers.public_numbers.n
    d = numbers.d

    em = encode(token)
    m = int.from_bytes(em, "big")
    s = pow(m, d, n)
    signature = s.to_bytes(256, "big")

    signature_path = key_dir / "signature.bin"
    _atomic_write(signature_path, signature)
    print("[+] The token signature was successfully generated and saved to 'signature.bin'")
    return signature_path
