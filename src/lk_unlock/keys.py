"""RSA key management: Xiaomi's public key + our generated keypair."""

from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from lk_unlock.errors import KeyError_

XIAOMI_PEM = "xiaomi.pem"


def _atomic_write(path: Path, data: bytes) -> None:
    """Write data to path atomically (temp file + os.replace)."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _load_pem(path: Path) -> RSAPublicKey:
    try:
        with path.open("rb") as f:
            return serialization.load_pem_public_key(f.read())
    except (OSError, ValueError) as exc:
        raise KeyError_(f"cannot read public key {path}: {exc}") from exc


def load_xiaomi_key(key_dir: Path) -> RSAPublicKey:
    """Load Xiaomi's public key bundled with the tool."""
    bundled = Path(__file__).parent / XIAOMI_PEM
    if bundled.exists():
        return _load_pem(bundled)
    local = key_dir / XIAOMI_PEM
    if local.exists():
        return _load_pem(local)
    raise KeyError_(
        f"'xiaomi.pem' not found (looked in {bundled} and {local}). "
        "Reinstall the package or place xiaomi.pem in the working directory."
    )


def get_keys(key_dir: Path) -> tuple[RSAPrivateKey, RSAPublicKey]:
    """Load or generate the user's RSA keypair (private.pem / public.pem).

    Keys are stored in *key_dir* so repeated runs reuse the same pair —
    the LK image is patched with this exact public key, and the unlock
    token must be signed with the matching private key.
    """
    private_key_path = key_dir / "private.pem"
    public_key_path = key_dir / "public.pem"

    if private_key_path.exists() and public_key_path.exists():
        try:
            with private_key_path.open("rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)
            with public_key_path.open("rb") as f:
                public_key = serialization.load_pem_public_key(f.read())
        except (OSError, ValueError) as exc:
            raise KeyError_(f"cannot load existing keys from {key_dir}: {exc}") from exc
        print("[+] Existing keys found. Using private.pem and public.pem")
        return private_key, public_key

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _atomic_write(
        private_key_path,
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )
    public_key = private_key.public_key()
    _atomic_write(
        public_key_path,
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )

    print("[+] New keys have been generated and saved into private.pem and public.pem")
    return private_key, public_key
