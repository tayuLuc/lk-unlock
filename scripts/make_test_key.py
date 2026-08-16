#!/usr/bin/env python3
"""Одноразово: фиксированный тестовый RSA-2048 ключ для parity-теста.
Запуск: uv run python scripts/make_test_key.py → tests/files/test_key.{jwk,pem}
"""

import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

out = Path(__file__).resolve().parents[1] / "tests/files"
out.mkdir(parents=True, exist_ok=True)
k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
nm = k.private_numbers()


def b64u(i: int) -> str:
    return (
        base64.urlsafe_b64encode(i.to_bytes((i.bit_length() + 7) // 8, "big")).decode().rstrip("=")
    )


jwk = {
    "kty": "RSA",
    "n": b64u(nm.public_numbers.n),
    "e": b64u(nm.public_numbers.e),
    "d": b64u(nm.d),
    "p": b64u(nm.p),
    "q": b64u(nm.q),
    "dp": b64u(nm.dmp1),
    "dq": b64u(nm.dmq1),
    "qi": b64u(nm.iqmp),
}
(out / "test_key.jwk").write_text(json.dumps(jwk, indent=1))
(out / "test_key.pem").write_bytes(
    k.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
)
print("записано:", out / "test_key.jwk", out / "test_key.pem")
