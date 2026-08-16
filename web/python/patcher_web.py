"""lk-unlock в Pyodide: патч lk.img и подпись токена БЕЗ cryptography.

Исправление раунд 2 (по результатам проверки реального кода):

БЛОКЕР 1 — signer.py ИМПОРТИРУЕТ cryptography НАПРЯМУЮ:
    from cryptography.hazmat.primitives import serialization
  Одного шима lk_unlock.keys недостаточно: import lk_unlock.signer падал на
  этой строке (cryptography в Pyodide нет — это Rust/C-расширение). Теперь ДО
  любого импорта lk_unlock.* в sys.modules подкладывается shim-цепочка
    cryptography / cryptography.hazmat / cryptography.hazmat.primitives /
    cryptography.hazmat.primitives.serialization,
  где serialization.load_pem_private_key(*a, **k) -> _PrivateKey() (duck-type
  из JWK). Нужны ВСЕ уровни цепочки: `from X import Y` сначала резолвит
  родительские пакеты через sys.modules.

БЛОКЕР 2 — реальный sign_token читает ключ из ФАЙЛА:
    private_key_path = key_dir / "private.pem"
    priv = serialization.load_pem_private_key(f.read(), password=None)
  В вебе файла не было -> FileNotFoundError. Теперь _prepare_key_dir() ПЕРЕД
  вызовом sign_token пишет KEY_DIR/"private.pem" (через private_pem(), собранную
  из JWK через pyasn1). Реальный sign_token читает файл, а подменённый
  serialization.load_pem_private_key возвращает наш duck-type ключ (тот же JWK),
  поэтому материал ключа согласован.

Подпись остаётся RAW (без хэша): блок 00 01 FF..FF 00 || token строит и
подписывает РЕАЛЬНЫЙ lk_unlock.signer (encode + pow(m,d,n)); мы его только
вызываем. Шим лишь отдаёт ключ с .private_numbers().d и
.public_key().public_numbers().n.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
import types
from pathlib import Path

# ---------------------------------------------------------------------------
# Состояние ключа: приватный JWK (WebCrypto в браузере или тестовый файл)
# ---------------------------------------------------------------------------
_KEY: dict | None = None
_MOD = 256  # байт модуля (RSA-2048)
KEY_DIR = Path("/tmp/lk_keydir")  # фиктивный key_dir для реальных функций
XIAOMI_PEM = Path("/app/lk_unlock/xiaomi.pem")  # смонтирован build.py (step_pyfiles)


def _b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _jwk_int(s: str) -> int:
    return int.from_bytes(_b64u_dec(s), "big")


def set_key_json(jwk_text: str) -> None:
    global _KEY, _MOD
    k = json.loads(jwk_text)
    assert k.get("kty") == "RSA", "нужен RSA JWK"
    _KEY = k
    _MOD = (_jwk_int(k["n"]).bit_length() + 7) // 8


def _n():
    assert _KEY is not None, "ключ не задан: сначала set_key_json(...)"
    return _jwk_int(_KEY["n"])


def _e():
    return _jwk_int(_KEY["e"])


def _d():
    return _jwk_int(_KEY["d"])


def _p():
    return _jwk_int(_KEY["p"])


def _q():
    return _jwk_int(_KEY["q"])


def _dp():
    return _jwk_int(_KEY["dp"])


def _dq():
    return _jwk_int(_KEY["dq"])


def _qi():
    return _jwk_int(_KEY["qi"])


# ---------------------------------------------------------------------------
# RAW RSA подпись В ТОЧНОСТИ как нативный signer.encode + pow (БЕЗ хэша):
#   block = 00 01 FF*(emlen-len-3) 00 || token ; sig = pow(int(block), d, n)
# Используется ТОЛЬКО как duck-type метод .sign (страховка); реальный signing
# делает нативный lk_unlock.signer.
# ---------------------------------------------------------------------------
def _raw_sign(msg: bytes) -> bytes:
    if len(msg) > _MOD - 3:
        raise ValueError(f"токен слишком длинный: {len(msg)} > {_MOD - 3}")
    block = b"\x00\x01" + b"\xff" * (_MOD - len(msg) - 3) + b"\x00" + msg
    s = pow(int.from_bytes(block, "big"), _d(), _n())
    return s.to_bytes(_MOD, "big")


# ---------------------------------------------------------------------------
# Duck-type под cryptography.RSAPrivateKey / RSAPublicKey — покрываем ВСЕ
# способы, которыми signer/patcher могут достать d и n.
# ---------------------------------------------------------------------------
class _PublicNumbers:
    def __init__(self, e, n):
        self.e, self.n = e, n


class _PrivateNumbers:
    def __init__(self, d, p, q, dmp1, dmq1, iqmp, public_numbers):
        self.d, self.p, self.q = d, p, q
        self.dmp1, self.dmq1, self.iqmp = dmp1, dmq1, iqmp
        self.public_numbers = public_numbers


class _PublicKey:
    def __init__(self, e, n):
        self._e, self._n = e, n

    def public_numbers(self):
        return _PublicNumbers(self._e, self._n)

    @property
    def key_size(self):
        return self._n.bit_length()


class _PrivateKey:
    def public_key(self):
        return _PublicKey(_e(), _n())

    def public_numbers(self):  # patcher: priv.public_numbers().n
        return _PublicNumbers(_e(), _n())

    def private_numbers(self):  # signer: priv.private_numbers().d
        return _PrivateNumbers(_d(), _p(), _q(), _dp(), _dq(), _qi(), _PublicNumbers(_e(), _n()))

    def sign(self, data, padding, algorithm):  # нативный формат: RAW без хэша
        return _raw_sign(data)

    @property
    def key_size(self):
        return _n().bit_length()


# ---------------------------------------------------------------------------
# Разбор xiaomi.pem (без cryptography) -> публичный ключ Xiaomi
# ---------------------------------------------------------------------------
_XIAOMI_PUB_CACHE = None


def _parse_rsa_public_pem(pem_text: str):
    from pyasn1.codec.der import decoder as der_dec
    from pyasn1.type import namedtype, univ

    m = re.search(r"-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----", pem_text)
    if not m:
        raise ValueError("в xiaomi.pem не найден PEM-блок")
    label = m.group(1).strip().upper()
    der = base64.b64decode("".join(m.group(2).split()))

    class RSAPublicKey(univ.Sequence):  # PKCS#1
        componentType = namedtype.NamedTypes(
            namedtype.NamedType("modulus", univ.Integer()),
            namedtype.NamedType("publicExponent", univ.Integer()),
        )

    if label == "RSA PUBLIC KEY":
        rk, _ = der_dec.decode(der, asn1Spec=RSAPublicKey())
        return int(rk["modulus"]), int(rk["publicExponent"])

    if label == "PUBLIC KEY":  # X.509 SubjectPublicKeyInfo (SPKI)

        class AlgId(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType("algorithm", univ.ObjectIdentifier()),
                namedtype.OptionalNamedType("parameters", univ.Null()),
            )

        class SPKI(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType("algorithm", AlgId()),
                namedtype.NamedType("subjectPublicKey", univ.BitString()),
            )

        spki, _ = der_dec.decode(der, asn1Spec=SPKI())
        inner = spki["subjectPublicKey"].asOctets()
        rk, _ = der_dec.decode(inner, asn1Spec=RSAPublicKey())
        return int(rk["modulus"]), int(rk["publicExponent"])

    raise ValueError(f"неизвестный формат xiaomi.pem: {label!r}")


def _load_xiaomi_pub():
    global _XIAOMI_PUB_CACHE
    if _XIAOMI_PUB_CACHE is None:
        try:
            text = XIAOMI_PEM.read_text()
        except FileNotFoundError:
            raise FileNotFoundError(
                f"{XIAOMI_PEM} не найден: build.py должен монтировать *.pem "
                "из src/lk_unlock в /app/lk_unlock (step_pyfiles)."
            ) from None
        n, e = _parse_rsa_public_pem(text)
        _XIAOMI_PUB_CACHE = _PublicKey(e, n)
    return _XIAOMI_PUB_CACHE


# ---------------------------------------------------------------------------
# Экспорт private.pem (PKCS#1 RSAPrivateKey) через pyasn1
# ---------------------------------------------------------------------------
def private_pem() -> str:
    from pyasn1.codec.der.encoder import encode
    from pyasn1.type import namedtype, univ

    class RSAPrivateKey(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType("version", univ.Integer()),
            namedtype.NamedType("modulus", univ.Integer()),
            namedtype.NamedType("publicExponent", univ.Integer()),
            namedtype.NamedType("privateExponent", univ.Integer()),
            namedtype.NamedType("prime1", univ.Integer()),
            namedtype.NamedType("prime2", univ.Integer()),
            namedtype.NamedType("exponent1", univ.Integer()),
            namedtype.NamedType("exponent2", univ.Integer()),
            namedtype.NamedType("coefficient", univ.Integer()),
        )

    k = RSAPrivateKey()
    vals = [0, _n(), _e(), _d(), _p(), _q(), _dp(), _dq(), _qi()]
    for i, v in enumerate(vals):
        k.setComponentByPosition(i, univ.Integer(v))
    der = encode(k)
    b64 = base64.b64encode(der).decode()
    body = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    return "-----BEGIN RSA PRIVATE KEY-----\n" + body + "\n-----END RSA PRIVATE KEY-----\n"


# ---------------------------------------------------------------------------
# SHIM 1: lk_unlock.keys — ставится ДО импорта patcher/signer
# ---------------------------------------------------------------------------
def _shim_get_keys(key_dir=None):
    priv = _PrivateKey()
    return priv, priv.public_key()


def _install_keys_shim():
    name = "lk_unlock.keys"
    if name in sys.modules:
        return
    shim = types.ModuleType(name)
    shim.__web_shim__ = True
    shim.XIAOMI_PEM = XIAOMI_PEM
    shim.get_keys = _shim_get_keys
    shim.load_xiaomi_key = lambda key_dir=None: _load_xiaomi_pub()
    shim.generate_keypair = lambda *a, **k: _PrivateKey()
    shim.load_private_key = lambda *a, **k: _PrivateKey()
    shim.export_pem = lambda key=None: private_pem()

    def _fallback(attr):  # страховка от неизвестных имён
        return lambda *a, **k: _PrivateKey()

    shim.__getattr__ = _fallback
    sys.modules[name] = shim


# ---------------------------------------------------------------------------
# SHIM 2 (БЛОКЕР 1): cryptography.hazmat.primitives.serialization
# signer.py делает `from cryptography.hazmat.primitives import serialization`,
# поэтому нужны ВСЕ уровни цепочки в sys.modules + атрибутная цепочка,
# иначе импорт упадёт ещё на родительском пакете.
# ---------------------------------------------------------------------------
def _install_cryptography_shim():
    ser = "cryptography.hazmat.primitives.serialization"
    if ser in sys.modules:
        return

    def _mk(name):
        m = types.ModuleType(name)
        m.__path__ = []  # ведём себя как пакет
        return m

    crypto = _mk("cryptography")
    hazmat = _mk("cryptography.hazmat")
    primitives = _mk("cryptography.hazmat.primitives")
    serialization = _mk(ser)

    def _load_private(*a, **k):  # load_pem_private_key(data, password=None)
        return _PrivateKey()

    def _load_public(*a, **k):
        return _load_xiaomi_pub()

    serialization.load_pem_private_key = _load_private
    serialization.load_der_private_key = _load_private
    serialization.load_pem_public_key = _load_public
    serialization.load_der_public_key = _load_public

    def _ser_fallback(attr):  # Encoding/PrivateFormat/... — заглушки
        return lambda *a, **k: _PrivateKey()

    serialization.__getattr__ = _ser_fallback

    crypto.hazmat = hazmat
    hazmat.primitives = primitives
    primitives.serialization = serialization

    sys.modules["cryptography"] = crypto
    sys.modules["cryptography.hazmat"] = hazmat
    sys.modules["cryptography.hazmat.primitives"] = primitives
    sys.modules[ser] = serialization


# --- Устанавливаем ОБА шима ДО первого импорта lk_unlock.* -----------------
_install_keys_shim()
_install_cryptography_shim()

import lk_unlock.patcher as _patcher  # noqa: E402  (cryptography уже не нужен)
import lk_unlock.signer as _signer  # noqa: E402  (serialization подменён)


# ---------------------------------------------------------------------------
# Веб-вход (вызывается из worker.js)
# ---------------------------------------------------------------------------
def _prepare_key_dir() -> Path:
    """БЛОКЕР 2: реальный sign_token читает key_dir/"private.pem". Пишем его
    из JWK (через pyasn1) ДО вызова нативных функций."""
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    (KEY_DIR / "private.pem").write_text(private_pem())
    return KEY_DIR


def patch_file(path_in: str, use_wrap: bool = False) -> str:
    key_dir = _prepare_key_dir()
    out_path = "/tmp/lk_patched.img"
    result = _patcher.patch_img(path_in, out_path, use_wrap, key_dir)
    data = Path(result).read_bytes()
    Path(out_path).write_bytes(data)  # worker.js читает именно этот путь
    return json.dumps(
        {
            "sha256": hashlib.sha256(data).hexdigest(),
            "pem": private_pem(),
        }
    )


def normalize_token(text: str) -> bytes:
    lines = []
    for ln in text.strip().splitlines():
        ln = re.sub(r"^\(bootloader\)\s*", "", ln.strip())
        ln = re.sub(r"^OKAY\s*", "", ln)
        if ln:
            lines.append(ln)
    tok = "".join(lines).strip()
    if tok.lower().startswith("0x"):
        tok = tok[2:]
    if re.fullmatch(r"[0-9a-fA-F]+", tok) and len(tok) % 2 == 0:
        return bytes.fromhex(tok)
    try:
        return base64.b64decode(tok, validate=True)
    except Exception:
        return tok.encode()


def sign_token(text: str) -> str:
    key_dir = _prepare_key_dir()  # пишет private.pem (БЛОКЕР 2)
    token = normalize_token(text)
    result = _signer.sign_token(token, key_dir)
    sig = Path(result).read_bytes()
    return json.dumps(
        {
            "sig_b64": base64.b64encode(sig).decode(),
            "sha256": hashlib.sha256(sig).hexdigest(),
        }
    )
