"""lk-unlock in Pyodide: patch lk.img and sign tokens WITHOUT cryptography.

Round 2 fixes (based on reviewing the real code):

BLOCKER 1 - signer.py IMPORTS cryptography DIRECTLY:
    from cryptography.hazmat.primitives import serialization
  Shimming lk_unlock.keys alone is not enough: importing lk_unlock.signer
  failed on this line (cryptography is not available in Pyodide - it is a
  Rust/C extension). Now, BEFORE any lk_unlock.* import, a shim chain is
  placed in sys.modules:
    cryptography / cryptography.hazmat / cryptography.hazmat.primitives /
    cryptography.hazmat.primitives.serialization,
  where serialization.load_pem_private_key(*a, **k) -> _PrivateKey()
  (duck-type from JWK). ALL chain levels are required: `from X import Y`
  resolves parent packages through sys.modules first.

BLOCKER 2 - the real sign_token reads the key from a FILE:
    private_key_path = key_dir / "private.pem"
    priv = serialization.load_pem_private_key(f.read(), password=None)
  The file did not exist in the web build -> FileNotFoundError. Now
  _prepare_key_dir() writes KEY_DIR/"private.pem" (built from the JWK via
  pyasn1) BEFORE calling sign_token. The real sign_token reads the file, and
  the shimmed serialization.load_pem_private_key returns our duck-type key
  (the same JWK), so the key material stays consistent.

The signature stays RAW (no hash): block 00 01 FF..FF 00 || token is built
and signed by the REAL lk_unlock.signer (encode + pow(m,d,n)); we only call
it. The shim merely supplies the key with .private_numbers().d and
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
# Key state: private JWK (WebCrypto in browser or test file)
# ---------------------------------------------------------------------------
_KEY: dict | None = None
_MOD = 256  # modulus bytes (RSA-2048)
KEY_DIR = Path("/tmp/lk_keydir")  # fake key_dir for real functions
XIAOMI_PEM = Path("/app/lk_unlock/xiaomi.pem")  # mounted by build.py (step_pyfiles)


def _b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _jwk_int(s: str) -> int:
    return int.from_bytes(_b64u_dec(s), "big")


def set_key_json(jwk_text: str) -> None:
    global _KEY, _MOD
    k = json.loads(jwk_text)
    assert k.get("kty") == "RSA", "RSA JWK required"
    _KEY = k
    _MOD = (_jwk_int(k["n"]).bit_length() + 7) // 8


def _n():
    assert _KEY is not None, "key not set: call set_key_json(...) first"
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
# RAW RSA signing exactly like native signer.encode + pow (NO hash):
#   block = 00 01 FF*(emlen-len-3) 00 || token ; sig = pow(int(block), d, n)
# Used ONLY as a duck-type .sign method (fallback); real signing is done
# by the native lk_unlock.signer.
# ---------------------------------------------------------------------------
def _raw_sign(msg: bytes) -> bytes:
    if len(msg) > _MOD - 3:
        raise ValueError(f"token too long: {len(msg)} > {_MOD - 3}")
    block = b"\x00\x01" + b"\xff" * (_MOD - len(msg) - 3) + b"\x00" + msg
    s = pow(int.from_bytes(block, "big"), _d(), _n())
    return s.to_bytes(_MOD, "big")


# ---------------------------------------------------------------------------
# Duck-type for cryptography.RSAPrivateKey / RSAPublicKey — covers ALL
# ways signer/patcher can obtain d and n.
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

    def sign(self, data, padding, algorithm):  # native format: RAW without hash
        return _raw_sign(data)

    @property
    def key_size(self):
        return _n().bit_length()


# ---------------------------------------------------------------------------
# Parse xiaomi.pem (no cryptography) -> Xiaomi public key
# ---------------------------------------------------------------------------
_XIAOMI_PUB_CACHE = None


def _parse_rsa_public_pem(pem_text: str):
    from pyasn1.codec.der import decoder as der_dec
    from pyasn1.type import namedtype, univ

    m = re.search(r"-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----", pem_text)
    if not m:
        raise ValueError("no PEM block found in xiaomi.pem")
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

    raise ValueError(f"unknown xiaomi.pem format: {label!r}")


def _load_xiaomi_pub():
    global _XIAOMI_PUB_CACHE
    if _XIAOMI_PUB_CACHE is None:
        try:
            text = XIAOMI_PEM.read_text()
        except FileNotFoundError:
            raise FileNotFoundError(
                f"{XIAOMI_PEM} not found: build.py must mount *.pem "
                "from src/lk_unlock into /app/lk_unlock (step_pyfiles)."
            ) from None
        n, e = _parse_rsa_public_pem(text)
        _XIAOMI_PUB_CACHE = _PublicKey(e, n)
    return _XIAOMI_PUB_CACHE


# ---------------------------------------------------------------------------
# Export private.pem (PKCS#1 RSAPrivateKey) via pyasn1
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
# Parse PKCS#1 "BEGIN RSA PRIVATE KEY" PEM -> JWK (for import from file)
# ---------------------------------------------------------------------------
def parse_private_pem(pem_text: str) -> str:
    """Parse PKCS#1 'BEGIN RSA PRIVATE KEY' PEM and return JWK as JSON string.

    Uses pyasn1 to decode the DER payload of the PEM block, extracts
    n, e, d, p, q, dp, dq, qi and packs them into a standard RSA JWK
    (base64url UInt, RFC 7518) compatible with WebCrypto.
    """
    from pyasn1.codec.der import decoder as der_dec
    from pyasn1.type import namedtype, univ

    m = re.search(r"-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----", pem_text)
    if not m:
        raise ValueError("no PEM block found")
    label = m.group(1).strip().upper()
    if label != "RSA PRIVATE KEY":
        raise ValueError(
            f"expected PKCS#1 'RSA PRIVATE KEY', got '{label}'. "
            "Only PKCS#1 private keys are supported (not PKCS#8 / 'PRIVATE KEY')."
        )
    der = base64.b64decode("".join(m.group(2).split()))

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

    rk, _ = der_dec.decode(der, asn1Spec=RSAPrivateKey())

    def to_b64u(i: int) -> str:
        # RFC 7518 Base64urlUInt: big-endian, minimal length, no leading zeros
        bl = max(1, (i.bit_length() + 7) // 8)
        return base64.urlsafe_b64encode(i.to_bytes(bl, "big")).decode().rstrip("=")

    jwk = {
        "kty": "RSA",
        "n": to_b64u(int(rk["modulus"])),
        "e": to_b64u(int(rk["publicExponent"])),
        "d": to_b64u(int(rk["privateExponent"])),
        "p": to_b64u(int(rk["prime1"])),
        "q": to_b64u(int(rk["prime2"])),
        "dp": to_b64u(int(rk["exponent1"])),
        "dq": to_b64u(int(rk["exponent2"])),
        "qi": to_b64u(int(rk["coefficient"])),
        "key_ops": ["sign"],
        "ext": True,
    }
    return json.dumps(jwk)


# ---------------------------------------------------------------------------
# Get current JWK (for saving to localStorage from the UI)
# ---------------------------------------------------------------------------
def get_jwk() -> str:
    """Return current private key as JWK JSON string."""
    assert _KEY is not None, "key not set: call set_key_json(...) first"
    return json.dumps(_KEY)


def diagnose_file(data: bytes) -> str:
    """Pre-patch diagnostics: magic bytes, size, OEM key presence.

    Runs read-only checks on the uploaded image so the UI can block a
    patch that would brick the device (wrong format, already-patched,
    foreign model). Returns a JSON summary.
    """
    result = {
        "size": len(data),
        "magic_ok": False,
        "magic_hex": data[:4].hex(),
        "has_oem_key": False,
        "oem_key_offset": None,
        "lk_partitions": [],
    }
    # MTK LK image header: magic at offset 0 (0x58881688), ext at 48 (0x58891689)
    if len(data) >= 8:
        magic = int.from_bytes(data[0:4], "little")
        result["magic_ok"] = magic == 0x58881688
    try:
        from liblk.image import LkImage
        image = LkImage(bytes(data))
        result["lk_partitions"] = list(image.partitions.keys())
    except Exception:
        result["lk_partitions"] = []
    try:
        old_n = _load_xiaomi_pub().public_numbers().n
        old_bytes = old_n.to_bytes(256, "big")
        pos = data.find(old_bytes)
        if pos != -1:
            result["has_oem_key"] = True
            result["oem_key_offset"] = pos
    except Exception:
        result["has_oem_key"] = False
    return json.dumps(result)


# ---------------------------------------------------------------------------
# UX 1: Parse and validate the MediaTek TLV unlock token
# ---------------------------------------------------------------------------
def parse_token(token_text: str) -> str:
    """Parse the MediaTek unlock token (from `fastboot oem get_token`).

    The token is base64 with a 0x55 prefix; the raw bytes embed the device
    codename as an ASCII string (e.g. "fleur"). We validate base64 + prefix
    and extract the device name by scanning the decoded bytes - robust to
    the exact TLV layout, which varies across builds. Works on bytes only.
    """
    result = {"valid": False, "error": None, "device_name": None, "raw_length": 0}
    cleaned = (token_text or "").strip().replace(" ", "")
    if not cleaned:
        result["error"] = "Пустой токен"
        return json.dumps(result)
    pad = 4 - (len(cleaned) % 4)
    if pad != 4:
        cleaned += "=" * pad
    try:
        data = base64.b64decode(cleaned, validate=True)
    except Exception as e:
        result["error"] = f"Невалидный Base64: {e}"
        return json.dumps(result)
    result["raw_length"] = len(data)
    if not data:
        result["error"] = "Токен пуст после декода"
        return json.dumps(result)
    if data[0] != 0x55:
        result["error"] = f"Неверный префикс 0x{data[0]:02x} (ожидался 0x55)"
        return json.dumps(result)
    # Extract device codename: printable ASCII run of >=4 chars
    best = ""
    cur = []
    for b in data[1:]:
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= 4:
                best = "".join(cur)
            cur = []
    if len(cur) >= 4:
        best = "".join(cur)
    result["device_name"] = best or None
    result["valid"] = True
    return json.dumps(result)


# ---------------------------------------------------------------------------
# UX 2: Detect MIUI vs HyperOS from the build fingerprint
# ---------------------------------------------------------------------------
def detect_os(fingerprint: str) -> str:
    """Detect MIUI/HyperOS from the build fingerprint.

    Xiaomi changed naming: a fingerprint ending in /V816.* (MIUI 14 style)
    can actually be HyperOS 1.0. V814/V816 prefixes map to MIUI 14 on
    Android 13 but may be HyperOS. Returns JSON with os/version/warning.
    """
    result = {"os": "unknown", "version": "", "raw": fingerprint, "warning": None}
    if not fingerprint:
        return json.dumps(result)
    m = re.search(r"/((?:OS\d|V\d+)\.[\d.]+)\.[A-Z]{3,6}", fingerprint)
    if not m:
        return json.dumps(result)
    code = m.group(1)
    if code.startswith("OS"):
        result["os"] = "HyperOS"
        result["version"] = code
        result["warning"] = "Это HyperOS, НЕ MIUI — проверьте совместимость lk.img"
    elif code.startswith("V816") or code.startswith("V814"):
        result["os"] = "MIUI"
        result["version"] = code
        result["warning"] = "MIUI 14 (возможно HyperOS 1.0) — проверьте реальную ОС"
    elif code.startswith("V13") or code.startswith("V12") or code.startswith("V14"):
        result["os"] = "MIUI"
        result["version"] = code
    else:
        result["os"] = "unknown"
        result["version"] = code
    return json.dumps(result)


# ---------------------------------------------------------------------------
# UX 3: Visual fingerprint of the public key (SHA-256 of SPKI)
# ---------------------------------------------------------------------------
def pem_fingerprint() -> str:
    """Return a visual fingerprint of the PUBLIC key (not the private part).

    Builds the RSA SPKI DER from n/e, hashes it with SHA-256, and returns a
    MAC-like short string, a 5x5 color grid and an emoji string. Never hashes
    the private key material; suitable for visual comparison between sessions.
    """
    from pyasn1.codec.der.encoder import encode as der_enc
    from pyasn1.type import namedtype, univ

    assert _KEY is not None, "key not set: call set_key_json(...) first"

    class AlgId(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType("algorithm", univ.ObjectIdentifier()),
            namedtype.OptionalNamedType("parameters", univ.Any()),
        )

    class RsaPub(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType("modulus", univ.Integer()),
            namedtype.NamedType("publicExponent", univ.Integer()),
        )

    class SPKI(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType("algorithm", AlgId()),
            namedtype.NamedType("subjectPublicKey", univ.BitString()),
        )

    rsa = RsaPub()
    rsa.setComponentByName("modulus", _jwk_int(_KEY["n"]))
    rsa.setComponentByName("publicExponent", _jwk_int(_KEY["e"]))
    rsa_der = der_enc(rsa)
    alg = AlgId()
    alg.setComponentByName("algorithm", univ.ObjectIdentifier((1, 2, 840, 113549, 1, 1, 1)))
    alg.setComponentByName("parameters", univ.Null())
    spki = SPKI()
    spki.setComponentByName("algorithm", alg)
    spki.setComponentByName("subjectPublicKey", univ.BitString(hexValue=rsa_der.hex()))
    sha = hashlib.sha256(der_enc(spki)).digest()
    short = ":".join(f"{b:02x}" for b in sha[:8])
    grid = [f"hsl({(sha[i] * 1.4) % 360:.0f}, {50 + sha[i] % 50}%, 50%)" for i in range(25)]
    pool = [
        "🔐", "🔑", "🛡️", "⚡", "🌟", "💎", "🎯",
        "🔥", "✨", "⚙️", "🔒", "🌐", "💫", "🎨", "🌈", "⭐",
    ]
    emoji = "".join(pool[b % len(pool)] for b in sha[:8])
    return json.dumps({"spki_sha256": sha.hex(), "short": short, "grid": grid, "emoji": emoji})


# ---------------------------------------------------------------------------
# SHIM 1: lk_unlock.keys — installed BEFORE importing patcher/signer
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

    def _fallback(attr):  # fallback for unknown names
        return lambda *a, **k: _PrivateKey()

    shim.__getattr__ = _fallback
    sys.modules[name] = shim


# ---------------------------------------------------------------------------
# SHIM 2 (BLOCKER 1): cryptography.hazmat.primitives.serialization
# signer.py does `from cryptography.hazmat.primitives import serialization`,
# so ALL chain levels must exist in sys.modules + attribute chain,
# otherwise the import fails on the parent package.
# ---------------------------------------------------------------------------
def _install_cryptography_shim():
    ser = "cryptography.hazmat.primitives.serialization"
    if ser in sys.modules:
        return

    def _mk(name):
        m = types.ModuleType(name)
        m.__path__ = []  # behave as a package
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

    def _ser_fallback(attr):  # Encoding/PrivateFormat/... — stubs
        return lambda *a, **k: _PrivateKey()

    serialization.__getattr__ = _ser_fallback

    crypto.hazmat = hazmat
    hazmat.primitives = primitives
    primitives.serialization = serialization

    sys.modules["cryptography"] = crypto
    sys.modules["cryptography.hazmat"] = hazmat
    sys.modules["cryptography.hazmat.primitives"] = primitives
    sys.modules[ser] = serialization


# --- Install BOTH shims BEFORE the first lk_unlock.* import -----------------
_install_keys_shim()
_install_cryptography_shim()

import lk_unlock.patcher as _patcher  # noqa: E402  (cryptography no longer needed)
import lk_unlock.signer as _signer  # noqa: E402  (serialization shimmed)


# ---------------------------------------------------------------------------
# Web entry point (called from worker.js)
# ---------------------------------------------------------------------------
def _prepare_key_dir() -> Path:
    """BLOCKER 2: the real sign_token reads key_dir/"private.pem". Write it
    from the JWK (via pyasn1) BEFORE calling the native functions."""
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    (KEY_DIR / "private.pem").write_text(private_pem())
    return KEY_DIR


def patch_file(path_in: str, use_wrap: bool = False) -> str:
    key_dir = _prepare_key_dir()
    out_path = "/tmp/lk_patched.img"
    result = _patcher.patch_img(path_in, out_path, use_wrap, key_dir)
    data = Path(result).read_bytes()
    Path(out_path).write_bytes(data)  # worker.js reads exactly this path
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
    key_dir = _prepare_key_dir()  # writes private.pem (BLOCKER 2)
    token = normalize_token(text)
    result = _signer.sign_token(token, key_dir)
    sig = Path(result).read_bytes()
    return json.dumps(
        {
            "sig_b64": base64.b64encode(sig).decode(),
            "sha256": hashlib.sha256(sig).hexdigest(),
        }
    )
