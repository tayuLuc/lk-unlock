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
import struct
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


_POLICY_STRUCT_FORMAT = "<IIIIIbbbbI"
_POLICY_STRUCT_SIZE = struct.calcsize(_POLICY_STRUCT_FORMAT)
_POLICY_NAME_LIMIT = 128
_POLICY_SCAN_LIMIT = 32 * 1024 * 1024
_POLICY_DEFAULT_OFFSET_LIMIT = 1024
_POLICY_HIT_LIMIT = 65536
_POLICY_PREFERRED_PARTITIONS = (
    "lk",
    "lk1",
    "lk2",
    "lk_a",
    "lk_b",
    "bootloader",
    "bootloader_a",
    "bootloader_b",
    "aboot",
    "abl",
    "sbl",
    "sbl1",
)


def _to_bytes(data):
    if isinstance(data, bytes):
        return data
    if isinstance(data, (bytearray, memoryview)):
        return bytes(data)
    try:
        if hasattr(data, "to_bytes"):
            return data.to_bytes()
        return bytes(data)
    except Exception:
        return bytes(memoryview(data))


def _to_u32(value):
    try:
        return int(value) & 0xFFFFFFFF
    except Exception:
        try:
            return int(str(value), 0) & 0xFFFFFFFF
        except Exception:
            return 0


def _ordered_policy_partitions(partitions):
    names = list(partitions.keys())
    lower_to_name = {}
    for name in names:
        key = str(name).lower()
        if key not in lower_to_name:
            lower_to_name[key] = name

    ordered = []

    for name in _POLICY_PREFERRED_PARTITIONS:
        real = lower_to_name.get(name.lower())
        if real is not None and real not in ordered:
            ordered.append(real)

    for name in names:
        key = str(name).lower()
        if name not in ordered and ("lk" in key or "bootloader" in key):
            ordered.append(name)

    for name in names:
        if name not in ordered:
            ordered.append(name)

    return ordered


def _find_default_policy_offsets(data):
    offsets = []
    pos = data.find(b"default\0")
    while pos != -1:
        offsets.append(pos)
        if len(offsets) >= _POLICY_DEFAULT_OFFSET_LIMIT:
            break
        pos = data.find(b"default\0", pos + 1)
    return offsets


def _iter_policy_pointer_hits(data, default_offsets, load_address, address_mask):
    if not default_offsets or len(data) < 8:
        return

    yielded = 0

    # Fast path: full 32-bit address, exact pointer value.
    if address_mask == 0xFFFFFFFF:
        for off in default_offsets:
            needle = struct.pack("<I", (off + load_address) & 0xFFFFFFFF)
            pos = data.find(needle)
            while pos != -1:
                if (pos & 3) == 0:
                    yield pos
                    yielded += 1
                    if yielded >= _POLICY_HIT_LIMIT:
                        return

                # Original scanner only checks 4-byte aligned pointers.
                step = 4 - (pos & 3)
                pos = data.find(needle, pos + step)
        return

    # Masked address: one aligned scan.
    default_set = {off for off in default_offsets if off <= address_mask}
    if not default_set:
        return

    aligned_len = len(data) & ~3
    if aligned_len <= 0:
        return

    mv = memoryview(data)[:aligned_len]
    try:
        iterator = struct.iter_unpack("<I", mv)
    except Exception:
        iterator = struct.iter_unpack("<I", data[:aligned_len])

    for idx, (value,) in enumerate(iterator):
        if ((value - load_address) & address_mask) in default_set:
            yield idx << 2
            yielded += 1
            if yielded >= _POLICY_HIT_LIMIT:
                return


def _decode_policy_name(data, offset):
    end_limit = min(offset + _POLICY_NAME_LIMIT, len(data))
    end = data.find(b"\0", offset, end_limit)
    if end == -1:
        end = end_limit
    return data[offset:end].decode("utf-8", "replace")


def _parse_policy_table(data, start_pos, load_address, address_mask):
    policies = []
    pos = start_pos
    data_len = len(data)

    while pos + _POLICY_STRUCT_SIZE <= data_len and len(policies) < 1024:
        try:
            (
                swid,
                p1,
                p2,
                p3,
                p4,
                pol1,
                pol2,
                pol3,
                pol4,
                hbind,
            ) = struct.unpack_from(_POLICY_STRUCT_FORMAT, data, pos)
        except struct.error:
            break

        if p1 == 0:
            break

        name_offset = (p1 - load_address) & address_mask
        if name_offset >= data_len:
            break

        name = _decode_policy_name(data, name_offset)
        if not name or name == "NULL":
            break

        policies.append(
            {
                "name": name,
                "nosbc_lock": pol1,
                "nosbc_unlock": pol2,
                "sbc_lock": pol3,
                "sbc_unlock": pol4,
            }
        )

        pos += _POLICY_STRUCT_SIZE

    return policies


def _analyze_partition_policies(data, load_address):
    load_address = _to_u32(load_address)
    address_mask = 0x000FFFFF if load_address == 0xFFFFFFFF else 0xFFFFFFFF

    default_offsets = _find_default_policy_offsets(data)

    report = {
        "load_address": f"0x{load_address:08x}",
        "address_mask": f"0x{address_mask:08x}",
        "default_policy_candidates": len(default_offsets),
        "policy_table_found": False,
        "policies": [],
    }

    if not default_offsets:
        return report

    seen = set()
    multiple = False

    try:
        for ptr_pos in _iter_policy_pointer_hits(
            data,
            default_offsets,
            load_address,
            address_mask,
        ):
            pos = ptr_pos - 4
            if pos < 0 or pos in seen:
                continue
            seen.add(pos)

            if pos + _POLICY_STRUCT_SIZE > len(data):
                continue

            try:
                (
                    swid,
                    p1,
                    p2,
                    p3,
                    p4,
                    pol1,
                    pol2,
                    pol3,
                    pol4,
                    hbind,
                ) = struct.unpack_from(_POLICY_STRUCT_FORMAT, data, pos)
            except struct.error:
                continue

            if swid != 0 or p2 != 0 or p3 != 0:
                continue

            if report["policy_table_found"]:
                multiple = True
                continue

            policies = _parse_policy_table(data, pos, load_address, address_mask)
            if policies:
                report["policy_table_found"] = True
                report["policy_table_offset"] = f"0x{pos:x}"
                report["policies"] = policies
    except Exception:
        if not report["policy_table_found"]:
            report["warning"] = "Policy scan failed"

    if multiple:
        report["warning"] = "Multiple policy tables found"

    return report


def _analyze_policies_obj(data, partitions=None):
    empty = {
        "partition": None,
        "policy_table_found": False,
        "policies": [],
        "default_policy_candidates": 0,
        "load_address": None,
        "address_mask": None,
        "partitions_scanned": [],
    }

    try:
        data = _to_bytes(data)
    except Exception:
        empty["error"] = "Не удалось прочитать данные образа"
        return empty

    if len(data) < 8:
        return empty

    if partitions is None:
        try:
            from liblk.image import LkImage

            image = LkImage(data)
            partitions = getattr(image, "partitions", None) or {}
        except Exception:
            partitions = {}

    scanned = []
    skipped = []

    if partitions:
        for name in _ordered_policy_partitions(partitions):
            part = partitions[name]

            try:
                part_data = _to_bytes(getattr(part, "data", b""))
            except Exception:
                skipped.append(name)
                continue

            if not part_data:
                continue

            if len(part_data) > _POLICY_SCAN_LIMIT:
                skipped.append(name)
                continue

            load_address = getattr(part, "lk_address", None)
            if load_address is None:
                load_address = getattr(
                    getattr(part, "header", None),
                    "memory_address",
                    0,
                )

            load_address = _to_u32(load_address)
            scanned.append(name)

            try:
                report = _analyze_partition_policies(part_data, load_address)
            except Exception:
                continue

            if report.get("policy_table_found"):
                report["partition"] = name
                report["partitions_scanned"] = scanned
                if skipped:
                    report["partitions_skipped"] = skipped
                return report

        empty["partitions_scanned"] = scanned
        if skipped:
            empty["partitions_skipped"] = skipped
        return empty

    # Fallback: treat the whole input as one raw LK partition.
    if len(data) <= _POLICY_SCAN_LIMIT:
        try:
            report = _analyze_partition_policies(data, 0)
            if report.get("policy_table_found"):
                report["partition"] = "raw"
                report["partitions_scanned"] = ["raw"]
                return report
        except Exception:
            pass

    return empty


def analyze_policies(data) -> str:
    try:
        return json.dumps(_analyze_policies_obj(data))
    except Exception as e:
        return json.dumps(
            {
                "partition": None,
                "policy_table_found": False,
                "policies": [],
                "error": str(e),
            }
        )


def diagnose_file(data) -> str:
    """Pre-patch diagnostics: magic bytes, size, OEM key presence.

    Runs read-only checks on the uploaded image so the UI can block a
    patch that would brick the device (wrong format, already-patched,
    foreign model). Returns a JSON summary.
    """
    try:
        data = _to_bytes(data)
    except Exception:
        data = b""

    result = {
        "size": len(data),
        "magic_ok": False,
        "magic_hex": data[:4].hex(),
        "has_oem_key": False,
        "oem_key_offset": None,
        "lk_partitions": [],
        "policies": None,
    }

    if len(data) >= 8:
        magic = int.from_bytes(data[0:4], "little")
        result["magic_ok"] = magic == 0x58881688

    partitions = {}
    try:
        from liblk.image import LkImage

        image = LkImage(bytes(data))
        partitions = getattr(image, "partitions", None) or {}
        result["lk_partitions"] = list(partitions.keys())
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

    try:
        result["policies"] = _analyze_policies_obj(data, partitions)
    except Exception:
        result["policies"] = None

    return json.dumps(result)

def _decode_token_bytes(tok: str) -> bytes:
    if not tok:
        raise ValueError("Пустой токен")

    hex_candidate = None

    if re.fullmatch(r"[0-9a-fA-F]+", tok) and len(tok) % 2 == 0:
        try:
            hex_candidate = bytes.fromhex(tok)
        except ValueError as e:
            raise ValueError(f"Невалидный HEX: {e}")

        if hex_candidate and hex_candidate[0] == 0x55:
            return hex_candidate

    stripped = tok.rstrip("=")
    existing_pad = len(tok) - len(stripped)

    if existing_pad > 2:
        raise ValueError("Невалидный Base64: некорректный padding")

    if "=" in stripped:
        raise ValueError("Невалидный Base64: '=' внутри данных")

    if len(stripped) % 4 == 1:
        raise ValueError("Невалидный Base64: некорректная длина")

    need_pad = (4 - (len(stripped) % 4)) % 4

    if existing_pad and existing_pad != need_pad:
        raise ValueError("Невалидный Base64: некорректный padding")

    if not re.fullmatch(r"[A-Za-z0-9+/]*", stripped):
        if hex_candidate is not None:
            return hex_candidate
        raise ValueError("Невалидный Base64: некорректные символы")

    padded = stripped + ("=" * need_pad)

    try:
        data = base64.b64decode(padded, validate=True)
    except Exception as e:
        if hex_candidate is not None:
            return hex_candidate
        raise ValueError(f"Невалидный Base64: {e}")

    if data and data[0] == 0x55:
        return data

    if hex_candidate is not None:
        return hex_candidate

    return data


def parse_token(token_text: str) -> str:
    """Parse the MediaTek unlock token (from `fastboot oem get_token`).

    The token is base64 with a 0x55 prefix; the raw bytes embed the device
    codename as an ASCII string (e.g. "fleur"). We validate base64 + prefix
    and extract the device name by scanning the decoded bytes - robust to
    the exact TLV layout, which varies across builds. Works on bytes only.
    """
    result = {
        "valid": False,
        "error": None,
        "device_name": None,
        "device_name_offset": None,
        "device_name_length": 0,
        "prefix_offset": 0,
        "prefix_ok": False,
        "raw_length": 0,
    }

    try:
        tok = _token_payload(token_text)
        if not tok:
            result["error"] = "Пустой токен"
            return json.dumps(result)

        data = _decode_token_bytes(tok)

    except ValueError as e:
        result["error"] = str(e)
        return json.dumps(result)

    except Exception as e:
        result["error"] = f"Ошибка разбора токена: {e}"
        return json.dumps(result)

    result["raw_length"] = len(data)
    if not data:
        result["error"] = "Токен пуст после декода"
        return json.dumps(result)
    if data[0] != 0x55:
        result["error"] = f"Неверный префикс 0x{data[0]:02x} (ожидался 0x55)"
        return json.dumps(result)
    result["prefix_ok"] = True
    result["prefix_offset"] = 0
    # Extract device codename: first printable ASCII run of >=4 chars.
    best = ""
    best_start = -1
    best_len = 0
    cur = []
    cur_start = -1
    for idx, b in enumerate(data[1:], start=1):
        if 32 <= b < 127:
            if not cur:
                cur_start = idx
            cur.append(chr(b))
        else:
            if len(cur) >= 4:
                best = "".join(cur)
                best_start = cur_start
                best_len = len(cur)
                break  # first device-name run wins
            cur = []
            cur_start = -1
    if not best and len(cur) >= 4:
        best = "".join(cur)
        best_start = cur_start
        best_len = len(cur)
    result["device_name"] = best or None
    result["device_name_offset"] = best_start if best else None
    result["device_name_length"] = best_len if best else 0
    result["valid"] = True
    return json.dumps(result)


# ---------------------------------------------------------------------------
# UX 2: Detect MIUI vs HyperOS from the build fingerprint
# ---------------------------------------------------------------------------
# Version prefix -> (os_name, warning). Xiaomi changes naming often; keep
# this data-driven so new schemes are a one-line addition. V816/V814 look
# like MIUI 14 but can actually be HyperOS 1.0.
_OS_PREFIX_MAP = {
    "OS1": ("HyperOS", "Это HyperOS, НЕ MIUI — проверьте совместимость lk.img"),
    "OS2": ("HyperOS", "Это HyperOS, НЕ MIUI — проверьте совместимость lk.img"),
    "V816": ("MIUI", "MIUI 14 (возможно HyperOS 1.0) — проверьте реальную ОС"),
    "V814": ("MIUI", "MIUI 14 (возможно HyperOS 1.0) — проверьте реальную ОС"),
    "V13": ("MIUI", None),
    "V12": ("MIUI", None),
    "V14": ("MIUI", None),
}


def detect_os(fingerprint: str) -> str:
    """Detect MIUI/HyperOS from the build fingerprint.

    Xiaomi changed naming: a fingerprint ending in /V816.* (MIUI 14 style)
    can actually be HyperOS 1.0. Version mapping lives in _OS_PREFIX_MAP so
    new naming schemes are easy to add. Returns JSON with os/version/warning.
    """
    result = {"os": "unknown", "version": "", "raw": fingerprint, "warning": None}
    if not fingerprint:
        return json.dumps(result)
    m = re.search(r"/((?:OS\d|V\d+)\.[\d.]+)\.[A-Z]{3,6}", fingerprint)
    if not m:
        return json.dumps(result)
    code = m.group(1)
    prefix = code.split(".")[0]
    os_name, warning = _OS_PREFIX_MAP.get(prefix, (None, None))
    if os_name:
        result["os"] = os_name
        result["version"] = code
        if warning:
            result["warning"] = warning
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
    tok = _token_payload(text)
    try:
        return _decode_token_bytes(tok)
    except ValueError:
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
