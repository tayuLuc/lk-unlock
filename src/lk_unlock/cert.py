"""Certificate bypass logic.

Replaces Xiaomi's public key inside an LK image with our own, then patches
the certificate (cert2) blocks so the modified image still passes hash
verification. Based on the cert bypass vulnerability originally implemented
in lkpatcher (https://github.com/R0rt1z2/lkpatcher/).
"""

from __future__ import annotations

from collections.abc import Callable
from enum import Enum

from liblk.image import LkImage
from liblk.structures.certificate import Certificate
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type.univ import BitString


class CertBypassMode(str, Enum):
    WRAP = "wrap"
    OVERRIDE = "override"


def build_bypass_cert2_wrap(original_cert2: bytes, header_hash: bytes, image_hash: bytes) -> bytes:
    """Wrap mode: append a forged certificate after the original (CVE-2023-20696)."""
    cert = Certificate.from_bytes(original_cert2)
    verified_copy = der_encode(BitString(hexValue=bytes(original_cert2).hex()))
    forged_copy = cert.encode_with_hashes(header_hash, image_hash)
    return verified_copy + forged_copy


def build_bypass_cert2_override(
    original_cert2: bytes, header_hash: bytes, image_hash: bytes
) -> bytes:
    """Override mode: prepend a hash override block (2026 vuln, no CVE)."""
    cert = Certificate.from_bytes(original_cert2)
    override = cert.build_hash_override_block(header_hash, image_hash)
    return override + bytes(original_cert2)


_CERT_BUILDERS: dict[CertBypassMode, Callable[[bytes, bytes, bytes], bytes]] = {
    CertBypassMode.WRAP: build_bypass_cert2_wrap,
    CertBypassMode.OVERRIDE: build_bypass_cert2_override,
}


def apply_cert_bypass(image: LkImage, mode: CertBypassMode = CertBypassMode.OVERRIDE) -> list[str]:
    """Patch cert2 on every signed partition so the image passes verification.

    Returns the names of partitions that were modified.
    """
    build = _CERT_BUILDERS[CertBypassMode(mode)]
    signed: list[str] = []

    for name, partition in image.partitions.items():
        if partition.cert2 is None:
            continue

        status = partition.matches_cert2()

        if status is None:
            print(f"[-] Partition '{name}' cert2 could not be parsed. Skipping cert bypass.")
            continue

        if status:
            continue

        header_hash, image_hash = partition.compute_hashes()
        original = bytes(partition.cert2.data)
        new_cert = build(original, header_hash, image_hash)
        if len(new_cert) > partition.header.data_size:
            print(
                f"[-] Partition '{name}': cert2 would grow from {len(original)} to "
                f"{len(new_cert)} bytes, exceeding its {partition.header.data_size}-byte "
                "partition. Skipping cert bypass."
            )
            continue
        partition.cert2.data = new_cert

        print(
            f"[+] Cert bypass applied to partition '{name}' "
            f"({mode.value}, cert2 {len(original)} -> {len(partition.cert2.data)} bytes)"
        )
        signed.append(name)

    if signed:
        image._rebuild_contents()

    return signed
