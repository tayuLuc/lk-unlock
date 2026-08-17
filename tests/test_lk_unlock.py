"""Tests for lk-unlock."""

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from liblk.image import LkImage
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type.univ import BitString, Integer, Sequence

from lk_unlock.cert import (
    CertBypassMode,
    apply_cert_bypass,
    build_bypass_cert2_override,
    build_bypass_cert2_wrap,
)
from lk_unlock.errors import LkUnlockError
from lk_unlock.signer import encode

FILES = Path(__file__).parent / "files"
TEST_LK = FILES / "lk.img"


def _fake_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _fake_cert2() -> bytes:
    """Minimal valid MediaTek cert2: DER sequence, image hash at index 10,
    header hash at index 14."""
    seq = Sequence()
    for i in range(15):
        seq.setComponentByPosition(i, Integer(0))
    seq.setComponentByPosition(10, BitString(hexValue="AA" * 32))
    seq.setComponentByPosition(14, BitString(hexValue="BB" * 32))
    return der_encode(seq)


def test_encode_pkcs1():
    token = b"deadbeef"
    em = encode(token)
    assert em[0] == 0x00
    assert em[1] == 0x01
    assert em[2] == 0xFF
    assert em[-len(token) - 1] == 0x00
    assert em[-len(token) :] == token
    assert len(em) == 256


def test_encode_rejects_long_token():
    with pytest.raises(ValueError):
        encode(b"\x00" * 254)


def test_cert_builders():
    if not TEST_LK.exists():
        pytest.skip("test lk.img not present")
    img = LkImage(TEST_LK)
    cert2 = bytes(img.partitions["lk"].cert2.data)
    header_hash, image_hash = img.partitions["lk"].compute_hashes()

    wrap = build_bypass_cert2_wrap(cert2, header_hash, image_hash)
    override = build_bypass_cert2_override(cert2, header_hash, image_hash)

    assert len(wrap) > len(cert2)
    assert len(override) > len(cert2)
    # Wrap mode wraps the original cert in a BIT STRING (0x03 tag).
    assert wrap.startswith(b"\x03")
    # Override mode prepends the hash-override block ([0] tag).
    assert override.startswith(b"\xa0")


def test_cert_bypass_modes():
    assert {m.value for m in CertBypassMode} == {"wrap", "override"}


def test_key_pair_modulus_size():
    priv = _fake_key()
    n_bytes = priv.public_key().public_numbers().n.to_bytes(256, "big")
    assert len(n_bytes) == 256


@pytest.mark.skipif(not TEST_LK.exists(), reason="test lk.img not present")
def test_real_lk_bypass_repairs_modified_partition():
    img = LkImage(TEST_LK)
    lk = img.partitions["lk"]
    assert lk.matches_cert2() is True

    # Corrupt the partition data so it no longer matches its cert2.
    data = bytearray(lk.data)
    data[0x100] ^= 0xFF
    lk.data = bytes(data)
    assert lk.matches_cert2() is False

    signed = apply_cert_bypass(img)
    assert "lk" in signed
    # The forged cert2 must carry the override block ([0] tag) as a prefix.
    assert bytes(img.partitions["lk"].cert2.data).startswith(b"\xa0")


@pytest.mark.skipif(not TEST_LK.exists(), reason="test lk.img not present")
def test_real_lk_unmodified_needs_no_bypass():
    img = LkImage(TEST_LK)
    signed = apply_cert_bypass(img)
    assert signed == []


@pytest.mark.skipif(not TEST_LK.exists(), reason="test lk.img not present")
def test_real_lk_matches_cert2():
    img = LkImage(TEST_LK)
    for name, p in img.partitions.items():
        if p.cert2 is not None:
            assert p.matches_cert2() is True, f"{name} should match its cert2"


@pytest.mark.skipif(not TEST_LK.exists(), reason="test lk.img not present")
def test_list_and_dump_partitions(tmp_path):
    from lk_unlock.cli import _dump_partition, _list_partitions

    _list_partitions(str(TEST_LK))  # smoke test - must not raise

    out = tmp_path / "lk_dump.bin"
    _dump_partition(str(TEST_LK), "lk", str(out))
    assert out.exists()
    assert len(out.read_bytes()) == len(LkImage(TEST_LK).partitions["lk"].data)

    with pytest.raises(LkUnlockError):
        _dump_partition(str(TEST_LK), "nonexistent", str(tmp_path / "x.bin"))


@pytest.mark.skipif(not TEST_LK.exists(), reason="test lk.img not present")
def test_apply_patch_categories(tmp_path):
    from lk_unlock.cli import _patch_and_save
    from lk_unlock.patches import DEFAULT_PATCHES

    # Patch with a guaranteed-present needle from the lk partition body.
    lk = LkImage(TEST_LK).partitions["lk"].data
    needle = lk[0x100:0x104].hex()
    custom = {"test_cat": {needle: "deadbeef"}}

    out = tmp_path / "patched.img"
    _patch_and_save(str(TEST_LK), str(out), ["test_cat"], custom)
    assert out.exists()

    patched_lk = LkImage(out).partitions["lk"].data
    assert patched_lk[0x100:0x104].hex() == "deadbeef"

    # Default patches may or may not apply to this image - must not crash.
    _patch_and_save(str(TEST_LK), str(tmp_path / "all.img"), list(DEFAULT_PATCHES))


def test_validate_custom_patches_rejects_bad_json():
    from lk_unlock.cli import _validate_custom_patches
    from lk_unlock.errors import LkUnlockError

    with pytest.raises(LkUnlockError):
        _validate_custom_patches([])  # not a dict
    with pytest.raises(LkUnlockError):
        _validate_custom_patches({"cat": {}})  # empty category
    with pytest.raises(LkUnlockError):
        _validate_custom_patches({"cat": {"abc": "00207047"}})  # odd-length hex
    with pytest.raises(LkUnlockError):
        _validate_custom_patches({"cat": {1: "00207047"}})  # non-str needle

    ok = _validate_custom_patches({"cat": {"aabb": "0020"}})
    assert ok == {"cat": {"aabb": "0020"}}


def test_patch_and_save_rejects_same_output(tmp_path):
    from lk_unlock.cli import _patch_and_save
    from lk_unlock.errors import LkUnlockError

    if not TEST_LK.exists():
        pytest.skip("test lk.img not present")
    with pytest.raises(LkUnlockError):
        _patch_and_save(str(TEST_LK), str(TEST_LK), ["fastboot"])


def test_lk_partition_selection_ab_slots():
    from lk_unlock.patches import _lk_partitions

    class FakeImage:
        def __init__(self, parts):
            self.partitions = parts

    assert _lk_partitions(FakeImage({"lk": 1, "lk_main_dtb": 2})) == ["lk"]
    assert _lk_partitions(FakeImage({"lk_a": 1, "lk_b": 2, "boot": 3})) == ["lk_a", "lk_b"]
    assert _lk_partitions(FakeImage({"boot": 1, "super": 2})) == []
