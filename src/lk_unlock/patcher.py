"""LK image patching: swap Xiaomi's key for ours + cert bypass."""

from __future__ import annotations

import tempfile
from pathlib import Path

from liblk.image import LkImage

from lk_unlock.cert import CertBypassMode, apply_cert_bypass
from lk_unlock.errors import KeyError_, PatchError
from lk_unlock.keys import get_keys, load_xiaomi_key


def patch_img(
    img_path: str,
    output_path: str | None = None,
    use_wrap: bool = False,
    key_dir: Path | None = None,
) -> Path:
    """Patch an LK image: replace Xiaomi's key with ours and fix certs.

    Returns the path of the patched image.
    """
    if key_dir is None:
        key_dir = Path.cwd()

    if output_path is None:
        img = Path(img_path)
        output_path = str(img.with_name(f"{img.stem}_patched{img.suffix}"))

    _, new_pub_key = get_keys(key_dir)
    new_n_bytes = new_pub_key.public_numbers().n.to_bytes(256, byteorder="big")

    try:
        old_pub_key = load_xiaomi_key(key_dir)
    except KeyError_ as exc:
        raise PatchError(str(exc)) from exc

    old_n_bytes = old_pub_key.public_numbers().n.to_bytes(256, byteorder="big")
    try:
        data = Path(img_path).read_bytes()
    except FileNotFoundError as exc:
        raise PatchError(f"'{img_path}' file not found.") from exc

    pos = data.find(old_n_bytes)
    if pos == -1:
        raise PatchError("Xiaomi's public key modulus not found in LK image. Nothing to patch.")

    print(f"[+] Original key modulus found at offset 0x{pos:X}")

    patched_data = data[:pos] + new_n_bytes + data[pos + len(new_n_bytes) :]
    print("[+] Public key patched successfully")

    try:
        image = LkImage(patched_data)
        mode = CertBypassMode.WRAP if use_wrap else CertBypassMode.OVERRIDE
        print(f"[+] Selected cert bypass mode: {mode.value}")
        signed = apply_cert_bypass(image, mode)
        if signed:
            patched_data = bytes(image.contents)
            print(f"[+] Cert bypass completed for: {', '.join(signed)}")
        else:
            print("[+] Cert bypass was not needed")
    except Exception as exc:
        raise PatchError(f"Failed to apply cert bypass: {exc}") from exc

    out = Path(output_path)
    fd, tmp = tempfile.mkstemp(dir=out.parent, prefix=f".{out.name}.", suffix=".tmp")
    with open(fd, "wb") as f:
        f.write(patched_data)
    import os

    os.replace(tmp, out)
    print(f"[+] All done! Lk saved to: {out}")

    return out
