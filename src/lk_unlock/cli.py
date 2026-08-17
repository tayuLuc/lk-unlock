"""Command-line interface for lk-unlock."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from lk_unlock import __version__
from lk_unlock.errors import LkUnlockError
from lk_unlock.fastboot import get_token, unlock_device
from lk_unlock.patcher import patch_img
from lk_unlock.patches import DEFAULT_PATCHES, WARNING_CATEGORIES, apply_patch_categories
from lk_unlock.signer import sign_token


def _list_partitions(img: str) -> None:
    from liblk.image import LkImage

    image = LkImage(img)
    for name, part in image.partitions.items():
        size = len(part.data)
        c1 = part.cert1 is not None
        c2 = part.cert2 is not None
        print(f"{name:24s} {size:>10,} bytes  cert1={c1} cert2={c2}")


def _dump_partition(img: str, name: str, output: str | None) -> None:
    from liblk.image import LkImage

    if any(c in name for c in "/\\"):
        raise LkUnlockError(f"invalid partition name: {name!r}")
    image = LkImage(img)
    if name not in image.partitions:
        raise LkUnlockError(f"partition '{name}' not found in {img}")
    out = Path(output) if output else Path(img).with_name(f"{name}.bin")
    _check_output_path(img, out)
    out.write_bytes(image.partitions[name].data)
    print(f"[+] Dumped '{name}' ({len(image.partitions[name].data)} bytes) to {out}")


def _check_output_path(img: str, out: Path) -> None:
    if out.resolve() == Path(img).resolve():
        raise LkUnlockError("output path cannot be the same as the input image")


def _patch_and_save(
    img: str, output: str | None, categories: list[str], patches: dict | None = None
) -> None:
    from liblk.image import LkImage

    image = LkImage(img)
    results = apply_patch_categories(image, categories, patches)
    for cat, count in results.items():
        print(f"[+] '{cat}': {count} patch(es) applied")
    if not any(results.values()):
        raise LkUnlockError("no patches could be applied - needles not found in image")
    out = Path(output) if output else Path(img).with_name(
        f"{Path(img).stem}_patched{Path(img).suffix}"
    )
    _check_output_path(img, out)
    image.save(str(out))
    print(f"[+] All done! Saved to: {out}")


def _validate_custom_patches(data) -> dict[str, dict[str, str]]:
    """Validate patch-custom JSON: {category: {needle_hex: replacement_hex}}."""
    if not isinstance(data, dict) or not data:
        raise LkUnlockError("custom patches must be a non-empty JSON object")
    result: dict[str, dict[str, str]] = {}
    for cat, recipes in data.items():
        if not isinstance(cat, str) or not isinstance(recipes, dict) or not recipes:
            raise LkUnlockError(f"category '{cat}' must map to a non-empty object")
        clean: dict[str, str] = {}
        for needle, replacement in recipes.items():
            if not all(isinstance(v, str) for v in (needle, replacement)):
                raise LkUnlockError(f"category '{cat}': needle/replacement must be hex strings")
            if len(needle) % 2 or len(replacement) % 2:
                raise LkUnlockError(f"category '{cat}': hex strings must have even length")
            clean[needle] = replacement
        result[cat] = clean
    return result


def _show_info(img: str) -> None:
    from liblk.image import LkImage

    image = LkImage(img)
    print(f"image version: {image.version}")
    print(f"partitions: {len(image.partitions)}")
    total = 0
    for name, part in image.partitions.items():
        size = len(part.data)
        total += size
        addr = getattr(part.header, "memory_address", 0)
        print(
            f"  {name:24s} {size:>10,} bytes  @0x{addr:08x}  "
            f"cert1={part.cert1 is not None} cert2={part.cert2 is not None}"
        )
    print(f"total data: {total:,} bytes")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lk-unlock",
        description="Unlocking Xiaomi mtk bootloader by patching the public key.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "-d",
        "--key-dir",
        type=Path,
        default=Path.cwd(),
        help="Directory for private.pem/public.pem/signature.bin (default: cwd)",
    )
    parser.add_argument(
        "-s",
        "--serial",
        default="",
        help="fastboot device serial (required if more than one device is connected)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    patch_parser = subparsers.add_parser("patch", help="Patch lk.img")
    patch_parser.add_argument("img", help="lk.img file path")
    patch_parser.add_argument("-o", "--output", help="Output file path", default=None)
    patch_parser.add_argument("--wrap", action="store_true", help="Use wrap mode for cert bypass")

    list_parser = subparsers.add_parser("list", help="List partitions in lk.img")
    list_parser.add_argument("img", help="lk.img file path")

    dump_parser = subparsers.add_parser("dump", help="Dump a partition from lk.img")
    dump_parser.add_argument("img", help="lk.img file path")
    dump_parser.add_argument("name", help="Partition name to dump")
    dump_parser.add_argument("-o", "--output", help="Output file path", default=None)

    info_parser = subparsers.add_parser("info", help="Show lk.img information")
    info_parser.add_argument("img", help="lk.img file path")

    patch_fb = subparsers.add_parser("patch-fastboot", help="Unlock fastboot access")
    patch_fb.add_argument("img", help="lk.img file path")
    patch_fb.add_argument("-o", "--output", help="Output file path", default=None)

    patch_warn = subparsers.add_parser("patch-warnings", help="Remove bootup warnings")
    patch_warn.add_argument("img", help="lk.img file path")
    patch_warn.add_argument("-o", "--output", help="Output file path", default=None)

    patch_all = subparsers.add_parser("patch-all", help="Apply all known patches")
    patch_all.add_argument("img", help="lk.img file path")
    patch_all.add_argument("-o", "--output", help="Output file path", default=None)

    patch_custom = subparsers.add_parser("patch-custom", help="Apply custom patches from JSON")
    patch_custom.add_argument("img", help="lk.img file path")
    patch_custom.add_argument(
        "patches_json", help="JSON file: {category: {needle_hex: replacement_hex}}"
    )
    patch_custom.add_argument("-o", "--output", help="Output file path", default=None)

    sign_parser = subparsers.add_parser("sign", help="Sign the token")
    sign_parser.add_argument("token", help="Token string")

    unlock_parser = subparsers.add_parser("unlock", help="Unlock patched device automatically")
    unlock_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Read and sign token, but skip stage and unlock",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    print(f"[*] LK-Unlock v{__version__}")

    try:
        if args.command == "patch":
            patch_img(args.img, args.output, args.wrap, key_dir=args.key_dir)
        elif args.command == "list":
            _list_partitions(args.img)
        elif args.command == "dump":
            _dump_partition(args.img, args.name, args.output)
        elif args.command == "info":
            _show_info(args.img)
        elif args.command == "patch-fastboot":
            _patch_and_save(args.img, args.output, ["fastboot"])
        elif args.command == "patch-warnings":
            _patch_and_save(args.img, args.output, list(WARNING_CATEGORIES))
        elif args.command == "patch-all":
            _patch_and_save(args.img, args.output, list(DEFAULT_PATCHES))
        elif args.command == "patch-custom":
            with Path(args.patches_json).open() as f:
                custom = _validate_custom_patches(json.load(f))
            _patch_and_save(args.img, args.output, list(custom), custom)
        elif args.command == "sign":
            sign_token(args.token, key_dir=args.key_dir)
        elif args.command == "unlock":
            signature_path = args.key_dir / "signature.bin"
            token = None
            if not signature_path.exists() or args.dry_run:
                token = get_token(args.serial)
                print(f"[+] Token received: {token}")
                sign_token(token, key_dir=args.key_dir)
            unlock_device(
                dry_run=args.dry_run,
                signature_path=signature_path,
                serial=args.serial,
                token=token,
            )
    except LkUnlockError as exc:
        print(f"[-] {exc}")
        return 1
    except KeyboardInterrupt:
        print("\n[-] Interrupted.")
        return 130

    return 0


if __name__ == "__main__":
    sys.exit(main())
