"""Command-line interface for lk-unlock."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from lk_unlock import __version__
from lk_unlock.errors import LkUnlockError
from lk_unlock.fastboot import get_token, unlock_device
from lk_unlock.patcher import patch_img
from lk_unlock.signer import sign_token


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
        elif args.command == "sign":
            sign_token(args.token, key_dir=args.key_dir)
        elif args.command == "unlock":
            signature_path = args.key_dir / "signature.bin"
            if not signature_path.exists() or args.dry_run:
                token = get_token(args.serial)
                print(f"[+] Token received: {token}")
                sign_token(token, key_dir=args.key_dir)
            unlock_device(dry_run=args.dry_run, signature_path=signature_path, serial=args.serial)
    except LkUnlockError as exc:
        print(f"[-] {exc}")
        return 1
    except KeyboardInterrupt:
        print("\n[-] Interrupted.")
        return 130

    return 0


if __name__ == "__main__":
    sys.exit(main())
