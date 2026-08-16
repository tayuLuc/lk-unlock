"""Fastboot interaction: token read, signature stage, unlock command."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from lk_unlock.errors import FastbootError


def _fastboot_binary() -> str:
    exe = shutil.which("fastboot")
    if exe is None:
        raise FastbootError(
            "fastboot binary not found. Install Android platform-tools "
            "or put fastboot in the program folder / PATH."
        )
    return exe


def _run(*args: str) -> subprocess.CompletedProcess:
    command = [_fastboot_binary(), *args]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError as exc:
        raise FastbootError(f"Failed to run fastboot: {exc}") from exc

    if result.returncode != 0:
        error_text = (result.stderr or result.stdout).strip()
        if error_text:
            raise FastbootError(f"fastboot {' '.join(args)} failed: {error_text}")
        raise FastbootError(f"fastboot {' '.join(args)} failed")
    return result


def get_devices() -> list[str]:
    """Return serials of connected fastboot devices."""
    result = _run("devices")
    return [line.strip().split(" ")[0] for line in result.stdout.splitlines() if line.strip()]


def _serial_prefix(serial: str) -> tuple[str, ...]:
    return ("-s", serial) if serial else ()


def extract_token(output: str) -> str:
    """Pull the token out of `fastboot oem get_token` output."""
    token_lines = []
    for line in output.splitlines():
        match = re.match(r"^\(bootloader\)\s+token:\s*(.+)$", line.strip(), re.IGNORECASE)
        if match:
            token_lines.append(match.group(1).strip())
    return "".join(token_lines)


def get_token(serial: str = "") -> str:
    """Read the unlock token from the device."""
    token_result = _run(*_serial_prefix(serial), "oem", "get_token")
    token_output = (token_result.stdout or "") + (token_result.stderr or "")
    token = extract_token(token_output)
    if not token:
        raise FastbootError("Failed to extract token from fastboot output.")
    return token


def unlock_device(
    dry_run: bool = False, signature_path: Path | None = None, serial: str = ""
) -> None:
    """Perform the fastboot unlock sequence with a (pre-signed) signature."""
    if signature_path is None:
        raise FastbootError("signature.bin path required (sign the token first).")

    devices = get_devices()
    if not devices:
        raise FastbootError("No fastboot devices found.")
    if serial and serial not in devices:
        raise FastbootError(f"Device {serial} not found in fastboot.")
    target = serial or devices[0]
    print(f"[+] Device found: {target}")

    token = get_token(target)
    print(f"[+] Token received: {token}")

    if dry_run:
        print("[+] Dry run enabled. Skipping fastboot stage and fastboot oem unlock")
        return

    print("[+] Uploading signature.bin to device...")
    _run(*_serial_prefix(target), "stage", str(signature_path))

    print("[+] Sending unlock command...")
    _run(*_serial_prefix(target), "oem", "unlock")

    print("[+] Device unlock command completed successfully")


def reboot_bootloader(serial: str = "") -> None:
    """Reboot the device into fastboot mode."""
    _run(*_serial_prefix(serial), "reboot", "bootloader")
