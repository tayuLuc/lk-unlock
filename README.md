
# lk-unlock

Unlock the bootloader of Xiaomi devices with MTK SoCs by patching the little
kernel (LK) image. Replaces Xiaomi's public key with your own and generates
the unlock signature locally — no Xiaomi server, no waiting, no account.
Made possible by a **cert bypass vulnerability**, originally implemented in
[lkpatcher](https://github.com/R0rt1z2/lkpatcher/).

> **⚠️ WARNING:** This method is dangerous and could brick your device.
> Proceed only if you understand what you are doing and know how to restore
> the device. **After unlocking, do NOT install OTA updates** — they can
> overwrite `lk` and re-lock (or brick) the device. Flash via PC only.

## How it works

Xiaomi bootloader unlocking uses asymmetric RSA. The device generates a
one-time token, sent to the server; the server signs it with its private key
and sends it back; the device verifies the signature using the public key
embedded in the bootloader (for MTK — in LK). No one knows Xiaomi's private
key, so offline unlocking was impossible — until a vulnerability affecting
all MTK devices broke secure boot, allowing a modified LK to run. This tool
patches LK by swapping Xiaomi's public key for yours (for which the private
key is known), so the unlock token can be signed locally.

## Requirements

- Python 3.10+ (or use a prebuilt binary — see [Binaries](#binaries))
- `fastboot` in `PATH` (Android platform-tools)
- [uv](https://docs.astral.sh/uv/) for reproducible installs (optional for
  prebuilt binaries)

## Installation

```bash
uv sync            # installs deps + the `lk-unlock` CLI into .venv
uv run lk-unlock --help
```

Dependencies are locked in `uv.lock`; `liblk` is **vendored** under
`vendor/liblk/` (see `THIRD_PARTY.md`) so builds never depend on GitHub
availability.

## Usage

Three subcommands: `patch`, `sign`, `unlock`.

### 1. Patch the LK image

Obtain your device's `lk.img` (from a firmware, or read it from the device
directly in brom mode via MTKClient).

```bash
lk-unlock patch lk.img -o lk_patched.img
```

Options:
- `--wrap` — use wrap mode for cert bypass (default is `override`).
- `-d/--key-dir` — directory for keys (default: current dir).

This will:
- Generate `private.pem` and `public.pem` if not present.
- Replace Xiaomi's public key modulus with yours.
- Apply cert bypass to all signed partitions.
- Save the patched image to `lk_patched.img`.

### 2. Flash the patched LK image

One of these methods:

1. [MTKClient](https://github.com/bkerler/mtkclient) (if your device is supported):
   ```bash
   python mtk.py r lk_a,lk_b lk_a_backup.img,lk_b_backup.img
   python mtk.py w lk_a,lk_b lk_patched.img,lk_patched.img
   ```
2. Official Xiaomi BROM auth (paid service in Telegram / elsewhere).
3. Temp root exploits (Ghostlock, etc.).
4. UFS programmer / other hardware tool.

### 3. Unlock the device

Reboot into fastboot and run:

```bash
lk-unlock unlock                # one device connected
lk-unlock unlock -s <serial>    # specific device if several are connected
lk-unlock unlock --dry-run      # read + sign token, skip stage/unlock
```

This will:
- Detect your device in fastboot mode.
- Request an unlock token.
- Sign it using `private.pem`.
- Stage and send the unlock command.

### 4. Manual token signing (optional)

```bash
fastboot oem get_token
lk-unlock sign "TOKEN"
fastboot stage signature.bin
fastboot oem unlock
```

## Cert bypass modes

- **Override** (default): inserts a custom hash override block into the
  certificate (2026 vulnerability, no CVE code).
- **Wrap** (`--wrap`): appends a forged certificate after the original,
  causing the verifier to use the forged data (CVE-2023-20696).

## Binaries

Prebuilt single-file binaries for Linux / macOS / Windows are attached to
every `v*` tag release (built by GitHub Actions with PyInstaller; SHA256
checksums included). Download, `chmod +x` (on Unix), and run — no Python
needed.

## Development

```bash
uv sync --dev
uv run ruff check src/ tests/      # lint
uv run ruff format --check src/ tests/   # format
uv run pytest tests/ -v            # tests
```

## Credits

- Cert bypass code adapted from [lkpatcher](https://github.com/R0rt1z2/lkpatcher/) by R0rt1z2.
- [liblk](https://github.com/R0rt1z2/liblk) by R0rt1z2 (vendored, see `THIRD_PARTY.md`).
- [MTKClient](https://github.com/bkerler/mtkclient) for flashing the patched image.
- [Xiaomi bootloader research](https://github.com/lrh2000/Xiaomi-bootloader).

## Disclaimer

This tool is for educational and research purposes only. The authors are not
responsible for any damage caused by the use of this tool. Always back up
your device data and proceed with caution.

## License

AGPL-3.0. The code is free and is not intended for sale, commercial use, or
illegal purposes. Vendored `liblk` remains GPL-3.0 (compatible, see
`THIRD_PARTY.md`).
