# AGENTS.md

lk-unlock patches the Xiaomi MTK bootloader (LK image) by swapping Xiaomi's
RSA public key for the user's, then signs the unlock token locally. Ships as a
Python CLI (PyInstaller binaries) **and** a self-hosted, fully-offline web app
(Pyodide/WASM) deployed to GitHub Pages.

## Branch & deploy (critical)

- **Default + live branch is `uv-migration`**, NOT `main`. `main` has no Pages
  workflow. Push to `uv-migration` to trigger deploy.
- `pages.yml` builds `web/` via `web/build.py` and auto-deploys to
  https://tayuluc.github.io/lk-unlock/ on every push to `uv-migration`.
- `ci.yml` runs `ruff check` + `ruff format --check` on `src/ tests/`, then
  `web/build.py` + `playwright install chromium` + `pytest`.
- **Every pushed change must pass CI AND have a green Pages deploy run.** Check
  with `gh run list --limit 3`.

## Python package

- Layout: `src/lk_unlock/` (src layout), `liblk` **vendored** under
  `vendor/liblk/` (not on PyPI; pinned via `[tool.uv.sources]` path). See
  `THIRD_PARTY.md` for provenance/update steps.
- Key modules: `cli.py` (patch/sign/unlock), `patcher.py` (patch LK + cert
  bypass), `signer.py` (sign token), `cert.py`, `keys.py`, `fastboot.py`,
  `patches.py` (binary patch recipes), `errors.py`.
- Dev commands (must use `uv run` — deps in `.venv`):
  ```bash
  uv sync --dev
  uv run ruff check src/ tests/
  uv run ruff format --check src/ tests/
  uv run pytest tests/ -q        # 14 tests
  ```
- `ruff` config: line-length 100, select E/F/W/I/UP/B/SIM.

## Web app (Pyodide/WASM) — key quirks

- **Single-file UI in `web/index.html`** (HTML+CSS+JS all inline, no bundler).
  UI strings are **Russian**, code comments **English**.
- `web/worker.js`: Web Worker that boots Pyodide, mounts Python sources into
  FS from `web/gen/pyfiles.js` (generated), installs `pyasn1` from a local
  wheel. **Do not hand-edit generated files** (`web/gen/*`, `web/pyodide/`,
  `web/vendor/`, `web/.cache/`) — they're gitignored and produced by
  `web/build.py`.
- `web/python/patcher_web.py`: the web-exposed Python API (parse_token,
  detect_os, pem_fingerprint, diagnose_file). **Must stay API-compatible with
  the native package** — `tests/web/test_web_parity.py` asserts WASM output
  SHA-equals native Python output.
- **ADB module** (WebUSB + WebSocket) lives in `web/index.html`, **inlined
  from `web/vendor/adb-daemon-browser.js` by `web/build.py`** (build-time
  only; runtime stays fully offline). Read-only getprop → auto-fills
  fingerprint. **Read-only only, NO flashing.**
  - `web/vendor/adb-daemon-browser.js` is the **single source of truth**
    (self-contained ESM, committed in this repo). See
    `notes/adb_websocket_howto.md` for protocol notes (CNXN word, auth
    types, device-only features, no `delayed_ack`, ws://localhost allowed
    on https).
  - Two connectors: `connectAdb()` (WebUSB) and `connectAdbWs(url)`
    (WebSockify bridge, no WebUSB needed).
  - A big refactor plan exists in `notes/webusb_refactor_plan.md`
    (ES-module split, state machine, mock for Playwright) — deferred.
- `web/index.html` is **large** (100k+ bytes). After editing, validate JS
  syntax by extracting the `<script>` and `node --check` it.

### Build & test the web bundle

```bash
uv run python web/build.py          # needs network ONLY at build time
uv run playwright install chromium  # once
uv run python -m http.server -d web 8000   # local smoke
uv run pytest tests/ -q             # runs full suite incl. WASM parity
uv run pytest tests/web/test_web_parity.py -v   # parity only
```

Parity test requires `web/build.py` already run and `tests/files/lk.img` +
`test_key.{jwk,pem}` present (regenerate via `scripts/make_test_key.py`).

## Testing conventions

- `tests/files/` holds fixtures: `lk.img`, `test_key.pem`, `test_key.jwk`.
- The web parity test boots real Chromium + Pyodide and compares WASM output
  to native — slow (~minutes). It is the main correctness gate for web changes.
- Native CLI tests are in `tests/test_lk_unlock.py` (14 total).

## Style / workflow

- User-facing UI text: **Russian**. Code, comments, commit messages: **English**.
- Before applying web/UX changes, the user wants them reviewed by the local
  Qwen model (see `~/.agents/skills/qwen-llm-bot/`). Run in background via
  `chat.sh`, never synchronously.
- Do NOT add a bundler (Vite/webpack) — the web app must stay a static
  single-file Pages deploy.
