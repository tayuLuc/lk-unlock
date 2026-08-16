"""Parity: результат lk-unlock в Pyodide (WASM) == нативному Python (по sha256).

Запуск: uv run pytest tests/web/test_web_parity.py -v
Нужно: uv run playwright install chromium; uv run python web/build.py

Исправлено: эталон считается РЕАЛЬНЫМИ функциями пакета (patch_img/sign_token),
подпись RAW без хэша — как в signer.py.
"""

import base64
import hashlib
import http.server
import json
import threading
from pathlib import Path

import pytest
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web"
LK_IMG = ROOT / "tests/files/lk.img"
TEST_KEY_JWK = ROOT / "tests/files/test_key.jwk"
TEST_KEY_PEM = ROOT / "tests/files/test_key.pem"

# TODO(интеграция): подставьте значение по умолчанию вашего CLI для use_wrap
USE_WRAP = False

# Токен 64 байта (< 253, иначе raw-блок не влезет в 256 байт модуля).
TOKEN_BYTES = bytes.fromhex("ab" * 64)
TOKEN_TEXT = "(bootloader) " + TOKEN_BYTES.hex()


def sha(b):
    return hashlib.sha256(b).hexdigest()


def native_reference(tmp_path) -> dict:
    """Эталон: тот же lk.img и тот же ключ, но РЕАЛЬНЫЙ нативный код."""
    from cryptography.hazmat.primitives import serialization

    import lk_unlock.keys as K
    import lk_unlock.patcher as P
    import lk_unlock.signer as S

    priv = serialization.load_pem_private_key(TEST_KEY_PEM.read_bytes(), password=None)
    pub = priv.public_key()

    key_dir = tmp_path / "keydir"
    key_dir.mkdir()
    # страховка, если код читает ключ из файла помимо get_keys/load_private_key
    (key_dir / "private.pem").write_bytes(TEST_KEY_PEM.read_bytes())

    def fake_get_keys(key_dir=None):
        return priv, pub

    def fake_load_private_key(*a, **k):
        return priv

    patched = []
    for mod in (K, P, S):
        for fname, fake in (
            ("get_keys", fake_get_keys),
            ("load_private_key", fake_load_private_key),
        ):
            if hasattr(mod, fname):
                patched.append((mod, fname, getattr(mod, fname)))
                setattr(mod, fname, fake)
    try:
        out_img = key_dir / "lk_patched.img"
        res = P.patch_img(str(LK_IMG), str(out_img), USE_WRAP, key_dir)
        patched_bytes = Path(res).read_bytes()
        sig_res = S.sign_token(TOKEN_BYTES, key_dir)
        sig_bytes = Path(sig_res).read_bytes()
    finally:
        for mod, fname, orig in patched:
            setattr(mod, fname, orig)
    return {"patched": sha(patched_bytes), "sig": sha(sig_bytes)}


@pytest.fixture(scope="module")
def server():
    class H(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **k):
            super().__init__(*a, directory=str(WEB), **k)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_wasm_equals_native(server, tmp_path):
    assert (WEB / "pyodide/pyodide.js").exists(), "сначала: uv run python web/build.py"
    assert LK_IMG.exists(), "нужен tests/files/lk.img"
    assert TEST_KEY_JWK.exists() and TEST_KEY_PEM.exists(), (
        "нужны tests/files/test_key.{jwk,pem} (scripts/make_test_key.py)"
    )

    exp = native_reference(tmp_path)

    img_b64 = base64.b64encode(LK_IMG.read_bytes()).decode()
    jwk = json.loads(TEST_KEY_JWK.read_text())

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(server + "/index.html")
        page.wait_for_function("window.lkUnlock && window.lkUnlock.ready()", timeout=180_000)

        # 1) патч через WASM фиксированным ключом
        #    (ВАЖНО: выполняется ДО sign, чтобы зафиксировать тестовый ключ)
        r = page.evaluate(
            """async ({img, jwk}) => {
            const buf = Uint8Array.from(atob(img), c => c.charCodeAt(0)).buffer;
            const r = await window.lkUnlock.patchBuffer(buf, jwk);
            return {sha: r.sha256, pem: r.pem};
        }""",
            {"img": img_b64, "jwk": jwk},
        )
        assert r["sha"] == exp["patched"], "lk_patched.img: WASM != нативный Python"
        assert r["pem"].startswith("-----BEGIN RSA PRIVATE KEY-----")

        # 2) подпись токена через WASM тем же ключом (RAW, без хэша)
        s = page.evaluate("t => window.lkUnlock.signToken(t)", TOKEN_TEXT)
        assert s["sha256"] == exp["sig"], "signature.bin: WASM != нативный Python"

        # 3) прогон через реальный UI (скачивание lk_patched.img)
        with page.expect_download() as dl:
            page.set_input_files("#lkfile", str(LK_IMG))
            page.click("#btnPatch")
        assert dl.value.suggested_filename == "lk_patched.img"
        assert sha(Path(dl.value.path()).read_bytes()) == exp["patched"]

        assert not errors, f"ошибки страницы: {errors}"
        browser.close()
