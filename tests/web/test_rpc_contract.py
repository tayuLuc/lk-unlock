"""RPC contract test: UI methods == worker methods == Python registry.

Single source of truth is patcher_web.RPC_REGISTRY; the manifest travels
worker → UI via rpc.describe. This test fails if the three layers drift.

Run: uv run pytest tests/web/test_rpc_contract.py -v
"""

import http.server
import threading
from pathlib import Path

import pytest
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web"

# lkUnlock keys that are NOT plain RPC methods (registry entries are the rest).
NON_RPC_KEYS = {
    "ready",
    "rpcDescribe",
    "init",
    "patchBufferLegacy",
    "importPem",
    "getPem",
    "getJwk",
    "diagnose",
    "diagnoseImage",
    "validatePatch",
    "patchBuffer",
    "parseToken",
    "detectOS",
    "pemFingerprint",
    "signToken",
}


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


def test_rpc_contract(server):
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(server + "/index.html")
        page.wait_for_function("window.lkUnlock && window.lkUnlock.ready()", timeout=180_000)

        ui_keys = set(page.evaluate("Object.keys(window.lkUnlock)"))
        res = page.evaluate("async () => await window.lkUnlock.rpcDescribe()")
        manifest = res["manifest"]
        worker_methods = set(manifest["methods"])

        ui_rpc_keys = ui_keys - NON_RPC_KEYS
        assert ui_rpc_keys == worker_methods, (
            "RPC mismatch!\n"
            f"Only in UI: {ui_rpc_keys - worker_methods}\n"
            f"Only in Worker/Python: {worker_methods - ui_rpc_keys}"
        )

        duplicate = page.evaluate(
            """() => {
                try { window.__registerRpc('set_key_json', () => {}); return false; }
                catch (e) { return e.message; }
            }"""
        )
        assert duplicate == "duplicate RPC method: set_key_json"

        assert not errors, f"page errors: {errors}"
        browser.close()
