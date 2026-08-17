"use strict";
/* Web Worker: Pyodide + lk-unlock. All self-hosted: ./pyodide/, ./vendor/, ./gen/. */
importScripts("./pyodide/pyodide.js");
importScripts("./gen/pyfiles.js");

let pyodide = null, pw = null, hasKey = false;
const pyLog = (...a) => self.postMessage({type: "log", message: a.join(" ")});

async function ensurePyodide() {
  if (pyodide) return;
  pyLog("loadPyodide...");
  pyodide = await loadPyodide({indexURL: "./pyodide/"});
  await pyodide.loadPackage("micropip");
  const micropip = pyodide.pyimport("micropip");
  const vinfo = await (await fetch("./gen/vendor.json")).json();
  pyLog("Installing pyasn1 (local wheel)...");
  await micropip.install("./vendor/" + vinfo.wheel);
  pyLog("Mounting Python sources into FS...");
  const FS = pyodide.FS;
  for (const [path, content] of Object.entries(self.__PYFILES__)) {
    const full = "/app/" + path;
    FS.mkdirTree(full.slice(0, full.lastIndexOf("/")));
    FS.writeFile(full, content);
  }
  pyodide.runPython(`
import sys
sys.path.insert(0, "/app")
import patcher_web   # lk_unlock.keys shim is installed BEFORE importing patcher
`);
  pw = pyodide.pyimport("patcher_web");
}

async function genJwk() {
  const kp = await crypto.subtle.generateKey(
    {name: "RSASSA-PKCS1-v1_5", modulusLength: 2048,
     publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256"},
    true, ["sign", "verify"]);
  return await crypto.subtle.exportKey("jwk", kp.privateKey);
}

/**
 * Ensure a key is loaded in the Python side.
 * @param {object|null} jwk   - JWK object (from WebCrypto or localStorage)
 * @param {string|null} pem   - PKCS#1 PEM text (from file import)
 * @returns {object} the active JWK (for localStorage)
 */
async function ensureKey(jwk, pem) {
  await ensurePyodide();

  if (pem) {
    const jwkStr = pw.parse_private_pem(pem);
    pw.set_key_json(jwkStr);
    hasKey = true;
    pyLog("Imported key from PEM (PKCS#1).");
    return JSON.parse(jwkStr);
  }

  if (!hasKey || jwk) {
    const key = jwk || await genJwk();
    const jwkStr = JSON.stringify(key);
    pw.set_key_json(jwkStr);
    hasKey = true;
    pyLog(jwk ? "Using external/test key."
              : "Generated a new RSA-2048 pair (WebCrypto).");
    return key;
  }

  return JSON.parse(pw.get_jwk());
}

async function handle(msg) {
  switch (msg.type) {
    case "init": {
      const jwk = await ensureKey(msg.jwk || null, msg.pem || null);
      return {type: "ready", jwk: jwk};
    }
    case "patch": {
      await ensureKey(msg.jwk || null);
      pyodide.FS.writeFile("/tmp/lk_in.img", new Uint8Array(msg.buf));
      const meta = JSON.parse(pw.patch_file("/tmp/lk_in.img"));
      const out = pyodide.FS.readFile("/tmp/lk_patched.img");
      const copy = new Uint8Array(out);
      return {type: "result", img: copy.buffer, pem: meta.pem, sha256: meta.sha256};
    }
    case "sign": {
      await ensureKey(msg.jwk || null);
      const r = JSON.parse(pw.sign_token(msg.token));
      const sig = Uint8Array.from(atob(r.sig_b64), c => c.charCodeAt(0));
      return {type: "result", sig: sig.buffer, sha256: r.sha256};
    }
    case "pem":
      await ensureKey(null);
      return {type: "result", pem: pw.private_pem()};
    case "get_jwk":
      await ensurePyodide();
      return {type: "result", jwk: JSON.parse(pw.get_jwk())};
    case "diagnose": {
      await ensurePyodide();
      const r = JSON.parse(pw.diagnose_file(msg.buf));
      return {type: "result", ...r};
    }
    case "parse_token": {
      await ensurePyodide();
      const r = JSON.parse(pw.parse_token(msg.token));
      return {type: "result", ...r};
    }
    case "detect_os": {
      await ensurePyodide();
      const r = JSON.parse(pw.detect_os(msg.fingerprint));
      return {type: "result", ...r};
    }
    case "pem_fingerprint": {
      await ensureKey(msg.jwk || null);
      const r = JSON.parse(pw.pem_fingerprint());
      return {type: "result", ...r};
    }
  }
  throw new Error("unknown message type: " + msg.type);
}

self.onmessage = async (e) => {
  const msg = e.data;
  try {
    const r = await handle(msg);
    const transfer = [];
    if (r.img) transfer.push(r.img);
    if (r.sig) transfer.push(r.sig);
    self.postMessage({...r, id: msg.id}, transfer);
  } catch (err) {
    self.postMessage({type: "error", id: msg.id,
                      message: String(err && err.message || err)});
  }
};
