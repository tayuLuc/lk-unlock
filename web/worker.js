"use strict";
/* Web Worker: Pyodide + lk-unlock. Всё self-hosted: ./pyodide/, ./vendor/, ./gen/. */
importScripts("./pyodide/pyodide.js");
importScripts("./gen/pyfiles.js");

let pyodide = null, pw = null, hasKey = false;
const pyLog = (...a) => self.postMessage({type: "log", message: a.join(" ")});

async function ensurePyodide() {
  if (pyodide) return;
  pyLog("loadPyodide…");
  pyodide = await loadPyodide({indexURL: "./pyodide/"});
  await pyodide.loadPackage("micropip");
  const micropip = pyodide.pyimport("micropip");
  const vinfo = await (await fetch("./gen/vendor.json")).json();
  pyLog("Установка pyasn1 (локальный wheel)…");
  await micropip.install("./vendor/" + vinfo.wheel);
  pyLog("Монтирование Python-исходников в FS…");
  const FS = pyodide.FS;
  for (const [path, content] of Object.entries(self.__PYFILES__)) {
    const full = "/app/" + path;
    FS.mkdirTree(full.slice(0, full.lastIndexOf("/")));
    FS.writeFile(full, content);
  }
  pyodide.runPython(`
import sys
sys.path.insert(0, "/app")
import patcher_web   # shim lk_unlock.keys ставится ДО импорта patcher
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

async function ensureKey(jwk) {
  await ensurePyodide();
  if (!hasKey || jwk) {
    pw.set_key_json(JSON.stringify(jwk || await genJwk()));
    hasKey = true;
    pyLog(jwk ? "Использован внешний/тестовый ключ."
              : "Сгенерирована новая RSA-2048 пара (WebCrypto).");
  }
}

async function handle(msg) {
  switch (msg.type) {
    case "init":
      await ensureKey(msg.jwk || null);
      return {type: "ready"};
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
