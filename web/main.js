"use strict";
const $ = (id) => document.getElementById(id);
const logEl = $("log");
const log = (m) => { logEl.textContent += `[${new Date().toLocaleTimeString()}] ${m}\n`; };

const worker = new Worker("./worker.js");
let seq = 0, ready = false;
const pending = new Map();

worker.onmessage = (e) => {
  const m = e.data;
  if (m.type === "log") return log(m.message);
  const p = pending.get(m.id); if (!p) return;
  pending.delete(m.id);
  m.type === "error" ? p.rej(new Error(m.message)) : p.res(m);
};
worker.onerror = (e) => log("worker error: " + e.message);

function rpc(type, payload, transfer) {
  return new Promise((res, rej) => {
    const id = ++seq; pending.set(id, {res, rej});
    worker.postMessage({type, id, ...payload}, transfer || []);
  });
}

function saveBlob(name, blob) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 30000);
}

async function doPatch() {
  const f = $("lkfile").files[0];
  if (!f) return log("Выберите lk.img");
  const buf = await f.arrayBuffer();
  $("btnPatch").disabled = true;
  log(`Патчим ${f.name} (${buf.byteLength} байт)…`);
  const r = await rpc("patch", {buf}, [buf]);
  saveBlob("lk_patched.img", new Blob([r.img], {type: "application/octet-stream"}));
  saveBlob("private.pem", new Blob([r.pem], {type: "application/x-pem-file"}));
  $("btnPem").disabled = false; $("btnPatch").disabled = false;
  log(`OK. sha256(lk_patched.img)=${r.sha256}`);
}

async function doSign() {
  const text = $("token").value.trim();
  if (!text) return log("Вставьте токен");
  const r = await rpc("sign", {token: text});
  saveBlob("signature.bin", new Blob([r.sig], {type: "application/octet-stream"}));
  log(`OK. sha256(signature.bin)=${r.sha256}`);
}

$("btnPatch").onclick = doPatch;
$("btnSign").onclick = doSign;
$("btnPem").onclick = async () =>
  saveBlob("private.pem", new Blob([(await rpc("pem")).pem], {type: "application/x-pem-file"}));

// Публичный API (используется Playwright-тестом)
window.lkUnlock = {
  ready: () => ready,
  init: (jwk) => rpc("init", {jwk}),
  patchBuffer: (buf, jwk) => rpc("patch", {buf, jwk}, [buf]),
  signToken: (t) => rpc("sign", {token: t}),
};

(async () => {
  log("Загрузка Pyodide (WASM)…");
  await rpc("init", {});
  ready = true;
  $("btnPatch").disabled = $("btnSign").disabled = false;
  log("Готово. RSA-2048 ключ будет создан WebCrypto при первом действии.");
})().catch((e) => log("Ошибка инициализации: " + e.message));
