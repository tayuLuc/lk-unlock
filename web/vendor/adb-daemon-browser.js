// Self-contained ADB daemon client for the browser.
//
// Transport-agnostic: works over WebUSB or WebSocket (WebSockify bridge).
// Proven against a POCO M4 Pro (MIUI/HyperOS) over a WebSocket bridge:
// AUTH handshake → OPEN ×3 → getprop fills device fingerprint.
//
// Key protocol facts discovered while debugging (do not "simplify"):
// - CNXN command word is 0x4e584e43 (little-endian "CNXN"); the byte-swapped
//   0x4e58434e is silently dropped by the device.
// - Modern adbd requires auth types Token=1, Signature=2, PublicKey=3.
// - Over TCP the device only answers a server-exact CNXN feature list with
//   no trailing ';' (see CNXN_FEATURES).
// - Device→host packets carry the host's local socket id in arg1, not arg0.
// - WebCrypto's RSASSA double-hashes the token, so signatures are computed
//   with raw BigInt modular math instead (PKCS#1 v1.5, SHA-1).
// - adbd expects AUTH_PUBLICKEY payload = base64(mincrypt RSAPublicKey
//   struct) + " " + comment + NUL, not an SPKI key.

const ADB = {
    CMD_CNXN: 0x4e584e43, CMD_AUTH: 0x48545541, CMD_OPEN: 0x4e45504f,
    CMD_OKAY: 0x59414b4f, CMD_CLSE: 0x45534c43, CMD_WRTE: 0x45545257,
    AUTH_TOKEN: 1, AUTH_SIGNATURE: 2, AUTH_RSAPUBLICKEY: 3,
    VERSION: 0x01000001, MAX_PAYLOAD: 1024 * 1024,
};

// Optional packet logging (default off).
let packetLogger = null;
// fn(dir, cmdLabel, a0Label, arg1, len) — called for every ADB packet.
// Pass null to disable.
function setPacketLogger(fn) {
    packetLogger = fn;
}

// ── BigInt modular math for raw RSA ───────────────────────────────────────
function modPow(base, exp, mod) {
    let res = 1n; base %= mod;
    while (exp > 0n) {
        if (exp % 2n === 1n) res = (res * base) % mod;
        exp /= 2n; base = (base * base) % mod;
    }
    return res;
}
function b64UrlToBytes(b64) {
    const s = b64.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(s);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
}
function bytesToBigInt(bytes) {
    let r = 0n;
    for (let i = 0; i < bytes.length; i++) r = (r << 8n) | BigInt(bytes[i]);
    return r;
}
function bigIntToBytes(n, len) {
    const b = new Uint8Array(len);
    for (let i = 0; i < len; i++) { b[len - 1 - i] = Number(n & 0xFFn); n >>= 8n; }
    return b;
}

async function signToken(privateKey, token) {
    const jwk = await crypto.subtle.exportKey('jwk', privateKey);
    const d = bytesToBigInt(b64UrlToBytes(jwk.d)), n = bytesToBigInt(b64UrlToBytes(jwk.n));
    // ADB signs SHA1(token): the device compares the digest embedded in the
    // signature against SHA1(token) — the raw 20-byte token is NOT the hash.
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-1', token));
    // PKCS#1 v1.5 block (256 bytes): 00 01 FF..FF 00 || SHA-1 DigestInfo || SHA1(token)
    const block = new Uint8Array(256);
    block[0] = 0x00; block[1] = 0x01;
    for (let i = 2; i < 220; i++) block[i] = 0xFF;
    block[220] = 0x00;
    block.set([0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14], 221);
    block.set(digest, 236);
    return bigIntToBytes(modPow(bytesToBigInt(block), d, n), 256);
}

// Android adbd expects AUTH_PUBLICKEY payload = base64(mincrypt
// RSAPublicKey struct) + " " + comment + NUL. Struct (524 bytes):
// words(4) n0inv(4) n(256) rr=R^2 mod n(256) e(4) — little-endian words.
async function getAdbPublicKeyPayload(cryptoKey, comment) {
    const jwk = await crypto.subtle.exportKey('jwk', cryptoKey);
    const n = bytesToBigInt(b64UrlToBytes(jwk.n)), e = bytesToBigInt(b64UrlToBytes(jwk.e));
    const WORDS = 64, r32 = 1n << 32n, R = 1n << 2048n, rr = (R * R) % n, rem = n % r32;
    function modInverse(a, m) {
        let [m0, x0, x1] = [m, 0n, 1n];
        while (a > 1n) {
            let q = a / m, t = m;
            m = a % m; a = t; t = x0;
            x0 = x1 - q * x0; x1 = t;
        }
        if (x1 < 0n) x1 += m0;
        return x1;
    }
    let n0inv = (-modInverse(rem, r32)) % r32;
    if (n0inv < 0n) n0inv += r32;
    const buf = new Uint8Array(524), view = new DataView(buf.buffer);
    view.setUint32(0, WORDS, true); view.setUint32(4, Number(n0inv), true);
    let off = 8;
    for (let i = 0; i < WORDS; i++) { view.setUint32(off, Number((n >> BigInt(i * 32)) & 0xffffffffn), true); off += 4; }
    for (let i = 0; i < WORDS; i++) { view.setUint32(off, Number((rr >> BigInt(i * 32)) & 0xffffffffn), true); off += 4; }
    view.setUint32(off, Number(e), true);
    let bin = '';
    for (let i = 0; i < buf.length; i++) bin += String.fromCharCode(buf[i]);
    return new TextEncoder().encode(btoa(bin) + ' ' + comment + '\0');
}

// localStorage ADB key store (shared with the app's WebUSB flow).
// Two-phase commit: a key is only persisted after a successful CNXN, so a
// timed-out handshake does not leave an unconfirmed (junk) key behind.
const KeyStore = {
    async iterateKeys() {
        const json = localStorage.getItem('adb_keys');
        if (!json) return [];
        const out = [];
        for (const k of JSON.parse(json)) {
            const bin = Uint8Array.from(atob(k.privateKey), c => c.charCodeAt(0));
            const priv = await crypto.subtle.importKey('pkcs8', bin, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-1' }, true, ['sign']);
            out.push({ privateKey: priv, publicKeyPayload: new TextEncoder().encode(k.publicKey) });
        }
        return out;
    },
    // Generates a key but does NOT persist it yet.
    async generatePendingKey() {
        const pair = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' }, true, ['sign']);
        const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
        let bin = '';
        for (let i = 0; i < pkcs8.length; i++) bin += String.fromCharCode(pkcs8[i]);
        const pubPayload = await getAdbPublicKeyPayload(pair.publicKey, 'lk-unlock@' + location.hostname);
        return {
            privateKey: pair.privateKey,
            publicKeyPayload: pubPayload,
            _storageData: { privateKey: btoa(bin), publicKey: new TextDecoder().decode(pubPayload) },
        };
    },
    // Persists only after a successful handshake.
    async commitPendingKey(pending) {
        const keys = JSON.parse(localStorage.getItem('adb_keys') || '[]');
        keys.push(pending._storageData);
        localStorage.setItem('adb_keys', JSON.stringify(keys));
    },
};

// ── Low-level packet I/O with optional packet log ─────────────────────────
const PKT_CMDS = { 0x4e584e43: 'CNXN', 0x48545541: 'AUTH', 0x4e45504f: 'OPEN', 0x59414b4f: 'OKAY', 0x45534c43: 'CLSE', 0x45545257: 'WRTE', 0x434e5953: 'SYNC' };
const AUTH_TYPES = { 1: 'TOKEN', 2: 'SIGNATURE', 3: 'PUBKEY' };
function pktCmd(c) { return PKT_CMDS[c] || '0x' + c.toString(16).toUpperCase().padStart(8, '0'); }
function calculateChecksum(p) { let s = 0; for (let i = 0; i < p.length; i++) s = (s + p[i]) & 0xffffffff; return s >>> 0; }
function logPkt(dir, cmd, arg0, arg1, len) {
    if (packetLogger) {
        packetLogger(dir, pktCmd(cmd), cmd === ADB.CMD_AUTH ? `${arg0}(${AUTH_TYPES[arg0] || '?'})` : String(arg0), arg1, len);
    }
}

// ── Transport Abstraction (USB / WebSocket) ───────────────────────────────
// Both transports expose send(bytes) + readBytes(count) + close(), so the
// packet layer, AUTH handshake and socket multiplexing are transport-agnostic.
class UsbTransport {
    constructor(device, inEp, outEp) {
        this.device = device; this.inEp = inEp; this.outEp = outEp;
        this.buf = new Uint8Array(0); this.closed = false;
    }
    async send(bytes) {
        if (this.closed) throw new Error('Transport closed');
        return await this.device.transferOut(this.outEp, bytes);
    }
    async readBytes(count, timeoutMs = 15000) {
        if (this.closed) throw new Error('Transport closed');
        const withTimeout = p => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error('USB read timeout')), timeoutMs))]);
        while (this.buf.length < count) {
            const res = await withTimeout(this.device.transferIn(this.inEp, 16384));
            if (res.status !== 'ok') throw new Error('USB transfer error (status ' + res.status + ')');
            const chunk = new Uint8Array(res.data.buffer, res.data.byteOffset, res.data.byteLength);
            const merged = new Uint8Array(this.buf.length + chunk.length);
            merged.set(this.buf); merged.set(chunk, this.buf.length);
            this.buf = merged;
        }
        const res = this.buf.slice(0, count);
        this.buf = this.buf.slice(count);
        return res;
    }
    async close() {
        this.closed = true;
        try { await this.device.close(); } catch (_) { }
    }
}

class WsTransport {
    constructor(url) {
        this.url = url; this.ws = null; this.buf = new Uint8Array(0);
        this.pendingReads = []; this.closed = false;
    }
    async connect() {
        this.ws = new WebSocket(this.url);
        this.ws.binaryType = 'arraybuffer';
        await new Promise((resolve, reject) => {
            this.ws.onopen = resolve;
            this.ws.onerror = () => reject(new Error('WebSocket connect failed'));
        });
        this.ws.onmessage = (e) => {
            const chunk = new Uint8Array(e.data);
            const merged = new Uint8Array(this.buf.length + chunk.length);
            merged.set(this.buf); merged.set(chunk, this.buf.length);
            this.buf = merged;
            this._processReads();
        };
        this.ws.onclose = () => this.close();
    }
    _processReads() {
        while (this.pendingReads.length > 0 && this.buf.length >= this.pendingReads[0].count) {
            const req = this.pendingReads.shift();
            clearTimeout(req.timer);
            const res = this.buf.slice(0, req.count);
            this.buf = this.buf.slice(req.count);
            req.resolve(res);
        }
    }
    async send(bytes) {
        if (this.closed) throw new Error('Transport closed');
        this.ws.send(bytes);
    }
    async readBytes(count, timeoutMs = 15000) {
        if (this.closed) throw new Error('Transport closed');
        if (this.buf.length >= count) {
            const res = this.buf.slice(0, count);
            this.buf = this.buf.slice(count);
            return res;
        }
        return new Promise((resolve, reject) => {
            const req = { count, resolve, reject, timer: null };
            req.timer = setTimeout(() => {
                this.pendingReads = this.pendingReads.filter(r => r !== req);
                reject(new Error('WS read timeout'));
            }, timeoutMs);
            this.pendingReads.push(req);
        });
    }
    async close() {
        if (this.closed) return;
        this.closed = true;
        if (this.ws) this.ws.close();
        this.pendingReads.forEach(r => { clearTimeout(r.timer); r.reject(new Error('Transport closed')); });
        this.pendingReads = [];
    }
}

// Packet I/O — takes a transport, not (device, inEp, outEp).
async function sendPacket(transport, cmd, arg0, arg1, payload = new Uint8Array()) {
    const h = new ArrayBuffer(24), v = new DataView(h);
    v.setUint32(0, cmd, true); v.setUint32(4, arg0, true); v.setUint32(8, arg1, true);
    v.setUint32(12, payload.length, true); v.setUint32(16, calculateChecksum(payload), true); v.setUint32(20, cmd ^ 0xffffffff, true);
    const packet = new Uint8Array(24 + payload.length); packet.set(new Uint8Array(h), 0); packet.set(payload, 24);
    logPkt('OUT', cmd, arg0, arg1, payload.length);
    return await transport.send(packet);
}

async function readPacket(transport, timeoutMs = 15000) {
    const header = await transport.readBytes(24, timeoutMs);
    const v = new DataView(header.buffer, header.byteOffset, 24);
    const cmd = v.getUint32(0, true), arg0 = v.getUint32(4, true), arg1 = v.getUint32(8, true), len = v.getUint32(12, true);
    const payload = len > 0 ? await transport.readBytes(len, timeoutMs) : new Uint8Array(0);
    logPkt('IN', cmd, arg0, arg1, len);
    return { cmd, arg0, arg1, payload };
}

// Device feature list announced in CNXN (matches AOSP AdbDeviceFeatures,
// minus delayed_ack which this minimal client does not implement).
const CNXN_FEATURES = 'shell_v2,cmd,stat_v2,ls_v2,fixed_push_mkdir,apex,abb,fixed_push_symlink_timestamp,abb_exec,remount_shell,track_app,sendrecv_v2,sendrecv_v2_brotli,sendrecv_v2_lz4,sendrecv_v2_zstd,sendrecv_v2_dry_run_send,devraw,app_info';

// AUTH handshake: token → signatures with known keys → public key.
// Machine-to-machine packets (CNXN/AUTH) use a short timeout; the final
// PUBKEY phase waits for the user to confirm on the phone screen (up to
// 2 min), so it must not use the short transport timeout.
async function authenticate(transport, firstPacket) {
    let packet = firstPacket || await readPacket(transport, 15000);
    if (packet.cmd === ADB.CMD_CNXN) return packet.payload; // already authorized
    if (packet.cmd !== ADB.CMD_AUTH || packet.arg0 !== ADB.AUTH_TOKEN) throw new Error('Expected AUTH TOKEN');
    let token = packet.payload;
    const keys = await KeyStore.iterateKeys();
    for (const key of keys) {
        const sig = await signToken(key.privateKey, token);
        await sendPacket(transport, ADB.CMD_AUTH, ADB.AUTH_SIGNATURE, 0, sig);
        packet = await readPacket(transport, 15000);
        if (packet.cmd === ADB.CMD_CNXN) return packet.payload;
        if (packet.cmd === ADB.CMD_AUTH && packet.arg0 === ADB.AUTH_TOKEN) { token = packet.payload; continue; }
        throw new Error('Unexpected AUTH response');
    }
    const pending = await KeyStore.generatePendingKey();
    await sendPacket(transport, ADB.CMD_AUTH, ADB.AUTH_RSAPUBLICKEY, 0, pending.publicKeyPayload);
    // Wait for the user to confirm on the phone (RSA dialog) — long timeout.
    packet = await readPacket(transport, 120000);
    if (packet.cmd === ADB.CMD_CNXN) {
        await KeyStore.commitPendingKey(pending); // persist only on success
        return packet.payload;
    }
    throw new Error('Auth failed or rejected');
}

// ── Socket multiplexing (OPEN/OKAY/WRTE/CLSE) — minimal for getprop ───────
class AdbSocket {
    constructor(daemon, localId) {
        this.daemon = daemon; this.localId = localId; this.remoteId = 0;
        this.chunks = []; this.waitingReads = []; this.closed = false;
        this.connectedPromise = new Promise((res, rej) => { this._resolveConnected = res; this._rejectConnected = rej; });
    }
    _onOkay(remoteId) { this.remoteId = remoteId; this._resolveConnected(); }
    _onData(data) {
        if (this.waitingReads.length > 0) this.waitingReads.shift().resolve(data);
        else this.chunks.push(data);
    }
    _onClose() {
        this.closed = true;
        this.waitingReads.forEach(r => r.resolve(null));
        this.waitingReads = [];
    }
    async read() {
        if (this.chunks.length) return this.chunks.shift();
        if (this.closed) return null;
        return new Promise(resolve => { this.waitingReads.push({ resolve }); });
    }
    async write(data) {
        if (typeof data === 'string') data = new TextEncoder().encode(data);
        await sendPacket(this.daemon.transport, ADB.CMD_WRTE, this.localId, this.remoteId, data);
    }
    async close() {
        if (!this.closed) {
            await sendPacket(this.daemon.transport, ADB.CMD_CLSE, this.localId, this.remoteId);
            this.closed = true; this.daemon.sockets.delete(this.localId);
        }
    }
}

class AdbDaemon {
    constructor(transport) {
        this.transport = transport; this.sockets = new Map(); this.nextLocalId = 1; this.closed = false;
        this._readLoop();
    }
    async _readLoop() {
        try {
            for (;;) {
                const pkt = await readPacket(this.transport);
                if (pkt.cmd === ADB.CMD_OKAY) { const s = this.sockets.get(pkt.arg1); if (s) s._onOkay(pkt.arg0); }
                else if (pkt.cmd === ADB.CMD_WRTE) { const s = this.sockets.get(pkt.arg1); if (s) { s._onData(pkt.payload); sendPacket(this.transport, ADB.CMD_OKAY, s.localId, pkt.arg0).catch(() => { }); } }
                else if (pkt.cmd === ADB.CMD_CLSE) { const s = this.sockets.get(pkt.arg1); if (s) { s._onClose(); sendPacket(this.transport, ADB.CMD_CLSE, s.localId, pkt.arg0).catch(() => { }); this.sockets.delete(pkt.arg1); } }
            }
        } catch (e) {
            if (!this.closed) {
                console.error('Read loop error:', e);
                this.sockets.forEach(s => s._onClose());
            }
        }
    }
    async close() {
        this.closed = true;
        this.sockets.forEach(s => s._onClose());
        await this.transport.close();
    }
    async open(destination) {
        const localId = this.nextLocalId++;
        const socket = new AdbSocket(this, localId);
        this.sockets.set(localId, socket);
        await sendPacket(this.transport, ADB.CMD_OPEN, localId, 0, new TextEncoder().encode(destination + '\0'));
        await socket.connectedPromise;
        return socket;
    }
}

class AdbConnection {
    constructor(daemon, name = '', serial = '') {
        this.daemon = daemon; this.name = name; this.serial = serial;
    }
    createSocket(destination) { return this.daemon.open(destination); }
    async getProp(propName) {
        const socket = await this.createSocket('shell:getprop ' + propName);
        let out = ''; let chunk;
        while ((chunk = await socket.read()) !== null) out += new TextDecoder().decode(chunk);
        await socket.close();
        return out.trim();
    }
    async close() { await this.daemon.close(); }
}

// Convenience: connect over a WebSockify bridge.
async function connectWs(url) {
    const transport = new WsTransport(url);
    await transport.connect();
    const cnxnPayload = new TextEncoder().encode('host::features=' + CNXN_FEATURES);
    await sendPacket(transport, ADB.CMD_CNXN, ADB.VERSION, ADB.MAX_PAYLOAD, cnxnPayload);
    const firstPacket = await readPacket(transport);
    await authenticate(transport, firstPacket);
    return new AdbConnection(new AdbDaemon(transport), 'WebSocket Device', url);
}

export {
    ADB,
    KeyStore,
    UsbTransport,
    WsTransport,
    sendPacket,
    readPacket,
    calculateChecksum,
    authenticate,
    CNXN_FEATURES,
    AdbSocket,
    AdbDaemon,
    AdbConnection,
    connectWs,
    setPacketLogger,
};