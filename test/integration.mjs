// Integration tests: run the real public/app.js (a host and a joiner, each
// with a stub DOM) against `wrangler dev`, plus raw sockets playing a
// malicious relay and a malicious peer that holds the key.
// Needs Node >= 22 (global WebSocket, File, WebCrypto). `npm test` starts and
// stops its own wrangler dev on TEST_PORT (default 8799).
import fs from "node:fs";
import net from "node:net";
import { spawn, execSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { resolveObjectURL } from "node:buffer";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const PORT = Number(process.env.TEST_PORT || 8799);
const BASE = `http://localhost:${PORT}`;
const WSBASE = `ws://localhost:${PORT}`;

// ENVIRONMENT=dev: plain http, no canonical redirect, no Origin check.
const server = spawn("npx", ["wrangler", "dev", "--port", String(PORT), "--var", "ENVIRONMENT:dev"],
  { cwd: ROOT, shell: process.platform === "win32", stdio: "ignore", detached: process.platform !== "win32" });
function stopServer() {
  try {
    if (process.platform === "win32") execSync(`taskkill /pid ${server.pid} /T /F`, { stdio: "ignore" });
    else process.kill(-server.pid);
  } catch {}
}
process.on("exit", stopServer); // also covers a crash or startup timeout
const appSrc = fs.readFileSync(`${ROOT}/public/app.js`, "utf8");
const qrSrc = fs.readFileSync(`${ROOT}/public/qrcode.js`, "utf8");
const html = fs.readFileSync(`${ROOT}/public/index.html`, "utf8");
const qrcode = new Function(`${qrSrc}; return qrcode;`)();

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 5000, label = "condition") {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (await fn()) return; await sleep(25); }
  throw new Error(`timeout waiting for ${label}`);
}
let passed = 0, failed = 0;
async function test(name, fn) {
  try { await fn(); passed++; console.log(`PASS ${name}`); }
  catch (e) { failed++; console.log(`FAIL ${name}: ${e.message}`); }
}
const assert = (c, m) => { if (!c) throw new Error(m); };

// ---------- stub DOM ----------
class ClassList {
  constructor(list = []) { this.s = new Set(list); }
  add(c) { this.s.add(c); } remove(c) { this.s.delete(c); }
  contains(c) { return this.s.has(c); }
  toggle(c, force) { const on = force ?? !this.s.has(c); on ? this.s.add(c) : this.s.delete(c); return on; }
}
class El {
  constructor(tag, id) {
    this.tagName = tag; this.id = id; this.children = []; this.parent = null;
    this.classList = new ClassList(); this.style = {}; this.listeners = {};
    this.textContent = ""; this.value = ""; this.checked = false; this.files = [];
    this.selectionStart = 0; this.selectionEnd = 0;
  }
  set className(v) { this.classList = new ClassList(v.split(/\s+/).filter(Boolean)); }
  get className() { return [...this.classList.s].join(" "); }
  append(...c) { for (const x of c) { x.parent = this; this.children.push(x); } }
  prepend(...c) { for (const x of c.reverse()) { x.parent = this; this.children.unshift(x); } }
  remove() { if (this.parent) this.parent.children.splice(this.parent.children.indexOf(this), 1); }
  replaceChildren(...c) { this.children = []; this.append(...c); }
  matches(sel) { return sel.startsWith(".") ? this.classList.contains(sel.slice(1)) : this.tagName === sel; }
  find(sel) { for (const c of this.children) { if (c.matches(sel)) return c; const d = c.find(sel); if (d) return d; } return null; }
  querySelector(sel) { let cur = this; for (const p of sel.split(" ")) { cur = cur && cur.find(p); } return cur; }
  addEventListener(t, f) { (this.listeners[t] ||= []).push(f); }
  dispatchEvent(e) { for (const f of this.listeners[e.type] || []) f(e); }
  setSelectionRange(a, b) { this.selectionStart = a; this.selectionEnd = b; }
  getContext() { return { fillRect() {}, fillStyle: "" }; }
  click() {}
}

function makeClient(hash, { allowMore = false } = {}) {
  const byId = new Map();
  for (const m of html.matchAll(/<(\w+)([^>]*?)\bid="([^"]+)"([^>]*)>/g)) {
    const el = new El(m[1], m[3]);
    const cls = (m[2] + m[4]).match(/class="([^"]*)"/);
    if (cls) el.className = cls[1];
    byId.set(m[3], el);
  }
  const expiredBtn = new El("button");
  const store = () => { const m = new Map(); return {
    getItem: (k) => m.has(k) ? m.get(k) : null, setItem: (k, v) => m.set(k, String(v)), _m: m }; };
  const localStorage = store(), sessionStorage = store();
  if (allowMore) localStorage.setItem("pastecmd-allow-more", "1");
  const location = { hash, origin: BASE, host: `localhost:${PORT}`, protocol: "http:", pathname: "/", href: BASE + "/" + hash };
  const history = { replaceState: (_s, _t, url) => { location.hash = ""; location.href = BASE + url; } };
  const document = {
    getElementById: (id) => byId.get(id),
    querySelector: (sel) => sel === "#expired-card button" ? expiredBtn : null,
    createElement: (tag) => new El(tag),
    addEventListener() {}, activeElement: null,
  };
  const copied = [];
  const navigator = { clipboard: { writeText: async (t) => { copied.push(t); }, readText: async () => "" } };
  const window = { addEventListener() {} };
  const errors = [];
  const run = new Function("document", "location", "history", "localStorage", "sessionStorage",
    "window", "navigator", "qrcode", "Event", appSrc.replace(/\}\)\(\);\s*$/, "})().catch((e) => __err(e));").replace(/^/, "const __err = arguments[9];\n"));
  run(document, location, history, localStorage, sessionStorage, window, navigator, qrcode,
    class Event { constructor(t) { this.type = t; } }, (e) => errors.push(e));
  const $ = (id) => byId.get(id);
  return {
    $, errors, sessionStorage, location,
    status: () => $("status-text").textContent,
    async shareUrl() { $("copy-link").onclick(); await until(() => copied.length, 1000, "copy"); return copied.at(-1); },
    type(text) { $("clip").value = text; $("clip").dispatchEvent({ type: "input" }); },
    sendFiles(files) { $("file-input").files = files; $("file-input").onchange(); },
    rows: () => $("transfers").children,
    visible: (id) => !$(id).classList.contains("hidden"),
  };
}

// ---------- raw socket helpers ----------
function raw(path) {
  const ws = new WebSocket(`${WSBASE}${path}`);
  ws.binaryType = "arraybuffer";
  const got = [];
  ws.onmessage = (e) => got.push(e.data);
  const closed = new Promise((r) => { ws.onclose = (e) => r({ code: e.code, reason: e.reason }); });
  const opened = new Promise((r, j) => { ws.onopen = r; ws.onerror = j; });
  return { ws, got, closed, opened };
}
const te = new TextEncoder(), td = new TextDecoder();
const b64 = {
  enc: (b) => Buffer.from(b).toString("base64url"),
  dec: (s) => new Uint8Array(Buffer.from(s, "base64url")),
};
const cat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; };
async function attackerCrypto(fragment) {
  const keyRaw = b64.dec(fragment.split(".")[1]);
  const key = await crypto.subtle.importKey("raw", keyRaw, "AES-GCM", false, ["encrypt", "decrypt"]);
  const dev = crypto.getRandomValues(new Uint8Array(8));
  let seq = 0;
  const enc = async (bytes, aad) => {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    return { iv, ct: new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, key, bytes)) };
  };
  return {
    async sealed(type, bytes, extra = new Uint8Array(0), fields = {}, forceSeq) {
      const s = forceSeq ?? ++seq;
      const { iv, ct } = await enc(bytes, cat(te.encode(type), dev, u32(s), extra));
      return JSON.stringify({ type, ...fields, from: b64.enc(dev), seq: s, iv: b64.enc(iv), data: b64.enc(ct) });
    },
    async chunk(fileId, index, bytes) {
      const { iv, ct } = await enc(bytes, cat(te.encode("chunk"), fileId, u32(index)));
      return cat(fileId, u32(index), iv, ct).buffer;
    },
  };
}
const blobOf = async (row) => {
  const a = row.find("a"); if (!a) return null;
  return resolveObjectURL(a.href);
};
const fragOf = (url) => url.split("#")[1];
const rid = () => b64.enc(crypto.getRandomValues(new Uint8Array(9)));

// ================= tests =================
await until(async () => { try { return (await fetch(BASE + "/")).ok; } catch { return false; } }, 60000, "wrangler dev");

await test("headers: CSP forbids Trusted Types policies", async () => {
  const r = await fetch(BASE + "/");
  assert(r.headers.get("content-security-policy").includes("trusted-types 'none'"), "missing trusted-types 'none'");
});

await test("server: first connection without ?max is turned away as expired", async () => {
  const s = raw(`/ws/${rid()}?t=${b64.enc(crypto.getRandomValues(new Uint8Array(16)))}`);
  const c = await s.closed;
  assert(c.code === 4000 && c.reason === "expired", `got ${c.code} ${c.reason}`);
});

await test("server: /ws/ rejects non-12-char session IDs (not a WS route)", async () => {
  const r = await fetch(`${BASE}/ws/abcd`);
  assert(r.status !== 101, `status ${r.status}`);
});

await test("server: Upgrade header matched case-insensitively", async () => {
  const status = await new Promise((resolve, reject) => {
    const s = net.connect(PORT, "localhost", () => {
      s.write(`GET /ws/${rid()}?max=2 HTTP/1.1\r\nHost: localhost:${PORT}\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\n` +
        `Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n`);
    });
    s.once("data", (d) => { resolve(d.toString().split(" ")[1]); s.destroy(); });
    s.on("error", reject);
  });
  assert(status === "101", `status ${status}`);
});

// ---- two-device session via the real client ----
const host = makeClient("");
await until(() => host.status().startsWith("Waiting"), 5000, "host connect");
const url = await host.shareUrl();
const frag = fragOf(url);
const joiner = makeClient("#" + frag);

await test("client: host and joiner link (2 devices)", async () => {
  await until(() => host.status() === "Linked — 2 devices" && joiner.status() === "Linked — 2 devices", 5000, "linked");
});

await test("client: clip syncs host -> joiner", async () => {
  host.type("hello pastecmd");
  await until(() => joiner.$("clip").value === "hello pastecmd", 3000, "clip");
});

await test("client: 300 KB clip syncs (base64 fallback, no arg-spread overflow)", async () => {
  const big = "x".repeat(150_000) + "é".repeat(75_000);
  host.type(big);
  await until(() => joiner.$("clip").value === big, 5000, "big clip");
  assert(!host.visible("clip-too-big"), "warning shown for allowed size");
});

await test("client: >700 KB clip shows warning and is not sent", async () => {
  const before = joiner.$("clip").value;
  host.type("y".repeat(800_000));
  await sleep(700);
  assert(host.visible("clip-too-big"), "warning not shown");
  assert(joiner.$("clip").value === before, "oversized clip arrived");
  host.type("small again");
  await until(() => joiner.$("clip").value === "small again", 3000, "clip after");
  assert(!host.visible("clip-too-big"), "warning not cleared");
});

await test("client: multi-chunk file transfer, exact bytes, octet-stream download", async () => {
  const data = crypto.getRandomValues(new Uint8Array(600_000).subarray(0, 65536)); // seed
  const bytes = new Uint8Array(600_000); for (let i = 0; i < bytes.length; i++) bytes[i] = data[i % data.length];
  const n0 = joiner.rows().length;
  host.sendFiles([new File([bytes], "evil.html", { type: "text/html" }), new File([bytes.subarray(0, 1000)], "pic.png", { type: "image/png" })]);
  await until(() => joiner.rows().length === n0 + 2 && joiner.rows().every((r) => r.find("a")), 10000, "files received");
  const [png, htmlRow] = joiner.rows();
  const b = await blobOf(htmlRow);
  assert(b.type === "application/octet-stream", `html blob type ${b.type}`);
  assert(Buffer.compare(Buffer.from(await b.arrayBuffer()), Buffer.from(bytes)) === 0, "content mismatch");
  assert(!htmlRow.find("img"), "thumbnail for text/html");
  assert(png.find("img"), "no thumbnail for png");
  assert(htmlRow.find("a").download === "evil.html", "filename");
});

await test("server: third device turned away when session is full", async () => {
  const s = raw(`/ws/${frag.split(".")[0]}?t=${b64.enc(crypto.getRandomValues(new Uint8Array(16)))}`);
  const c = await s.closed;
  assert(c.code === 4001 && c.reason === "full", `got ${c.code} ${c.reason}`);
});

await test("server: same rejoin token replaces its old socket (no false 'full')", async () => {
  const sid = frag.split(".")[0];
  const tok = joiner.sessionStorage.getItem(`pastecmd-t-${sid}`);
  assert(tok && tok.length === 22, "joiner token missing");
  const s = raw(`/ws/${sid}?t=${tok}`);
  await s.opened;
  await until(() => joiner.visible("replaced-card"), 3000, "joiner shows replaced card");
  await until(() => s.got.some((m) => typeof m === "string" && m.startsWith("\u0000") && JSON.parse(m.slice(1)).count === 2), 3000, "count stays 2");
  assert(host.status() === "Linked — 2 devices", host.status());
  s.ws.close();
});

// ---- multi-user session: attacker holds the key and a slot ----
const host2 = makeClient("", { allowMore: true });
await until(() => host2.status().startsWith("Waiting"), 5000, "host2 connect");
const frag2 = fragOf(await host2.shareUrl());
const sid2 = frag2.split(".")[0];
const joiner2 = makeClient("#" + frag2);
await until(() => joiner2.status().startsWith("Linked"), 5000, "joiner2 linked");
const evil = raw(`/ws/${sid2}?t=${b64.enc(crypto.getRandomValues(new Uint8Array(16)))}`);
await evil.opened;
const spy = raw(`/ws/${sid2}?t=${b64.enc(crypto.getRandomValues(new Uint8Array(16)))}`);
await spy.opened;
const A = await attackerCrypto(frag2);
const peersMsgs = (s) => s.got.filter((m) => typeof m === "string" && !m.startsWith("\u0000"));

await test("replay: relay re-sending an older clip does not roll the box back", async () => {
  host2.type("v1");
  await until(() => joiner2.$("clip").value === "v1", 3000, "v1");
  host2.type("v2");
  await until(() => joiner2.$("clip").value === "v2", 3000, "v2");
  const v1 = peersMsgs(evil).find((m) => JSON.parse(m).type === "clip");
  evil.ws.send(v1);
  await sleep(400);
  assert(joiner2.$("clip").value === "v2", `rolled back to ${joiner2.$("clip").value}`);
});

await test("replay: re-delivering a whole file transfer is ignored", async () => {
  evil.got.length = 0;
  const n0 = joiner2.rows().length;
  host2.sendFiles([new File([new Uint8Array(300_000)], "a.bin")]);
  await until(() => joiner2.rows().length === n0 + 1 && joiner2.rows()[0].find("a"), 5000, "file");
  const captured = evil.got.filter((m) => typeof m !== "string" || !m.startsWith("\u0000"));
  for (const m of captured) evil.ws.send(m);
  await sleep(600);
  assert(joiner2.rows().length === n0 + 1, "replayed file produced a new row");
});

await test("forged high seq with bad ciphertext doesn't lock out the sender", async () => {
  const good = JSON.parse(await A.sealed("clip", te.encode("x")));
  evil.ws.send(JSON.stringify({ ...good, seq: 4_000_000_000, data: good.data.slice(0, -4) + "AAAA" }));
  evil.ws.send(await A.sealed("clip", te.encode("from attacker, seq 2")));
  await until(() => joiner2.$("clip").value === "from attacker, seq 2", 3000, "valid seq accepted after forged");
});

await test("duplicate chunk can't complete a transfer with a hole", async () => {
  const fileId = crypto.getRandomValues(new Uint8Array(4));
  const size = 256 * 1024 + 10;
  const body = crypto.getRandomValues(new Uint8Array(65536));
  const full = new Uint8Array(size); for (let i = 0; i < size; i++) full[i] = body[i % body.length];
  const n0 = joiner2.rows().length;
  evil.ws.send(await A.sealed("file-start", te.encode(JSON.stringify({ name: "d.bin", size, mime: "", chunks: 2 })), fileId, { id: b64.enc(fileId) }));
  const c0 = await A.chunk(fileId, 0, full.subarray(0, 256 * 1024));
  evil.ws.send(c0); evil.ws.send(c0); // duplicate back-to-back
  await sleep(400);
  assert(!joiner2.rows()[0].find("a"), "completed with only chunk 0");
  evil.ws.send(await A.chunk(fileId, 1, full.subarray(256 * 1024)));
  await until(() => joiner2.rows().length === n0 + 1 && joiner2.rows()[0].find("a"), 3000, "completed");
  const b = await blobOf(joiner2.rows()[0]);
  assert(Buffer.compare(Buffer.from(await b.arrayBuffer()), Buffer.from(full)) === 0, "content corrupted");
});

await test("malicious metadata: chunk count not matching size is rejected", async () => {
  const n0 = joiner2.rows().length;
  const fileId = crypto.getRandomValues(new Uint8Array(4));
  evil.ws.send(await A.sealed("file-start", te.encode(JSON.stringify({ name: "m", size: 1, mime: "", chunks: 1_000_000 })), fileId, { id: b64.enc(fileId) }));
  const fileId2 = crypto.getRandomValues(new Uint8Array(4));
  evil.ws.send(await A.sealed("file-start", te.encode(JSON.stringify({ name: "m2", size: 10, mime: "", chunks: -1 })), fileId2, { id: b64.enc(fileId2) }));
  await sleep(400);
  assert(joiner2.rows().length === n0, "row created for bogus metadata");
});

await test("malicious chunk: oversized frame ignored, exact one accepted", async () => {
  const fileId = crypto.getRandomValues(new Uint8Array(4));
  const n0 = joiner2.rows().length;
  evil.ws.send(await A.sealed("file-start", te.encode(JSON.stringify({ name: "s", size: 100, mime: "", chunks: 1 })), fileId, { id: b64.enc(fileId) }));
  evil.ws.send(await A.chunk(fileId, 0, new Uint8Array(500_000)));
  await sleep(400);
  assert(!joiner2.rows()[0].find("a"), "oversized chunk accepted");
  evil.ws.send(await A.chunk(fileId, 0, new Uint8Array(100).fill(7)));
  await until(() => joiner2.rows()[0].find("a"), 3000, "exact chunk");
  assert(joiner2.rows().length === n0 + 1, "row count");
  assert((await blobOf(joiner2.rows()[0])).size === 100, "size");
});

await test("receiver caps concurrent incoming transfers", async () => {
  const n0 = joiner2.rows().length;
  for (let i = 0; i < 10; i++) {
    const fileId = crypto.getRandomValues(new Uint8Array(4));
    evil.ws.send(await A.sealed("file-start", te.encode(JSON.stringify({ name: `c${i}`, size: 40 * 1024 * 1024, mime: "", chunks: 160 })), fileId, { id: b64.enc(fileId) }));
  }
  await until(() => joiner2.rows().length === n0 + 10, 3000, "rows");
  const skipped = joiner2.rows().slice(0, 10).filter((r) => r.find(".t-sub").textContent.startsWith("Skipped")).length;
  assert(skipped === 5, `expected 5 skipped (200 MB cap / 40 MB), got ${skipped}`);
});

await test("relay: control-prefixed and >1 MB UTF-8 strings are not relayed", async () => {
  spy.got.length = 0;
  evil.ws.send("\u0000" + JSON.stringify({ type: "peers", count: 1 }));
  evil.ws.send("€".repeat(400_000)); // 400k chars, 1.2 MB UTF-8
  evil.ws.send("ascii-ok-" + "a".repeat(400_000));
  await until(() => spy.got.some((m) => typeof m === "string" && m.startsWith("ascii-ok-")), 3000, "ascii relayed");
  assert(!spy.got.some((m) => typeof m === "string" && (m.startsWith("\u0000{\"type\":\"peers\",\"count\":1") || m.startsWith("€"))), "forbidden message relayed");
});

await test("no uncaught client errors", async () => {
  const errs = [...host.errors, ...joiner.errors, ...host2.errors, ...joiner2.errors];
  assert(!errs.length, errs.map(String).join("; "));
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
