// pastecmd client. Content is AES-GCM encrypted with a session key that never
// leaves the two devices: the joining device receives it through an ephemeral
// ECDH exchange that the 6-character code authenticates, so the relay only
// ever sees ciphertext. Every ciphertext is bound to its context via AES-GCM
// AAD ("clip"+sender+seq, "file-start"+sender+seq+fileId, or
// "chunk"+fileId+index) so a relay cannot replay one message as another,
// re-deliver an old one, or reorder file chunks.
// Server control messages (peer count) arrive prefixed with "\u0000"; the
// server refuses to relay client strings with that prefix, so a third device
// in the session cannot forge them.
(async () => {
  const $ = (id) => document.getElementById(id);
  const te = new TextEncoder(), td = new TextDecoder();
  const CONTROL = "\u0000";
  // Native base64 where available. The fallback converts in 32 KB slices:
  // spreading a whole buffer as call arguments overflows the engine's
  // argument limit (about 65k in Safari), which made large clips fail to send.
  const b64url = {
    encode: (buf) => {
      const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
      if (bytes.toBase64) return bytes.toBase64({ alphabet: "base64url", omitPadding: true });
      let bin = "";
      for (let i = 0; i < bytes.length; i += 0x8000) {
        bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
      }
      return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    },
    decode: (str) => Uint8Array.fromBase64
      ? Uint8Array.fromBase64(str, { alphabet: "base64url" })
      : Uint8Array.from(atob(str.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)),
  };
  const randomId = (bytes) => b64url.encode(crypto.getRandomValues(new Uint8Array(bytes)));
  const concatBytes = (...arrs) => {
    const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
    let o = 0;
    for (const a of arrs) { out.set(a, o); o += a.length; }
    return out;
  };
  const u32 = (n) => {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, n);
    return b;
  };

  // --- Pairing ------------------------------------------------------------
  // A six-character code is the whole pairing secret. Both devices derive the
  // same rendezvous ID from it with PBKDF2, so nothing has to be copied or
  // scanned, and the code works from any network: only the derived ID ever
  // reaches the server. The content key is separate — the host generates it
  // randomly and hands it over through an ephemeral ECDH exchange that the
  // code authenticates, so the key itself never travels on the wire.
  const CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
  const CODE_LEN = 6;
  const CODE_RE = new RegExp(`^[${CODE_ALPHABET}]{${CODE_LEN}}$`);
  // PBKDF2 stops the rendezvous ID from being an instant lookup of the ~2^30
  // code space: without it, anyone who saw an ID could enumerate the code and
  // MITM the handoff in milliseconds.
  const CODE_ITERATIONS = 600_000;
  const CODE_SALT = te.encode("pastecmd-pair-v1");
  const randomCode = () => {
    const bytes = crypto.getRandomValues(new Uint8Array(CODE_LEN));
    let s = "";
    for (const b of bytes) s += CODE_ALPHABET[b % CODE_ALPHABET.length];
    return s;
  };
  // 64 PBKDF2 bytes: 0-8 are the rendezvous ID (12 base64url characters, the
  // exact length /ws/ routes on), 9-40 the HMAC key that authenticates the
  // key handoff.
  async function deriveCode(c) {
    const base = await crypto.subtle.importKey("raw", te.encode(c), "PBKDF2", false, ["deriveBits"]);
    const bits = new Uint8Array(await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: CODE_SALT, iterations: CODE_ITERATIONS, hash: "SHA-256" },
      base, 512));
    return {
      roomId: b64url.encode(bits.subarray(0, 9)),
      authKey: await crypto.subtle.importKey("raw", bits.subarray(9, 41),
        { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]),
    };
  }
  const normalizeCode = (s) => String(s || "").toUpperCase().replace(/[^A-Z0-9]/g, "");

  const MAX_PEERS = 8;
  // sessionId is the rendezvous ID derived from the code. keyRaw/key stay null
  // on a joining device until the handoff completes.
  let sessionId = null, keyRaw = null, key = null, isHost = false, code = null;
  let authKey = null, paired = false;
  let joinTries = 0;
  // Hoisted so click handlers can reference them while the IIFE is still
  // booting — they would otherwise hit the temporal dead zone.
  let ws, expired = false, retryDelay = 500, peerCount = 1, generation = 0;
  let inbox = Promise.resolve();
  const statusEl = $("status"), statusText = $("status-text");

  async function importSessionKey() {
    key = await crypto.subtle.importKey("raw", keyRaw, "AES-GCM", false, ["encrypt", "decrypt"]);
  }

  // --- Per-tab reload recovery ---------------------------------------------
  // The key is not in the URL any more, so a reloaded tab keeps its session
  // (room, code and key) in sessionStorage. That store is per-tab: another
  // tab or device still has to enter the code.
  function saveRoom() {
    try {
      sessionStorage.setItem(`pastecmd-room-${sessionId}`, JSON.stringify({
        code, host: isHost, key: b64url.encode(keyRaw),
      }));
      sessionStorage.setItem("pastecmd-current", sessionId);
    } catch {}
  }
  function dropRoom() {
    try {
      sessionStorage.removeItem("pastecmd-current");
      if (sessionId) sessionStorage.removeItem(`pastecmd-room-${sessionId}`);
    } catch {}
  }
  async function restoreSession() {
    let rec = null, roomId = null;
    try {
      roomId = sessionStorage.getItem("pastecmd-current");
      rec = JSON.parse(sessionStorage.getItem(`pastecmd-room-${roomId}`) || "null");
    } catch {}
    if (!roomId || !rec || typeof rec.key !== "string" ||
        !CODE_RE.test(String(rec.code || ""))) return false;
    const d = await deriveCode(rec.code);
    if (d.roomId !== roomId) return false; // stale record
    const raw = b64url.decode(rec.key);
    if (raw.length !== 32) return false;
    code = rec.code;
    sessionId = roomId;
    authKey = d.authKey;
    keyRaw = raw;
    isHost = !!rec.host;
    paired = true;
    await importSessionKey();
    return true;
  }

  // --- Handoff crypto ------------------------------------------------------
  // The handoff authenticates both ends with the code (a relay that only
  // knows the rendezvous ID cannot impersonate either side) and carries the
  // content key inside an ECDH-derived key (so even someone who later learns
  // the code cannot unwrap a recorded handoff).
  const ECDH = { name: "ECDH", namedCurve: "P-256" };
  const newPair = async () => {
    const kp = await crypto.subtle.generateKey(ECDH, true, ["deriveBits"]);
    return { kp, pub: new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey)) };
  };
  const handoffAad = (transcript) => concatBytes(te.encode("pair-key"), transcript);
  async function handoffKey(secret, transcript) {
    const k = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({
      name: "HKDF", hash: "SHA-256", salt: transcript,
      info: te.encode("pastecmd-handoff-v1"),
    }, k, 256);
    return crypto.subtle.importKey("raw", bits, "AES-GCM", false, ["encrypt", "decrypt"]);
  }
  async function sharedSecret(privateKey, pub) {
    const peer = await crypto.subtle.importKey("raw", pub, ECDH, false, []);
    return new Uint8Array(await crypto.subtle.deriveBits(
      { name: "ECDH", public: peer }, privateKey, 256));
  }

  let ephPair = null, ephPub = null;   // joiner's ephemeral pair
  let hostPair = null, hostPub = null; // host's ephemeral pair, made on demand
  let joinNonce = null, joinNonceB64 = null, pairTimer = 0;

  async function sendPairJoin() {
    if (isHost || paired || !authKey || !ws || ws.readyState !== WebSocket.OPEN) return;
    ephPair ||= await newPair();
    ephPub ||= ephPair.pub;
    joinNonce = crypto.getRandomValues(new Uint8Array(16));
    joinNonceB64 = b64url.encode(joinNonce);
    const mac = new Uint8Array(await crypto.subtle.sign("HMAC", authKey,
      concatBytes(te.encode("join"), ephPub, joinNonce)));
    ws.send(JSON.stringify({
      type: "pair-join", eph: b64url.encode(ephPub),
      nonce: joinNonceB64, mac: b64url.encode(mac),
    }));
    // The relay may drop a frame; repeat the claim until the handoff lands.
    clearTimeout(pairTimer);
    const gen = generation;
    pairTimer = setTimeout(() => {
      if (gen === generation && !paired) sendPairJoin().catch(() => {});
    }, 4000);
  }

  // Host: verify the claim before handing over the content key.
  async function hostOnPairJoin(msg) {
    if (!isHost || !authKey || !keyRaw) return;
    let pub, nonce, mac;
    try {
      pub = b64url.decode(msg.eph);
      nonce = b64url.decode(msg.nonce);
      mac = b64url.decode(msg.mac);
    } catch { return; }
    if (pub.length !== 65 || nonce.length !== 16 || mac.length !== 32) return;
    if (!await crypto.subtle.verify("HMAC", authKey, mac,
      concatBytes(te.encode("join"), pub, nonce))) return;
    hostPair ||= await newPair();
    hostPub ||= hostPair.pub;
    const transcript = concatBytes(hostPub, pub, nonce);
    const handoff = await handoffKey(await sharedSecret(hostPair.kp.privateKey, pub), transcript);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const wrapped = new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: handoffAad(transcript) }, handoff, keyRaw));
    const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", authKey,
      concatBytes(te.encode("key"), transcript, iv, wrapped)));
    ws.send(JSON.stringify({
      type: "pair-key", eph: b64url.encode(hostPub), nonce: b64url.encode(nonce),
      iv: b64url.encode(iv), data: b64url.encode(wrapped), mac: b64url.encode(hmac),
    }));
  }

  // Joiner: check the host proved the code, then unwrap the content key.
  async function joinerOnPairKey(msg) {
    if (isHost || paired || !ephPair || !authKey || !ephPub) return;
    let pub, nonce, iv, wrapped, mac;
    try {
      pub = b64url.decode(msg.eph);
      nonce = b64url.decode(msg.nonce);
      iv = b64url.decode(msg.iv);
      wrapped = b64url.decode(msg.data);
      mac = b64url.decode(msg.mac);
    } catch { return; }
    if (pub.length !== 65 || nonce.length !== 16 || iv.length !== 12 ||
        wrapped.length !== 48 || mac.length !== 32) return;
    if (msg.nonce !== joinNonceB64) return; // not for this handshake
    const transcript = concatBytes(pub, ephPub, nonce);
    if (!await crypto.subtle.verify("HMAC", authKey, mac,
      concatBytes(te.encode("key"), transcript, iv, wrapped))) return;
    const handoff = await handoffKey(await sharedSecret(ephPair.kp.privateKey, pub), transcript);
    let raw;
    try {
      raw = new Uint8Array(await crypto.subtle.decrypt(
        { name: "AES-GCM", iv, additionalData: handoffAad(transcript) }, handoff, wrapped));
    } catch { return; }
    if (raw.length !== 32) return;
    keyRaw = raw;
    await importSessionKey();
    paired = true;
    clearTimeout(pairTimer);
    saveRoom();
    $("clip-card").classList.remove("hidden");
    setStatus("linked", `Linked — ${Math.max(peerCount, 2)} devices`);
    if (clip.value) await sendClip();
  }

  // --- Host / joiner setup -------------------------------------------------
  async function startNewHost() {
    isHost = true;
    paired = true;
    code = randomCode();
    // AES-256: symmetric-only crypto, so the construction is post-quantum
    // resistant — Grover halves effective strength, leaving 128-bit margin.
    keyRaw = crypto.getRandomValues(new Uint8Array(32));
    const d = await deriveCode(code);
    sessionId = d.roomId;
    authKey = d.authKey;
    await importSessionKey();
    saveRoom();
    drawQR();
    showHostUI();
  }
  async function joinWithCode(c) {
    isHost = false;
    paired = false;
    code = c;
    const d = await deriveCode(c);
    sessionId = d.roomId;
    authKey = d.authKey;
    // A reloaded tab already holds this room's key; no handoff needed.
    let rec = null;
    try { rec = JSON.parse(sessionStorage.getItem(`pastecmd-room-${sessionId}`) || "null"); } catch {}
    if (rec && rec.code === c && typeof rec.key === "string") {
      const raw = b64url.decode(rec.key);
      if (raw.length === 32) {
        keyRaw = raw;
        await importSessionKey();
        paired = true;
      }
    }
    if (!paired) setStatus("", "Pairing…");
    $("clip-card").classList.remove("hidden");
  }

  // Device cap (host-controlled). Default: locked to 2 — pairing two devices is
  // the core use case, so security is the default and "allow more" is opt-in.
  const allowMore = () => isHost && localStorage.getItem("pastecmd-allow-more") === "1";
  const maxDevices = () => allowMore() ? MAX_PEERS : 2;

  // --- Host: the QR carries just the code ----------------------------------
  // It is the same six characters as a short URL: scanning it opens this page
  // and joins. There is no long link to copy anywhere.
  function drawQR() {
    const shareUrl = `${location.origin}/#${code}`;
    const qr = qrcode(0, "M");
    qr.addData(shareUrl);
    qr.make();
    // Draw modules to a canvas directly — no HTML-string sinks, so the page
    // stays clean under Trusted Types enforcement.
    const n = qr.getModuleCount();
    const scale = 8;
    const canvas = document.createElement("canvas");
    canvas.width = canvas.height = n * scale;
    const g = canvas.getContext("2d");
    g.fillStyle = "#fff";
    g.fillRect(0, 0, canvas.width, canvas.height);
    g.fillStyle = "#000";
    for (let r = 0; r < n; r++) {
      for (let c = 0; c < n; c++) {
        if (qr.isDark(r, c)) g.fillRect(c * scale, r * scale, scale, scale);
      }
    }
    $("qr-holder").replaceChildren(canvas);
  }

  // Once linked, collapse the QR behind a toggle: it stops dominating the page
  // and stops being shoulder-surfable. Re-expands if the other device drops.
  const qrBody = $("qr-body"), qrToggle = $("qr-toggle");
  qrToggle.onclick = () => {
    const show = qrBody.classList.contains("hidden");
    qrBody.classList.toggle("hidden", !show);
    qrToggle.textContent = show ? "Hide QR code" : "Show QR code";
  };
  function setQrLinked(linked) {
    if (!isHost || expired) return;
    qrBody.classList.toggle("hidden", linked);
    qrToggle.classList.toggle("hidden", !linked);
    qrToggle.textContent = "Show QR code";
  }

  // --- Host UI wiring ------------------------------------------------------
  function showHostUI() {
    $("code-host-text").textContent = code;
    $("code-host-copy").onclick = () => copyText(code, $("code-host-copy"), "Copy code");
    $("allow-more-wrap").classList.remove("hidden");
    const allowBox = $("allow-more");
    allowBox.checked = allowMore();
    allowBox.onchange = async () => {
      // Changing the cap needs a fresh room: the server locks the cap on the
      // creator's first connect, so a new code (and key) is generated.
      localStorage.setItem("pastecmd-allow-more", allowBox.checked ? "1" : "0");
      generation++;
      try { if (ws) ws.close(); } catch {}
      dropRoom();
      await startNewHost();
      connect();
    };
    $("qr-card").classList.remove("hidden");
    $("clip-card").classList.remove("hidden");
  }

  // --- Mode tabs: "New session" vs "Enter code" -----------------------------
  async function selectMode(mode) {
    $("mode-tab-new").setAttribute("aria-selected", String(mode === "new"));
    $("mode-tab-enter").setAttribute("aria-selected", String(mode === "enter"));
    if (mode === "enter") {
      // Discard the host identity minted on boot — we are going to join.
      generation++;
      try { ws && ws.close(); } catch {}
      dropRoom();
      isHost = false;
      paired = false;
      sessionId = null;
      keyRaw = null;
      key = null;
      $("mode-tabs").classList.add("hidden");
      $("qr-card").classList.add("hidden");
      $("allow-more-wrap").classList.add("hidden");
      $("clip-card").classList.add("hidden");
      $("code-join-missing").classList.add("hidden");
      $("code-join-card").classList.remove("hidden");
      setStatus("", "Enter the code shown on the other screen");
    } else {
      $("mode-tabs").classList.add("hidden");
      $("code-join-card").classList.add("hidden");
      await startNewHost();
      connect();
    }
  }
  const enterCodeInput = $("code-join-input");
  const showJoinError = (text) => {
    const el = $("code-join-missing");
    el.textContent = text;
    el.classList.remove("hidden");
  };
  $("mode-tab-new").onclick = () => selectMode("new");
  $("mode-tab-enter").onclick = () => selectMode("enter");
  $("code-join-back").onclick = () => selectMode("new");
  $("code-join-submit").onclick = async () => {
    const c = normalizeCode(enterCodeInput.value);
    $("code-join-missing").classList.add("hidden");
    if (!CODE_RE.test(c)) {
      showJoinError(`That is not a ${CODE_LEN}-character code — check the other screen.`);
      return;
    }
    enterCodeInput.value = "";
    $("code-join-card").classList.add("hidden");
    await joinWithCode(c);
    connect();
  };
  enterCodeInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") $("code-join-submit").click();
  });

  // --- Boot ----------------------------------------------------------------
  // A scanned QR arrives as #<code>. Anything else in the fragment is a stale
  // link from the old scheme, so it is dropped.
  const hashCode = normalizeCode(location.hash.slice(1));
  if (location.hash && !CODE_RE.test(hashCode)) {
    history.replaceState(null, "", location.pathname);
  }
  if (CODE_RE.test(hashCode)) {
    $("mode-tabs").classList.add("hidden");
    $("clip-card").classList.add("hidden");
    setStatus("", "Pairing…");
    await joinWithCode(hashCode);
  } else if (await restoreSession()) {
    // Reloaded tab: same room and code, straight back in.
    if (isHost) { drawQR(); showHostUI(); }
    else $("clip-card").classList.remove("hidden");
  } else {
    $("mode-tabs").classList.remove("hidden");
    await startNewHost();
  }

  // --- Crypto: AES-GCM with per-message random IV and context-binding AAD ---
  async function encryptBytes(bytes, aad) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aad }, key, bytes);
    return { iv, ct: new Uint8Array(ct) };
  }
  async function decryptBytes(iv, ct, aad) {
    return crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: aad }, key, ct);
  }

  // --- Replay protection ---
  // Each page load picks a random device ID and numbers every JSON message it
  // sends (clips and file-starts). Both go into the AAD so the relay can't
  // alter them, and receivers drop anything not newer than the last message
  // they authenticated from that device — the relay can't roll a clip back or
  // re-deliver a whole file. File chunks need no numbering: they're bound to
  // their fileId, which is only accepted once. (A device that has just loaded
  // has no history, so the first message it sees could still be a stale one;
  // closing that gap would need a handshake.)
  const deviceId = crypto.getRandomValues(new Uint8Array(8));
  const deviceIdB64 = b64url.encode(deviceId);
  const lastSeq = new Map(); // sender device ID (b64) -> highest authenticated seq
  let sendSeq = 0, outbox = Promise.resolve();
  const sealedAad = (type, from, seq, extra) =>
    concatBytes(te.encode(type), from, u32(seq), extra);

  // All sealed sends go through one queue so sequence numbers reach the wire
  // in order — otherwise a slow encrypt could put seq N behind N+1 and the
  // receiver would drop it as a replay.
  function sendSealed(type, bytes, extra = new Uint8Array(0), fields = {}) {
    const sent = outbox.then(async () => {
      const seq = ++sendSeq;
      const { iv, ct } = await encryptBytes(bytes, sealedAad(type, deviceId, seq, extra));
      ws.send(JSON.stringify({
        type, ...fields, from: deviceIdB64, seq,
        iv: b64url.encode(iv), data: b64url.encode(ct),
      }));
    });
    outbox = sent.catch(() => {});
    return sent;
  }

  // Returns the plaintext, or throws if the message is reflected, replayed,
  // malformed, or fails authentication.
  async function openSealed(msg, extra = new Uint8Array(0)) {
    if (msg.from === deviceIdB64) throw new Error("reflected");
    const from = b64url.decode(msg.from);
    if (from.length !== 8 || !Number.isInteger(msg.seq) || msg.seq < 1 || msg.seq > 0xffffffff) {
      throw new Error("malformed");
    }
    if (msg.seq <= (lastSeq.get(msg.from) || 0)) throw new Error("replayed");
    const pt = await decryptBytes(
      b64url.decode(msg.iv), b64url.decode(msg.data), sealedAad(msg.type, from, msg.seq, extra));
    // Only advance after authentication, so a forged high seq can't lock
    // out the real sender.
    lastSeq.set(msg.from, msg.seq);
    return pt;
  }

  // --- Status UI ---
  function setStatus(cls, text) {
    statusEl.className = cls;
    statusText.textContent = text;
  }

  // Per-tab rejoin token: lets this tab reclaim its own slot when it
  // reconnects, even if the server still holds its old, dead socket (see
  // Session.fetch). sessionStorage keeps it across a reload of this tab only;
  // it's keyed by session, so a regenerated session gets a fresh one.
  const tokens = new Map();
  function rejoinToken() {
    const k = `pastecmd-t-${sessionId}`;
    let t = tokens.get(k);
    try { t ||= sessionStorage.getItem(k); } catch {}
    if (!t || !/^[A-Za-z0-9_-]{22}$/.test(t)) t = randomId(16);
    tokens.set(k, t);
    try { sessionStorage.setItem(k, t); } catch {}
    return t;
  }

  // --- WebSocket ---
  const clip = $("clip");

  function connect() {
    if (!sessionId) return; // "Enter code" chosen, code not yet entered
    const gen = generation;
    const proto = location.protocol === "https:" ? "wss" : "ws";
    // Host advertises the cap; the server only honors it from the first (host)
    // connection, so a later joiner can't raise it.
    const q = (isHost ? `?max=${maxDevices()}&` : "?") + `t=${rejoinToken()}`;
    ws = new WebSocket(`${proto}://${location.host}/ws/${sessionId}${q}`);
    ws.binaryType = "arraybuffer";

    ws.onopen = async () => {
      retryDelay = 500;
      joinTries = 0;
      if (!paired) {
        // Joining: claim the room and wait for the key handoff.
        setStatus("", "Pairing…");
        await sendPairJoin();
        return;
      }
      setStatus("", isHost ? "Waiting for a device to enter the code…" : "Connected");
      // Late joiner should receive whatever is already in the box.
      if (clip.value && key) await sendClip();
    };

    // Handle messages strictly one at a time, in arrival order. An async
    // onmessage alone doesn't: every await (decrypt) lets the next message's
    // handler start, so chunks could race their own file-start, two copies of
    // a chunk could both pass the duplicate check, and clips could land
    // out of order.
    ws.onmessage = (ev) => {
      inbox = inbox.then(() => onMessage(ev)).catch(() => {});
    };

    ws.onclose = (ev) => {
      if (gen !== generation) return; // superseded (regenerated, or ended)
      // A joining device may get here before the host has claimed the room —
      // the relay answers "expired" until it is created with ?max. Keep
      // trying briefly instead of declaring the session over.
      if (ev.reason === "expired" && !isHost && !paired) {
        if (++joinTries <= 15) {
          setStatus("dead", "Waiting for the other device…");
          setTimeout(() => { if (gen === generation && !paired) connect(); }, 2000);
          return;
        }
        generation++;
        try { ws.close(); } catch {}
        setStatus("dead", "No device answered that code");
        $("clip-card").classList.add("hidden");
        $("code-join-card").classList.remove("hidden");
        showJoinError("No device answered that code. Check the characters and " +
          "try again — the code only works while the other screen is open.");
        return;
      }
      if (TERMINAL.has(ev.reason)) return endSession(ev.reason);
      setStatus("dead", "Reconnecting…");
      setTimeout(() => { if (gen === generation) connect(); }, retryDelay);
      retryDelay = Math.min(retryDelay * 2, 8000);
    };
  }

  // Final states, announced by the server in a control message and/or the
  // close reason (whichever arrives first). Not a retry loop.
  const TERMINAL = new Set(["expired", "full", "replaced"]);
  function endSession(reason) {
    generation++; // this socket's close event, whenever it lands, is ignored
    try { ws.close(); } catch {}
    if (reason === "expired") {
      expired = true;
      dropRoom();
      $("mode-tabs").classList.add("hidden");
      $("code-join-card").classList.add("hidden");
      $("qr-card").classList.add("hidden");
      $("clip-card").classList.add("hidden");
      $("expired-card").classList.remove("hidden");
    } else if (reason === "full") {
      // Turned away: the session is already at its device limit. For a legit
      // device this is the alarm that someone else holds the second slot.
      $("clip-card").classList.add("hidden");
      $("full-card").classList.remove("hidden");
    } else if (reason === "replaced") {
      // The same tab reconnected elsewhere — in practice a duplicated tab,
      // which carries a copy of this one's sessionStorage. Stand down rather
      // than fight over the slot.
      dropRoom();
      $("qr-card").classList.add("hidden");
      $("clip-card").classList.add("hidden");
      $("replaced-card").classList.remove("hidden");
    }
  }

  async function onMessage(ev) {
    if (ev.data instanceof ArrayBuffer) { await onFileChunk(ev.data); return; }
    if (typeof ev.data !== "string") return;

    if (ev.data.startsWith(CONTROL)) {
      // Server control message — cannot be forged by other devices.
      let msg;
      try { msg = JSON.parse(ev.data.slice(1)); } catch { return; }
      if (msg.type === "closing" && TERMINAL.has(msg.reason)) {
        endSession(msg.reason);
      } else if (msg.type === "peers") {
        peerCount = msg.count;
        if (!paired) {
          // Joining device: the slot is taken, but the key has not arrived.
          setStatus(msg.count >= 2 ? "linked" : "", msg.count >= 2
            ? "Pairing…" : "Waiting for the other device…");
        } else if (msg.count >= 2) {
          setStatus("linked", `Linked — ${msg.count} devices`);
        } else {
          setStatus("", isHost
            ? "Waiting for a device to enter the code…" : "Other device disconnected");
        }
        setQrLinked(msg.count >= 2);
        // Alone again: any half-received file can never complete — say so
        // instead of leaving its progress bar hanging forever.
        if (msg.count < 2 && incoming.size) {
          for (const t of incoming.values()) t.row.fail("Interrupted — other device disconnected");
          incoming.clear();
        }
      }
      return;
    }

    let msg;
    try { msg = JSON.parse(ev.data); } catch { return; }
    // Pairing handshake: plaintext framing, authenticated by HMACs keyed with
    // the code. They are only meaningful to a host and a device that knows
    // the same six characters.
    if (msg.type === "pair-join") { await hostOnPairJoin(msg); return; }
    if (msg.type === "pair-key") { await joinerOnPairKey(msg); return; }
    if (!key) return; // nothing sealed can be read before the handoff
    if (msg.type === "clip") {
      try {
        const pt = await openSealed(msg);
        const text = td.decode(pt);
        if (clip.value !== text) {
          // Assigning .value throws the caret to the end — restore it so a
          // remote update doesn't yank the cursor mid-typing.
          const focused = document.activeElement === clip;
          const start = clip.selectionStart, end = clip.selectionEnd;
          clip.value = text;
          if (focused) {
            clip.setSelectionRange(
              Math.min(start, text.length), Math.min(end, text.length));
          }
        }
      } catch { /* wrong key, tampered or replayed — ignore */ }
    } else if (msg.type === "file-start") {
      await onFileStart(msg);
    }
  }
  $("full-new").onclick = () => { location.href = "/"; };
  $("replaced-new").onclick = () => { location.href = "/"; };
  $("full-retry").onclick = () => {
    $("full-card").classList.add("hidden");
    $("clip-card").classList.remove("hidden");
    setStatus("dead", "Reconnecting…");
    connect();
  };
  connect();

  // --- Sync on typing (debounced) ---
  // The relay drops any message over 1 MB. Base64 and the JSON envelope add
  // about a third, so cap the text well under that and say so, rather than
  // letting an oversized clip silently never arrive.
  const MAX_CLIP_BYTES = 700_000;
  function sendClip() {
    if (!key) return Promise.resolve(); // not paired yet
    const bytes = te.encode(clip.value);
    const tooBig = bytes.length > MAX_CLIP_BYTES;
    $("clip-too-big").classList.toggle("hidden", !tooBig);
    if (tooBig) return Promise.resolve();
    return sendSealed("clip", bytes).catch(() => {});
  }
  let debounce;
  clip.addEventListener("input", () => {
    clearTimeout(debounce);
    debounce = setTimeout(async () => {
      if (ws && ws.readyState === WebSocket.OPEN && !expired && key) await sendClip();
    }, 200);
  });

  // --- Copy / paste buttons ---
  async function copyText(text, btn, label) {
    try {
      await navigator.clipboard.writeText(text);
      btn.textContent = "Copied!";
    } catch {
      btn.textContent = "Copy failed";
    }
    setTimeout(() => { btn.textContent = label; }, 1500);
  }
  $("copy-btn").onclick = () => copyText(clip.value, $("copy-btn"), "Copy");
  $("clear-btn").onclick = () => {
    clip.value = "";
    clip.dispatchEvent(new Event("input")); // syncs the empty box to the peer
  };
  $("paste-btn").onclick = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        clip.value = text;
        clip.dispatchEvent(new Event("input"));
      }
    } catch {
      $("paste-btn").textContent = "Not allowed — long-press the box instead";
      setTimeout(() => { $("paste-btn").textContent = "Paste from clipboard"; }, 2500);
    }
  };

  // --- File transfer ---
  // Files travel over the same relay, sliced into encrypted chunks sent as
  // binary frames: fileId(4) | chunkIndex(4) | iv(12) | ciphertext.
  // A JSON "file-start" message (with encrypted metadata) precedes the chunks.
  const CHUNK_SIZE = 256 * 1024;
  const MAX_FILE_BYTES = 50 * 1024 * 1024;
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const fmtSize = (n) => n >= 1e6 ? `${(n / 1e6).toFixed(1)} MB`
    : n >= 1e3 ? `${(n / 1e3).toFixed(0)} KB` : `${n} B`;
  const chunkAad = (fileId, index) => concatBytes(te.encode("chunk"), fileId, u32(index));
  const FRAME_HEADER = 20, GCM_TAG = 16;
  // Plaintext length of chunk `index`: every chunk is full except the last.
  const chunkLen = (meta, index) =>
    index < meta.chunks - 1 ? CHUNK_SIZE : meta.size - (meta.chunks - 1) * CHUNK_SIZE;

  function transferRow(name, size) {
    const el = document.createElement("div");
    el.className = "transfer";
    const info = document.createElement("div");
    info.className = "t-info";
    const nameEl = document.createElement("div");
    nameEl.className = "t-name";
    nameEl.textContent = name;
    const subEl = document.createElement("div");
    subEl.className = "t-sub";
    subEl.textContent = fmtSize(size);
    const bar = document.createElement("div");
    bar.className = "bar";
    bar.append(document.createElement("i"));
    info.append(nameEl, subEl, bar);
    el.append(info);
    $("transfers").prepend(el);
    return {
      el,
      progress(done, total) {
        el.querySelector(".bar i").style.width = `${Math.round(done / total * 100)}%`;
      },
      finish(text) {
        el.querySelector(".bar").remove();
        el.querySelector(".t-sub").textContent = `${fmtSize(size)} · ${text}`;
      },
      fail(text) {
        el.querySelector(".bar").remove();
        el.querySelector(".t-sub").textContent = text;
      },
    };
  }

  // Files go out one at a time: the receiver caps concurrent incoming
  // transfers, and parallel sends would only split the same bandwidth.
  let sendChain = Promise.resolve();
  function queueFile(file) {
    const row = transferRow(file.name, file.size);
    sendChain = sendChain.then(() => sendFile(file, row));
  }

  async function sendFile(file, row) {
    if (file.size > MAX_FILE_BYTES) return row.fail("Too big — 50 MB max");
    if (!key) return row.fail("Not paired yet — connect first");
    if (peerCount < 2) return row.fail("No other device connected — enter the code first");
    if (!ws || ws.readyState !== WebSocket.OPEN) return row.fail("Not connected");

    const fileId = crypto.getRandomValues(new Uint8Array(4));
    const chunks = Math.max(1, Math.ceil(file.size / CHUNK_SIZE));
    try {
      const meta = te.encode(JSON.stringify(
        { name: file.name, size: file.size, mime: file.type, chunks }));
      await sendSealed("file-start", meta, fileId, { id: b64url.encode(fileId) });

      for (let i = 0; i < chunks; i++) {
        // The receiver leaving mid-send would otherwise upload the rest of the
        // file to nobody with the progress bar happily advancing.
        if (peerCount < 2) throw new Error("peer-left");
        const buf = await file.slice(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE).arrayBuffer();
        const { iv, ct } = await encryptBytes(new Uint8Array(buf), chunkAad(fileId, i));
        const frame = new Uint8Array(20 + ct.byteLength);
        frame.set(fileId, 0);
        frame.set(u32(i), 4);
        frame.set(iv, 8);
        frame.set(ct, 20);
        // Backpressure: don't buffer the whole file into the socket at once.
        while (ws.bufferedAmount > 4 * CHUNK_SIZE) {
          if (ws.readyState !== WebSocket.OPEN) throw new Error("disconnected");
          await sleep(50);
        }
        ws.send(frame.buffer);
        row.progress(i + 1, chunks);
      }
      row.finish("Sent ✓");
    } catch (e) {
      row.fail(e && e.message === "peer-left"
        ? "Interrupted — other device disconnected" : "Failed — connection lost");
    }
  }

  // A peer holding the key is trusted with content, not with our memory. The
  // declared size is enforced chunk by chunk (so it bounds what we buffer),
  // in-flight transfers are capped, and a transfer that stops making progress
  // is dropped rather than holding its slot forever.
  const incoming = new Map(); // fileId (b64) -> { meta, fileId, parts, got, row, stall }
  const MAX_INCOMING = 8;
  const MAX_INCOMING_BYTES = 200 * 1024 * 1024;
  const STALL_MS = 60_000;
  const THUMB_TYPES = new Set(["image/png", "image/jpeg", "image/gif", "image/webp", "image/avif"]);

  function armStall(id, t) {
    clearTimeout(t.stall);
    t.stall = setTimeout(() => {
      if (incoming.get(id) !== t) return;
      incoming.delete(id);
      t.row.fail("Interrupted — transfer stalled");
    }, STALL_MS);
  }

  async function onFileStart(msg) {
    let meta, fileId;
    try {
      fileId = b64url.decode(msg.id);
      if (fileId.length !== 4) return;
      const pt = await openSealed(msg, fileId);
      meta = JSON.parse(td.decode(pt));
    } catch { return; /* wrong key, tampered or replayed — ignore */ }
    if (!meta || typeof meta.name !== "string" || typeof meta.mime !== "string" ||
        !Number.isSafeInteger(meta.size) || meta.size < 0 || meta.size > MAX_FILE_BYTES ||
        meta.chunks !== Math.max(1, Math.ceil(meta.size / CHUNK_SIZE))) return;
    if (incoming.has(msg.id)) return;
    const row = transferRow(meta.name, meta.size);
    let pending = 0;
    for (const t of incoming.values()) pending += t.meta.size;
    if (incoming.size >= MAX_INCOMING || pending + meta.size > MAX_INCOMING_BYTES) {
      return row.fail("Skipped — too many files arriving at once");
    }
    const t = { meta, fileId, parts: new Array(meta.chunks), got: 0, row };
    incoming.set(msg.id, t);
    armStall(msg.id, t);
  }

  async function onFileChunk(buf) {
    if (buf.byteLength < FRAME_HEADER) return;
    const id = b64url.encode(new Uint8Array(buf, 0, 4));
    const t = incoming.get(id);
    if (!t) return; // joined mid-transfer, or not for us
    const index = new DataView(buf).getUint32(4);
    if (index >= t.meta.chunks || t.parts[index]) return;
    // Pin every chunk to its exact expected size (checked before paying for
    // a decrypt), so the file can't grow past what file-start declared.
    if (buf.byteLength !== FRAME_HEADER + chunkLen(t.meta, index) + GCM_TAG) return;
    let plain;
    try {
      plain = await decryptBytes(
        new Uint8Array(buf, 8, 12), new Uint8Array(buf, 20), chunkAad(t.fileId, index));
    } catch { return; /* tampered or misplaced chunk — ignore */ }
    t.parts[index] = plain;
    t.got++;
    t.row.progress(t.got, t.meta.chunks);
    armStall(id, t);
    if (t.got === t.meta.chunks) {
      incoming.delete(id);
      clearTimeout(t.stall);
      // The download blob is always octet-stream: blob: URLs carry our origin,
      // so a peer-chosen type like text/html would render as a pastecmd.com
      // page if opened in a tab. Only an allowlist of raster formats gets a
      // typed view, and only for the <img> thumbnail.
      const blob = new Blob(t.parts, { type: "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      if (THUMB_TYPES.has(t.meta.mime)) {
        const img = document.createElement("img");
        img.className = "thumb";
        const thumbUrl = URL.createObjectURL(blob.slice(0, blob.size, t.meta.mime));
        // The decoded image outlives its URL; free it once loaded.
        img.onload = img.onerror = () => URL.revokeObjectURL(thumbUrl);
        img.src = thumbUrl;
        t.row.el.prepend(img);
      }
      const a = document.createElement("a");
      a.className = "dl";
      a.textContent = "Download";
      a.href = url;
      a.download = t.meta.name || "file";
      t.row.el.append(a);
      t.row.finish("Received");
    }
  }

  // --- File pickers: button, drag-drop, screenshot paste ---
  $("file-btn").onclick = () => $("file-input").click();
  $("file-input").onchange = () => {
    for (const f of $("file-input").files) queueFile(f);
    $("file-input").value = "";
  };

  let dragDepth = 0;
  window.addEventListener("dragenter", (e) => {
    e.preventDefault();
    if (++dragDepth === 1) $("drop-overlay").classList.remove("hidden");
  });
  window.addEventListener("dragleave", (e) => {
    e.preventDefault();
    if (--dragDepth === 0) $("drop-overlay").classList.add("hidden");
  });
  window.addEventListener("dragover", (e) => e.preventDefault());
  window.addEventListener("drop", (e) => {
    e.preventDefault();
    dragDepth = 0;
    $("drop-overlay").classList.add("hidden");
    for (const f of e.dataTransfer.files) queueFile(f);
  });

  document.addEventListener("paste", (e) => {
    const files = [...(e.clipboardData?.files || [])];
    if (files.length) {
      e.preventDefault();
      files.forEach(queueFile);
    }
  });

  document.querySelector("#expired-card button").onclick = () => { location.href = "/"; };
})();
