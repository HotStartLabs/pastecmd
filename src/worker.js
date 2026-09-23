// pastecmd — WebSocket relay for cross-device clipboard sessions.
// The server only relays opaque encrypted blobs; the AES key lives in the
// URL fragment and never reaches us.

const SESSION_TTL_MS = 10 * 60 * 1000; // idle sessions die after 10 minutes
const MAX_MESSAGE_BYTES = 1_000_000;
const utf8 = new TextEncoder();
const MAX_PEERS = 8;
const DEFAULT_PEERS = 2; // the safe default, matching the client's
const REJOIN_TOKEN = /^[A-Za-z0-9_-]{22}$/; // 128 random bits, base64url

// Turn a connection away with a reason the client can tell apart from a
// transient drop: establish the socket, then close it immediately. It's never
// accepted into the session, so it doesn't count toward the peer total.
function reject(code, reason) {
  const pair = new WebSocketPair();
  pair[1].accept();
  pair[1].close(code, reason);
  return new Response(null, { status: 101, webSocket: pair[0] });
}

// Server→client control messages are prefixed with NUL, and the relay refuses
// to forward client strings carrying that prefix — so a device in the session
// cannot forge a server message (e.g. spoof the peer count to hide itself).
const CONTROL_PREFIX = "\u0000";

// The app lives on exactly one origin, https://<CANONICAL_HOST> (a wrangler
// var). Every other hostname that reaches the worker is redirected there, and
// it's the only origin allowed to open relay connections or to be named in
// connect-src.

// connect-src varies by environment: `wrangler dev` serves plain http and the
// page connects over ws://, so dev needs the localhost entries — but they must
// never appear in the production policy.
const securityHeaders = (isDev, host) => ({
  "Content-Security-Policy":
    // script-src is 'self' with no exceptions. Notably that means enabling
    // Cloudflare Web Analytics at the edge would be BLOCKED by this header
    // rather than silently injecting a third-party script into the page that
    // holds pasted clipboard content. Adding analytics has to be a deliberate
    // edit here, not a dashboard toggle — which is the point.
    "default-src 'none'; script-src 'self'; style-src 'self'; " +
    (isDev
      ? "connect-src 'self' ws://localhost:8787 ws://127.0.0.1:8787; "
      : `connect-src 'self' wss://${host}; `) +
    // codecanary.org: the footer integrity badge image
    "img-src 'self' blob: https://codecanary.org; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; " +
    // Any future DOM-XSS sink assignment throws at runtime instead of
    // executing, and with no policies allowed (the page needs none), nothing
    // can register a permissive "default" policy to launder strings through.
    "require-trusted-types-for 'script'; trusted-types 'none'",
  // Two years + preload: submitted to hstspreload.org, so first visits are
  // HTTPS before any request is ever made.
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
  // Full cross-origin isolation: everything is same-origin, so COEP/CORP cost
  // nothing and foreclose Spectre-style cross-origin reads and embedding.
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Embedder-Policy": "require-corp",
  "Cross-Origin-Resource-Policy": "same-origin",
});

export class Session {
  constructor(ctx, env) {
    this.ctx = ctx;
  }

  async fetch(request) {
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("Expected WebSocket", { status: 426 });
    }

    // The session creator sets the concurrent-device cap; later joiners can't
    // widen it. Stored so it survives DO hibernation, and cleared with the
    // rest of the session on expiry.
    //
    // Only a connection that asks to create the session (the host, which
    // sends ?max) may start one. Otherwise a joiner reopening a dead link —
    // a reload, or history, where the key also sits — would silently bring
    // the session back to life under the old key.
    const params = new URL(request.url).searchParams;
    let max = await this.ctx.storage.get("max");
    if (max === undefined) {
      const param = params.get("max");
      if (param === null) return reject(4000, "expired");
      const req = parseInt(param, 10);
      max = Number.isInteger(req) ? Math.min(Math.max(req, 1), MAX_PEERS) : DEFAULT_PEERS;
      await this.ctx.storage.put("max", max);
    }

    // A device reconnecting after a network switch or reload presents the
    // per-tab token it joined with. Its old socket can be a dead connection
    // the runtime hasn't noticed yet, still holding a slot — so replace it
    // instead of turning the device away as "full" (a false intruder alarm).
    // The token is known only to that tab and to us, so someone else holding
    // the link can't use this to push a device out.
    const token = params.get("t");
    const rejoin = token && REJOIN_TOKEN.test(token) ? token : null;
    if (rejoin) {
      for (const old of this.liveSockets()) {
        if (old.deserializeAttachment()?.token === rejoin) {
          try { old.close(4003, "replaced"); } catch {}
        }
      }
    }

    // Session full: the client shows this as an alarm, since for a legit
    // device it means someone else holds a slot.
    if (this.liveSockets().length >= max) return reject(4001, "full");

    const pair = new WebSocketPair();
    this.ctx.acceptWebSocket(pair[1]);
    pair[1].serializeAttachment({ token: rejoin });
    await this.bumpExpiry();
    this.broadcastPeerCount();

    return new Response(null, { status: 101, webSocket: pair[0] });
  }

  async bumpExpiry() {
    // File transfers send hundreds of messages; throttle alarm writes so a
    // transfer costs one storage write per minute, not one per chunk.
    const now = Date.now();
    if (this.lastBump && now - this.lastBump < 60_000) return;
    this.lastBump = now;
    await this.ctx.storage.setAlarm(now + SESSION_TTL_MS);
  }

  // Sockets we've closed can linger in getWebSockets() until the close
  // handshake finishes (never, for a dead peer), so count only open ones.
  liveSockets(except) {
    return this.ctx.getWebSockets()
      .filter((ws) => ws !== except && ws.readyState === WebSocket.OPEN);
  }

  broadcastPeerCount(closing) {
    const sockets = this.liveSockets(closing);
    const msg = CONTROL_PREFIX + JSON.stringify({ type: "peers", count: sockets.length });
    for (const ws of sockets) {
      try { ws.send(msg); } catch {}
    }
  }

  async webSocketMessage(ws, message) {
    // Strings carry JSON clip/file messages; ArrayBuffers carry encrypted
    // file chunks. Both are opaque to us — just relay. The control prefix is
    // reserved for server messages: never relay a client string bearing it.
    const isString = typeof message === "string";
    if (isString && message.startsWith(CONTROL_PREFIX)) return;
    // Measure strings in UTF-8 bytes, not UTF-16 code units (.length), which
    // undercounts non-ASCII by up to 3x. The length pre-check skips encoding
    // anything already too long.
    if (isString && message.length > MAX_MESSAGE_BYTES) return;
    const size = isString ? utf8.encode(message).byteLength : message.byteLength;
    if (size > MAX_MESSAGE_BYTES) return;
    await this.bumpExpiry();
    for (const other of this.ctx.getWebSockets()) {
      if (other === ws) continue;
      try { other.send(message); } catch {}
    }
  }

  webSocketClose(ws) {
    this.broadcastPeerCount(ws);
  }

  webSocketError(ws) {
    this.broadcastPeerCount(ws);
  }

  async alarm() {
    for (const ws of this.ctx.getWebSockets()) {
      try { ws.close(1000, "expired"); } catch {}
    }
    await this.ctx.storage.deleteAll();
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    // Canonicalize to https://<CANONICAL_HOST>: force https, fold www and
    // pastecommand.com into the apex. The URL fragment (session key) survives
    // redirects — browsers re-apply it. No hostname is exempt: workers.dev
    // and preview URLs are disabled in wrangler.jsonc, and if one were ever
    // re-enabled it would redirect here rather than serve a second origin.
    // Skipped entirely in dev: `wrangler dev` serves plain http and simulates
    // the production hostname, so hostname checks can't distinguish dev.
    const isDev = env.ENVIRONMENT !== "production";
    const host = env.CANONICAL_HOST;
    if (!isDev && !host) return new Response("CANONICAL_HOST not set", { status: 500 });
    const offCanonicalHost = !isDev && url.hostname !== host;
    // Hop 1 — scheme upgrade on the SAME host. HSTS preload requires the
    // first redirect from http to stay on-host, and it's also how each host
    // gets to deliver its own HSTS header (which clients ignore over plain
    // http, hence no HSTS on this hop per RFC 6797).
    if (url.protocol === "http:" && !isDev) {
      url.protocol = "https:";
      const headers = { Location: url.toString(), ...securityHeaders(isDev, host) };
      delete headers["Strict-Transport-Security"];
      return new Response(null, { status: 301, headers });
    }
    // Hop 2 — canonical-host fold over https, HSTS included.
    if (offCanonicalHost) {
      url.hostname = host;
      return new Response(null, {
        status: 301,
        headers: { Location: url.toString(), ...securityHeaders(isDev, host) },
      });
    }
    // Session IDs are exactly 9 random bytes, base64url (see app.js).
    const match = url.pathname.match(/^\/ws\/([A-Za-z0-9_-]{12})$/);
    if (match) {
      // Browsers enforce none of the WS same-origin rules, so check Origin
      // here: only our own pages may open relay connections. Not enforced in
      // dev, where wrangler's host simulation rewrites the Origin header.
      const origin = request.headers.get("Origin");
      if (!isDev && origin && origin !== `https://${host}`) {
        return new Response("Forbidden", { status: 403 });
      }
      const id = env.SESSIONS.idFromName(match[1]);
      return env.SESSIONS.get(id).fetch(request);
    }

    const res = await env.ASSETS.fetch(request);
    const headers = new Headers(res.headers);
    for (const [k, v] of Object.entries(securityHeaders(isDev, host))) headers.set(k, v);
    return new Response(res.body, { status: res.status, headers });
  },
};
