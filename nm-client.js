// Native-messaging client — the extension's link to the companion app.
//
// In Phase A the companion isn't installed yet, so every call here degrades
// gracefully: isAvailable() returns false and the ladder simply sticks to the
// transports an extension can reach on its own. When the Phase B companion
// lands it registers the host name below and these calls start returning real
// transport control + health, with zero changes needed above this module.

const HOST = "com.openroute.host";
const CALL_TIMEOUT_MS = 4000;
const AVAIL_TTL_MS = 30 * 1000;

let availCache = { value: false, at: 0 };

// One-shot request/response over a fresh native port. Resolves with the first
// message, rejects on disconnect/timeout. Never throws synchronously.
// Slow commands (bringing up sing-box/Tor) can pass a longer timeoutMs.
export function send(message, timeoutMs = CALL_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    let port;
    let settled = false;
    const done = (fn, arg) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { port?.disconnect(); } catch {}
      fn(arg);
    };
    const timer = setTimeout(() => done(reject, new Error("companion timeout")), timeoutMs);

    try {
      port = chrome.runtime.connectNative(HOST);
    } catch (e) {
      clearTimeout(timer);
      return reject(e);
    }
    port.onMessage.addListener((msg) => done(resolve, msg));
    port.onDisconnect.addListener(() =>
      done(reject, new Error(chrome.runtime.lastError?.message || "companion disconnected")));
    try {
      port.postMessage(message);
    } catch (e) {
      done(reject, e);
    }
  });
}

// Cheap, cached probe so callers can branch on companion presence without
// hammering connectNative.
export async function isAvailable() {
  const now = Date.now();
  if (now - availCache.at < AVAIL_TTL_MS) return availCache.value;
  let ok = false;
  try {
    const pong = await send({ cmd: "ping" });
    ok = !!pong && (pong.ok === true || pong.pong === true || pong.cmd === "pong");
  } catch {
    ok = false;
  }
  availCache = { value: ok, at: now };
  return ok;
}

export function invalidate() {
  availCache = { value: false, at: 0 };
}

// Ask the companion for the transports it manages (Shadowsocks/Reality/Tor/…),
// so they can be merged into the roster. Returns [] when absent.
export async function listCompanionTransports() {
  if (!(await isAvailable())) return [];
  try {
    const r = await send({ cmd: "transports" });
    return Array.isArray(r?.transports) ? r.transports : [];
  } catch {
    return [];
  }
}
