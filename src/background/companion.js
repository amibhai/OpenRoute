// Native-messaging client — the extension's link to the optional companion
// (sing-box / Tor orchestration). Every call degrades gracefully: without the
// companion, isAvailable() is false and the ladder uses the transports a
// browser can reach on its own.

export const HOST = "com.openroute.host";
const CALL_TIMEOUT_MS = 4000;
const AVAIL_TTL_MS = 30 * 1000;

export function createCompanion(api) {
  let avail = { value: false, at: 0 };

  // One-shot request/response over a fresh native port. Never throws
  // synchronously; rejects on disconnect or timeout.
  function send(message, timeoutMs = CALL_TIMEOUT_MS) {
    return new Promise((resolve, reject) => {
      if (typeof api.runtime?.connectNative !== "function") {
        reject(new Error("native messaging is not supported in this browser"));
        return;
      }
      let port = null;
      let settled = false;
      const done = (fn, arg) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try { port?.disconnect(); } catch { /* already gone */ }
        fn(arg);
      };
      const timer = setTimeout(() => done(reject, new Error("companion timeout")), timeoutMs);
      try {
        port = api.runtime.connectNative(HOST);
      } catch (e) {
        done(reject, e);
        return;
      }
      port.onMessage.addListener((msg) => done(resolve, msg));
      port.onDisconnect.addListener(() =>
        done(reject, new Error(api.runtime.lastError?.message || "companion disconnected")));
      try {
        port.postMessage(message);
      } catch (e) {
        done(reject, e);
      }
    });
  }

  async function isAvailable() {
    if (Date.now() - avail.at < AVAIL_TTL_MS) return avail.value;
    let ok;
    try {
      const pong = await send({ cmd: "ping" });
      ok = !!pong && (pong.ok === true || pong.cmd === "pong");
    } catch {
      ok = false;
    }
    avail = { value: ok, at: Date.now() };
    return ok;
  }

  function invalidate() {
    avail = { value: false, at: 0 };
  }

  return { send, isAvailable, invalidate };
}
