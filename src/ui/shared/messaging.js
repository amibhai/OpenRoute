// Messaging from extension pages to the background. The MV3 worker may be
// asleep when a page opens; the browser wakes it for the message, but the
// very first attempt can race its start-up, so retry briefly.

export function getApi() {
  return globalThis.browser ?? globalThis.chrome;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function send(type, extra = {}, { retries = 4 } = {}) {
  const api = getApi();
  let lastError = "no response from the background";
  for (let i = 0; i <= retries; i++) {
    try {
      const res = await api.runtime.sendMessage({ type, ...extra });
      if (res !== undefined) return res;
    } catch (e) {
      lastError = String(e?.message || e);
    }
    await sleep(120 * (i + 1));
  }
  return { ok: false, error: lastError };
}
