// Split-tunnel router — turns the policy's routed-domain set into per-request
// proxy decisions so ONLY blocked domains detour; everything else stays direct
// and full-speed.
//
// Two engines behind one API, chosen by feature detection:
//   * Chromium (Chrome/Edge): owns proxy settings in pac_script mode — we emit a
//     PAC whose FindProxyForHost matches a host and its parent domains.
//   * Firefox: registers a proxy.onRequest listener that consults the same table
//     live and returns a proxy descriptor (with DIRECT fallback) per request.

import { routedDomains } from "./policy.js";
import { get as getTransport, pacDirective } from "./transports.js";

const hasChromiumProxy = () => !!(chrome.proxy && chrome.proxy.settings && chrome.proxy.settings.set);
const hasFirefoxProxy = () => !!(chrome.proxy && chrome.proxy.onRequest);

let lastSignature = null;     // avoid re-applying an identical table (resets connections)
let ffTable = {};             // domain -> transport, read live by the Firefox listener
let ffListenerAdded = false;

// Walk a host and each parent domain against a table; return the hit or null.
function matchHost(host, table) {
  host = ("" + host).toLowerCase();
  if (table[host]) return table[host];
  let dot = host.indexOf(".");
  while (dot !== -1) {
    host = host.substring(dot + 1);
    if (table[host]) return table[host];
    dot = host.indexOf(".");
  }
  return null;
}

// ---- Chromium PAC ----------------------------------------------------------

function buildPac(table) {
  const json = JSON.stringify(table);
  return `
var OPENROUTE = ${json};
function FindProxyForHost(host, url) {
  host = ("" + host).toLowerCase();
  if (OPENROUTE[host]) return OPENROUTE[host];
  var dot = host.indexOf(".");
  while (dot !== -1) {
    host = host.substring(dot + 1);
    if (OPENROUTE[host]) return OPENROUTE[host];
    dot = host.indexOf(".");
  }
  return "DIRECT";
}`.trim();
}

// ---- Firefox proxy.onRequest ----------------------------------------------

function ffDescriptor(t) {
  const type = t.scheme === "http" ? "http"
    : t.scheme === "https" ? "https"
    : t.scheme === "socks4" ? "socks4"
    : "socks"; // socks5
  const d = { type, host: t.host, port: Number(t.port) };
  if (type === "socks") d.proxyDNS = true; // resolve names at the proxy, not locally
  return d;
}

function ffOnRequest(requestInfo) {
  let host = "";
  try { host = new URL(requestInfo.url).hostname; } catch { return { type: "direct" }; }
  const t = matchHost(host, ffTable);
  if (!t) return { type: "direct" };
  return [ffDescriptor(t), { type: "direct" }]; // try the proxy, then fall back to direct
}

function ensureFirefoxListener() {
  if (ffListenerAdded || !hasFirefoxProxy()) return;
  chrome.proxy.onRequest.addListener(ffOnRequest, { urls: ["<all_urls>"] });
  ffListenerAdded = true;
}

// ---- shared API ------------------------------------------------------------

// Recompute the routing table from policy + transports and push it to the engine.
export async function apply() {
  const routed = await routedDomains();

  const map = {}; // domain -> transport
  for (const { domain, proxyId } of routed) {
    const t = await getTransport(proxyId);
    if (!t) continue;                       // transport was removed → skip
    map[domain] = t;
  }

  const signature = JSON.stringify(
    Object.fromEntries(Object.entries(map).map(([d, t]) => [d, `${t.scheme}:${t.host}:${t.port}`]))
  );
  if (signature === lastSignature) return { changed: false, count: Object.keys(map).length };
  lastSignature = signature;

  // Firefox: hand the table to the live listener.
  if (hasFirefoxProxy() && !hasChromiumProxy()) {
    ffTable = map;
    ensureFirefoxListener();
    return { changed: true, count: Object.keys(map).length, engine: "firefox" };
  }

  // Chromium: (re)build the PAC, or hand control back if nothing is routed.
  if (!Object.keys(map).length) {
    await clearProxy();
    return { changed: true, count: 0 };
  }
  const table = {};
  for (const [d, t] of Object.entries(map)) table[d] = pacDirective(t);
  await chrome.proxy.settings.set({
    value: { mode: "pac_script", pacScript: { data: buildPac(table), mandatory: false } },
    scope: "regular"
  });
  return { changed: true, count: Object.keys(map).length, engine: "chromium" };
}

export async function clearProxy() {
  ffTable = {};
  if (hasChromiumProxy()) {
    try {
      await chrome.proxy.settings.clear({ scope: "regular" });
    } catch (e) {
      console.warn("OpenRoute proxy clear failed:", e);
    }
  }
  lastSignature = "{}";
}

// Surface proxy errors (bad PAC, unreachable proxy) so the ladder/health layer
// can react instead of the user just seeing a dead tab.
export function onProxyError(handler) {
  if (chrome.proxy?.onProxyError) chrome.proxy.onProxyError.addListener(handler);        // Chromium
  else if (chrome.proxy?.onError) chrome.proxy.onError.addListener(handler);             // Firefox
}
