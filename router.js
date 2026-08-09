// Split-tunnel router — turns the policy's routed-domain set into a Chrome PAC
// script so ONLY blocked domains detour through a proxy; everything else stays
// direct and full-speed.
//
// Chrome lets exactly one extension own the proxy settings. We take the
// "regular" scope in pac_script mode. The generated PAC carries an explicit
// {domain -> directive} table and matches a host against it plus its parent
// domains, so "www.blocked.com" and "cdn.blocked.com" both follow the policy
// set for "blocked.com".

import { routedDomains } from "./policy.js";
import { get as getTransport, pacDirective } from "./transports.js";

let lastSignature = null; // avoid re-applying an identical PAC (which resets connections)

// Build the PAC source from a {domain: "SOCKS5 host:port"} table.
function buildPac(table) {
  // The table is embedded as JSON; FindProxyForHost walks the host and each of
  // its parent domains looking for a match.
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

// Recompute the routing table from policy + transports and push it to Chrome.
export async function apply() {
  const routed = await routedDomains();

  const table = {};
  for (const { domain, proxyId } of routed) {
    const t = await getTransport(proxyId);
    if (!t) continue;                       // transport was removed → skip
    table[domain] = pacDirective(t);
  }

  const signature = JSON.stringify(table);
  if (signature === lastSignature) return { changed: false, count: Object.keys(table).length };
  lastSignature = signature;

  if (!Object.keys(table).length) {
    // Nothing to route → hand control back to the system so we add zero overhead.
    await clearProxy();
    return { changed: true, count: 0 };
  }

  await chrome.proxy.settings.set({
    value: { mode: "pac_script", pacScript: { data: buildPac(table), mandatory: false } },
    scope: "regular"
  });
  return { changed: true, count: Object.keys(table).length };
}

export async function clearProxy() {
  try {
    await chrome.proxy.settings.clear({ scope: "regular" });
  } catch (e) {
    console.warn("OpenRoute proxy clear failed:", e);
  }
  lastSignature = "{}";
}

// Surface proxy errors (bad PAC, unreachable proxy) so the ladder/health layer
// can react instead of the user just seeing a dead tab.
export function onProxyError(handler) {
  if (chrome.proxy?.onProxyError) {
    chrome.proxy.onProxyError.addListener(handler);
  }
}
