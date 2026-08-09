// OpenRoute control plane.
//
// Pipeline:  navigation fails  →  diagnose over DoH  →  classify the block  →
//            hand it to the ladder, which picks a rung and (when needed) routes
//            the domain through a proxy via a split-tunnel PAC.  A successful
//            navigation later verifies the rung actually worked.
//
// This file owns detection, diagnostics logging, and popup messaging; the
// routing brain lives in ladder.js / router.js / policy.js / transports.js.

import { diagnose } from "./doh.js";
import * as policy from "./policy.js";
import * as transports from "./transports.js";
import * as ladder from "./ladder.js";
import * as router from "./router.js";
import * as health from "./health.js";
import * as nm from "./nm-client.js";

const STORAGE_KEY = "blockedSites";     // diagnostic log (rich detail per host)
const SETTINGS_KEY = "settings";
const MAX_ENTRIES = 200;

const DEFAULT_SETTINGS = {
  detectionEnabled: true,
  dohProvider: "cloudflare",
  autoRoute: true,     // auto-route blocked domains through a proxy when guidance can't fix them
  autoReload: true     // reload the failed tab once a routing fix is applied
};

// ---- helpers ---------------------------------------------------------------

async function getSettings() {
  const { [SETTINGS_KEY]: s } = await chrome.storage.local.get(SETTINGS_KEY);
  return { ...DEFAULT_SETTINGS, ...(s || {}) };
}

function hostFromUrl(url) {
  try { return new URL(url).hostname; } catch { return null; }
}

// Serialize writes to the diagnostic log.
let writeChain = Promise.resolve();
function mutate(fn) {
  const next = writeChain.then(fn).catch((e) => console.warn("OpenRoute mutate:", e));
  writeChain = next.catch(() => {});
  return next;
}

// Short DoH cache so a page that retries in a burst reuses one diagnosis
// instead of a lookup storm — but every error still reaches the ladder, so
// escalation is never skipped.
const diagCache = new Map();
const DIAG_TTL_MS = 30 * 1000;
async function diagnoseCached(host, provider) {
  const hit = diagCache.get(host);
  if (hit && Date.now() - hit.at < DIAG_TTL_MS) return hit.diag;
  const diag = await diagnose(host, { preferred: provider });
  diagCache.set(host, { diag, at: Date.now() });
  if (diagCache.size > 256) diagCache.clear();
  return diag;
}

// ---- classification (diagnostic labels) ------------------------------------

function classify(error, diag) {
  const e = error || "";
  const resolved = diag.ok;
  if (/ERR_NAME_NOT_RESOLVED|ERR_NAME_RESOLUTION_FAILED|ERR_DNS/.test(e)) {
    if (diag.injected) return "doh-tampered";
    if (resolved) return "dns-tampering";
    return "dns-nxdomain";
  }
  if (/ERR_CONNECTION_RESET|ERR_SSL|ERR_SSL_PROTOCOL_ERROR|ERR_SSL_VERSION_OR_CIPHER_MISMATCH|ERR_CONNECTION_CLOSED|ERR_QUIC_PROTOCOL_ERROR/.test(e)) {
    return "sni-dpi";
  }
  if (/ERR_CONNECTION_TIMED_OUT|ERR_ADDRESS_UNREACHABLE|ERR_CONNECTION_REFUSED|ERR_NETWORK_ACCESS_DENIED|ERR_TIMED_OUT|ERR_CONNECTION_FAILED/.test(e)) {
    return resolved ? "ip-block" : "unreachable";
  }
  if (/ERR_BLOCKED_BY_ADMINISTRATOR|ERR_BLOCKED_BY_CLIENT|ERR_BLOCKED_BY_RESPONSE/.test(e)) {
    return "policy-block";
  }
  return "unknown";
}

const REMEDIATION = {
  "dns-tampering": "ISP is faking DNS. Secure DNS fixes this at full speed; if not, OpenRoute routes it.",
  "dns-nxdomain":  "DNS says this domain doesn't exist — could be genuine, or deeper DNS blocking.",
  "doh-tampered":  "Even encrypted DNS returned a fake/private IP. OpenRoute will route around it.",
  "sni-dpi":       "TLS handshake reset — SNI/DPI filtering. ECH or a proxy defeats it.",
  "ip-block":      "ISP is dropping the server's IP. Needs a proxy/tunnel — OpenRoute routes it.",
  "unreachable":   "Server unreachable — may be down, or blocked at the IP level.",
  "policy-block":  "Blocked by a device/browser policy — not your ISP.",
  "unknown":       "Couldn't classify. OpenRoute will try routing it."
};

async function updateBadge() {
  const { [STORAGE_KEY]: sites = {} } = await chrome.storage.local.get(STORAGE_KEY);
  const n = Object.keys(sites).length;
  await chrome.action.setBadgeText({ text: n ? String(n) : "" });
}

function prune(map) {
  const entries = Object.values(map);
  if (entries.length <= MAX_ENTRIES) return map;
  entries.sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0));
  const kept = {};
  for (const it of entries.slice(0, MAX_ENTRIES)) kept[it.host] = it;
  return kept;
}

// ---- lifecycle -------------------------------------------------------------

async function ensureInit() {
  chrome.action.setBadgeBackgroundColor({ color: "#c0392b" });
  await chrome.storage.local.set({ [SETTINGS_KEY]: await getSettings() });
  await router.apply();   // restore the split-tunnel PAC from stored policy
  await updateBadge();
}

health.init();
router.onProxyError((err) => console.warn("OpenRoute proxy error:", err?.error || err));

chrome.runtime.onInstalled.addListener(() => { ensureInit(); });
chrome.runtime.onStartup.addListener(() => { ensureInit(); });
ensureInit(); // also run on cold service-worker start

// ---- detection + routing ---------------------------------------------------

chrome.webNavigation.onErrorOccurred.addListener(async (details) => {
  try {
    if (details.frameId !== 0) return;
    if (!/^https?:/.test(details.url)) return;
    if (/ERR_ABORTED/.test(details.error || "")) return;

    const settings = await getSettings();
    if (!settings.detectionEnabled) return;

    const host = hostFromUrl(details.url);
    if (!host) return;
    if (/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|\[)/.test(host)) return;

    const diag = await diagnoseCached(host, settings.dohProvider);
    const type = classify(details.error, diag);

    // 1) Log the rich diagnosis for the UI.
    await mutate(async () => {
      const { [STORAGE_KEY]: existing = {} } = await chrome.storage.local.get(STORAGE_KEY);
      const prev = existing[host];
      existing[host] = {
        host, url: details.url, error: details.error, type,
        remediation: REMEDIATION[type] || REMEDIATION.unknown,
        resolvedIPs: diag.addresses, dohProvider: diag.resolver || settings.dohProvider,
        hasHTTPS: diag.hasHTTPS, echLikely: diag.echLikely, injected: diag.injected,
        firstSeen: prev?.firstSeen || Date.now(), lastSeen: Date.now(),
        count: (prev?.count || 0) + 1
      };
      await chrome.storage.local.set({ [STORAGE_KEY]: prune(existing) });
    });
    await updateBadge();

    // 2) Drive the failover ladder (may route + auto-reload the tab).
    await ladder.onBlocked(host, details.error, diag, type, details.tabId);
  } catch (err) {
    console.warn("OpenRoute detection error:", err);
  }
});

// Verifier: a completed top-level navigation confirms whatever rung carried it.
chrome.webNavigation.onCompleted.addListener(async (details) => {
  try {
    if (details.frameId !== 0) return;
    const host = hostFromUrl(details.url);
    if (host) await ladder.onVerified(host);
  } catch (err) {
    console.warn("OpenRoute verify error:", err);
  }
});

// ---- popup messaging -------------------------------------------------------

const HANDLERS = {
  async getState() {
    const [pol, tlist, settings, activeId, companion] = await Promise.all([
      policy.getAll(),
      transports.list(),
      getSettings(),
      transports.getActiveId(),
      nm.isAvailable().then((available) => ({ available })).catch(() => ({ available: false }))
    ]);
    const { [STORAGE_KEY]: sites = {} } = await chrome.storage.local.get(STORAGE_KEY);
    return { policy: pol, transports: tlist, settings, activeTransportId: activeId, companion, sites };
  },
  async recheck({ host }) {
    const settings = await getSettings();
    const diag = await diagnose(host, { preferred: settings.dohProvider });
    diagCache.set(host, { diag, at: Date.now() });
    await mutate(async () => {
      const { [STORAGE_KEY]: existing = {} } = await chrome.storage.local.get(STORAGE_KEY);
      if (existing[host]) {
        existing[host] = { ...existing[host], resolvedIPs: diag.addresses,
          dohProvider: diag.resolver || settings.dohProvider, hasHTTPS: diag.hasHTTPS,
          echLikely: diag.echLikely, injected: diag.injected, lastChecked: Date.now() };
        await chrome.storage.local.set({ [STORAGE_KEY]: existing });
      }
    });
    return { diag };
  },
  async setRung({ domain, rung, proxyId }) { return { policy: await ladder.setRung(domain, rung, proxyId) }; },
  async clearDomain({ domain }) { await ladder.clearDomain(domain); return { ok: true }; },
  async clearAllPolicy() {
    const all = await policy.getAll();
    for (const d of Object.keys(all)) await policy.remove(d);
    await router.apply();
    return { ok: true };
  },
  async saveSettings({ patch }) {
    const s = { ...(await getSettings()), ...patch };
    await chrome.storage.local.set({ [SETTINGS_KEY]: s });
    return { settings: s };
  },
  async addTransport({ transport }) { return { transports: await transports.upsert(transport) }; },
  async removeTransport({ id }) { await transports.remove(id); await router.apply(); return { transports: await transports.list() }; },
  async setActiveTransport({ id }) { await transports.setActiveId(id); return { ok: true }; }
};

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  const handler = HANDLERS[msg?.type];
  if (!handler) return false;
  Promise.resolve(handler(msg))
    .then((res) => sendResponse({ ok: true, ...res }))
    .catch((err) => sendResponse({ ok: false, error: String(err) }));
  return true; // async response
});
