// Deep detection from request metadata (webRequest, observe-only): catches
// blocks that never surface as a navigation error.
//
//   * Block page via DNS injection — the page "loaded", but the browser
//     connected to a private/bogon address for a public hostname (how many
//     ISPs serve their block pages). Confirmed against encrypted DNS.
//   * HTTP 451 — "Unavailable For Legal Reasons".
//   * Subresource blocks — a site we are routing still fails to load some of
//     its own hosts (CDN, API); those get routed along with it.
//
// Guards against false positives: the extension's own requests (tabId -1) are
// ignored; loopback addresses are ignored (local proxies, Pi-hole sinkholes);
// an address that serves most page loads is a proxy, not an injected answer;
// on Firefox requests that went through a proxy carry proxyInfo and are
// skipped; subresources are only acted on for sites already being routed.
//
// Chromium delivers these events only for hosts the extension has permission
// for (optional "<all_urls>": the "deep detection" opt-in); Firefox already has
// site access for routing.

import { normalizeError, isCandidate } from "../errors.js";
import { isBogon } from "../dns/bogons.js";
import { isRouted } from "../policy.js";
import { TYPES } from "../diagnosis.js";
import { hostFromUrl, isLocalHost, normalizeHost } from "../../shared/hosts.js";

const RECENT = 24;                 // main-frame responses remembered for the proxy guard
const PROXY_SHARE = 0.5;           // an IP serving ≥ half of recent pages is a proxy
const SUBRESOURCE_BUDGET = 10;     // new subresource routes per tab per minute
const ROUTABLE_SUBRESOURCE = new Set([TYPES.DNS_TAMPERING, TYPES.DNS_POISONED, TYPES.DNS_UNVERIFIED, TYPES.SNI_DPI, TYPES.TLS_MITM, TYPES.IP_BLOCK]);

const isLoopback = (ip) => /^127\./.test(ip) || ip === "::1" || /^::ffff:127\./i.test(ip);

export function createRequestWatcher(ctx, { onBlockpage, onSubresourceBlock }) {
  const { api } = ctx;
  const recent = [];                // [{ host, ip }]
  const budgets = new Map();        // tabId → [timestamps]

  // A proxy serves (nearly) every page from one address; an injected block
  // page address serves only the blocked sites while other pages show public
  // addresses. Without that contrast yet, don't accuse DNS.
  function proxyLike(ip) {
    if (recent.length < 2) return true;
    const same = recent.filter((r) => r.ip === ip);
    const share = same.length / recent.length;
    return share > PROXY_SHARE || new Set(same.map((r) => r.host)).size > 8;
  }

  async function enabled() {
    return (await ctx.settings.get()).deepDetection !== false && (await ctx.settings.get()).detectionEnabled !== false;
  }

  async function onResponseStarted(details) {
    if (details.type !== "main_frame" || details.tabId < 0 || details.frameId !== 0) return;
    const host = hostFromUrl(details.url);
    if (!host || isLocalHost(host) || !/^https?:/.test(details.url)) return;
    const ip = normalizeHost(details.ip || "");
    if (ip) {
      recent.push({ host, ip });
      if (recent.length > RECENT) recent.shift();
    }
    if (!(await enabled())) return;
    if (details.proxyInfo) return; // Firefox: it went through a proxy
    const pol = await ctx.ladder.policyFor(host);
    if (isRouted(pol)) return;

    if (details.statusCode === 451) {
      await onBlockpage(host, { reason: "http-451", tabId: details.tabId, url: details.url, ip });
      return;
    }
    if (ip && isBogon(ip) && !isLoopback(ip) && !proxyLike(ip)) {
      await onBlockpage(host, { reason: "bogon-ip", tabId: details.tabId, url: details.url, ip });
    }
  }

  function takeBudget(tabId) {
    const now = Date.now();
    const list = (budgets.get(tabId) || []).filter((t) => now - t < 60_000);
    if (list.length >= SUBRESOURCE_BUDGET) { budgets.set(tabId, list); return false; }
    list.push(now);
    budgets.set(tabId, list);
    return true;
  }

  async function onErrorOccurred(details) {
    if (details.type === "main_frame" || details.tabId < 0) return; // navigations: webNavigation handles them
    const err = normalizeError(details.error);
    if (!isCandidate(err.kind)) return;
    const host = hostFromUrl(details.url);
    if (!host || isLocalHost(host)) return;
    if (!(await enabled())) return;
    if (isRouted(await ctx.ladder.policyFor(host))) return; // its own route failing is handled on navigation
    // Only for the sites we're already routing: their missing pieces.
    const frame = await api.webNavigation.getFrame({ tabId: details.tabId, frameId: 0 }).catch(() => null);
    const topHost = hostFromUrl(frame?.url || details.initiator || details.originUrl || "");
    const parent = topHost ? await ctx.ladder.policyFor(topHost) : null;
    if (!isRouted(parent)) return;
    if (!takeBudget(details.tabId)) return;
    await onSubresourceBlock(host, { err, parent, tabId: details.tabId, url: details.url, routable: ROUTABLE_SUBRESOURCE });
  }

  return {
    register() {
      const wr = api.webRequest;
      if (!wr) return;
      const filter = { urls: ["<all_urls>"] };
      wr.onResponseStarted?.addListener((d) => onResponseStarted(d).catch(() => {}), { ...filter, types: ["main_frame"] });
      wr.onErrorOccurred?.addListener((d) => onErrorOccurred(d).catch(() => {}), filter);
    },
    // exposed for tests
    _onResponseStarted: onResponseStarted,
    _onErrorOccurred: onErrorOccurred
  };
}
