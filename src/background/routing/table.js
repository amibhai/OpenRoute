// Routing table compilation + matching, shared by both engines.
//
// compileRoutes() turns persisted state into the table the engines execute:
//   routes        domain → transport chain (primary first; [] = explicit DIRECT)
//   probes        probe id → chain, used only by marked health-check requests
//   defaultRoute  chain for everything else (full-tunnel mode), or null
// matchRoute() is the reference matcher; the Chromium PAC carries an
// equivalent ES5 copy (tests assert they agree).

import { isRouted } from "../policy.js";
import { normalizeHost, isIpLiteral, isLocalHost } from "../../shared/hosts.js";
import { PROBE_PARAM } from "./pac.js";
import { rankTransports } from "../transports/registry.js";

export const CHAIN_LENGTH = 3; // primary + up to two automatic failovers

export function compileRoutes({
  policies = {}, transports = [], health = {}, mode = "smart", rules = {},
  dohVia = null, dohHosts = [], candidates = [], activeId = null, chainLength = CHAIN_LENGTH,
  exclude = new Set()
} = {}) {
  const enabled = transports.filter((t) => t.enabled !== false);
  const byId = new Map(enabled.map((t) => [t.id, t]));
  const ranked = rankTransports(enabled.filter((t) => (health[t.id]?.state ?? "unknown") !== "down"), health, activeId);
  const chainFor = (primary) => [primary, ...ranked.filter((t) => t.id !== primary.id)].slice(0, chainLength);

  const probes = { direct: [] };
  for (const t of enabled) probes[`t-${t.id}`] = [t];
  for (const c of candidates) probes[`c-${c.port}-${c.scheme}`] = [{ id: `c-${c.port}`, scheme: c.scheme, host: "127.0.0.1", port: c.port }];

  if (mode === "off") return { routes: {}, probes, defaultRoute: null, mode };

  const routes = {};
  for (const p of Object.values(policies)) {
    if (!isRouted(p) || exclude.has(normalizeHost(p.domain))) continue;
    const t = byId.get(p.proxyId);
    if (!t) continue; // transport gone/disabled — the ladder re-homes; never route to a ghost
    // A pinned route is exactly the user's choice; automatic ones get failovers.
    routes[normalizeHost(p.domain)] = p.pinned ? [t] : chainFor(t);
  }

  // Encrypted DNS itself is blocked: reach the resolvers through a transport.
  const via = dohVia && byId.get(dohVia);
  if (via) for (const h of dohHosts) if (!routes[h]) routes[h] = chainFor(via);

  const best = ranked[0] || null;
  for (const d of rules.always || []) if (best) routes[normalizeHost(d)] = chainFor(best);
  for (const d of rules.never || []) routes[normalizeHost(d)] = []; // explicit DIRECT, beats everything

  const defaultRoute = mode === "full" && best ? chainFor(best) : null;
  return { routes, probes, defaultRoute, mode };
}

export function probeIdFromUrl(url) {
  const i = String(url).indexOf(PROBE_PARAM + "=");
  if (i === -1) return null;
  const rest = url.slice(i + PROBE_PARAM.length + 1);
  const amp = rest.indexOf("&");
  try { return decodeURIComponent(amp === -1 ? rest : rest.slice(0, amp)); } catch { return null; }
}

// → transport chain (array; [] = DIRECT) for a URL, or null for "not ours".
export function matchRoute(compiled, url, host) {
  const h = normalizeHost(host ?? safeHost(url));
  const probe = probeIdFromUrl(url);
  if (probe && compiled.probes && Object.prototype.hasOwnProperty.call(compiled.probes, probe)) {
    return compiled.probes[probe];
  }
  if (!h || isLocalHost(h)) return null;
  const routes = compiled.routes || {};
  if (isIpLiteral(h)) return Object.prototype.hasOwnProperty.call(routes, h) ? routes[h] : compiled.defaultRoute || null;
  let d = h;
  for (;;) {
    if (Object.prototype.hasOwnProperty.call(routes, d)) return routes[d];
    const dot = d.indexOf(".");
    if (dot === -1) return compiled.defaultRoute || null;
    d = d.slice(dot + 1);
  }
}

function safeHost(url) {
  try { return new URL(url).hostname; } catch { return ""; }
}

// Firefox proxy.onRequest descriptor for one transport.
export function firefoxDescriptor(t) {
  const type = t.scheme === "http" ? "http"
    : t.scheme === "https" ? "https"
      : t.scheme === "socks4" ? "socks4"
        : "socks";
  const d = { type, host: String(t.host), port: Number(t.port) };
  if (type === "socks") d.proxyDNS = true;           // resolve names at the proxy, not locally
  if (t.auth?.username) {
    if (type === "socks") { d.username = t.auth.username; d.password = t.auth.password || ""; }
    else d.proxyAuthorizationHeader = "Basic " + btoa(`${t.auth.username}:${t.auth.password || ""}`);
  }
  return d;
}

export function signature(compiled) {
  const flat = (chain) => (chain || []).map((t) => `${t.scheme}://${t.host}:${t.port}`).join(",");
  const routes = Object.entries(compiled.routes || {}).sort().map(([d, c]) => `${d}=${flat(c)}`);
  const probes = Object.entries(compiled.probes || {}).sort().map(([d, c]) => `${d}=${flat(c)}`);
  return JSON.stringify([routes, probes, flat(compiled.defaultRoute)]);
}

// Does this table route anything for real (beyond probe routes)?
export function hasRealRoutes(compiled) {
  return Object.keys(compiled.routes || {}).length > 0 || !!compiled.defaultRoute?.length;
}
