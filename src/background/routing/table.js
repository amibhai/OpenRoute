// Routing table compilation + matching, shared by both engines.
//
// compileRoutes() turns persisted policy + transports into the table the
// engines execute. matchRoute() is the reference matcher; the Chromium PAC
// carries an equivalent ES5 copy (tests assert they agree).

import { isRouted } from "../policy.js";
import { normalizeHost, isIpLiteral, isLocalHost } from "../../shared/hosts.js";
import { PROBE_PARAM } from "./pac.js";

export function compileRoutes({ policies = {}, transports = [], probes = {}, defaultRoute = null }) {
  const byId = new Map(transports.filter((t) => t.enabled !== false).map((t) => [t.id, t]));
  const routes = {};
  for (const p of Object.values(policies)) {
    if (!isRouted(p)) continue;
    const t = byId.get(p.proxyId);
    if (!t) continue; // transport gone/disabled — ladder re-homes; never route to a ghost
    routes[normalizeHost(p.domain)] = [t];
  }
  return { routes, probes, defaultRoute };
}

export function probeIdFromUrl(url) {
  const i = String(url).indexOf(PROBE_PARAM + "=");
  if (i === -1) return null;
  const rest = url.slice(i + PROBE_PARAM.length + 1);
  const amp = rest.indexOf("&");
  return decodeURIComponent(amp === -1 ? rest : rest.slice(0, amp));
}

// → transport chain (array) for a URL, or null for DIRECT.
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
