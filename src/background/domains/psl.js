// Registrable-domain ("eTLD+1") computation from the Public Suffix List.
//
// When "www.example.co.uk" is blocked, the thing to route is "example.co.uk"
// (and with it cdn./static./api. siblings) — but never "co.uk", and never
// "github.io" for one user's page. The PSL encodes exactly those boundaries.

import PSL_DATA from "./psl-data.js";
import { normalizeHost, isIpLiteral } from "../../shared/hosts.js";

let rules = null;

function load() {
  if (rules) return rules;
  const exact = new Set();
  const wildcard = new Set(); // "*.ck" stored as "ck"
  const exception = new Set(); // "!www.ck" stored as "www.ck"
  for (const r of PSL_DATA.split("\n")) {
    if (!r) continue;
    if (r[0] === "!") exception.add(r.slice(1));
    else if (r.startsWith("*.")) wildcard.add(r.slice(2));
    else exact.add(r);
  }
  rules = { exact, wildcard, exception };
  return rules;
}

/** The public suffix of a hostname (longest matching rule; implicit "*"). */
export function publicSuffix(host) {
  const h = normalizeHost(host);
  if (!h || h.startsWith(".") || h.includes("..")) return null;
  const { exact, wildcard, exception } = load();
  const labels = h.split(".");
  for (let i = 0; i < labels.length; i++) {
    const candidate = labels.slice(i).join(".");
    if (exception.has(candidate)) return labels.slice(i + 1).join(".");
    if (exact.has(candidate)) return candidate;
    if (i + 1 < labels.length && wildcard.has(labels.slice(i + 1).join("."))) return candidate;
  }
  return labels[labels.length - 1];
}

/** eTLD+1, or null when the host is itself a public suffix. IPs map to themselves. */
export function registrableDomain(host) {
  const h = normalizeHost(host);
  if (!h) return null;
  if (isIpLiteral(h)) return h;
  const suffix = publicSuffix(h);
  if (!suffix || suffix === h) return null;
  const rest = h.slice(0, h.length - suffix.length - 1);
  return `${rest.slice(rest.lastIndexOf(".") + 1)}.${suffix}`;
}
