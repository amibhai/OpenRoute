// DNS-over-HTTPS engine.
//
//   * Resilient  — several independent resolvers, each reachable by hostname
//                  *and* by IP literal, so one blocked or poisoned resolver
//                  never stalls a diagnosis.
//   * Bounded    — every request has an AbortController timeout; a hung fetch
//                  can't wedge the worker.
//   * Honest     — answers are validated against bogon ranges, so "the ISP is
//                  faking DNS" is told apart from "even DoH is being tampered
//                  with", and "no resolver reachable" is never mistaken for
//                  NXDOMAIN.
//
// Speaks the JSON DoH API (?name=&type=) with numeric RR types. The IP-literal
// endpoints matter: when a censor poisons a resolver's *hostname*, it's still
// reachable by IP because those certificates carry IP SANs.

import { isBogon } from "./bogons.js";

const DEFAULT_TIMEOUT_MS = 3500;
const DEFAULT_RETRIES = 1;

export const RESOLVERS = {
  cloudflare: {
    label: "Cloudflare",
    endpoints: ["https://cloudflare-dns.com/dns-query", "https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query"],
    headers: { accept: "application/dns-json" }
  },
  google: {
    label: "Google",
    endpoints: ["https://dns.google/resolve", "https://8.8.8.8/resolve", "https://8.8.4.4/resolve"],
    headers: { accept: "application/dns-json" }
  },
  quad9: {
    label: "Quad9",
    endpoints: ["https://dns.quad9.net/dns-query", "https://9.9.9.9/dns-query"],
    headers: { accept: "application/dns-json" }
  }
};

export const RR = { A: 1, CNAME: 5, AAAA: 28, HTTPS: 65 };

// Best-effort ECH hint from an HTTPS/SVCB answer's presentation form
// ("ech=") or unknown-RDATA hex (SvcParamKey 5 = "0005"). Advisory only.
function looksLikeECH(rr) {
  const d = String(rr.data || "").toLowerCase();
  return d.includes("ech=") || /(?:^|[^0-9a-f])0005[0-9a-f]{2,}/.test(d.replace(/\s+/g, ""));
}

async function timedFetchJSON(fetchImpl, url, headers, timeoutMs) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const resp = await fetchImpl(url, { headers, cache: "no-store", credentials: "omit", signal: ctrl.signal });
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    return await resp.json();
  } finally {
    clearTimeout(timer);
  }
}

function parseAnswer(hostname, type, resolverKey, data) {
  const status = typeof data?.Status === "number" ? data.Status : null;
  const answers = Array.isArray(data?.Answer) ? data.Answer : [];
  const addresses = answers
    .filter((a) => a.type === RR.A || a.type === RR.AAAA)
    .map((a) => String(a.data).trim())
    .filter(Boolean);
  const httpsRecords = answers.filter((a) => a.type === RR.HTTPS);
  const bogons = addresses.filter(isBogon);
  return {
    hostname, type, resolver: resolverKey, status, addresses,
    hasHTTPS: httpsRecords.length > 0,
    echLikely: httpsRecords.some(looksLikeECH),
    injected: addresses.length > 0 && bogons.length === addresses.length,
    bogons,
    ok: status === 0 && addresses.length > 0 && bogons.length < addresses.length
  };
}

async function queryResolver(fetchImpl, resolverKey, hostname, type, opts) {
  const cfg = RESOLVERS[resolverKey];
  if (!cfg) throw new Error("unknown resolver " + resolverKey);
  const timeout = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const retries = opts.retries ?? DEFAULT_RETRIES;
  let lastErr;
  for (const base of cfg.endpoints) {
    const url = `${base}?name=${encodeURIComponent(hostname)}&type=${RR[type] ?? type}`;
    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        return parseAnswer(hostname, type, resolverKey, await timedFetchJSON(fetchImpl, url, cfg.headers, timeout));
      } catch (err) {
        lastErr = err;
      }
    }
  }
  throw lastErr || new Error("all endpoints failed for " + resolverKey);
}

// A NOERROR or NXDOMAIN answer is one we can act on.
const authoritative = (r) => r && (r.status === 0 || r.status === 3);

/**
 * Resolve resiliently: the preferred resolver first, then race the rest and
 * take the first authoritative answer. Never rejects.
 */
export async function resolveResilient(hostname, opts = {}) {
  const fetchImpl = opts.fetch || globalThis.fetch;
  const type = opts.type || "A";
  const preferred = RESOLVERS[opts.preferred] ? opts.preferred : "cloudflare";
  const order = [preferred, ...Object.keys(RESOLVERS).filter((k) => k !== preferred)];

  try {
    const r = await queryResolver(fetchImpl, preferred, hostname, type, opts);
    if (authoritative(r)) return { ...r, triedResolvers: [preferred] };
  } catch { /* fall through to the race */ }

  const attempts = order.slice(1).map((k) => queryResolver(fetchImpl, k, hostname, type, opts));
  try {
    const r = await Promise.any(attempts.map(async (p) => {
      const v = await p;
      if (authoritative(v)) return v;
      throw new Error("non-authoritative");
    }));
    return { ...r, triedResolvers: order };
  } catch { /* nobody was authoritative */ }

  const settled = await Promise.allSettled(attempts);
  const any = settled.find((s) => s.status === "fulfilled");
  if (any) return { ...any.value, triedResolvers: order };

  return {
    hostname, type, ok: false, status: null, addresses: [], bogons: [],
    hasHTTPS: false, echLikely: false, injected: false,
    resolver: null, triedResolvers: order, unreachable: true, error: "all resolvers failed"
  };
}

/** A/AAAA reachability plus an HTTPS/SVCB lookup for ECH awareness. Never rejects. */
export async function diagnose(hostname, opts = {}) {
  const [a, https] = await Promise.all([
    resolveResilient(hostname, { ...opts, type: "A" }),
    resolveResilient(hostname, { ...opts, type: "HTTPS" }).catch(() => null)
  ]);
  return {
    hostname,
    ok: a.ok,
    status: a.status,
    addresses: a.addresses,
    bogons: a.bogons || [],
    injected: !!a.injected,
    unreachable: !!a.unreachable,
    resolver: a.resolver,
    triedResolvers: a.triedResolvers || [],
    hasHTTPS: !!https?.hasHTTPS,
    echLikely: !!https?.echLikely,
    error: a.error,
    at: Date.now()
  };
}

// Diagnoses for a host are cached briefly so a page that retries in a burst
// reuses one lookup instead of starting a storm.
export function createDiagnoser({ getPreferred, ttlMs = 30_000, fetchImpl } = {}) {
  const cache = new Map();
  async function diagnoseCached(host, { fresh = false } = {}) {
    const hit = cache.get(host);
    if (!fresh && hit && Date.now() - hit.at < ttlMs) return hit.diag;
    const diag = await diagnose(host, { preferred: await getPreferred?.(), fetch: fetchImpl });
    cache.set(host, { diag, at: Date.now() });
    if (cache.size > 256) cache.delete(cache.keys().next().value);
    return diag;
  }
  diagnoseCached.invalidate = (host) => cache.delete(host);
  return diagnoseCached;
}
