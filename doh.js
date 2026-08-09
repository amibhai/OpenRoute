// DNS-over-HTTPS engine for OpenRoute.
//
// Design goals for Stage 1:
//   * Resilient  — several independent resolvers, each reachable by hostname
//                  *and* by IP literal, so one blocked or poisoned resolver
//                  never stalls a diagnosis.
//   * Fail-proof — every network call is time-boxed with AbortController and
//                  retried; a hung fetch can't wedge the service worker.
//   * Honest     — answers are validated (bogon / private-IP checks) so we can
//                  tell "the ISP is faking DNS" apart from "even DoH is being
//                  tampered with", instead of trusting whatever comes back.
//
// We speak the JSON DoH API (name/type query params, RFC 8427-style answers),
// which Cloudflare, Google and Quad9 all implement. The IP-literal endpoints
// (https://1.1.1.1/…) matter: when a censor poisons the *hostname* of a
// resolver, we can still reach it by IP because the certs served on those
// addresses carry IP SANs, so TLS keeps validating.

const DEFAULT_TIMEOUT_MS = 4000;
const DEFAULT_RETRIES = 1;

// Public so the popup can label things; keep in sync with popup.html options.
export const RESOLVERS = {
  cloudflare: {
    label: "Cloudflare",
    endpoints: [
      "https://cloudflare-dns.com/dns-query",
      "https://1.1.1.1/dns-query",
      "https://1.0.0.1/dns-query"
    ],
    headers: { accept: "application/dns-json" }
  },
  google: {
    label: "Google",
    endpoints: [
      "https://dns.google/resolve",
      "https://8.8.8.8/resolve",
      "https://8.8.4.4/resolve"
    ],
    headers: {}
  },
  quad9: {
    label: "Quad9",
    endpoints: [
      "https://dns.quad9.net/dns-query",
      "https://9.9.9.9/dns-query"
    ],
    headers: { accept: "application/dns-json" }
  }
};

const RR = { A: 1, AAAA: 28, CNAME: 5, HTTPS: 65 };

// ---- answer validation -----------------------------------------------------

// RFC1918 / loopback / link-local / CGNAT / reserved. A public site whose
// "authoritative" answer points into one of these ranges is almost certainly
// an injected/blockpage response rather than the real address.
function isBogonV4(ip) {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip);
  if (!m) return false;
  const a = +m[1], b = +m[2];
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true;           // link-local
  if (a === 172 && b >= 16 && b <= 31) return true;  // 172.16/12
  if (a === 192 && b === 168) return true;           // 192.168/16
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64/10
  if (a >= 224) return true;                         // multicast / reserved
  return false;
}

function isBogonV6(ip) {
  const s = ip.toLowerCase();
  return s === "::" || s === "::1" || s.startsWith("fe80") ||
         s.startsWith("fc") || s.startsWith("fd") || s.startsWith("::ffff:0");
}

function isBogon(ip) {
  return ip.includes(":") ? isBogonV6(ip) : isBogonV4(ip);
}

// Best-effort ECH hint. An HTTPS/SVCB record's presentation form exposes an
// "ech=" SvcParam; the unknown-RDATA form (\# len hex) exposes SvcParamKey 5
// as the bytes "0005". Either way this is advisory — we phrase the UI as
// "ECH may be available", never as a guarantee.
function looksLikeECH(rr) {
  const d = String(rr.data || "").toLowerCase();
  return d.includes("ech=") || /(?:^|[^0-9a-f])0005[0-9a-f]{2,}/.test(d.replace(/\s+/g, ""));
}

// ---- transport -------------------------------------------------------------

async function timedFetchJSON(url, headers, timeoutMs) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const resp = await fetch(url, { headers, cache: "no-store", signal: ctrl.signal });
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    return await resp.json();
  } finally {
    clearTimeout(timer);
  }
}

function parseAnswer(hostname, type, resolverKey, data) {
  const status = typeof data.Status === "number" ? data.Status : null;
  const answers = Array.isArray(data.Answer) ? data.Answer : [];

  const addresses = answers
    .filter((a) => a.type === RR.A || a.type === RR.AAAA)
    .map((a) => String(a.data).trim())
    .filter(Boolean);

  const httpsRecords = answers.filter((a) => a.type === RR.HTTPS);
  const bogons = addresses.filter(isBogon);

  return {
    hostname,
    type,
    resolver: resolverKey,
    status,                                              // 0 NOERROR, 3 NXDOMAIN
    addresses,
    hasHTTPS: httpsRecords.length > 0,
    echLikely: httpsRecords.some(looksLikeECH),
    // Every returned address is bogus → the answer itself is injected.
    injected: addresses.length > 0 && bogons.length === addresses.length,
    bogons,
    ok: status === 0 && addresses.length > 0
  };
}

// Walk one resolver's endpoints (hostname first, then IP literals) until one
// answers. Each endpoint gets its own timeout + retry budget.
async function queryResolver(resolverKey, hostname, type, opts) {
  const cfg = RESOLVERS[resolverKey];
  if (!cfg) throw new Error("unknown resolver " + resolverKey);

  const timeout = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const retries = opts.retries ?? DEFAULT_RETRIES;
  let lastErr;

  for (const base of cfg.endpoints) {
    const url = `${base}?name=${encodeURIComponent(hostname)}&type=${type}`;
    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        const data = await timedFetchJSON(url, cfg.headers, timeout);
        return parseAnswer(hostname, type, resolverKey, data);
      } catch (err) {
        lastErr = err;
      }
    }
  }
  throw lastErr || new Error("all endpoints failed for " + resolverKey);
}

// ---- orchestration ---------------------------------------------------------

// An answer we can act on: a normal NOERROR or an authoritative NXDOMAIN.
function authoritative(r) {
  return r && (r.status === 0 || r.status === 3);
}

async function okOrThrow(promise) {
  const r = await promise;
  if (authoritative(r)) return r;
  throw new Error("non-authoritative");
}

/**
 * Resolve a hostname resiliently.
 *  1. Ask the user's preferred resolver first (fast path, respects choice).
 *  2. If that can't give an authoritative answer, race every other resolver
 *     and take the first authoritative response.
 * Never rejects — always resolves to a result object.
 */
export async function resolveResilient(hostname, opts = {}) {
  const type = opts.type || "A";
  const preferred = RESOLVERS[opts.preferred] ? opts.preferred : "cloudflare";
  const order = [preferred, ...Object.keys(RESOLVERS).filter((k) => k !== preferred)];

  try {
    const r = await queryResolver(preferred, hostname, type, opts);
    if (authoritative(r)) return { ...r, triedResolvers: [preferred] };
  } catch { /* fall through to the race */ }

  const rest = order.slice(1);
  const attempts = rest.map((k) => queryResolver(k, hostname, type, opts));

  // Prefer the first authoritative answer…
  try {
    const r = await Promise.any(attempts.map(okOrThrow));
    return { ...r, triedResolvers: order };
  } catch { /* nobody was authoritative */ }

  // …otherwise surface whatever did come back (e.g. SERVFAIL), else fail clean.
  const settled = await Promise.allSettled(attempts);
  const any = settled.find((s) => s.status === "fulfilled");
  if (any) return { ...any.value, triedResolvers: order };

  return {
    hostname, type, ok: false, status: null, addresses: [], bogons: [],
    hasHTTPS: false, echLikely: false, injected: false,
    resolver: null, triedResolvers: order, error: "all resolvers failed"
  };
}

/**
 * Full diagnosis for a host: A/AAAA reachability plus an HTTPS/SVCB lookup for
 * ECH awareness, run in parallel. Always resolves.
 */
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
    resolver: a.resolver,
    triedResolvers: a.triedResolvers || [],
    hasHTTPS: !!(https && https.hasHTTPS),
    echLikely: !!(https && https.echLikely),
    error: a.error
  };
}

// Back-compat shim: the old single-shot API some callers may still use.
export async function resolveDoH(hostname, type = "A", provider = "cloudflare") {
  const r = await resolveResilient(hostname, { type, preferred: provider });
  return { ...r, provider: r.resolver || provider };
}
