// Per-domain routing policy — the memory behind the failover ladder. Pure
// model helpers; persistence happens through store.tx in ladder.js.

export const RUNGS = Object.freeze({
  direct:   { order: 0, label: "Direct",           route: false, guidance: false },
  doh:      { order: 1, label: "Secure DNS",       route: false, guidance: true },
  ech:      { order: 2, label: "Secure DNS + ECH", route: false, guidance: true },
  proxy:    { order: 3, label: "Proxy",            route: true,  guidance: false },
  fallback: { order: 9, label: "Read-only",        route: false, guidance: false }
});

export const STATUS = Object.freeze({
  BLOCKED: "blocked",        // seen failing, not acted on yet
  ROUTING: "routing",        // routed through a transport, awaiting a successful load
  FIXED: "fixed",            // a real navigation succeeded on the current rung
  NEEDS_USER: "needs-user",  // only the user can fix it (Secure DNS, add a transport…)
  EXHAUSTED: "exhausted",    // every transport failed; retried on a backoff schedule
  MANUAL: "manual"           // user pinned a non-routing rung
});

// Retry schedule after exhaustion: 10 min → 30 min → 2 h → 6 h → daily.
export const BACKOFF_MS = Object.freeze([10 * 60e3, 30 * 60e3, 2 * 3600e3, 6 * 3600e3, 24 * 3600e3]);
export const MAX_ATTEMPTS = 6;     // escalations per episode before backing off
export const MAX_POLICIES = 500;
export const MAX_SITES = 300;

export function backoffFor(retryCount) {
  return BACKOFF_MS[Math.min(Math.max(retryCount | 0, 0), BACKOFF_MS.length - 1)];
}

export function blankPolicy(domain, now = Date.now()) {
  return {
    domain,
    rung: "direct",
    proxyId: null,
    status: STATUS.BLOCKED,
    pinned: false,
    lastError: null,
    lastType: null,
    attempts: 0,
    triedProxies: [],
    successes: 0,
    failures: 0,
    retryCount: 0,
    retryAt: null,
    exhaustedReason: null,
    firstSeen: now,
    updatedAt: now,
    lastVerified: null
  };
}

// Is this domain currently detouring through a transport?
export function isRouted(p) {
  return !!p && !!RUNGS[p.rung]?.route && !!p.proxyId && p.status !== STATUS.EXHAUSTED;
}

// Keep pinned + most recently touched when over the cap.
export function prunePolicies(map, max = MAX_POLICIES) {
  const entries = Object.values(map);
  if (entries.length <= max) return map;
  entries.sort((a, b) => (Number(b.pinned) - Number(a.pinned)) || ((b.updatedAt || 0) - (a.updatedAt || 0)));
  return Object.fromEntries(entries.slice(0, max).map((p) => [p.domain, p]));
}

export function pruneSites(map, max = MAX_SITES) {
  const entries = Object.values(map);
  if (entries.length <= max) return map;
  entries.sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0));
  return Object.fromEntries(entries.slice(0, max).map((s) => [s.host, s]));
}
