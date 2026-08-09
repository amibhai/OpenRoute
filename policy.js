// Per-domain routing policy — the memory behind the failover ladder.
//
// For each domain we've had to unblock we remember which rung is currently
// carrying it, whether that rung has actually been *verified* to work, and a
// little history so the ladder can escalate/de-escalate intelligently and the
// popup can show what's going on.

const POLICY_KEY = "domainPolicy";
const MAX_POLICIES = 500;

// The ladder, cheapest/fastest first. `route` marks the rungs that actually
// change proxy routing (vs. rungs that are guidance the browser applies itself,
// like turning on Secure DNS).
export const RUNGS = {
  direct:   { order: 0, label: "Direct",        route: false },
  doh:      { order: 1, label: "Secure DNS",    route: false },
  ech:      { order: 2, label: "Secure DNS + ECH", route: false },
  proxy:    { order: 3, label: "Proxy",         route: true  },
  fallback: { order: 7, label: "Read-only",     route: false }
};

// Order in which the ladder climbs when a rung fails to fix a domain.
export const LADDER_ORDER = ["direct", "doh", "ech", "proxy", "fallback"];

export function nextRung(rung) {
  const i = LADDER_ORDER.indexOf(rung);
  if (i < 0) return "doh";
  return LADDER_ORDER[Math.min(i + 1, LADDER_ORDER.length - 1)];
}

function blank(domain) {
  return {
    domain,
    rung: "direct",
    proxyId: null,        // which transport is carrying it, when rung === "proxy"
    status: "blocked",    // blocked | routing | verifying | fixed | needs-user | exhausted
    lastError: null,
    attempts: 0,          // how many times we've escalated this domain
    successes: 0,
    failures: 0,
    firstSeen: Date.now(),
    updatedAt: Date.now(),
    lastVerified: null,
    pinned: false         // user manually chose a rung → don't auto-escalate past it
  };
}

export async function getAll() {
  const { [POLICY_KEY]: p } = await chrome.storage.local.get(POLICY_KEY);
  return p || {};
}

export async function get(domain) {
  const all = await getAll();
  return all[domain] || null;
}

// Serialized read-modify-write so overlapping navigations can't clobber policy.
let chain = Promise.resolve();
export function update(domain, mutator) {
  const step = chain.then(async () => {
    const all = await getAll();
    const cur = all[domain] || blank(domain);
    const next = { ...cur, ...mutator(cur), domain, updatedAt: Date.now() };
    all[domain] = next;
    await chrome.storage.local.set({ [POLICY_KEY]: prune(all) });
    return next;
  });
  chain = step.catch(() => {});
  return step;
}

export async function remove(domain) {
  await chain;
  const all = await getAll();
  delete all[domain];
  await chrome.storage.local.set({ [POLICY_KEY]: all });
}

// Every domain currently on a routing rung, with the transport carrying it.
// The router turns this into a PAC script.
export async function routedDomains() {
  const all = await getAll();
  const out = [];
  for (const p of Object.values(all)) {
    if (RUNGS[p.rung]?.route && p.proxyId && p.status !== "exhausted") {
      out.push({ domain: p.domain, proxyId: p.proxyId });
    }
  }
  return out;
}

function prune(all) {
  const entries = Object.values(all);
  if (entries.length <= MAX_POLICIES) return all;
  // Keep pinned + most-recently-touched.
  entries.sort((a, b) => (b.pinned - a.pinned) || (b.updatedAt - a.updatedAt));
  const kept = {};
  for (const p of entries.slice(0, MAX_POLICIES)) kept[p.domain] = p;
  return kept;
}
