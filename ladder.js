// Ladder engine — the failover brain.
//
// Given a detected block + DoH diagnosis it decides which rung should carry a
// domain, applies split-tunnel routing when a rung needs it, and climbs the
// ladder automatically when a rung fails to actually fix the site. A verifier
// (onVerified) closes the loop: a rung is only "fixed" once a real navigation
// through it succeeds.

import * as policy from "./policy.js";
import * as transports from "./transports.js";
import * as router from "./router.js";

const MAX_ATTEMPTS = 6;          // hard stop so we can never loop forever
const REROUTE_SETTLE_MS = 350;   // let Chrome apply the PAC before we reload

// Which starting rung a fresh diagnosis maps to. Guidance rungs (doh/ech) come
// first when they're the correct, full-speed fix; the rest go straight to a
// proxy because guidance alone can't fix them.
function startRungFor(type, diag) {
  switch (type) {
    case "dns-tampering": return "doh";
    case "sni-dpi":       return diag?.echLikely ? "ech" : "proxy";
    case "doh-tampered":
    case "ip-block":
    case "unknown":       return "proxy";
    case "unreachable":   return "proxy";   // best-effort; may still be down
    case "dns-nxdomain":
    case "policy-block":  return "fallback"; // routing can't help these
    default:              return "proxy";
  }
}

const NEEDS_USER_MSG = {
  doh: "Turn on Secure DNS to fix this at full speed. If it's still blocked after that, OpenRoute will route it automatically.",
  ech: "Turn on Secure DNS (it enables Encrypted ClientHello). If the block survives that, OpenRoute will route it automatically.",
  fallback: "This one can't be fixed by routing. Open it read-only via Wayback/Reader, or check it's actually up."
};

// Central settings read (kept tiny; detailed defaults live in background.js).
async function autoRouteOn() {
  const { settings } = await chrome.storage.local.get("settings");
  return settings?.autoRoute !== false; // default on
}

/**
 * A top-level navigation to `domain` failed. Drive the ladder.
 * @param {string} domain
 * @param {string} error   chrome error string (ERR_…)
 * @param {object} diag    result from doh.diagnose()
 * @param {string} type    classifier verdict
 * @param {number} [tabId] tab to auto-reload once a routing fix is applied
 */
export async function onBlocked(domain, error, diag, type, tabId) {
  const cur = await policy.get(domain);

  // A domain that was "fixed" and just broke again → its rung stopped working.
  if (cur && cur.status === "fixed") {
    return escalate(domain, error, tabId, "regressed");
  }

  // Respect a manual pin: apply it, record the failure, but don't climb past it.
  if (cur?.pinned) {
    await policy.update(domain, (p) => ({
      status: p.rung === "proxy" ? "routing" : "needs-user",
      lastError: error, failures: p.failures + 1
    }));
    if (cur.rung === "proxy") { await router.apply(); await maybeReload(tabId); }
    return policy.get(domain);
  }

  // Fresh (or still-direct) block → choose a starting rung from the diagnosis.
  if (!cur || cur.rung === "direct") {
    const start = startRungFor(type, diag);
    return applyRung(domain, start, error, tabId);
  }

  // Already on a rung and still failing → climb.
  return escalate(domain, error, tabId, "rung-failed");
}

// Put a domain on a specific rung and do whatever that rung requires.
async function applyRung(domain, rung, error, tabId) {
  // Guidance rungs: we can't enforce them, so record + prompt. If auto-route is
  // on we *also* pre-stage a proxy so a single retry escalates instantly.
  if (rung === "doh" || rung === "ech") {
    await policy.update(domain, () => ({
      rung, proxyId: null, status: "needs-user",
      lastError: error, attempts: 0
    }));
    return policy.get(domain);
  }

  if (rung === "proxy") {
    if (!(await autoRouteOn())) {
      await policy.update(domain, () => ({ rung: "proxy", status: "needs-user", lastError: error }));
      return policy.get(domain);
    }
    const t = await transports.pickBest();
    if (!t) {
      // Nothing to route through yet → tell the user, offer read-only.
      await policy.update(domain, () => ({
        rung: "fallback", proxyId: null, status: "needs-user", lastError: error
      }));
      return policy.get(domain);
    }
    await policy.update(domain, (p) => ({
      rung: "proxy", proxyId: t.id, status: "routing",
      lastError: error, attempts: p.attempts + 1
    }));
    await router.apply();
    await maybeReload(tabId);
    return policy.get(domain);
  }

  // fallback
  await policy.update(domain, () => ({
    rung: "fallback", proxyId: null, status: "exhausted", lastError: error
  }));
  return policy.get(domain);
}

// Climb to the next thing that might work.
async function escalate(domain, error, tabId, reason) {
  const cur = await policy.get(domain);
  if (!cur) return null;

  if (cur.attempts >= MAX_ATTEMPTS) {
    await policy.update(domain, () => ({ status: "exhausted", lastError: error }));
    return policy.get(domain);
  }

  // If we were on a proxy, that transport just failed us — score it down and
  // try the next-best transport before abandoning the proxy rung entirely.
  if (cur.rung === "proxy" && cur.proxyId) {
    await transports.recordOutcome(cur.proxyId, false);
    const tried = new Set(cur.triedProxies || [cur.proxyId]);
    tried.add(cur.proxyId);
    const next = await transports.pickBest([...tried]);
    if (next) {
      await policy.update(domain, (p) => ({
        proxyId: next.id, status: "routing", lastError: error,
        attempts: p.attempts + 1, triedProxies: [...tried]
      }));
      await router.apply();
      await maybeReload(tabId);
      return policy.get(domain);
    }
    // Out of transports → read-only.
    await policy.update(domain, () => ({ rung: "fallback", status: "exhausted", lastError: error }));
    await router.apply(); // drops this domain from the PAC
    return policy.get(domain);
  }

  // Already exhausted and still failing → stay exhausted, don't loop.
  if (cur.rung === "fallback") {
    await policy.update(domain, () => ({ status: "exhausted", lastError: error }));
    return policy.get(domain);
  }

  // From a guidance rung (doh/ech) or direct, guidance didn't stick → the only
  // thing left the extension can enforce is routing. Jump straight to proxy
  // (skipping the pointless doh→ech hop for e.g. DNS tampering).
  return applyRung(domain, "proxy", error, tabId);
}

/**
 * A top-level navigation to `domain` succeeded. If we were carrying it, the
 * current rung is verified working.
 */
export async function onVerified(domain) {
  const cur = await policy.get(domain);
  if (!cur) return;
  if (cur.status === "fixed") return;
  if (!["routing", "verifying", "needs-user", "blocked"].includes(cur.status)) return;

  if (cur.rung === "proxy" && cur.proxyId) {
    await transports.recordOutcome(cur.proxyId, true);
  }
  await policy.update(domain, (p) => ({
    status: "fixed", lastVerified: Date.now(), successes: p.successes + 1
  }));
}

// --- manual controls (popup) ------------------------------------------------

// User pins a domain to a rung/transport. We honor it and stop auto-climbing.
// rung === "auto" releases the pin and lets the ladder decide again.
export async function setRung(domain, rung, proxyId = null) {
  if (rung === "auto") {
    await policy.update(domain, () => ({
      pinned: false, rung: "direct", proxyId: null, status: "blocked",
      attempts: 0, triedProxies: []
    }));
  } else {
    await policy.update(domain, () => ({
      rung, proxyId, pinned: true,
      status: policy.RUNGS[rung]?.route ? "routing" : "needs-user"
    }));
  }
  await router.apply();
  return policy.get(domain);
}

export async function clearDomain(domain) {
  await policy.remove(domain);
  await router.apply();
}

async function maybeReload(tabId) {
  if (!tabId) return;
  const { settings } = await chrome.storage.local.get("settings");
  if (settings?.autoReload === false) return;
  // Give Chrome a beat to install the new PAC, then reload the failed tab so the
  // fix takes effect without the user clicking anything.
  setTimeout(() => {
    chrome.tabs.reload(tabId).catch(() => {});
  }, REROUTE_SETTLE_MS);
}
