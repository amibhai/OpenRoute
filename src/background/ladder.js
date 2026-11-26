// Ladder engine — the failover brain.
//
// Given a classified block it picks a rung, routes through a transport when
// the rung needs one, escalates to the next transport when a route fails,
// backs off (instead of giving up forever) when every transport has failed,
// and closes the loop on success. Every loop is bounded:
//   * per-episode escalations are capped (MAX_ATTEMPTS),
//   * auto-reloads only happen when routing actually changed, only while the
//     tab still shows the failed site, and only within a per-tab budget,
//   * exhausted domains are retried on a growing backoff schedule.

import { RUNGS, STATUS, MAX_ATTEMPTS, blankPolicy, isRouted, backoffFor, prunePolicies } from "./policy.js";
import { startRung } from "./diagnosis.js";
import { KIND } from "./errors.js";
import { HEALTH } from "./transports/health.js";
import { bundleFor } from "./domains/bundles.js";
import { lookupDomain, hostFromUrl } from "../shared/hosts.js";

const PROBE_FRESH_MS = 2 * 60 * 1000;   // a probe this recent is trusted without re-probing
const MAX_PREROUTE_PROBES = 3;
// Direct re-checks of routed sites: a day, three days, then weekly.
export const RECHECK_MS = Object.freeze([24 * 3600e3, 3 * 24 * 3600e3, 7 * 24 * 3600e3]);

const RELOAD_SETTLE_MS = 350;          // give the browser a beat to install the new route
const RELOAD_WINDOW_MS = 2 * 60 * 1000;
const RELOAD_BUDGET = 3;               // auto-reloads per tab+domain per window

export function createLadder(ctx) {
  const { api, store, session, transports, health, router, settings, log, caps } = ctx;
  const now = () => Date.now();

  async function allPolicies() {
    return store.get("policies", {});
  }

  async function update(domain, fn) {
    return store.tx(["policies"], (d) => {
      const all = d.policies || {};
      const cur = all[domain] || blankPolicy(domain, now());
      const patch = fn(cur) || {};
      const next = { ...cur, ...patch, domain, updatedAt: now() };
      all[domain] = next;
      d.policies = prunePolicies(all);
      return next;
    });
  }

  async function policyFor(host) {
    const all = await allPolicies();
    const d = lookupDomain(host, all);
    return d ? all[d] : null;
  }

  // ---- reload control -------------------------------------------------------

  async function takeReloadToken(tabId, domain) {
    const key = `${tabId}|${domain}`;
    return session.tx(["reloads"], (d) => {
      const all = d.reloads || {};
      const recent = (all[key] || []).filter((t) => now() - t < RELOAD_WINDOW_MS);
      if (recent.length >= RELOAD_BUDGET) { all[key] = recent; d.reloads = all; return false; }
      recent.push(now());
      all[key] = recent;
      for (const k of Object.keys(all)) if (!all[k].some((t) => now() - t < RELOAD_WINDOW_MS)) delete all[k];
      d.reloads = all;
      return true;
    });
  }

  function frameHost(url) {
    if (!url) return null;
    // Firefox error pages: about:neterror?e=…&u=<original url>
    if (url.startsWith("about:neterror")) {
      try { return hostFromUrl(new URLSearchParams(url.split("?")[1]).get("u") || ""); } catch { return null; }
    }
    return hostFromUrl(url);
  }

  async function maybeReload(tabId, domain) {
    if (tabId == null || tabId < 0) return;
    if (!(await settings.get()).autoReload) return;
    if (!(await takeReloadToken(tabId, domain))) {
      log.add("reload-skipped", { domain, reason: "budget" });
      return;
    }
    setTimeout(async () => {
      try {
        const frame = await api.webNavigation.getFrame({ tabId, frameId: 0 });
        const h = frameHost(frame?.url);
        // Only reload if the tab is still showing the site we just re-routed.
        if (!h || lookupDomain(h, { [domain]: true }) !== domain) return;
        await api.tabs.reload(tabId);
      } catch { /* tab closed */ }
    }, RELOAD_SETTLE_MS);
  }

  // ---- rung application -----------------------------------------------------

  async function exhaust(domain, reason, lastError) {
    const next = await update(domain, (p) => ({
      status: STATUS.EXHAUSTED,
      rung: "proxy",
      proxyId: null,
      retryCount: (p.retryCount || 0) + 1,
      retryAt: now() + backoffFor(p.retryCount || 0),
      exhaustedReason: reason,
      lastError: lastError ?? p.lastError
    }));
    await router.apply();
    log.add("exhausted", { domain, reason, retryAt: next.retryAt });
    return next;
  }

  // The best transport that is known to work: unmeasured / degraded ones get a
  // quick probe first, so a domain is never sent down a dead path (e.g. the
  // Tor Browser preset when Tor Browser isn't running).
  async function pickVerified(exclude) {
    const skip = [...exclude];
    for (let i = 0; i <= MAX_PREROUTE_PROBES; i++) {
      const t = await transports.pickBest(skip);
      if (!t) return null;
      const h = (await health.getAll())[t.id];
      if (h?.state === HEALTH.UP || !ctx.verifyTransport) return t;      // last outcome was good
      const justFailed = h?.lastProbe && now() - h.lastProbe < PROBE_FRESH_MS;
      if (justFailed) { skip.push(t.id); continue; }                     // known bad right now
      if (i === MAX_PREROUTE_PROBES) return t;
      const r = await ctx.verifyTransport(t.id, { timeout: 4000 });
      if (r.ok || r.error === "no-control") return t; // can't probe → don't punish, just use it
      skip.push(t.id);
    }
    return null;
  }

  async function routeVia(domain, info, exclude = []) {
    const lastError = info.err?.raw ?? null;
    if (!caps.canRoute) {
      return update(domain, () => ({ rung: "proxy", proxyId: null, status: STATUS.NEEDS_USER, exhaustedReason: "no-proxy-api", lastError }));
    }
    if (!(await settings.get()).autoRoute) {
      return update(domain, () => ({ rung: "proxy", proxyId: null, status: STATUS.NEEDS_USER, exhaustedReason: "auto-route-off", lastError }));
    }
    const before = (await allPolicies())[domain] || null;
    const t = await pickVerified(exclude);
    if (!t) return exhaust(domain, exclude.length ? "all-transports-failed" : "no-transport", lastError);

    const next = await update(domain, (p) => ({
      rung: "proxy",
      proxyId: t.id,
      status: STATUS.ROUTING,
      lastError,
      lastType: info.type ?? p.lastType,
      attempts: (p.attempts || 0) + 1,
      triedProxies: [...new Set([...exclude, t.id])],
      retryAt: null,
      exhaustedReason: null
    }));
    if (next.via !== "bundle") await routeBundle(domain, t.id);
    await router.apply();
    log.add("routed", { domain, via: t.id, attempt: next.attempts });
    const changed = !isRouted(before) || before.proxyId !== t.id;
    if (changed) await maybeReload(info.tabId, domain);
    return next;
  }

  // Route the rest of a site's bundle (its CDNs/API hosts) along with it, and
  // keep bundle members on the same transport as their parent.
  async function routeBundle(domain, transportId) {
    if ((await settings.get()).bundles === false) return [];
    const bundle = bundleFor(domain);
    if (!bundle) return [];
    return store.tx(["policies"], (d) => {
      const all = d.policies || {};
      const added = [];
      for (const m of bundle.members) {
        if (m === domain) continue;
        const cur = all[m];
        if (!cur) {
          all[m] = {
            ...blankPolicy(m, now()), rung: "proxy", proxyId: transportId, status: STATUS.ROUTING,
            via: "bundle", bundle: bundle.name, parent: domain, attempts: 1, triedProxies: [transportId]
          };
          added.push(m);
        } else if (cur.via === "bundle" && cur.parent === domain && !cur.pinned && cur.status !== STATUS.EXHAUSTED) {
          all[m] = { ...cur, proxyId: transportId, updatedAt: now() };
        }
      }
      d.policies = prunePolicies(all);
      if (added.length) log.add("bundle", { domain, bundle: bundle.name, added });
      return added;
    });
  }

  // One of a routed site's own hosts (CDN, API) is blocked too: route it via
  // the parent's transport, so the whole page leaves through one exit.
  async function routeSubresource(domain, parent, info) {
    const cur = (await allPolicies())[domain] || null;
    if (cur && (isRouted(cur) || cur.pinned)) return cur;
    const parentTransport = parent.proxyId ? await transports.get(parent.proxyId) : null;
    const t = parentTransport || await pickVerified([]);
    if (!t) return null;
    const next = await update(domain, () => ({
      rung: "proxy", proxyId: t.id, status: STATUS.ROUTING, via: "subresource", parent: parent.domain,
      lastError: info.err?.raw ?? null, lastType: info.type, attempts: 1, triedProxies: [t.id], retryAt: null
    }));
    await router.apply();
    log.add("routed-subresource", { domain, parent: parent.domain, via: t.id });
    await maybeReload(info.tabId, parent.domain);
    return next;
  }

  async function applyRung(domain, rung, info) {
    const lastError = info.err?.raw ?? null;
    if (rung === "doh" || rung === "ech") {
      return update(domain, () => ({ rung, proxyId: null, status: STATUS.NEEDS_USER, lastError, lastType: info.type, attempts: 0 }));
    }
    if (rung === "fallback") {
      return update(domain, () => ({ rung: "fallback", proxyId: null, status: STATUS.NEEDS_USER, lastError, lastType: info.type }));
    }
    return routeVia(domain, info, []);
  }

  // ---- events ---------------------------------------------------------------

  /** A fresh (not currently routed) domain failed and was diagnosed. */
  async function onBlocked(domain, info) {
    const cur = (await allPolicies())[domain] || null;

    if (cur?.pinned) {
      return update(domain, (p) => ({ lastError: info.err?.raw ?? null, failures: p.failures + 1 }));
    }
    if (cur?.status === STATUS.EXHAUSTED && cur.retryAt && now() < cur.retryAt) {
      return update(domain, (p) => ({ lastError: info.err?.raw ?? null, failures: p.failures + 1 }));
    }

    const fresh = !cur || cur.rung === "direct" || cur.status === STATUS.EXHAUSTED;
    if (fresh) {
      log.add("blocked", { domain, type: info.type, error: info.err?.code });
      return applyRung(domain, startRung(info.type, info.diag), info);
    }
    if (RUNGS[cur.rung]?.guidance) {
      // Secure DNS / ECH guidance didn't (yet) fix it — route it so the site
      // works now; the user can still enable Secure DNS for full speed.
      return applyRung(domain, "proxy", info);
    }
    if (cur.rung === "fallback") {
      const start = startRung(info.type, info.diag);
      if (start !== "fallback") return applyRung(domain, start, info);
      return update(domain, (p) => ({ lastError: info.err?.raw ?? null, failures: p.failures + 1, lastType: info.type }));
    }
    // On the proxy rung but not routed (auto-route was off / no transport):
    return applyRung(domain, "proxy", info);
  }

  // Which transports did the browser actually try? Only connection-to-proxy
  // failures make it fall over down the chain; anything else (the proxy
  // answered but the site didn't) means only the primary was used.
  async function triedChain(domain, cur, err) {
    const failover = err?.kind === KIND.PROXY && err.code !== "SOCKS_CONNECTION_HOST_UNREACHABLE";
    if (!failover) return [cur.proxyId];
    const compiled = await router.compile();
    const chain = (compiled.routes?.[domain] || []).map((t) => t.id);
    return chain.length ? chain : [cur.proxyId];
  }

  /** A navigation to a domain we ARE routing failed: that route isn't working. */
  async function onRouteFailure(domain, info) {
    const cur = (await allPolicies())[domain] || null;
    if (!isRouted(cur)) return cur;
    const chain = await triedChain(domain, cur, info.err);

    // A failed page doesn't prove the proxy is broken (the site may be down
    // everywhere); let a probe decide each transport's health.
    for (const id of chain) {
      if (ctx.verifyTransport) ctx.verifyTransport(id).catch(() => {});
      else health.record(id, false).catch(() => {});
    }

    if (cur.pinned) {
      // The user chose this route: report the problem, never auto-climb or
      // auto-reload past their choice.
      return update(domain, (p) => ({ status: STATUS.NEEDS_USER, lastError: info.err?.raw ?? null, failures: p.failures + 1 }));
    }
    if ((cur.attempts || 0) >= MAX_ATTEMPTS) return exhaust(domain, "max-attempts", info.err?.raw);
    const tried = [...new Set([...(cur.triedProxies || []), ...chain])];
    log.add("route-failed", { domain, via: cur.proxyId, chain, error: info.err?.code });
    return routeVia(domain, { ...info, type: cur.lastType }, tried);
  }

  /** A top-level navigation succeeded. */
  async function onSuccess(host) {
    const all = await allPolicies();
    const domain = lookupDomain(host, all);
    if (!domain) return null;
    const p = all[domain];

    if (isRouted(p)) {
      const stale = !p.lastVerified || now() - p.lastVerified > 60 * 60 * 1000;
      if (p.status === STATUS.FIXED && !stale) {
        // Remember the site is in use (throttled), so a direct re-check never
        // disturbs it mid-session.
        if (now() - (p.lastVisited || 0) > 5 * 60 * 1000) await update(domain, () => ({ lastVisited: now() }));
        return p;
      }
      // With a failover chain the page may have come through a fallback, so
      // only a single-transport (pinned) route proves its transport works.
      if (p.pinned) await health.record(p.proxyId, true);
      const next = await update(domain, (q) => ({
        status: STATUS.FIXED, lastVerified: now(), lastVisited: now(), successes: q.successes + 1,
        attempts: 0, retryCount: 0, triedProxies: [q.proxyId],
        recheckAt: q.recheckAt || now() + RECHECK_MS[0]
      }));
      // Bundle members load as subresources (no navigation of their own):
      // the parent page working is their verification too.
      await store.tx(["policies"], (d) => {
        for (const s of Object.values(d.policies || {})) {
          if ((s.via === "bundle" || s.via === "subresource") && s.parent === domain && s.status === STATUS.ROUTING) {
            s.status = STATUS.FIXED;
            s.lastVerified = now();
          }
        }
      });
      if (p.status !== STATUS.FIXED) log.add("verified", { domain, via: p.proxyId });
      return next;
    }
    if (p.pinned) return p;
    if (RUNGS[p.rung]?.guidance) {
      if (p.status === STATUS.FIXED) return p;
      log.add("verified", { domain, via: p.rung });
      return update(domain, (q) => ({ status: STATUS.FIXED, lastVerified: now(), successes: q.successes + 1 }));
    }
    if (p.status === STATUS.FIXED && p.rung === "direct") return p;
    // Loaded directly although we had it as blocked/exhausted: the block was
    // lifted or transient. Self-heal back to direct.
    log.add("works-direct", { domain });
    return update(domain, (q) => ({
      rung: "direct", proxyId: null, status: STATUS.FIXED, lastVerified: now(),
      successes: q.successes + 1, attempts: 0, retryCount: 0, retryAt: null, exhaustedReason: null
    }));
  }

  // ---- maintenance ----------------------------------------------------------

  /**
   * De-escalation: blocks get lifted. Re-check routed sites on their direct
   * path now and then; two consecutive direct passes (an hour apart) demote a
   * site back to direct, full-speed. directCheck(policy) → {ok}|{inconclusive}.
   */
  async function recheckDue(directCheck, { max = 3 } = {}) {
    if (!directCheck) return 0;
    const due = Object.values(await allPolicies())
      .filter((p) => isRouted(p) && p.status === STATUS.FIXED && !p.pinned && !p.via && p.recheckAt && p.recheckAt <= now())
      .slice(0, max);
    let demoted = 0;
    for (const p of due) {
      const r = await directCheck(p).catch(() => ({ inconclusive: true }));
      if (r.inconclusive) {
        await update(p.domain, () => ({ recheckAt: now() + 6 * 3600e3 }));
      } else if (r.ok && (p.directPasses || 0) + 1 >= 2) {
        await demote(p.domain);
        demoted++;
      } else if (r.ok) {
        await update(p.domain, () => ({ directPasses: 1, recheckAt: now() + 3600e3 }));
      } else {
        const n = (p.recheckCount || 0) + 1;
        await update(p.domain, () => ({ directPasses: 0, recheckCount: n, recheckAt: now() + RECHECK_MS[Math.min(n, RECHECK_MS.length - 1)] }));
      }
    }
    return demoted;
  }

  async function demote(domain) {
    await store.tx(["policies"], (d) => {
      const all = d.policies || {};
      for (const [k, s] of Object.entries(all)) {
        if ((s.via === "bundle" || s.via === "subresource") && s.parent === domain) delete all[k];
      }
      if (all[domain]) {
        all[domain] = {
          ...all[domain], rung: "direct", proxyId: null, status: STATUS.FIXED, directPasses: 0,
          recheckAt: null, recheckCount: 0, triedProxies: [], lastVerified: now(), updatedAt: now()
        };
      }
      d.policies = all;
    });
    await router.apply();
    log.add("demoted", { domain, reason: "works directly again" });
  }

  /** Re-enter exhausted domains whose backoff elapsed (or all, when forced). */
  async function retryDue({ force = false } = {}) {
    const due = Object.values(await allPolicies())
      .filter((p) => p.status === STATUS.EXHAUSTED && !p.pinned && (force || !p.retryAt || p.retryAt <= now()));
    if (!due.length) return 0;
    let rerouted = 0;
    for (const p of due) {
      const t = await transports.pickBest();
      if (t) {
        await update(p.domain, () => ({
          status: STATUS.ROUTING, rung: "proxy", proxyId: t.id, attempts: 0,
          triedProxies: [t.id], retryAt: null, exhaustedReason: null
        }));
        rerouted++;
        log.add("retry", { domain: p.domain, via: t.id });
      } else {
        await update(p.domain, (q) => ({
          retryAt: now() + backoffFor(q.retryCount || 0), retryCount: (q.retryCount || 0) + 1
        }));
      }
    }
    if (rerouted) await router.apply();
    return rerouted;
  }

  /** A transport went away: move every domain it carried onto a live one. */
  async function rehome(removedId) {
    const affected = Object.values(await allPolicies()).filter((p) => p.proxyId === removedId);
    for (const p of affected) {
      const t = await transports.pickBest([removedId]);
      if (t) {
        await update(p.domain, () => ({ proxyId: t.id, status: STATUS.ROUTING, pinned: false, attempts: 0, triedProxies: [t.id] }));
        log.add("rehomed", { domain: p.domain, from: removedId, to: t.id });
      } else {
        await update(p.domain, (q) => ({
          status: STATUS.EXHAUSTED, proxyId: null, pinned: false, exhaustedReason: "transport-removed",
          retryCount: (q.retryCount || 0) + 1, retryAt: now() + backoffFor(q.retryCount || 0)
        }));
      }
    }
    await router.apply();
    return affected.length;
  }

  // ---- manual controls (popup) ---------------------------------------------

  async function setRung(domain, rung, proxyId = null) {
    if (rung === "auto") {
      await update(domain, () => ({
        pinned: false, rung: "direct", proxyId: null, status: STATUS.BLOCKED,
        attempts: 0, triedProxies: [], retryAt: null, retryCount: 0, exhaustedReason: null
      }));
    } else if (rung === "proxy") {
      if (!proxyId || !(await transports.get(proxyId))) throw new Error("pick an existing transport");
      await update(domain, () => ({
        rung: "proxy", proxyId, pinned: true, status: STATUS.ROUTING,
        attempts: 0, triedProxies: [proxyId], retryAt: null, exhaustedReason: null
      }));
    } else if (RUNGS[rung]) {
      await update(domain, () => ({ rung, proxyId: null, pinned: true, status: STATUS.MANUAL, retryAt: null }));
    } else {
      throw new Error(`unknown rung "${rung}"`);
    }
    await router.apply();
    log.add("manual", { domain, rung, proxyId });
    return (await allPolicies())[domain];
  }

  // Forget a domain: its policy, the bundle members it brought along, and
  // every diagnosed host under it.
  async function clearDomain(domain) {
    await store.tx(["policies", "sites"], (d) => {
      for (const [k, p] of Object.entries(d.policies || {})) {
        if (k === domain || ((p.via === "bundle" || p.via === "subresource") && p.parent === domain)) delete d.policies[k];
      }
      for (const host of Object.keys(d.sites || {})) {
        if (lookupDomain(host, { [domain]: true })) delete d.sites[host];
      }
    });
    await router.apply();
  }

  async function clearAll() {
    await store.tx(["policies", "sites"], (d) => { d.policies = undefined; d.sites = undefined; });
    await router.apply();
  }

  return { policyFor, onBlocked, onRouteFailure, onSuccess, routeSubresource, retryDue, recheckDue, demote, rehome, setRung, clearDomain, clearAll };
}
