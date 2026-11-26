// OpenRoute control plane — wiring.
//
//   navigation fails → normalize error → (routed? that route failed → next
//   transport) or (diagnose over DoH → classify → ladder picks a rung) →
//   router installs the split-tunnel table → a successful navigation verifies.
//
// createBackground() builds a fresh, self-contained instance (no module-level
// state), so a worker restart — or a test — always starts clean.

import { detectCapabilities, detectBrowser, accessStatus } from "./platform.js";
import { isBogon } from "./dns/bogons.js";
import { createStore, createSessionArea, migrate } from "./store.js";
import { normalizeError, KIND } from "./errors.js";
import { classify } from "./diagnosis.js";
import { createDoH, createDiagnoser } from "./dns/doh.js";
import { createHealth } from "./transports/health.js";
import { createTransports } from "./transports/registry.js";
import { createRouter } from "./routing/router.js";
import { createLadder } from "./ladder.js";
import { createCompanion } from "./companion.js";
import { createEventLog } from "./eventlog.js";
import { createHandlers } from "./messages.js";
import { createProber, probeIds, candidateTransport, DISCOVERY_CANDIDATES } from "./probe.js";
import { createRequestWatcher } from "./detect/requests.js";
import { TYPES } from "./diagnosis.js";
import { hasRealRoutes } from "./routing/table.js";
import { STATUS, isRouted, pruneSites } from "./policy.js";
import { registrableDomain } from "./domains/psl.js";
import { hostFromUrl, isLocalHost, isIpLiteral, lookupDomain, normalizeHost } from "../shared/hosts.js";

export const DEFAULT_SETTINGS = Object.freeze({
  detectionEnabled: true,
  autoRoute: true,
  autoReload: true,
  dohProvider: "cloudflare",
  customDoH: null,          // optional https://… RFC 8484 endpoint (e.g. your own server)
  mode: "smart",            // smart = route only blocked sites · full = everything · off = nothing
  routeScope: "registrable", // route example.co.uk (+ subdomains) for www.example.co.uk; "host" = exact host
  bundles: true,            // route a site's known CDN/API domains along with it
  deepDetection: true,      // block pages, HTTP 451, blocked subresources (needs site access on Chromium)
  webrtcProtection: false,  // keep WebRTC from bypassing the proxy (needs the optional "privacy" permission)
  // Checking a failing site against encrypted DNS sends its domain to the DoH
  // provider. On Firefox this also requires the built-in data consent.
  remoteDiagnosis: true
});

export const MAINTENANCE_ALARM = "openroute-maintenance";
const MAINTENANCE_PERIOD_MIN = 5;
const LEGACY_ALARMS = ["openroute-health"];

export function createBackground({ api }) {
  const caps = detectCapabilities(api);
  const store = createStore(api.storage.local, { name: "local", onError: (e) => console.warn("OpenRoute store:", e) });
  const session = createStore(createSessionArea(api), { name: "session" });
  const ctx = { api, caps, store, session };

  ctx.settings = {
    async get() { return { ...DEFAULT_SETTINGS, ...(await store.get("settings", {})) }; },
    async patch(patch) {
      return store.tx(["settings"], (d) => {
        d.settings = { ...DEFAULT_SETTINGS, ...(d.settings || {}), ...patch };
        return d.settings;
      });
    }
  };
  ctx.log = createEventLog(store);
  ctx.companion = createCompanion(api);
  ctx.health = createHealth({ store });
  ctx.transports = createTransports({ store, health: ctx.health, caps });
  ctx.router = createRouter({
    api, caps, store, session, transports: ctx.transports, health: ctx.health,
    getSettings: () => ctx.settings.get(), log: ctx.log
  });
  ctx.prober = createProber();

  // Probe one transport through the routing table; health is earned here.
  ctx.verifyTransport = (id, { timeout = 6000 } = {}) => ctx.router.withProbes(async (canProbe) => {
    if (!canProbe) return { ok: false, error: "no-control" };
    const r = await ctx.prober.run(probeIds.transport(id), { timeout });
    await ctx.health.record(id, r.ok, { latencyMs: r.ok ? r.latencyMs : undefined, probe: true });
    return r;
  });

  // Does a routed site work on its direct path again?
  //   Firefox: onRequest sees full https URLs, so the probe marker sends just
  //            this request direct — no disturbance at all.
  //   Chromium: the PAC can't see https markers, so the site is unrouted for
  //            the few seconds of the check — only when nobody's using it.
  ctx.directCheck = async (p) => {
    const url = `https://${p.domain}/`;
    if (caps.proxyEngine === "firefox") {
      return { ok: (await ctx.prober.reach(url, probeIds.direct, { timeout: 8000 })).ok };
    }
    if (caps.proxyEngine === "chromium") {
      if (p.lastVisited && Date.now() - p.lastVisited < 30 * 60 * 1000) return { inconclusive: true };
      return ctx.router.withExclusion(p.domain, async () =>
        ({ ok: (await ctx.prober.reach(url, probeIds.direct, { timeout: 8000 })).ok }));
    }
    return { inconclusive: true };
  };

  // Keep WebRTC from leaking around the proxy (opt-in; optional permission).
  ctx.applyWebRtc = async () => {
    const setting = api.privacy?.network?.webRTCIPHandlingPolicy;
    if (!setting) return { applied: false, reason: "needs the optional \"privacy\" permission" };
    if ((await ctx.settings.get()).webrtcProtection) await setting.set({ value: "disable_non_proxied_udp" });
    else await setting.clear({});
    return { applied: true };
  };

  // Find circumvention proxies already running on this machine.
  ctx.discover = () => ctx.router.withProbes(async (canProbe) => {
    if (!canProbe) return { found: [], tested: 0, error: "OpenRoute doesn't control the proxy settings right now" };
    const results = await Promise.all(DISCOVERY_CANDIDATES.map(async (c) =>
      ({ c, r: await ctx.prober.run(probeIds.candidate(c), { timeout: 5000 }) })));
    const existing = await ctx.transports.configs();
    const found = [];
    for (const { c, r } of results) {
      if (!r.ok) continue;
      const same = existing.find((t) => t.host === "127.0.0.1" && Number(t.port) === c.port && t.scheme === c.scheme);
      const t = same || await ctx.transports.upsert(candidateTransport(c));
      await ctx.health.record(t.id, true, { latencyMs: r.latencyMs, probe: true });
      found.push({ id: t.id, label: t.label, port: c.port, scheme: c.scheme, latencyMs: r.latencyMs, added: !same });
    }
    ctx.log.add("discovery", { tested: results.length, found: found.map((f) => f.port) });
    return { found, tested: results.length };
  });
  ctx.doh = createDoH({
    getConfig: async () => {
      const s = await ctx.settings.get();
      return { preferred: s.dohProvider, customUrl: s.customDoH || null };
    }
  });
  ctx.diagnose = createDiagnoser({ doh: ctx.doh });
  ctx.ladder = createLadder(ctx);

  let browser = { family: caps.proxyEngine === "firefox" ? "firefox" : "chromium", name: "", version: "", mobile: false };
  let readyPromise = null;
  const ready = () => readyPromise || (readyPromise = init());

  async function step(name, fn) {
    try { return await fn(); }
    catch (e) { console.warn(`OpenRoute init (${name}):`, e); ctx.log.add("init-error", { step: name, error: String(e?.message || e) }); }
  }

  async function init() {
    await step("migrate", () => migrate(store));
    await step("browser", async () => { browser = await detectBrowser(api); });
    await step("alarms", ensureAlarms);
    await step("badge-color", () => api.action?.setBadgeBackgroundColor?.({ color: "#c0392b" }));
    await step("router", () => ctx.router.apply());
    await step("webrtc", async () => { if ((await ctx.settings.get()).webrtcProtection) await ctx.applyWebRtc(); });
    await step("badge", updateBadge);
  }

  async function ensureAlarms() {
    for (const name of LEGACY_ALARMS) await api.alarms.clear(name).catch(() => {});
    // Re-creating an existing alarm resets its timer — a frequently-woken
    // worker would then never tick. Only create it when missing or changed.
    const existing = await api.alarms.get(MAINTENANCE_ALARM);
    if (!existing || existing.periodInMinutes !== MAINTENANCE_PERIOD_MIN) {
      await api.alarms.create(MAINTENANCE_ALARM, { periodInMinutes: MAINTENANCE_PERIOD_MIN, delayInMinutes: 1 });
    }
  }

  async function updateBadge() {
    const policies = await store.get("policies", {});
    const n = Object.values(policies).filter((p) => p.status === STATUS.NEEDS_USER || p.status === STATUS.EXHAUSTED).length;
    await api.action?.setBadgeText?.({ text: n ? String(n) : "" });
  }

  async function remoteDiagnosisAllowed() {
    if ((await ctx.settings.get()).remoteDiagnosis === false) return false;
    if (!caps.dataCollectionConsent) return true;
    const { dataConsent } = await accessStatus(api, caps);
    return dataConsent !== false; // null = runtime without the consent system
  }

  // Firefox only: what the *system* resolver says (TRR bypassed). A bogon
  // answer here while DoH has a real one is direct evidence of DNS tampering.
  async function localResolve(host) {
    if (!caps.dnsApi) return null;
    try {
      const r = await api.dns.resolve(host, ["disable_trr", "bypass_cache"]);
      const addresses = r?.addresses || [];
      return { addresses, injected: addresses.length > 0 && addresses.every(isBogon), failed: false };
    } catch {
      return { addresses: [], injected: false, failed: true };
    }
  }

  async function diagnoseHost(host) {
    if (isIpLiteral(host)) return { ok: true, status: 0, addresses: [host], bogons: [], ipLiteral: true };
    const [allowed, local] = await Promise.all([remoteDiagnosisAllowed(), localResolve(host)]);
    const diag = allowed
      ? { ...(await ctx.diagnose(host)) }
      : { ok: false, status: null, addresses: [], bogons: [], unreachable: true, skipped: "consent" };
    if (allowed && diag.unreachable && caps.canRoute) {
      // Encrypted DNS itself is blocked here. Reach the resolvers through a
      // transport for a while, so later diagnoses are precise again. Routing
      // this site doesn't wait for it: "dns-unverified" already routes.
      const t = await ctx.transports.pickBest();
      if (t) {
        ctx.router.useTransportForDoH(t.id).catch(() => {});
        ctx.diagnose.invalidate();
        ctx.log.add("doh-via-transport", { via: t.id });
      }
    }
    if (local) {
      diag.localAddresses = local.addresses;
      diag.localInjected = local.injected;
      diag.localFailed = local.failed;
    }
    return diag;
  }

  async function recordSite(host, url, err, diag, type) {
    const t = Date.now();
    await store.tx(["sites"], (d) => {
      const sites = d.sites || {};
      const prev = sites[host];
      sites[host] = {
        host, url, type,
        error: err.raw, errorCode: err.code, errorKind: err.kind,
        resolvedIPs: diag?.addresses || [],
        dohProvider: diag?.resolver || null,
        dohUnreachable: !!diag?.unreachable && !diag?.skipped,
        dohSkipped: diag?.skipped || null,
        localIPs: diag?.localAddresses || null,
        localInjected: !!diag?.localInjected,
        hasHTTPS: !!diag?.hasHTTPS, echLikely: !!diag?.echLikely, injected: !!diag?.injected,
        firstSeen: prev?.firstSeen || t, lastSeen: t, count: (prev?.count || 0) + 1
      };
      d.sites = pruneSites(sites);
    });
  }

  // Only real, user-visible, top-level navigations count.
  function isTopLevel(details) {
    if (details.frameId !== 0) return false;
    if (details.frameType && details.frameType !== "outermost_frame") return false;
    if (details.documentLifecycle && details.documentLifecycle !== "active") return false;
    return /^https?:/i.test(details.url || "");
  }

  async function onNavigationError(details) {
    await ready();
    if (!isTopLevel(details)) return;
    const host = hostFromUrl(details.url);
    if (!host || isLocalHost(host)) return;
    if (!(await ctx.settings.get()).detectionEnabled) return;

    const err = normalizeError(details.error);
    if (err.kind === KIND.IGNORE || err.kind === KIND.OFFLINE) return;
    if (await neverRoute(host)) return; // the user said: leave this site alone
    const info = { err, tabId: details.tabId, url: details.url };

    const pol = await ctx.ladder.policyFor(host);
    if (isRouted(pol)) {
      // We're routing this domain and it still failed: the route is broken.
      // The site's original diagnosis stays as it was.
      await ctx.ladder.onRouteFailure(pol.domain, info);
      await updateBadge();
      return;
    }
    if (err.kind === KIND.PROXY) return; // a proxy we don't manage (system / another extension)

    const diag = await diagnoseHost(host);
    const type = classify(err.kind, diag);
    await recordSite(host, details.url, err, diag, type);
    if (err.kind === KIND.POLICY) return;

    await ctx.ladder.onBlocked(pol?.domain || (await policyDomainFor(host)), { ...info, diag, type });
    await updateBadge();
  }

  // The unit a policy (and its route) covers: the registrable domain by
  // default, so "cdn.example.co.uk" rides along with "www.example.co.uk".
  async function policyDomainFor(host) {
    if ((await ctx.settings.get()).routeScope === "host") return host;
    return registrableDomain(host) || host;
  }

  // A page "loaded" but was a block page (injected address / HTTP 451).
  async function onBlockpage(host, { reason, tabId, url, ip }) {
    let type;
    let diag;
    if (reason === "http-451") {
      type = TYPES.LEGAL_451;
      diag = await diagnoseHost(host);
    } else {
      diag = await diagnoseHost(host);
      // Only a real encrypted-DNS answer that disagrees with where the browser
      // went proves injection.
      if (!diag.ok || diag.addresses.includes(ip)) return;
      type = TYPES.DNS_BLOCKPAGE;
    }
    const err = { raw: reason, code: reason.toUpperCase().replace(/-/g, "_"), kind: reason === "http-451" ? KIND.HTTP : KIND.DNS };
    await recordSite(host, url, err, { ...diag, connectedIp: ip }, type);
    const pol = await ctx.ladder.policyFor(host);
    await ctx.ladder.onBlocked(pol?.domain || (await policyDomainFor(host)), { err, diag, type, tabId, url });
    await updateBadge();
  }

  // A site we route still can't load one of its own hosts.
  async function onSubresourceBlock(host, { err, parent, tabId, url, routable }) {
    const diag = await diagnoseHost(host);
    const type = classify(err.kind, diag);
    if (!routable.has(type)) return;
    await recordSite(host, url, err, diag, type);
    await ctx.ladder.routeSubresource(await policyDomainFor(host), parent, { err, diag, type, tabId });
  }

  const watcher = createRequestWatcher(ctx, {
    onBlockpage: (...a) => ready().then(() => onBlockpage(...a)),
    onSubresourceBlock: (...a) => ready().then(() => onSubresourceBlock(...a))
  });

  async function onNavigationCompleted(details) {
    await ready();
    if (!isTopLevel(details)) return;
    const host = hostFromUrl(details.url);
    if (!host || isLocalHost(host)) return;
    const changed = await ctx.ladder.onSuccess(host, { tabId: details.tabId });
    if (changed) await updateBadge();
  }

  async function neverRoute(host) {
    const rules = await store.get("rules", {});
    const never = Object.fromEntries((rules.never || []).map((d) => [d, true]));
    return !!lookupDomain(host, never);
  }

  // Re-measure the transports that are carrying traffic right now, so a dead
  // one is noticed (and routed around) before the user hits it.
  async function probeActiveTransports() {
    const compiled = await ctx.router.compile();
    if (!hasRealRoutes(compiled) || !ctx.router.canProbe()) return;
    const ids = new Set([...Object.values(compiled.routes).flat(), ...(compiled.defaultRoute || [])].map((t) => t.id));
    const hs = await ctx.health.getAll();
    for (const id of ids) {
      const h = hs[id];
      if (!h?.lastProbe || Date.now() - h.lastProbe > 15 * 60 * 1000 || h.state !== "up") await ctx.verifyTransport(id);
    }
  }

  // Keep the companion's transports in step with what its daemon actually
  // serves: a port it had to change after a restart is picked up, and a
  // transport it no longer runs is removed (its domains re-homed).
  async function syncCompanionTransports() {
    const r = await ctx.companion.send({ cmd: "transports" });
    if (!r?.ok || !Array.isArray(r.transports)) return;
    const live = new Map(r.transports.map((t) => [String(t.id), t]));
    for (const t of await ctx.transports.configs()) {
      if (t.kind !== "companion") continue;
      const now = live.get(t.id);
      if (!now) {
        await ctx.transports.remove(t.id);
        await ctx.ladder.rehome(t.id);
      } else if (Number(now.port) !== Number(t.port)) {
        await ctx.transports.upsert({ ...t, port: Number(now.port) });
        ctx.log.add("companion-port", { id: t.id, port: now.port });
      }
    }
    for (const [id, t] of live) {
      if (!(await ctx.transports.get(id))) {
        await ctx.transports.upsert({ id, label: t.label, scheme: "socks5", host: "127.0.0.1", port: Number(t.port), kind: "companion", note: t.note });
      }
    }
    await ctx.router.apply();
  }

  async function maintenance() {
    await ctx.health.recover();
    await probeActiveTransports();
    if (caps.nativeMessaging && (await ctx.companion.isAvailable())) {
      try {
        const report = await ctx.companion.send({ cmd: "health" });
        await ctx.health.merge(report?.transports || []);
        await syncCompanionTransports();
      } catch { /* companion went away mid-tick */ }
    }
    await ctx.ladder.retryDue();
    await ctx.ladder.recheckDue(ctx.directCheck);
    await updateBadge();
  }

  async function onAlarm(alarm) {
    await ready();
    if (alarm?.name === MAINTENANCE_ALARM) await maintenance();
  }

  function onInstalled(details) {
    ready();
    if (details?.reason === "install") {
      api.tabs.create({ url: api.runtime.getURL("src/ui/onboarding.html") }).catch(() => {});
    }
  }

  const handlers = createHandlers(ctx, {
    updateBadge,
    getBrowser: () => browser,
    getAccess: () => accessStatus(api, caps),
    diagnoseHost
  });

  function isTrustedSender(sender) {
    if (!sender || sender.id !== api.runtime.id) return false;
    if (sender.url && !sender.url.startsWith(api.runtime.getURL(""))) return false; // content scripts / web pages
    return true;
  }

  function onMessage(msg, sender, sendResponse) {
    const handler = Object.prototype.hasOwnProperty.call(handlers, msg?.type) ? handlers[msg.type] : null;
    if (!handler || !isTrustedSender(sender)) return false;
    ready()
      .then(() => handler(msg))
      .then((res) => sendResponse({ ok: true, ...(res || {}) }),
        (err) => sendResponse({ ok: false, error: String(err?.message || err) }));
    return true; // async response
  }

  // Chromium: answer HTTP(S) proxy logins for transports that carry
  // credentials. (Firefox gets them in the onRequest descriptor instead.)
  // A second challenge for the same request means the credentials were
  // rejected — cancel instead of looping.
  const authAttempts = new Map();
  function onAuthRequired(details, callback) {
    const respond = (r) => { try { callback?.(r); } catch { /* request already gone */ } };
    if (!details?.isProxy) { respond({}); return; }
    ready().then(async () => {
      const n = (authAttempts.get(details.requestId) || 0) + 1;
      authAttempts.set(details.requestId, n);
      if (authAttempts.size > 500) authAttempts.clear();
      if (n > 1) {
        ctx.log.add("proxy-auth-rejected", { proxy: `${details.challenger?.host}:${details.challenger?.port}` });
        respond({ cancel: true });
        return;
      }
      const host = normalizeHost(details.challenger?.host);
      const port = Number(details.challenger?.port);
      const t = (await ctx.transports.configs()).find((x) => x.auth?.username && normalizeHost(x.host) === host && Number(x.port) === port);
      respond(t ? { authCredentials: { username: t.auth.username, password: t.auth.password || "" } } : {});
    }).catch(() => respond({}));
  }

  const guard = (name, fn) => (...args) =>
    Promise.resolve().then(() => fn(...args)).catch((e) => {
      console.warn(`OpenRoute ${name}:`, e);
      ctx.log.add("error", { where: name, error: String(e?.message || e) });
    });

  return {
    ctx,
    ready,
    handlers,
    // Everything here must run synchronously during the worker's first turn:
    // listeners added later don't wake a suspended MV3 worker / event page.
    registerListeners() {
      api.storage.onChanged.addListener((changes, area) => {
        if (area === "local") store.noteChanges(changes);
        else if (area === "session") session.noteChanges(changes);
      });
      api.runtime.onInstalled.addListener(onInstalled);
      api.runtime.onStartup?.addListener(() => { ready(); });
      api.runtime.onMessage.addListener(onMessage);
      api.webNavigation.onErrorOccurred.addListener(guard("navigation-error", onNavigationError));
      api.webNavigation.onCompleted.addListener(guard("navigation-completed", onNavigationCompleted));
      api.alarms.onAlarm.addListener(guard("alarm", onAlarm));
      ctx.router.install();
      watcher.register();
      if (caps.proxyEngine === "chromium" && api.webRequest?.onAuthRequired) {
        api.webRequest.onAuthRequired.addListener(onAuthRequired, { urls: ["<all_urls>"] }, ["asyncBlocking"]);
      }
    }
  };
}
