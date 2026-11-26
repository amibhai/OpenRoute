// OpenRoute control plane — wiring.
//
//   navigation fails → normalize error → (routed? that route failed → next
//   transport) or (diagnose over DoH → classify → ladder picks a rung) →
//   router installs the split-tunnel table → a successful navigation verifies.
//
// createBackground() builds a fresh, self-contained instance (no module-level
// state), so a worker restart — or a test — always starts clean.

import { detectCapabilities, detectBrowser } from "./platform.js";
import { createStore, createSessionArea, migrate } from "./store.js";
import { normalizeError, KIND } from "./errors.js";
import { classify } from "./diagnosis.js";
import { createDiagnoser } from "./dns/doh.js";
import { createHealth } from "./transports/health.js";
import { createTransports } from "./transports/registry.js";
import { createRouter } from "./routing/router.js";
import { createLadder } from "./ladder.js";
import { createCompanion } from "./companion.js";
import { createEventLog } from "./eventlog.js";
import { createHandlers } from "./messages.js";
import { STATUS, isRouted, pruneSites } from "./policy.js";
import { hostFromUrl, isLocalHost, isIpLiteral } from "../shared/hosts.js";

export const DEFAULT_SETTINGS = Object.freeze({
  detectionEnabled: true,
  autoRoute: true,
  autoReload: true,
  dohProvider: "cloudflare"
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
  ctx.transports = createTransports({ store, health: ctx.health });
  ctx.router = createRouter({ api, caps, store, transports: ctx.transports, log: ctx.log });
  ctx.diagnose = createDiagnoser({ getPreferred: async () => (await ctx.settings.get()).dohProvider });
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
        dohUnreachable: !!diag?.unreachable,
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

    const diag = isIpLiteral(host)
      ? { ok: true, status: 0, addresses: [host], bogons: [], ipLiteral: true }
      : await ctx.diagnose(host);
    const type = classify(err.kind, diag);
    await recordSite(host, details.url, err, diag, type);
    if (err.kind === KIND.POLICY) return;

    await ctx.ladder.onBlocked(pol?.domain || host, { ...info, diag, type });
    await updateBadge();
  }

  async function onNavigationCompleted(details) {
    await ready();
    if (!isTopLevel(details)) return;
    const host = hostFromUrl(details.url);
    if (!host || isLocalHost(host)) return;
    const changed = await ctx.ladder.onSuccess(host, { tabId: details.tabId });
    if (changed) await updateBadge();
  }

  async function maintenance() {
    await ctx.health.recover();
    if (caps.nativeMessaging && (await ctx.companion.isAvailable())) {
      try {
        const report = await ctx.companion.send({ cmd: "health" });
        await ctx.health.merge(report?.transports || []);
      } catch { /* companion went away mid-tick */ }
    }
    await ctx.ladder.retryDue();
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

  const handlers = createHandlers(ctx, { updateBadge, getBrowser: () => browser });

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
    }
  };
}
