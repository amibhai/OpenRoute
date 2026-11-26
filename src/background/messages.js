// The popup/options/onboarding API. Every request is validated; pages never
// write storage directly, so the background's store stays the only writer.

import { RESOLVERS } from "./dns/doh.js";
import { secureDnsGuide } from "./platform.js";
import { isRouted } from "./policy.js";
import { presets } from "./transports/registry.js";
import { registrableDomain } from "./domains/psl.js";
import { normalizeHost, isValidHostname, hostFromUrl, isLocalHost, lookupDomain } from "../shared/hosts.js";

export const BACKUP_FORMAT = "openroute-backup";

const SETTINGS_SCHEMA = {
  detectionEnabled: (v) => typeof v === "boolean",
  autoRoute: (v) => typeof v === "boolean",
  autoReload: (v) => typeof v === "boolean",
  remoteDiagnosis: (v) => typeof v === "boolean",
  dohProvider: (v) => typeof v === "string" && Object.prototype.hasOwnProperty.call(RESOLVERS, v),
  customDoH: (v) => v === null || isHttpsUrl(v),
  mode: (v) => ["smart", "full", "off"].includes(v),
  routeScope: (v) => v === "registrable" || v === "host",
  bundles: (v) => typeof v === "boolean",
  deepDetection: (v) => typeof v === "boolean",
  webrtcProtection: (v) => typeof v === "boolean"
};

const MAX_RULES = 1000;

function isHttpsUrl(v) {
  try {
    const u = new URL(v);
    return u.protocol === "https:" && !u.username && !u.password && v.length <= 300;
  } catch {
    return false;
  }
}

function domainArg(v) {
  const d = normalizeHost(v);
  if (!isValidHostname(d)) throw new Error("invalid domain");
  return d;
}

// The sites list, grouped the way routing works: one group per policy domain
// (registrable domain by default), holding the hosts seen under it and the
// bundle / subresource domains that ride along with it.
export function groupSites(policies = {}, sites = {}) {
  const groups = new Map();
  const ensure = (domain) => {
    if (!groups.has(domain)) groups.set(domain, { domain, policy: policies[domain] || null, hosts: [], members: [], lastActivity: 0 });
    return groups.get(domain);
  };
  const ownerOf = (domain) => {
    const p = policies[domain];
    return p && (p.via === "bundle" || p.via === "subresource") && p.parent && policies[p.parent] ? p.parent : domain;
  };
  for (const [domain, p] of Object.entries(policies)) {
    const owner = ownerOf(domain);
    const g = ensure(owner);
    if (owner !== domain) g.members.push(domain);
    g.lastActivity = Math.max(g.lastActivity, p.updatedAt || 0);
  }
  for (const [host, site] of Object.entries(sites)) {
    const d = lookupDomain(host, policies);
    const g = ensure(d ? ownerOf(d) : registrableDomain(host) || host);
    g.hosts.push(host);
    g.lastActivity = Math.max(g.lastActivity, site.lastSeen || 0);
  }
  return [...groups.values()].sort((a, b) => b.lastActivity - a.lastActivity || a.domain.localeCompare(b.domain));
}

// Stable stand-ins for domains in a shareable report.
function aliaser(on) {
  const seen = new Map();
  return (d) => {
    if (!on || !d) return d;
    if (!seen.has(d)) seen.set(d, `site-${seen.size + 1}`);
    return seen.get(d);
  };
}

export function createHandlers(ctx, { updateBadge, getBrowser, getAccess, diagnoseHost, policyDomainFor, toggleSite, neverRouteSite, openDashboard }) {
  const { api, store, caps, transports, router, ladder, companion, settings, log } = ctx;

  async function upsertCompanionTransport(id, label, port, note) {
    await transports.upsert({ id, label, scheme: "socks5", host: "127.0.0.1", port, kind: "companion", note });
    await router.apply();
    await ladder.retryDue({ force: true });
  }

  const h = {
    async getState() {
      const [s, policies, sites, list, activeTransportId, available, eventLog, access, rules] = await Promise.all([
        settings.get(), store.get("policies", {}), store.get("sites", {}), transports.list(),
        transports.getActiveId(),
        caps.nativeMessaging ? companion.isAvailable().catch(() => false) : false,
        log.list(60), getAccess(), store.get("rules", {})
      ]);
      const browser = getBrowser();
      return {
        schemaVersion: await store.get("schemaVersion", 0),
        version: api.runtime.getManifest?.().version,
        settings: s, policies, sites, groups: groupSites(policies, sites), transports: list, activeTransportId, rules,
        companion: { available, supported: caps.nativeMessaging },
        router: router.status(), capabilities: caps, browser, access,
        secureDns: secureDnsGuide(browser), resolvers: Object.keys(RESOLVERS), eventLog
      };
    },

    // Everything the popup's "this site" card needs about one tab: by its URL,
    // or — where the page can't see it (Firefox for Android shows the popup
    // as a tab of its own) — by the site this tab was last seen on.
    async tabState({ url, tabId }) {
      let u = String(url || "");
      if (!/^https?:/i.test(u) && Number.isInteger(tabId)) {
        const known = (await ctx.session.get("tabHosts", {}))[tabId];
        if (known) u = `https://${known}/`;
      }
      const host = /^https?:/i.test(u) ? hostFromUrl(u) : null;
      if (!host || isLocalHost(host)) return { web: false };
      const [policy, sites, rules, list] = await Promise.all([
        ladder.policyFor(host), store.get("sites", {}), store.get("rules", {}), transports.list()
      ]);
      const ruleFor = (name) => (rules[name] || []).find((d) => lookupDomain(host, { [d]: true })) || null;
      const never = ruleFor("never");
      const always = ruleFor("always");
      return {
        web: true, host, url: u,
        domain: policy?.domain || (await policyDomainFor(host)),
        policy, routed: isRouted(policy),
        site: sites[host] || null,
        rule: never ? "never" : always ? "always" : null,
        ruleDomain: never || always || null,
        transport: policy?.proxyId ? list.find((t) => t.id === policy.proxyId) || null : null
      };
    },

    // Route a domain now: through the given transport, or the best one.
    async routeSite({ domain, proxyId }) {
      const d = domainArg(domain);
      const t = proxyId ? await transports.get(String(proxyId)) : await transports.pickBest();
      if (!t) throw new Error("no transport to route through; add one first");
      const policy = await ladder.setRung(d, "proxy", t.id);
      await updateBadge();
      return { policy };
    },

    async toggleSite({ url, tabId }) {
      return { result: await toggleSite(String(url || ""), Number.isInteger(tabId) ? tabId : null) };
    },

    async neverRouteSite({ url, tabId }) {
      return { result: await neverRouteSite(String(url || ""), Number.isInteger(tabId) ? tabId : null) };
    },

    async openDashboard({ section } = {}) {
      const s = String(section || "");
      await openDashboard(/^[a-z]{0,20}$/.test(s) ? s : "");
      return {};
    },

    async recheck({ host }) {
      const h = domainArg(host);
      ctx.diagnose.invalidate?.(h);
      const diag = await diagnoseHost(h);
      await store.tx(["sites"], (d) => {
        if (!d.sites?.[h]) return;
        d.sites[h] = {
          ...d.sites[h], resolvedIPs: diag.addresses, dohProvider: diag.resolver || null,
          dohUnreachable: !!diag.unreachable && !diag.skipped, dohSkipped: diag.skipped || null,
          localIPs: diag.localAddresses || null, localInjected: !!diag.localInjected,
          hasHTTPS: !!diag.hasHTTPS, echLikely: !!diag.echLikely, injected: !!diag.injected, lastChecked: Date.now()
        };
      });
      return { diag };
    },

    async setRung({ domain, rung, proxyId }) {
      const policy = await ladder.setRung(domainArg(domain), String(rung), proxyId ?? null);
      await updateBadge();
      return { policy };
    },

    async clearDomain({ domain }) {
      await ladder.clearDomain(domainArg(domain));
      await updateBadge();
      return {};
    },

    async clearAll() {
      await ladder.clearAll();
      await updateBadge();
      return {};
    },

    async saveSettings({ patch }) {
      if (!patch || typeof patch !== "object") throw new Error("patch must be an object");
      const clean = {};
      for (const [k, v] of Object.entries(patch)) {
        if (!SETTINGS_SCHEMA[k]) throw new Error(`unknown setting "${k}"`);
        if (!SETTINGS_SCHEMA[k](v)) throw new Error(`invalid value for "${k}"`);
        clean[k] = v;
      }
      const next = await settings.patch(clean);
      if ("mode" in clean) await router.apply();
      const webrtc = "webrtcProtection" in clean ? await ctx.applyWebRtc() : undefined;
      if (clean.autoRoute === true) await ladder.retryDue({ force: true });
      return { settings: next, webrtc };
    },

    async addTransport({ transport }) {
      const t = await transports.upsert(transport);
      await router.apply();
      // Measure it right away so it never carries a site while dead.
      const probe = ctx.verifyTransport ? await ctx.verifyTransport(t.id, { timeout: 5000 }) : null;
      await ladder.retryDue({ force: true }); // a new transport is a new chance for exhausted domains
      return { transport: t, probe, transports: await transports.list() };
    },

    async probeTransport({ id }) {
      if (!(await transports.get(String(id)))) throw new Error("no such transport");
      return { result: await ctx.verifyTransport(String(id)), transports: await transports.list() };
    },

    async discoverLocalProxies() {
      const result = await ctx.discover();
      if (result.found?.length) {
        await router.apply();
        await ladder.retryDue({ force: true });
      }
      return { ...result, transports: await transports.list() };
    },

    // list: "always" | "never" | null (remove the rule)
    async setRule({ domain, list }) {
      const d = domainArg(domain);
      if (list !== null && list !== "always" && list !== "never") throw new Error('list must be "always", "never" or null');
      await store.tx(["rules"], (draft) => {
        const rules = draft.rules || {};
        rules.always = (rules.always || []).filter((x) => x !== d);
        rules.never = (rules.never || []).filter((x) => x !== d);
        if (list) {
          if (rules[list].length >= MAX_RULES) throw new Error("too many rules");
          rules[list].push(d);
        }
        draft.rules = rules;
      });
      await router.apply();
      return { rules: await store.get("rules", {}) };
    },

    async removeTransport({ id }) {
      await transports.remove(String(id));
      await ladder.rehome(String(id));
      await updateBadge();
      return { transports: await transports.list() };
    },

    async setActiveTransport({ id }) {
      await transports.setActiveId(id == null ? null : String(id));
      return {};
    },

    async openSecureDnsSettings() {
      const guide = secureDnsGuide(getBrowser());
      if (guide.url) {
        try {
          await api.tabs.create({ url: guide.url });
          return { opened: true, guide };
        } catch { /* some forks block their settings URL — fall back to steps */ }
      }
      return { opened: false, guide };
    },

    async getEventLog({ limit } = {}) {
      return { events: await log.list(Math.min(Number(limit) || 100, 300)) };
    },

    // ---- companion (native helper) -----------------------------------------

    async companionConnect({ link, links, label }) {
      companion.invalidate();
      const list = Array.isArray(links) ? links.filter((s) => typeof s === "string" && s.trim()) : [];
      if (!list.length && typeof link === "string" && link.trim()) list.push(link.trim());
      if (!list.length) throw new Error("paste at least one share link");
      const name = String(label || "").trim().slice(0, 60) || "Companion";
      const result = await companion.send({ cmd: "connect", id: "companion", label: name, links: list }, 25000);
      if (result?.ok) {
        await upsertCompanionTransport("companion", name, Number(result.socksPort) || 1080);
        await transports.setActiveId("companion");
      }
      return { result };
    },

    async companionConnectTor({ mode, label, bridges }) {
      companion.invalidate();
      const m = ["direct", "obfs4", "snowflake", "meek", "webtunnel", "auto"].includes(mode) ? mode : "direct";
      const result = await companion.send({
        cmd: "connectTor", mode: m, label,
        bridges: Array.isArray(bridges) ? bridges.filter((b) => typeof b === "string") : undefined
      }, 25000);
      if (result?.ok) {
        await upsertCompanionTransport("companion-tor", String(label || "").slice(0, 60) || `Tor (${m})`,
          Number(result.socksPort) || 9250, "free network · slower");
      }
      return { result };
    },

    // Serverless DPI bypass (TLS ClientHello fragmentation) — two transports,
    // so the ladder can try records, then segments, then a real tunnel.
    async companionConnectDpi() {
      companion.invalidate();
      const result = await companion.send({ cmd: "connectDpi" }, 45000);
      if (result?.ok) {
        for (const t of result.transports || []) {
          await transports.upsert({ id: t.id, label: t.label, scheme: "socks5", host: "127.0.0.1", port: Number(t.port), kind: "companion", note: t.note });
        }
        await router.apply();
        for (const t of result.transports || []) await ctx.verifyTransport?.(t.id, { timeout: 5000 });
        await ladder.retryDue({ force: true });
      }
      return { result };
    },

    async companionNewIdentity() {
      return { result: await companion.send({ cmd: "newIdentity" }) };
    },

    async companionRefreshBridges({ viaSocks } = {}) {
      return { result: await companion.send({ cmd: "refreshBridges", viaSocks: Number(viaSocks) || 0 }, 45000) };
    },

    async companionDisconnect({ kind } = {}) {
      let result;
      try { result = await companion.send({ cmd: "disconnect", kind: kind || "" }); }
      catch (e) { result = { ok: false, error: String(e?.message || e) }; }
      const dpi = ["companion-dpi-record", "companion-dpi-segment"];
      const ids = kind === "tor" ? ["companion-tor"] : kind === "singbox" ? ["companion"] : kind === "dpi" ? dpi : ["companion", "companion-tor", ...dpi];
      for (const id of ids) {
        if (await transports.get(id)) {
          await transports.remove(id);
          await ladder.rehome(id);
        }
      }
      return { result };
    },

    async companionStatus() {
      try { return { status: await companion.send({ cmd: "status" }) }; }
      catch (e) { return { status: { ok: false, error: String(e?.message || e) } }; }
    },

    // ---- backup, reset, diagnostics ------------------------------------------

    // Settings, rules and your own transports. Proxy passwords only on request.
    async exportData({ includeSecrets = false } = {}) {
      const [s, rules, configs, activeTransportId] = await Promise.all([
        settings.get(), store.get("rules", {}), transports.configs(), transports.getActiveId()
      ]);
      const own = configs.filter((t) => t.kind !== "companion").map((t) => {
        const { auth, ...rest } = t;
        if (!auth) return rest;
        return { ...rest, auth: includeSecrets ? { ...auth } : { username: auth.username } };
      });
      return {
        data: {
          format: BACKUP_FORMAT, version: 1, exportedAt: new Date().toISOString(),
          app: api.runtime.getManifest?.().version, settings: s, rules, transports: own, activeTransportId
        }
      };
    },

    // Validates everything as if typed in; what doesn't fit is skipped and
    // reported, never half-applied.
    async importData({ data }) {
      if (!data || data.format !== BACKUP_FORMAT || data.version !== 1) throw new Error("that file isn't an OpenRoute backup");
      const report = { settings: 0, rules: 0, transports: 0, skipped: [], needsPassword: [] };
      const patch = {};
      for (const [k, v] of Object.entries(data.settings || {})) {
        if (SETTINGS_SCHEMA[k]?.(v)) {
          patch[k] = v;
          report.settings++;
        } else {
          report.skipped.push(`setting ${k}`);
        }
      }
      if (Object.keys(patch).length) await h.saveSettings({ patch });
      for (const list of ["always", "never"]) {
        for (const domain of Array.isArray(data.rules?.[list]) ? data.rules[list] : []) {
          try {
            await h.setRule({ domain, list });
            report.rules++;
          } catch {
            report.skipped.push(`rule ${String(domain).slice(0, 80)}`);
          }
        }
      }
      for (const t of Array.isArray(data.transports) ? data.transports : []) {
        if (!t || t.kind === "companion") continue;
        try {
          await transports.upsert(t);
          report.transports++;
          if (t.auth?.username && t.auth.password === undefined) report.needsPassword.push(String(t.label || t.id).slice(0, 60));
        } catch (e) {
          report.skipped.push(`transport ${String(t.label || t.id || "?").slice(0, 60)}: ${e.message}`);
        }
      }
      if (data.activeTransportId && (await transports.get(String(data.activeTransportId)))) await transports.setActiveId(String(data.activeTransportId));
      await router.apply();
      await ladder.retryDue({ force: true });
      return { report };
    },

    // Back to a fresh install: no sites, rules, settings or own transports.
    // The companion's transports stay (it still runs them) and so do the
    // presets.
    async resetAll() {
      await ladder.clearAll();
      await store.tx(["settings", "rules", "eventLog", "transports", "activeTransportId"], (d) => {
        const kept = (Array.isArray(d.transports) ? d.transports : []).filter((t) => t.kind === "companion");
        d.settings = undefined;
        d.rules = undefined;
        d.eventLog = undefined;
        d.activeTransportId = undefined;
        d.transports = kept.length ? [...presets(), ...kept] : undefined;
      });
      await router.apply();
      await ctx.applyWebRtc?.().catch(() => {});
      await updateBadge();
      return {};
    },

    // A report to attach to a bug: what OpenRoute saw and decided. Domains
    // are replaced by stand-ins unless asked otherwise; proxy addresses and
    // credentials never appear.
    async diagnosticsReport({ redactDomains = true } = {}) {
      const st = await h.getState();
      const alias = aliaser(redactDomains !== false);
      const policies = Object.fromEntries(Object.values(st.policies).map((p) => [alias(p.domain), {
        status: p.status, rung: p.rung, pinned: !!p.pinned, via: p.via || null, parent: alias(p.parent) || null,
        attempts: p.attempts || 0, exhaustedReason: p.exhaustedReason || null, transport: p.proxyId ? "(set)" : null
      }]));
      const sites = Object.fromEntries(Object.values(st.sites).map((s) => [alias(s.host), {
        type: s.type, errorCode: s.errorCode, errorKind: s.errorKind, count: s.count,
        dohUnreachable: !!s.dohUnreachable, injected: !!s.injected, localInjected: !!s.localInjected, echLikely: !!s.echLikely
      }]));
      const events = (await log.list(300)).map((e) => {
        const out = { ...e };
        for (const k of ["domain", "parent"]) if (out[k]) out[k] = alias(out[k]);
        if (out.host) out.host = alias(out.host);
        if (out.url) out.url = alias(hostFromUrl(out.url) || "url");
        if (out.proxy) out.proxy = "(proxy)";
        return out;
      });
      return {
        report: {
          generatedAt: new Date().toISOString(), version: st.version, browser: st.browser, capabilities: st.capabilities,
          router: st.router, access: st.access,
          settings: { ...st.settings, customDoH: st.settings.customDoH ? "(set)" : null },
          transports: st.transports.map((t) => ({
            kind: t.kind, scheme: t.scheme, local: t.host === "127.0.0.1" || t.host === "localhost", port: t.host === "127.0.0.1" ? t.port : undefined,
            health: t.health, latencyMs: t.latencyMs, failures: t.failures, successes: t.successes, auth: !!t.auth
          })),
          companion: st.companion, policies, sites, events, redactedDomains: redactDomains !== false
        }
      };
    }
  };
  return h;
}
