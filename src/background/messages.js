// The popup/options/onboarding API. Every request is validated; pages never
// write storage directly, so the background's store stays the only writer.

import { RESOLVERS } from "./dns/doh.js";
import { secureDnsGuide } from "./platform.js";
import { normalizeHost, isValidHostname } from "../shared/hosts.js";

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

export function createHandlers(ctx, { updateBadge, getBrowser, getAccess, diagnoseHost }) {
  const { api, store, caps, transports, router, ladder, companion, settings, log } = ctx;

  async function upsertCompanionTransport(id, label, port, note) {
    await transports.upsert({ id, label, scheme: "socks5", host: "127.0.0.1", port, kind: "companion", note });
    await router.apply();
    await ladder.retryDue({ force: true });
  }

  return {
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
        settings: s, policies, sites, transports: list, activeTransportId, rules,
        companion: { available, supported: caps.nativeMessaging },
        router: router.status(), capabilities: caps, browser, access,
        secureDns: secureDnsGuide(browser), eventLog
      };
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

    async companionDisconnect({ kind } = {}) {
      let result;
      try { result = await companion.send({ cmd: "disconnect", kind: kind || "" }); }
      catch (e) { result = { ok: false, error: String(e?.message || e) }; }
      const ids = kind === "tor" ? ["companion-tor"] : kind === "singbox" ? ["companion"] : ["companion", "companion-tor"];
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
    }
  };
}
