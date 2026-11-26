// The two proxy engines behind one interface, plus a null engine for
// browsers without a proxy API (diagnose-only).
//
//   chromium  chrome.proxy.settings in pac_script mode. Only one extension can
//             control proxy settings; we check levelOfControl and report
//             conflicts instead of silently doing nothing.
//   firefox   proxy.onRequest. The listener MUST be registered synchronously
//             at top level so a suspended event page is woken for requests;
//             on a cold wake it awaits the table from storage (listeners may
//             return a Promise).

import { buildPac } from "./pac.js";
import { matchRoute, firefoxDescriptor, signature, hasRealRoutes, probeIdFromUrl } from "./table.js";

const routeCount = (c) => Object.keys(c.routes || {}).length + (c.defaultRoute?.length ? 1 : 0);

export function createChromiumEngine(api) {
  let lastSig = null;
  let level = "unknown";

  async function readControl() {
    try {
      const s = await api.proxy.settings.get({ incognito: false });
      level = s?.levelOfControl || "unknown";
      return s;
    } catch {
      level = "unknown";
      return null;
    }
  }

  return {
    name: "chromium-pac",
    get level() { return level; },
    install({ onConflict, onProxyError } = {}) {
      api.proxy.onProxyError?.addListener((details) => onProxyError?.(details));
      api.proxy.settings.onChange?.addListener((d) => {
        level = d?.levelOfControl || level;
        onConflict?.(level);
      });
    },
    async apply(compiled, { probing = false } = {}) {
      const current = await readControl();
      if (level === "not_controllable" || level === "controlled_by_other_extensions") {
        lastSig = null;
        return { applied: false, level, count: routeCount(compiled) };
      }
      const sig = signature(compiled);
      // Only hold the proxy setting while something is really routed (or a
      // health probe is running). An idle PAC would answer DIRECT for every
      // request and silently override an OS/corporate proxy.
      if (!hasRealRoutes(compiled) && !probing) {
        if (level === "controlled_by_this_extension") await api.proxy.settings.clear({ scope: "regular" });
        lastSig = sig;
        return { applied: true, cleared: true, level: "controllable_by_this_extension", count: 0 };
      }
      const pac = buildPac(compiled);
      const alreadyLive = level === "controlled_by_this_extension" &&
        current?.value?.mode === "pac_script" && current.value.pacScript?.data === pac;
      if (sig === lastSig && alreadyLive) return { applied: true, unchanged: true, level, count: routeCount(compiled) };
      if (!alreadyLive) {
        await api.proxy.settings.set({ value: { mode: "pac_script", pacScript: { data: pac, mandatory: false } }, scope: "regular" });
      }
      lastSig = sig;
      level = "controlled_by_this_extension";
      return { applied: true, level, count: routeCount(compiled) };
    }
  };
}

export function createFirefoxEngine(api, { loadCompiled }) {
  let table = null;
  let loading = null;

  function decide(compiled, details) {
    const chain = matchRoute(compiled, details.url);
    if (chain && chain.length) {
      // No trailing {type:"direct"}: a routed domain must not fall back to the
      // censored path. Firefox tries each proxy in order.
      return chain.map((t) => ({ ...firefoxDescriptor(t), failoverTimeout: 5 }));
    }
    // A "direct" health probe must really go direct; anything else that isn't
    // ours returns nothing, so Firefox applies the user's own proxy settings.
    if (chain && probeIdFromUrl(details.url)) return { type: "direct" };
    return undefined;
  }

  function ensure() {
    if (table) return Promise.resolve(table);
    if (!loading) {
      loading = loadCompiled()
        .then((c) => { table = table || c; return table; })
        .finally(() => { loading = null; });
    }
    return loading;
  }

  function onRequest(details) {
    if (table) return decide(table, details);
    return ensure().then((t) => decide(t, details), () => undefined);
  }

  return {
    name: "firefox-onrequest",
    level: "controlled_by_this_extension",
    install({ onProxyError } = {}) {
      api.proxy.onRequest.addListener(onRequest, { urls: ["<all_urls>"] });
      api.proxy.onError?.addListener((e) => onProxyError?.(e));
    },
    async apply(compiled) {
      table = compiled;
      return { applied: true, level: "controlled_by_this_extension", count: routeCount(compiled) };
    }
  };
}

export function createNullEngine() {
  return {
    name: "none",
    level: "not_controllable",
    install() {},
    async apply(compiled) {
      return { applied: false, level: "not_controllable", reason: "this browser has no proxy API", count: routeCount(compiled) };
    }
  };
}
