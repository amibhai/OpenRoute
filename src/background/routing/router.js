// Router: compiles policy + transports + rules into a routing table and hands
// it to the browser's proxy engine. Applies are serialized (a later apply
// always runs after, and sees the state of, every earlier one), so concurrent
// ladder decisions can never install a stale table.

import { compileRoutes } from "./table.js";
import { createChromiumEngine, createFirefoxEngine, createNullEngine } from "./engines.js";
import { DISCOVERY_CANDIDATES } from "../probe.js";
import { RESOLVER_HOSTS } from "../dns/doh.js";

export function createRouter({ api, caps, store, session, transports, health, getSettings, log }) {
  // Domains briefly taken off the table (a direct re-check on Chromium). In
  // memory on purpose: if the worker dies mid-check, the route comes back.
  const excluded = new Set();

  const compile = async () => {
    const [policies, list, hs, settings, rules, dohVia, activeId] = await Promise.all([
      store.get("policies", {}), transports.configs(), health.getAll(), getSettings(),
      store.get("rules", {}), session.get("dohVia", null), transports.getActiveId()
    ]);
    const via = dohVia && dohVia.until > Date.now() ? dohVia.id : null;
    return compileRoutes({
      policies, transports: list, health: hs, mode: settings.mode, rules,
      dohVia: via, dohHosts: RESOLVER_HOSTS, candidates: DISCOVERY_CANDIDATES, activeId, exclude: excluded
    });
  };

  const engine = caps.proxyEngine === "firefox" ? createFirefoxEngine(api, { loadCompiled: compile })
    : caps.proxyEngine === "chromium" ? createChromiumEngine(api)
      : createNullEngine();

  let queue = Promise.resolve();
  let probing = 0;
  let status = { engine: engine.name, level: engine.level, applied: false, count: 0, error: null, at: null };

  function apply() {
    const run = queue.then(async () => {
      const result = await engine.apply(await compile(), { probing: probing > 0 });
      status = { engine: engine.name, error: null, at: Date.now(), ...result };
      return result;
    });
    queue = run.catch((e) => {
      status = { ...status, engine: engine.name, error: String(e?.message || e), at: Date.now() };
      log?.add("router-error", { error: status.error });
    });
    return run;
  }

  // Run fn while probe routes are live. On Chromium that may mean installing
  // the PAC just for the probe; refcounted so overlapping probes share it.
  async function withProbes(fn) {
    probing++;
    try {
      await apply();
      return await fn(canProbe());
    } finally {
      probing--;
      if (probing === 0) apply().catch(() => {});
    }
  }

  // Probes only mean something when our table decides the route.
  function canProbe() {
    if (engine.name === "firefox-onrequest") return true;
    return engine.name === "chromium-pac" && engine.level === "controlled_by_this_extension";
  }

  // Run fn with `domain` temporarily unrouted (so a plain request to it goes
  // direct), then restore the route — even if fn throws.
  async function withExclusion(domain, fn) {
    excluded.add(domain);
    try {
      await apply();
      return await fn();
    } finally {
      excluded.delete(domain);
      await apply().catch(() => {});
    }
  }

  return {
    engineName: engine.name,
    compile,
    apply,
    withProbes,
    withExclusion,
    canProbe,
    status: () => ({ ...status, level: engine.level ?? status.level }),
    // Route encrypted-DNS traffic through a transport for a while (when the
    // resolvers are unreachable directly).
    async useTransportForDoH(id, ms = 30 * 60 * 1000) {
      await session.tx(["dohVia"], (d) => { d.dohVia = id ? { id, until: Date.now() + ms } : undefined; });
      await apply();
    },
    // Must be called synchronously at worker start-up (Firefox wake-up).
    install(hooks = {}) {
      engine.install({
        onProxyError: (e) => { log?.add("proxy-error", { error: String(e?.error || e?.message || e) }); hooks.onProxyError?.(e); },
        onConflict: (level) => {
          log?.add("proxy-control", { level });
          if (level === "controllable_by_this_extension") apply().catch(() => {});
          hooks.onConflict?.(level);
        }
      });
    }
  };
}
