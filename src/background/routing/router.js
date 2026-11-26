// Router: compiles policy + transports into a routing table and hands it to
// the browser's proxy engine. Applies are serialized (a later apply always
// runs after, and sees the state of, every earlier one), so concurrent
// ladder decisions can never install a stale table.

import { compileRoutes } from "./table.js";
import { createChromiumEngine, createFirefoxEngine, createNullEngine } from "./engines.js";

export function createRouter({ api, caps, store, transports, log }) {
  const compile = async () => {
    const [policies, list] = await Promise.all([store.get("policies", {}), transports.configs()]);
    return compileRoutes({ policies, transports: list });
  };

  const engine = caps.proxyEngine === "firefox" ? createFirefoxEngine(api, { loadCompiled: compile })
    : caps.proxyEngine === "chromium" ? createChromiumEngine(api)
      : createNullEngine();

  let queue = Promise.resolve();
  let status = { engine: engine.name, level: engine.level, applied: false, count: 0, error: null, at: null };

  function apply() {
    const run = queue.then(async () => {
      const result = await engine.apply(await compile());
      status = { engine: engine.name, error: null, at: Date.now(), ...result };
      return result;
    });
    queue = run.catch((e) => {
      status = { ...status, engine: engine.name, error: String(e?.message || e), at: Date.now() };
      log?.add("router-error", { error: status.error });
    });
    return run;
  }

  return {
    engineName: engine.name,
    compile,
    apply,
    status: () => ({ ...status, level: engine.level ?? status.level }),
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
