// Storage layer. ALL persistent state goes through here.
//
// One FIFO queue serializes every read-modify-write across every key, so two
// events racing (a navigation error and a health tick, say) can never lose
// each other's updates. Reads are served from a write-through cache kept
// coherent by storage.onChanged.
//
// Rule: never call tx() from inside a tx() mutator — the queue is serial, so
// that would deadlock. Mutators get a draft object, change it in place (or set
// a key to undefined to delete it), and may return a value.

export const SCHEMA_VERSION = 2;

const clone = (v) => (v === undefined ? undefined : structuredClone(v));
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

export function createStore(area, { name = "local", onError } = {}) {
  const cache = new Map();
  let queue = Promise.resolve();

  async function raw(key) {
    if (cache.has(key)) return cache.get(key);
    const res = await area.get(key);
    const v = res?.[key];
    // Another write may have landed while we were reading; don't clobber it.
    if (!cache.has(key) && v !== undefined) cache.set(key, v);
    return cache.has(key) ? cache.get(key) : v;
  }

  return {
    name,

    // Called from the storage.onChanged listener the background registers.
    // onChanged events arrive asynchronously, possibly after later writes
    // already updated the cache — so never *apply* them (that could resurrect
    // an older value). If an event disagrees with the cache, drop the entry:
    // the next read goes to storage, which always holds the committed value.
    noteChanges(changes) {
      for (const [k, change] of Object.entries(changes || {})) {
        if (!cache.has(k)) continue;
        if (!same(cache.get(k), change.newValue)) cache.delete(k);
      }
    },

    async get(key, fallback) {
      const v = await raw(key);
      return v === undefined ? fallback : clone(v);
    },

    async getMany(keys) {
      const out = {};
      for (const k of keys) out[k] = clone(await raw(k));
      return out;
    },

    tx(keys, mutate) {
      const keyList = [].concat(keys);
      const run = queue.then(async () => {
        const before = {};
        for (const k of keyList) before[k] = clone(await raw(k));
        const draft = clone(before);
        const result = await mutate(draft);
        const sets = {};
        const removes = [];
        for (const k of keyList) {
          if (same(draft[k], before[k])) continue;
          if (draft[k] === undefined) removes.push(k);
          else sets[k] = draft[k];
        }
        if (Object.keys(sets).length) {
          await area.set(sets);
          for (const [k, v] of Object.entries(sets)) cache.set(k, clone(v));
        }
        if (removes.length) {
          await area.remove(removes);
          for (const k of removes) cache.delete(k);
        }
        return result;
      });
      queue = run.catch((e) => onError?.(e));
      return run;
    },

    // Wait for every queued write to land (tests, shutdown paths).
    flush() {
      return queue.then(() => undefined);
    }
  };
}

// storage.session when the browser has it (ephemeral, survives worker
// restarts, cleared on browser restart); an in-memory map otherwise.
export function createSessionArea(api) {
  if (api?.storage?.session) return api.storage.session;
  const data = new Map();
  return {
    async get(key) { return data.has(key) ? { [key]: structuredClone(data.get(key)) } : {}; },
    async set(items) { for (const [k, v] of Object.entries(items)) data.set(k, structuredClone(v)); },
    async remove(keys) { for (const k of [].concat(keys)) data.delete(k); }
  };
}

// ---- migrations ------------------------------------------------------------

// 0.3.x stored: blockedSites, domainPolicy, transports (health inline),
// settings, activeTransportId. v2 renames the maps and splits health out so
// config writes and health writes don't contend.
export async function migrate(store) {
  const version = await store.get("schemaVersion", 0);
  if (version >= SCHEMA_VERSION) return { migrated: false, from: version };
  await store.tx(["schemaVersion", "blockedSites", "domainPolicy", "sites", "policies", "transports", "transportHealth"], (d) => {
    if (d.blockedSites && !d.sites) {
      d.sites = {};
      for (const [host, s] of Object.entries(d.blockedSites)) {
        if (!s || typeof s !== "object") continue;
        const rest = { ...s };
        delete rest.remediation; // UI copy is derived from `type` now, not stored
        d.sites[host] = { ...rest, host };
      }
    }
    if (d.domainPolicy && !d.policies) {
      d.policies = {};
      for (const [domain, p] of Object.entries(d.domainPolicy)) {
        if (!p || typeof p !== "object") continue;
        d.policies[domain] = { ...p, domain, retryCount: p.retryCount || 0, retryAt: p.retryAt || null };
      }
    }
    if (Array.isArray(d.transports)) {
      d.transportHealth = d.transportHealth || {};
      d.transports = d.transports.map((t) => {
        const { health, successes, failures, streak, lastOk, latencyMs, ...cfg } = t;
        if (!d.transportHealth[t.id]) {
          d.transportHealth[t.id] = {
            state: health || "unknown", successes: successes || 0, failures: failures || 0,
            streak: streak || 0, lastOk: lastOk || null, lastFail: null, latencyMs: latencyMs ?? null
          };
        }
        return { enabled: true, ...cfg };
      });
    }
    d.blockedSites = undefined;
    d.domainPolicy = undefined;
    d.schemaVersion = SCHEMA_VERSION;
  });
  return { migrated: true, from: version };
}
