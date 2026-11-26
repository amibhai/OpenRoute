// Transport health, earned from real outcomes — never guessed.
//
// Stored apart from transport config (key "transportHealth") so frequent
// health writes never contend with user edits. A simple breaker:
//   success            → UP, streak reset
//   1–2 failures       → DEGRADED
//   3 failures in a row → DOWN (skipped by pickBest)
//   DOWN for > cooldown → UNKNOWN again (half-open: gets one more chance)

export const HEALTH = Object.freeze({ UP: "up", DEGRADED: "degraded", DOWN: "down", UNKNOWN: "unknown" });
export const DOWN_AFTER = 3;
export const DOWN_COOLDOWN_MS = 10 * 60 * 1000;

export function blankHealth() {
  return { state: HEALTH.UNKNOWN, successes: 0, failures: 0, streak: 0, lastOk: null, lastFail: null, latencyMs: null };
}

export function createHealth({ store, now = () => Date.now() }) {
  async function getAll() {
    return store.get("transportHealth", {});
  }

  async function record(id, ok, { latencyMs } = {}) {
    if (!id) return null;
    return store.tx(["transportHealth"], (d) => {
      const all = d.transportHealth || {};
      const h = { ...blankHealth(), ...(all[id] || {}) };
      if (ok) {
        h.successes += 1;
        h.streak = 0;
        h.lastOk = now();
        h.state = HEALTH.UP;
      } else {
        h.failures += 1;
        h.streak += 1;
        h.lastFail = now();
        h.state = h.streak >= DOWN_AFTER ? HEALTH.DOWN : HEALTH.DEGRADED;
      }
      if (latencyMs != null) h.latencyMs = Math.round(latencyMs);
      all[id] = h;
      d.transportHealth = all;
      return h;
    });
  }

  // Give DOWN transports a fresh shot once their cooldown has passed.
  async function recover(cooldownMs = DOWN_COOLDOWN_MS) {
    return store.tx(["transportHealth"], (d) => {
      const all = d.transportHealth || {};
      let recovered = 0;
      for (const h of Object.values(all)) {
        if (h.state === HEALTH.DOWN && now() - (h.lastFail || 0) > cooldownMs) {
          h.state = HEALTH.UNKNOWN;
          h.streak = 0;
          recovered++;
        }
      }
      d.transportHealth = all;
      return recovered;
    });
  }

  // Fold in measurements reported by the native companion.
  async function merge(reports = []) {
    if (!reports.length) return;
    return store.tx(["transportHealth"], (d) => {
      const all = d.transportHealth || {};
      for (const r of reports) {
        if (!r?.id || !Object.values(HEALTH).includes(r.health)) continue;
        const h = { ...blankHealth(), ...(all[r.id] || {}) };
        h.state = r.health;
        if (r.latencyMs != null) h.latencyMs = r.latencyMs;
        if (r.health === HEALTH.UP) { h.lastOk = now(); h.streak = 0; }
        all[r.id] = h;
      }
      d.transportHealth = all;
    });
  }

  async function forget(id) {
    return store.tx(["transportHealth"], (d) => {
      const all = d.transportHealth || {};
      delete all[id];
      d.transportHealth = all;
    });
  }

  return { getAll, record, recover, merge, forget };
}
