// Health monitor — keeps the transport roster honest over time.
//
// Routing outcomes already score transports in real time (transports.recordOutcome).
// This module runs on a chrome.alarms tick to (a) let a transport that was
// marked DOWN recover after a cooldown, so a brief outage isn't a life sentence,
// and (b) pull live health from the native companion once it exists.

import * as transports from "./transports.js";
import * as nm from "./nm-client.js";

const ALARM = "openroute-health";
const TICK_MINUTES = 5;
const DOWN_COOLDOWN_MS = 10 * 60 * 1000; // a DOWN transport gets another chance after 10 min

export function init() {
  chrome.alarms.create(ALARM, { periodInMinutes: TICK_MINUTES });
  chrome.alarms.onAlarm.addListener((a) => {
    if (a.name === ALARM) tick().catch((e) => console.warn("OpenRoute health tick:", e));
  });
}

async function tick() {
  await recoverStaleDown();
  await pullCompanionHealth();
}

// Give a DOWN transport a fresh shot once its cooldown has elapsed: reset it to
// UNKNOWN so pickBest() will consider it again instead of permanently avoiding it.
async function recoverStaleDown() {
  const all = await transports.list();
  let changed = false;
  const now = Date.now();
  for (const t of all) {
    if (t.health === transports.HEALTH.DOWN) {
      const since = t.lastOk || 0;
      if (now - since > DOWN_COOLDOWN_MS) {
        t.health = transports.HEALTH.UNKNOWN;
        t.streak = 0;
        changed = true;
      }
    }
  }
  if (changed) await transports.save(all);
}

// When the companion is installed it can actively measure each transport's
// latency/reachability far better than we can from the extension. Fold that in.
async function pullCompanionHealth() {
  if (!(await nm.isAvailable())) return;
  try {
    const report = await nm.send({ cmd: "health" });
    if (!report?.transports) return;
    const all = await transports.list();
    for (const rt of report.transports) {
      const t = all.find((x) => x.id === rt.id);
      if (t) {
        t.health = rt.health || t.health;
        t.latencyMs = rt.latencyMs ?? t.latencyMs;
        if (rt.health === transports.HEALTH.UP) t.lastOk = Date.now();
      }
    }
    await transports.save(all);
  } catch (e) {
    // Companion went away mid-tick — not fatal, health just stays as-is.
  }
}
