// Characterization tests for MV3 worker lifecycle behavior.

import { test } from "node:test";
import assert from "node:assert/strict";
import { bootExtension } from "../../helpers/harness.mjs";

test("A6 — a worker restart does not re-arm (postpone) existing periodic alarms", async () => {
  const ext = await bootExtension({ flavor: "chromium" });
  const created = ext.state.alarmCreates.length;
  assert.ok(created > 0, "the background schedules at least one periodic alarm");
  const names = [...ext.state.alarms.keys()];

  await ext.restart(); // the SW is killed after ~30 s idle and restarted by the next event

  const recreated = ext.state.alarmCreates.slice(created).filter((a) => names.includes(a.name));
  assert.deepEqual(recreated.map((a) => a.name), [],
    "re-creating an alarm with the same name resets its timer, so a busy worker would never tick");
});
