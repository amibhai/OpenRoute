// Characterization tests for ladder failure handling (reload loops, retry
// after exhaustion). Phase 0; see chromium-routing.test.mjs for conventions.

import { before, test } from "node:test";
import assert from "node:assert/strict";
import { setTimeout as sleep } from "node:timers/promises";
import { bootExtension } from "../../helpers/harness.mjs";

const ZONE = { "pinned.example": { A: ["93.184.215.14"] }, "flaky.example": { A: ["93.184.215.15"] } };

let ext;
before(async () => {
  ext = await bootExtension({ flavor: "chromium", zone: ZONE });
  await ext.send("addTransport", {
    transport: { id: "vps", label: "VPS", scheme: "socks5", host: "127.0.0.1", port: 1081, kind: "user" }
  });
  await ext.send("setActiveTransport", { id: "vps" });
  // Make "vps" the only transport, so exhaustion is reachable.
  for (const t of (await ext.view()).transports) {
    if (t.id !== "vps") await ext.send("removeTransport", { id: t.id });
  }
});

test("B1 — a pinned domain whose proxy is dead does not reload the tab forever", async () => {
  await ext.send("setRung", { domain: "pinned.example", rung: "proxy", proxyId: "vps" });
  for (let i = 0; i < 8; i++) {
    await ext.fail("https://pinned.example/", "net::ERR_PROXY_CONNECTION_FAILED", { tabId: 9 });
    await sleep(450); // longer than any reload settle delay
  }
  const n = ext.reloadsFor(9);
  assert.ok(n <= 3, `tab was auto-reloaded ${n} times for the same dead route (budget is ≤ 3)`);
});

test("B5 — an exhausted domain is retried after a backoff instead of abandoned forever", async (t) => {
  await ext.fail("https://flaky.example/", "net::ERR_CONNECTION_TIMED_OUT", { tabId: 11 });
  for (let i = 0; i < 10 && (await ext.policy("flaky.example"))?.status !== "exhausted"; i++) {
    await ext.fail("https://flaky.example/", "net::ERR_PROXY_CONNECTION_FAILED", { tabId: 11 });
  }
  assert.equal((await ext.policy("flaky.example"))?.status, "exhausted", "precondition: domain exhausted");

  t.mock.timers.enable({ apis: ["Date"], now: Date.now() });
  t.mock.timers.tick(25 * 60 * 60 * 1000); // a day later — past any backoff
  await ext.mock.fireAllAlarms();          // the periodic maintenance tick
  await ext.mock.settle();

  const pol = await ext.policy("flaky.example");
  assert.equal(pol?.status, "routing", `expected the ladder to retry; status is ${pol?.status}`);
  assert.equal((await ext.route("https://flaky.example/")).split(";")[0].trim(), "SOCKS5 127.0.0.1:1081",
    "the retried route is live in the PAC");
});
