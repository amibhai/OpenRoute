// Ladder behavior through the black-box harness: escalation, bounds,
// verification, self-healing, manual controls.

import { test } from "node:test";
import assert from "node:assert/strict";
import { setTimeout as sleep } from "node:timers/promises";
import { bootExtension, firstHop } from "../helpers/harness.mjs";

const IP = "93.184.215.14";
const zone = (...hosts) => Object.fromEntries(hosts.map((h) => [h, { A: [IP] }]));

async function withTransports(ext, ports) {
  for (const t of (await ext.view()).transports) await ext.send("removeTransport", { id: t.id });
  for (const p of ports) {
    await ext.send("addTransport", { transport: { id: `p${p}`, label: `P${p}`, scheme: "socks5", host: "127.0.0.1", port: p } });
  }
}

test("escalates through every transport, then backs off — each step bounded", async () => {
  const ext = await bootExtension({ zone: zone("esc.example") });
  await withTransports(ext, [3001, 3002, 3003]);
  await ext.fail("https://esc.example/", "net::ERR_CONNECTION_TIMED_OUT", { tabId: 4 });
  const used = [(await ext.policy("esc.example")).proxyId];
  for (let i = 0; i < 2; i++) {
    await ext.fail("https://esc.example/", "net::ERR_PROXY_CONNECTION_FAILED", { tabId: 4 });
    used.push((await ext.policy("esc.example")).proxyId);
  }
  assert.deepEqual(new Set(used), new Set(["p3001", "p3002", "p3003"]), "tried every transport once");
  await ext.fail("https://esc.example/", "net::ERR_PROXY_CONNECTION_FAILED", { tabId: 4 });
  const pol = await ext.policy("esc.example");
  assert.equal(pol.status, "exhausted");
  assert.equal(pol.exhaustedReason, "all-transports-failed");
  assert.ok(pol.retryAt > Date.now(), "a retry is scheduled");
  assert.equal(await ext.route("https://esc.example/"), "DIRECT", "an exhausted domain isn't routed into a dead end");
  await sleep(450);
  assert.ok(ext.reloadsFor(4) <= 3, `reloads ${ext.reloadsFor(4)} within budget`);
});

test("a successful load verifies the route and credits the transport", async () => {
  const ext = await bootExtension({ zone: zone("ver.example") });
  await withTransports(ext, [3101]);
  await ext.fail("https://ver.example/", "net::ERR_CONNECTION_RESET");
  await ext.ok("https://www.ver.example/page");
  const pol = await ext.policy("ver.example");
  assert.equal(pol.status, "fixed");
  assert.ok(pol.lastVerified);
  assert.equal((await ext.view()).transports.find((t) => t.id === "p3101").health, "up");
});

test("Secure DNS guidance first for DNS tampering; routed if it fails again", async () => {
  const ext = await bootExtension({ zone: zone("guide.example") });
  await withTransports(ext, [3201]);
  await ext.fail("https://guide.example/", "net::ERR_NAME_NOT_RESOLVED");
  let pol = await ext.policy("guide.example");
  assert.equal(pol.rung, "doh");
  assert.equal(pol.status, "needs-user");
  assert.equal(await ext.route("https://guide.example/"), "DIRECT", "guidance doesn't route");
  await ext.fail("https://guide.example/", "net::ERR_NAME_NOT_RESOLVED");
  pol = await ext.policy("guide.example");
  assert.equal(pol.rung, "proxy");
  assert.equal(firstHop(await ext.route("https://guide.example/")), "SOCKS5 127.0.0.1:3201");
});

test("a blocked domain that later loads directly self-heals to direct", async () => {
  const ext = await bootExtension({ zone: zone("heal.example") });
  await withTransports(ext, []);
  await ext.fail("https://heal.example/", "net::ERR_CONNECTION_TIMED_OUT");
  assert.equal((await ext.policy("heal.example")).status, "exhausted", "no transport → exhausted");
  await ext.ok("https://heal.example/");
  const pol = await ext.policy("heal.example");
  assert.equal(pol.rung, "direct");
  assert.equal(pol.status, "fixed");
  assert.equal(pol.retryAt, null);
});

test("adding a transport immediately rescues exhausted domains", async () => {
  const ext = await bootExtension({ zone: zone("rescue.example") });
  await withTransports(ext, []);
  await ext.fail("https://rescue.example/", "net::ERR_CONNECTION_TIMED_OUT");
  assert.equal((await ext.policy("rescue.example")).exhaustedReason, "no-transport");
  await ext.send("addTransport", { transport: { id: "new", label: "New", scheme: "socks5", host: "127.0.0.1", port: 3301 } });
  assert.equal((await ext.policy("rescue.example")).status, "routing");
  assert.equal(firstHop(await ext.route("https://rescue.example/")), "SOCKS5 127.0.0.1:3301");
});

test("auto-route off: nothing is routed, the user is asked", async () => {
  const ext = await bootExtension({ zone: zone("manual.example") });
  await withTransports(ext, [3401]);
  await ext.send("saveSettings", { patch: { autoRoute: false } });
  await ext.fail("https://manual.example/", "net::ERR_CONNECTION_TIMED_OUT");
  const pol = await ext.policy("manual.example");
  assert.equal(pol.status, "needs-user");
  assert.equal(pol.exhaustedReason, "auto-route-off");
  assert.equal(await ext.route("https://manual.example/"), "DIRECT");
});

test("detection off: failures are ignored entirely", async () => {
  const ext = await bootExtension({ zone: zone("off.example") });
  await ext.send("saveSettings", { patch: { detectionEnabled: false } });
  await ext.fail("https://off.example/", "net::ERR_CONNECTION_RESET");
  assert.equal(await ext.site("off.example"), null);
});

test("manual pins: proxy requires a real transport; direct/read-only are respected", async () => {
  const ext = await bootExtension();
  await withTransports(ext, [3501]);
  const bad = await ext.send("setRung", { domain: "pin.example", rung: "proxy", proxyId: "nope" });
  assert.equal(bad.ok, false);
  await ext.send("setRung", { domain: "pin.example", rung: "proxy", proxyId: "p3501" });
  assert.equal(firstHop(await ext.route("https://pin.example/")), "SOCKS5 127.0.0.1:3501");
  await ext.send("setRung", { domain: "pin.example", rung: "direct" });
  assert.equal(await ext.route("https://pin.example/"), "DIRECT");
  assert.equal((await ext.policy("pin.example")).status, "manual");
  await ext.send("setRung", { domain: "pin.example", rung: "auto" });
  assert.equal((await ext.policy("pin.example")).pinned, false);
});

test("a failing subdomain of a routed domain counts as that route failing", async () => {
  const ext = await bootExtension({ zone: zone("parent.example") });
  await withTransports(ext, [3601, 3602]);
  await ext.fail("https://parent.example/", "net::ERR_CONNECTION_TIMED_OUT");
  const first = (await ext.policy("parent.example")).proxyId;
  await ext.fail("https://cdn.parent.example/x.js", "net::ERR_PROXY_CONNECTION_FAILED");
  const second = (await ext.policy("parent.example")).proxyId;
  assert.notEqual(first, second);
  assert.equal(await ext.policy("cdn.parent.example"), null, "no separate policy for the subdomain");
});

test("NXDOMAIN (confirmed by DoH) is never routed", async () => {
  const ext = await bootExtension({ zone: { "nx.example": "NXDOMAIN" } });
  await withTransports(ext, [3701]);
  await ext.fail("https://nx.example/", "net::ERR_NAME_NOT_RESOLVED");
  const pol = await ext.policy("nx.example");
  assert.equal(pol.rung, "fallback");
  assert.equal(await ext.route("https://nx.example/"), "DIRECT");
  assert.equal((await ext.site("nx.example")).type, "dns-nxdomain");
});

test("a reload only happens while the tab still shows the failed site", async () => {
  const ext = await bootExtension({ zone: zone("away.example") });
  await withTransports(ext, [3801]);
  await ext.fail("https://away.example/", "net::ERR_CONNECTION_TIMED_OUT", { tabId: 21 });
  ext.mock.setFrame(21, 0, "https://elsewhere.example/"); // user navigated on
  await sleep(450);
  assert.equal(ext.reloadsFor(21), 0);
});
