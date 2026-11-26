/* global chrome -- some callbacks run inside the extension service worker */
// End-to-end (real Chromium network stack): probe markers really reach the
// PAC (Chromium passes full http:// URLs to it), discovery finds a proxy that
// is actually listening on a well-known port, dead transports fail their
// probe, and the PAC's failover chain carries a site past a dead primary.

import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { startSocks5 } from "../fixtures/socks5-server.mjs";
import { startTarget } from "../fixtures/target-server.mjs";
import { launchWithExtension, waitFor } from "./helpers/chromium.mjs";
import { DISCOVERY_CANDIDATES } from "../../src/background/probe.js";

let target, socks, browser, deadPort, blockedPort;

const portFree = (port) => new Promise((resolve) => {
  const s = net.createServer().once("error", () => resolve(false)).listen(port, "127.0.0.1", () => s.close(() => resolve(true)));
});
const closedPort = () => new Promise((resolve) => {
  const s = net.createServer().listen(0, "127.0.0.1", () => { const { port } = s.address(); s.close(() => resolve(port)); });
});

before(async () => {
  target = await startTarget();
  // Listen on the first free well-known candidate port, like a real v2rayN/NekoBox would.
  let discoverPort = null;
  for (const c of DISCOVERY_CANDIDATES.filter((c) => c.scheme === "socks5" && c.port !== 9150 && c.port !== 9050)) {
    if (await portFree(c.port)) { discoverPort = c.port; break; }
  }
  assert.ok(discoverPort, "a candidate port is free for the fixture");
  socks = await startSocks5({ port: discoverPort, resolve: () => ({ host: "127.0.0.1", port: target.port }) });
  deadPort = await closedPort();
  blockedPort = await closedPort();
  browser = await launchWithExtension({ hostRules: ["MAP failover.test 127.0.0.1"] });
});

after(async () => {
  await browser?.close();
  await socks?.close();
  await target?.close();
});

test("discovery finds the proxy listening on a well-known port (probe markers reach the PAC)", async () => {
  const r = await browser.send("discoverLocalProxies");
  assert.equal(r?.ok, true, JSON.stringify(r));
  const hit = r.found.find((f) => f.port === socks.port);
  assert.ok(hit, `found: ${JSON.stringify(r.found)}`);
  assert.ok(socks.log.some((l) => l.host === "connectivitycheck.gstatic.com"), "the probe travelled through the proxy by name");
  const t = r.transports.find((x) => x.port === socks.port);
  assert.equal(t.health, "up");
  const state = await browser.send("getState");
  assert.notEqual(state.router.level, "controlled_by_this_extension", "proxy settings handed back after probing");
});

test("a transport nobody is listening on fails its probe", async () => {
  const add = await browser.send("addTransport", { transport: { id: "ghost", label: "Ghost", scheme: "socks5", host: "127.0.0.1", port: deadPort } });
  assert.equal(add.ok, true);
  assert.equal(add.probe.ok, false, JSON.stringify(add.probe));
  assert.equal(add.transports.find((t) => t.id === "ghost").health, "degraded");
});

test("pre-route probing skips a preferred transport that just failed its probe", async () => {
  await browser.send("setActiveTransport", { id: "ghost" }); // the user prefers the dead one
  const live = (await browser.send("getState")).transports.find((t) => t.port === socks.port);
  const page = await browser.context.newPage();
  await page.goto(`http://failover.test:${blockedPort}/`).catch(() => {});
  await waitFor(async () => (await page.textContent("#who").catch(() => null))?.includes("OK from failover.test"),
    { timeout: 25000, message: "the blocked site to load via the live transport" });
  const pol = (await browser.send("getState")).policies["failover.test"];
  assert.equal(pol.proxyId, live.id, "the dead preferred transport was skipped");
  await page.close();
});

test("Chromium's PAC failover carries a site past a dead primary hop", async () => {
  // An 'always' rule routes via the best chain; the user's preferred (dead)
  // transport is its primary hop, so the page only loads if Chromium falls
  // over to the next hop on its own.
  await browser.send("setRule", { domain: "chain.test", list: "always" });
  const route = await browser.worker.evaluate(async () => (await chrome.proxy.settings.get({})).value.pacScript?.data || "");
  assert.match(route, new RegExp(`127\\.0\\.0\\.1:${deadPort}`), "the dead transport is in the chain");
  const page = await browser.context.newPage();
  await page.goto(`http://chain.test:${target.port}/`);
  assert.match(await page.textContent("#who"), /OK from chain\.test/);
  assert.ok(socks.log.some((l) => l.host === "chain.test"), "delivered by the live fallback hop");
  await page.close();
});
