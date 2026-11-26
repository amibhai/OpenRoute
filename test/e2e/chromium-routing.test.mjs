// End-to-end: the real Chromium network stack runs OpenRoute's PAC.
//
//   blocked.test → mapped to a closed port on the direct path (connection
//                  refused, like an IP block). OpenRoute must diagnose it,
//                  route ONLY that domain through the SOCKS5 fixture, auto-
//                  reload, and the page must load through the proxy.
//   direct.test  → reachable directly; must never touch the proxy.

import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { startSocks5 } from "../fixtures/socks5-server.mjs";
import { startTarget } from "../fixtures/target-server.mjs";
import { launchWithExtension, waitFor } from "./helpers/chromium.mjs";

let target, socks, browser, DEAD_PORT;

// A port that was just free and is now closed: the direct path gets
// ERR_CONNECTION_REFUSED (an "IP block" stand-in). Well-known low ports are
// avoided — Chromium refuses many of them outright (ERR_UNSAFE_PORT).
function closedPort() {
  return new Promise((resolve) => {
    const s = net.createServer().listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

before(async () => {
  DEAD_PORT = await closedPort();
  target = await startTarget();
  socks = await startSocks5({ resolve: () => ({ host: "127.0.0.1", port: target.port }) });
  browser = await launchWithExtension({
    hostRules: ["MAP blocked.test 127.0.0.1", "MAP direct.test 127.0.0.1", "MAP sub.blocked.test 127.0.0.1"]
  });
  const add = await browser.send("addTransport", {
    transport: { id: "fixture", label: "Fixture SOCKS5", scheme: "socks5", host: "127.0.0.1", port: socks.port }
  });
  assert.equal(add?.ok, true, `addTransport: ${JSON.stringify(add)}`);
  await browser.send("setActiveTransport", { id: "fixture" });
});

after(async () => {
  await browser?.close();
  await socks?.close();
  await target?.close();
});

test("a blocked domain is detected, routed through the proxy, auto-reloaded and loads", async () => {
  const page = await browser.context.newPage();
  await page.goto(`http://blocked.test:${DEAD_PORT}/`).catch(() => {}); // fails on the direct path

  await waitFor(async () => (await page.textContent("#who").catch(() => null))?.includes("OK from blocked.test"),
    { timeout: 25000, message: "the blocked page to load through the proxy" });

  assert.ok(socks.hosts().includes("blocked.test"), `proxy saw: ${socks.hosts()}`);
  const state = await browser.send("getState");
  const pol = state.policies["blocked.test"];
  assert.equal(pol?.rung, "proxy");
  assert.equal(pol?.proxyId, "fixture");
  await waitFor(async () => (await browser.send("getState")).policies["blocked.test"]?.status === "fixed",
    { message: "the route to be verified" });
  assert.equal(state.router.engine, "chromium-pac");
  assert.equal(state.router.level, "controlled_by_this_extension");
  await page.close();
});

test("subdomains of a routed domain follow the route", async () => {
  const page = await browser.context.newPage();
  await page.goto(`http://sub.blocked.test:${DEAD_PORT}/`);
  assert.match(await page.textContent("#who"), /OK from sub\.blocked\.test/);
  assert.ok(socks.hosts().includes("sub.blocked.test"));
  await page.close();
});

test("split tunnel: an unblocked site never touches the proxy", async () => {
  const page = await browser.context.newPage();
  await page.goto(`http://direct.test:${target.port}/`);
  assert.match(await page.textContent("#who"), /OK from direct\.test/);
  assert.ok(!socks.hosts().includes("direct.test"), `proxy saw: ${socks.hosts()}`);
  await page.close();
});

test("the browser hands the hostname to the proxy (remote DNS, no local lookup)", async () => {
  const entry = socks.log.find((l) => l.host === "blocked.test");
  assert.ok(entry, "the proxy received a hostname, not an IP");
  assert.equal(entry.port, DEAD_PORT);
});
