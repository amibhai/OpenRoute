// End-to-end on the real Firefox: proxy.onRequest routing, the no-consent
// privacy path, and — the Phase 2 gate — routing still working after the
// background event page has been suspended.

import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { startSocks5 } from "../fixtures/socks5-server.mjs";
import { startTarget } from "../fixtures/target-server.mjs";
import { launchFirefox, firefoxAvailable } from "./helpers/firefox.mjs";
import { waitFor } from "./helpers/chromium.mjs";

const skip = !firefoxAvailable() && "Firefox or geckodriver not found (run: node scripts/setup-tools.mjs geckodriver)";

let target, socks, ff, DEAD_PORT;

function closedPort() {
  return new Promise((resolve) => {
    const s = net.createServer().listen(0, "127.0.0.1", () => { const { port } = s.address(); s.close(() => resolve(port)); });
  });
}

before(async () => {
  if (skip) return;
  DEAD_PORT = await closedPort();
  target = await startTarget();
  socks = await startSocks5({ resolve: () => ({ host: "127.0.0.1", port: target.port }) });
  ff = await launchFirefox({ localDomains: ["blocked.test", "sub.blocked.test", "direct.test"] });
  const add = await ff.send("addTransport", {
    transport: { id: "fixture", label: "Fixture SOCKS5", scheme: "socks5", host: "127.0.0.1", port: socks.port }
  });
  assert.equal(add?.ok, true, `addTransport: ${JSON.stringify(add)}`);
  await ff.send("setActiveTransport", { id: "fixture" });
});

after(async () => {
  await ff?.close();
  await socks?.close();
  await target?.close();
});

test("Firefox: a blocked domain is detected, routed via proxy.onRequest, reloaded and loads", { skip }, async () => {
  await ff.gotoAllowingError(`http://blocked.test:${DEAD_PORT}/`);
  await waitFor(async () => (await ff.textOf("who"))?.includes("OK from blocked.test"),
    { timeout: 30000, message: "the blocked page to load through the proxy" });
  assert.ok(socks.hosts().includes("blocked.test"), `proxy saw: ${socks.hosts()}`);
});

test("Firefox: no data consent → no domain was sent to a DoH resolver, yet routing worked", { skip }, async () => {
  await ff.openControl();
  const s = await ff.send("getState");
  assert.equal(s.access.dataConsent, false);
  assert.equal(s.sites["blocked.test"]?.dohSkipped, "consent");
  assert.equal(s.policies["blocked.test"]?.rung, "proxy");
  assert.equal(s.router.engine, "firefox-onrequest");
});

test("Firefox: split tunnel — an unblocked site never touches the proxy", { skip }, async () => {
  await ff.gotoAllowingError(`http://direct.test:${target.port}/`);
  assert.match(await ff.textOf("who") || "", /OK from direct\.test/);
  assert.ok(!socks.hosts().includes("direct.test"), `proxy saw: ${socks.hosts()}`);
});

test("Firefox: routing survives the event page being suspended (idle > timeout)", { skip }, async () => {
  await new Promise((r) => setTimeout(r, 9000)); // idle timeout is 3 s in this profile
  await ff.gotoAllowingError(`http://sub.blocked.test:${DEAD_PORT}/`);
  await waitFor(async () => (await ff.textOf("who"))?.includes("OK from sub.blocked.test"),
    { timeout: 20000, message: "a routed subdomain to load after the background was suspended" });
  assert.ok(socks.hosts().includes("sub.blocked.test"));
});
