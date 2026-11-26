// End-to-end (real Chromium, deep detection opted in): a site whose direct
// path answers "451 Unavailable For Legal Reasons" is detected from the
// response itself (there is no navigation error at all), routed, reloaded,
// and the real page then loads through the proxy.

import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { startSocks5 } from "../fixtures/socks5-server.mjs";
import { startTarget } from "../fixtures/target-server.mjs";
import { launchWithExtension, waitFor } from "./helpers/chromium.mjs";

let censored, real, socks, browser;

before(async () => {
  censored = await startTarget({ statusFor: (h) => (h === "legal.test" ? 451 : 200) }); // the direct path
  real = await startTarget();                                                              // what the proxy reaches
  socks = await startSocks5({ resolve: () => ({ host: "127.0.0.1", port: real.port }) });
  browser = await launchWithExtension({ allUrls: true, hostRules: ["MAP legal.test 127.0.0.1"] });
  await browser.send("addTransport", { transport: { id: "fixture", label: "Fixture", scheme: "socks5", host: "127.0.0.1", port: socks.port } });
  await browser.send("setActiveTransport", { id: "fixture" });
});

after(async () => {
  await browser?.close();
  await socks?.close();
  await real?.close();
  await censored?.close();
});

test("HTTP 451 on the direct path → detected, routed, reloaded, real page loads", async () => {
  const page = await browser.context.newPage();
  await page.goto(`http://legal.test:${censored.port}/`);
  await waitFor(async () => (await page.textContent("#who").catch(() => null))?.includes("OK from legal.test"),
    { timeout: 25000, message: "the real page to load through the proxy" });
  assert.ok(censored.log.some((l) => l.host?.startsWith("legal.test")), "the direct path was hit first (and censored)");
  const s = await browser.send("getState");
  assert.equal(s.sites["legal.test"]?.type, "http-451");
  assert.equal(s.policies["legal.test"]?.rung, "proxy");
  assert.ok(socks.hosts().includes("legal.test"));
  await page.close();
});
