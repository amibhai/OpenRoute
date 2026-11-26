// Phase 2: per-browser behavior — Firefox consent model, local DNS evidence,
// access reporting, per-browser Secure DNS guidance.

import { test } from "node:test";
import assert from "node:assert/strict";
import { bootExtension, firstHop } from "../helpers/harness.mjs";
import { secureDnsGuide, detectCapabilities } from "../../src/background/platform.js";
import { createWebExtMock } from "../helpers/webext-mock.mjs";

const IP = "93.184.215.14";
const addTransport = (ext) => ext.send("addTransport", { transport: { id: "v", scheme: "socks5", host: "127.0.0.1", port: 1081 } });

test("Firefox without data consent: zero DoH traffic, and blocked sites still get routed", async () => {
  const ext = await bootExtension({ flavor: "firefox", zone: { "quiet.example": { A: [IP] } } });
  await addTransport(ext);
  await ext.fail("https://quiet.example/", "Error code 2152398878"); // NS_ERROR_UNKNOWN_HOST
  assert.equal(ext.doh.queries.length, 0, "no domain left the browser for diagnosis");
  const site = await ext.site("quiet.example");
  assert.equal(site.dohSkipped, "consent");
  assert.equal(site.type, "dns-unverified");
  assert.equal(firstHop(await ext.route("https://quiet.example/"))?.port, 1081, "still routed");
});

test("Firefox with consent: DoH diagnosis runs", async () => {
  const ext = await bootExtension({
    flavor: "firefox", zone: { "loud.example": { A: [IP] } },
    setup: (m) => m.state.dataCollection.add("browsingActivity")
  });
  await ext.fail("https://loud.example/", "Error code 2152398878");
  assert.ok(ext.doh.queries.length > 0);
  assert.equal((await ext.site("loud.example")).type, "dns-tampering");
});

test("Chromium: the remoteDiagnosis setting turns DoH lookups off entirely", async () => {
  const ext = await bootExtension({ zone: { "opt.example": { A: [IP] } } });
  await ext.send("saveSettings", { patch: { remoteDiagnosis: false } });
  await ext.fail("https://opt.example/", "net::ERR_NAME_NOT_RESOLVED");
  assert.equal(ext.doh.queries.length, 0);
  assert.equal((await ext.site("opt.example")).dohSkipped, "consent");
});

test("Firefox local DNS evidence: a bogon system answer + real DoH answer = DNS tampering", async () => {
  const ext = await bootExtension({
    flavor: "firefox", zone: { "redirected.example": { A: [IP] } },
    setup: (m) => {
      m.state.dataCollection.add("browsingActivity");
      m.state.systemDns.set("redirected.example", ["10.10.34.36"]); // ISP block-page server
    }
  });
  await addTransport(ext);
  await ext.fail("https://redirected.example/", "Error code 2152398862"); // timeout to the block IP
  const site = await ext.site("redirected.example");
  assert.equal(site.localInjected, true);
  assert.deepEqual(site.localIPs, ["10.10.34.36"]);
  assert.equal(site.type, "dns-tampering", "not mistaken for an IP block");
  assert.equal((await ext.policy("redirected.example")).rung, "doh", "Secure DNS is the full-speed fix");
});

test("getState reports what access is missing, per browser", async () => {
  const ff = await bootExtension({ flavor: "firefox" });
  let s = await ff.send("getState");
  assert.deepEqual(s.access, { hostAccess: true, dataConsent: false, privateWindows: false });
  assert.equal(s.capabilities.needsHostAccessToRoute, true);
  ff.state.grantedOrigins.clear();
  s = await ff.send("getState");
  assert.equal(s.access.hostAccess, false, "revoking site access is detected");

  const cr = await bootExtension({ flavor: "chromium" });
  s = await cr.send("getState");
  assert.equal(s.access.dataConsent, null, "Chromium has no data-consent system");
  assert.equal(s.capabilities.needsHostAccessToRoute, false);
});

test("Secure DNS guidance per browser (URLs verified against real Edge 158 / Brave 158)", () => {
  assert.equal(secureDnsGuide({ family: "chromium", name: "Chrome" }).url, "chrome://settings/security");
  assert.equal(secureDnsGuide({ family: "chromium", name: "Edge" }).url, "edge://settings/privacy/security");
  assert.equal(secureDnsGuide({ family: "chromium", name: "Brave" }).url, "brave://settings/security");
  const ff = secureDnsGuide({ family: "firefox", name: "Firefox" });
  assert.equal(ff.url, null);
  assert.equal(ff.copyUrl, "about:preferences#privacy");
  assert.ok(secureDnsGuide({ family: "firefox", name: "Firefox", mobile: true }).steps.some((s) => /Settings/.test(s)));
});

test("capability detection picks the engine by API presence, never by name", () => {
  const cr = detectCapabilities(createWebExtMock({ flavor: "chromium" }).api);
  const ff = detectCapabilities(createWebExtMock({ flavor: "firefox" }).api);
  assert.equal(cr.proxyEngine, "chromium");
  assert.equal(ff.proxyEngine, "firefox", "Firefox also has proxy.settings — onRequest must win");
  assert.equal(detectCapabilities({ runtime: {} }).proxyEngine, "none");
  assert.equal(detectCapabilities({ runtime: {} }).canRoute, false);
});

test("a browser without a proxy API is diagnose-only (asks the user instead of routing)", async () => {
  const ext = await bootExtension({
    zone: { "safari.example": { A: [IP] } },
    setup: (m) => { delete m.api.proxy; }
  });
  await ext.fail("https://safari.example/", "net::ERR_CONNECTION_TIMED_OUT");
  const pol = await ext.policy("safari.example");
  assert.equal(pol.status, "needs-user");
  assert.equal(pol.exhaustedReason, "no-proxy-api");
  assert.equal((await ext.send("getState")).router.engine, "none");
});
