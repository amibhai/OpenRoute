// Proxy authentication, de-escalation (direct re-checks) and WebRTC protection.

import { test } from "node:test";
import assert from "node:assert/strict";
import { bootExtension, firstHop } from "../helpers/harness.mjs";

const PUBLIC = "93.184.215.14";
const DAY = 24 * 3600e3;

async function auth(ext, details) {
  const listener = ext.api.webRequest.onAuthRequired._listeners[0];
  assert.ok(listener, "an onAuthRequired listener is registered");
  assert.deepEqual(listener.extra[1], ["asyncBlocking"]);
  return new Promise((resolve) => listener.fn(details, resolve));
}

test("Chromium answers HTTP proxy logins for its transports, and never loops on bad credentials", async () => {
  const ext = await bootExtension();
  const r = await ext.send("addTransport", { transport: { id: "corp", scheme: "http", host: "proxy.example.net", port: 3128, auth: { username: "alice", password: "s3cret" } } });
  assert.equal(r.ok, true, r.error);
  const challenge = { requestId: "1", isProxy: true, challenger: { host: "proxy.example.net", port: 3128 } };
  assert.deepEqual(await auth(ext, challenge), { authCredentials: { username: "alice", password: "s3cret" } });
  assert.deepEqual(await auth(ext, challenge), { cancel: true }, "second challenge = rejected credentials");
  assert.deepEqual(await auth(ext, { requestId: "2", isProxy: false, challenger: { host: "site.example", port: 443 } }), {}, "site logins untouched");
  assert.deepEqual(await auth(ext, { requestId: "3", isProxy: true, challenger: { host: "other.example", port: 8080 } }), {});
});

test("passwords never reach the UI, and editing a transport without one keeps it", async () => {
  const ext = await bootExtension();
  await ext.send("addTransport", { transport: { id: "corp", scheme: "https", host: "proxy.example.net", port: 443, auth: { username: "alice", password: "s3cret" } } });
  const t = (await ext.view()).transports.find((x) => x.id === "corp");
  assert.deepEqual(t.auth, { username: "alice", hasPassword: true });
  assert.ok(!JSON.stringify(await ext.view()).includes("s3cret"));
  await ext.send("addTransport", { transport: { id: "corp", label: "Renamed", auth: { username: "alice" } } });
  const challenge = { requestId: "9", isProxy: true, challenger: { host: "proxy.example.net", port: 443 } };
  assert.deepEqual(await auth(ext, challenge), { authCredentials: { username: "alice", password: "s3cret" } });
});

test("SOCKS + credentials: refused on Chromium (it can't do SOCKS auth), carried by Firefox", async () => {
  const cr = await bootExtension();
  const bad = await cr.send("addTransport", { transport: { scheme: "socks5", host: "h.example", port: 1080, auth: { username: "u", password: "p" } } });
  assert.equal(bad.ok, false);
  assert.match(bad.error, /SOCKS/);

  const ff = await bootExtension({ flavor: "firefox", zone: { "s.example": { A: [PUBLIC] } } });
  await ff.send("addTransport", { transport: { id: "s", scheme: "socks5", host: "127.0.0.1", port: 6001, auth: { username: "u", password: "p" } } });
  await ff.send("setActiveTransport", { id: "s" });
  await ff.fail("https://s.example/", "Error code 2152398862");
  const hop = firstHop(await ff.route("https://s.example/"));
  assert.equal(hop.username, "u");
  assert.equal(hop.password, "p");
});

async function routedAndAged(ext, domain, { lastVisitedAgo = 2 * DAY } = {}) {
  for (const t of (await ext.view()).transports) await ext.send("removeTransport", { id: t.id });
  await ext.send("addTransport", { transport: { id: "t", scheme: "socks5", host: "127.0.0.1", port: 6101 } });
  await ext.fail(`https://${domain}/`, ext.state.flavor === "firefox" ? "Error code 2152398862" : "net::ERR_CONNECTION_TIMED_OUT");
  await ext.ok(`https://${domain}/`);
  const { policies } = await ext.mock.api.storage.local.get("policies");
  policies[domain].recheckAt = Date.now() - 1000;
  policies[domain].lastVisited = Date.now() - lastVisitedAgo;
  await ext.mock.api.storage.local.set({ policies });
  await ext.mock.settle();
}

async function tick(ext) {
  await ext.mock.fireAllAlarms();
  await ext.mock.settle();
}

for (const flavor of ["firefox", "chromium"]) {
  test(`${flavor}: a lifted block is noticed — two direct passes demote the site back to direct`, async () => {
    const ext = await bootExtension({ flavor, zone: { "lifted.example": { A: [PUBLIC] } } });
    await routedAndAged(ext, "lifted.example");
    await tick(ext);
    let pol = await ext.policy("lifted.example");
    assert.equal(pol.directPasses, 1, "first pass");
    assert.equal(pol.rung, "proxy", "one pass isn't enough");
    await ext.mock.api.storage.local.get("policies").then(async ({ policies }) => {
      policies["lifted.example"].recheckAt = Date.now() - 1000;
      await ext.mock.api.storage.local.set({ policies });
    });
    await ext.mock.settle();
    await tick(ext);
    pol = await ext.policy("lifted.example");
    assert.equal(pol.rung, "direct");
    assert.equal(pol.status, "fixed");
    assert.ok(!Array.isArray(await ext.route("https://lifted.example/")) || flavor === "chromium");
    const direct = ext.net.log.filter((l) => l.via === "direct" && l.url.startsWith("https://lifted.example/"));
    assert.ok(direct.length >= 2, "the checks really went direct");
  });

  test(`${flavor}: still blocked directly → stays routed and checks back later`, async () => {
    const ext = await bootExtension({ flavor, zone: { "stuck.example": { A: [PUBLIC] } } });
    ext.net.blockDirect("stuck.example");
    await routedAndAged(ext, "stuck.example");
    await tick(ext);
    const pol = await ext.policy("stuck.example");
    assert.equal(pol.rung, "proxy");
    assert.equal(pol.recheckCount, 1);
    assert.ok(pol.recheckAt > Date.now() + 2 * DAY, "backs off (days, not hours)");
  });
}

test("chromium: a site in active use is never unrouted for a check", async () => {
  const ext = await bootExtension({ zone: { "busy.example": { A: [PUBLIC] } } });
  await routedAndAged(ext, "busy.example", { lastVisitedAgo: 60 * 1000 });
  const sets = ext.state.settings.proxy.history.length;
  await tick(ext);
  assert.equal((await ext.policy("busy.example")).rung, "proxy");
  assert.equal(ext.state.settings.proxy.history.length, sets, "the PAC wasn't touched");
});

test("WebRTC protection: applied with the optional permission, removed when turned off", async () => {
  const ext = await bootExtension();
  let r = await ext.send("saveSettings", { patch: { webrtcProtection: true } });
  assert.equal(r.webrtc.applied, true);
  assert.equal(ext.state.settings.webRTCIPHandlingPolicy.value, "disable_non_proxied_udp");
  r = await ext.send("saveSettings", { patch: { webrtcProtection: false } });
  assert.equal(r.webrtc.applied, true);
  assert.equal(ext.state.settings.webRTCIPHandlingPolicy.value, "default");

  const noPerm = await bootExtension({ setup: (m) => { delete m.api.privacy; } });
  r = await noPerm.send("saveSettings", { patch: { webrtcProtection: true } });
  assert.equal(r.webrtc.applied, false);
  assert.match(r.webrtc.reason, /privacy/);
});
