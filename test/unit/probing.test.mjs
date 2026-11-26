// Active probing, discovery, failover chains, modes, rules, DoH-via-transport.
// The network simulator delivers each request along the route the browser
// would really take (PAC on Chromium, onRequest on Firefox).

import { test } from "node:test";
import assert from "node:assert/strict";
import { bootExtension, firstHop } from "../helpers/harness.mjs";
import { DISCOVERY_CANDIDATES } from "../../src/background/probe.js";

const IP = "93.184.215.14";
const zone = (...hosts) => Object.fromEntries(hosts.map((h) => [h, { A: [IP] }]));

async function onlyTransports(ext, specs) {
  for (const t of (await ext.view()).transports) await ext.send("removeTransport", { id: t.id });
  for (const s of specs) await ext.send("addTransport", { transport: { scheme: "socks5", host: "127.0.0.1", ...s } });
}

test("adding a transport probes it immediately: live → up, dead → degraded", async () => {
  const ext = await bootExtension();
  ext.net.dead(4002);
  await onlyTransports(ext, [{ id: "live", port: 4001 }, { id: "dead", port: 4002 }]);
  const ts = Object.fromEntries((await ext.view()).transports.map((t) => [t.id, t]));
  assert.equal(ts.live.health, "up");
  assert.ok(ts.live.latencyMs >= 0);
  assert.equal(ts.dead.health, "degraded");
  assert.ok(ext.net.log.some((l) => l.via === 4001 && /generate_204/.test(l.url)), "the probe really went through the transport");
});

test("pre-route probing skips a dead preset (Tor Browser not running) and uses a live transport", async () => {
  const ext = await bootExtension({ zone: zone("skip.example") });
  ext.net.dead(9150, 9050); // presets are listed but nothing is listening
  await ext.send("addTransport", { transport: { id: "vps", scheme: "socks5", host: "127.0.0.1", port: 4101 } });
  await ext.send("setActiveTransport", { id: "tor-browser" }); // even if the user prefers the dead one
  await ext.fail("https://skip.example/", "net::ERR_CONNECTION_TIMED_OUT");
  assert.equal((await ext.policy("skip.example")).proxyId, "vps");
  assert.equal(firstHop(await ext.route("https://skip.example/")), "SOCKS5 127.0.0.1:4101");
});

test("a proxy that answers with a block page is treated as broken", async () => {
  const ext = await bootExtension();
  ext.net.intercepting(4201);
  await onlyTransports(ext, [{ id: "mitm", port: 4201 }]);
  const r = await ext.send("probeTransport", { id: "mitm" });
  assert.equal(r.result.ok, false);
  assert.equal(r.result.intercepted, true);
});

test("discovery finds proxies already running locally and adds them", async () => {
  const ext = await bootExtension();
  ext.net.dead(...DISCOVERY_CANDIDATES.map((c) => c.port).filter((p) => p !== 10808 && p !== 9150));
  const r = await ext.send("discoverLocalProxies");
  assert.equal(r.ok, true);
  assert.equal(r.tested, DISCOVERY_CANDIDATES.length);
  assert.deepEqual(r.found.map((f) => f.port).sort((a, b) => a - b), [9150, 10808]);
  const v2 = r.transports.find((t) => t.port === 10808);
  assert.equal(v2.label, "v2rayN / v2rayNG");
  assert.equal(v2.health, "up");
  assert.equal(r.found.find((f) => f.port === 9150).added, false, "existing Tor Browser preset reused, not duplicated");
  assert.equal(r.transports.filter((t) => t.port === 9150).length, 1);
});

test("Chromium: probes never leave a PAC installed when nothing is routed (OS proxy stays in charge)", async () => {
  const ext = await bootExtension();
  await onlyTransports(ext, [{ id: "a", port: 4301 }]);
  await ext.send("probeTransport", { id: "a" });
  await ext.mock.settle();
  assert.notEqual(ext.state.settings.proxy.value.mode, "pac_script", "proxy settings handed back after the probe");
  assert.ok(ext.state.settings.proxy.cleared > 0);
});

test("Firefox: requests we don't route are left to the browser's own proxy settings", async () => {
  const ext = await bootExtension({ flavor: "firefox" });
  const listener = ext.api.proxy.onRequest._listeners[0].fn;
  assert.equal(await listener({ url: "https://unrelated.example/" }), undefined);
});

test("full-tunnel mode routes everything except local addresses and 'never' rules", async () => {
  const ext = await bootExtension();
  await onlyTransports(ext, [{ id: "t", port: 4401 }]);
  await ext.send("setRule", { domain: "bank.example", list: "never" });
  await ext.send("saveSettings", { patch: { mode: "full" } });
  assert.equal(firstHop(await ext.route("https://anything.example/")), "SOCKS5 127.0.0.1:4401");
  assert.equal(await ext.route("https://www.bank.example/"), "DIRECT");
  assert.equal(await ext.route("http://192.168.1.1/"), "DIRECT");
  await ext.send("saveSettings", { patch: { mode: "off" } });
  assert.equal(await ext.route("https://anything.example/"), "DIRECT");
  assert.notEqual(ext.state.settings.proxy.value.mode, "pac_script", "off means hands off the proxy settings");
});

test("'always' rules route a domain proactively; 'never' rules stop the ladder from touching it", async () => {
  const ext = await bootExtension({ zone: zone("leave.example") });
  await onlyTransports(ext, [{ id: "t", port: 4501 }]);
  await ext.send("setRule", { domain: "news.example", list: "always" });
  assert.equal(firstHop(await ext.route("https://cdn.news.example/a.js")), "SOCKS5 127.0.0.1:4501");
  await ext.send("setRule", { domain: "leave.example", list: "never" });
  await ext.fail("https://leave.example/", "net::ERR_CONNECTION_TIMED_OUT");
  assert.equal(await ext.policy("leave.example"), null);
  const r = await ext.send("setRule", { domain: "news.example", list: null });
  assert.deepEqual(r.rules.always, []);
  assert.equal(await ext.route("https://cdn.news.example/"), "DIRECT");
  assert.equal((await ext.send("setRule", { domain: "x.example", list: "sometimes" })).ok, false);
});

test("when encrypted DNS is blocked, the resolvers are reached through a transport", async () => {
  const ext = await bootExtension({ zone: zone("dohblock.example"), dohDown: true });
  await onlyTransports(ext, [{ id: "t", port: 4601 }]);
  await ext.fail("https://dohblock.example/", "net::ERR_NAME_NOT_RESOLVED");
  await ext.mock.settle();
  assert.equal((await ext.policy("dohblock.example")).rung, "proxy", "routed without waiting");
  assert.equal(firstHop(await ext.route("https://cloudflare-dns.com/dns-query")), "SOCKS5 127.0.0.1:4601");
  assert.equal(firstHop(await ext.route("https://8.8.8.8/dns-query")), "SOCKS5 127.0.0.1:4601");
});

test("maintenance re-probes transports carrying traffic and notices one that died", async () => {
  const ext = await bootExtension({ zone: zone("live.example") });
  await onlyTransports(ext, [{ id: "t", port: 4701 }]);
  await ext.fail("https://live.example/", "net::ERR_CONNECTION_TIMED_OUT");
  ext.net.dead(4701);
  const h0 = (await ext.view()).transports[0].health;
  assert.equal(h0, "up");
  // Make the last probe look old, then tick maintenance.
  await ext.mock.api.storage.local.get("transportHealth").then(async ({ transportHealth }) => {
    transportHealth.t.lastProbe = Date.now() - 60 * 60 * 1000;
    await ext.mock.api.storage.local.set({ transportHealth });
  });
  await ext.mock.settle();
  await ext.mock.fireAllAlarms();
  await ext.mock.settle();
  assert.equal((await ext.view()).transports[0].health, "degraded");
});

test("registrable-domain routing: www.news.co.uk routes news.co.uk and its siblings, never co.uk", async () => {
  const ext = await bootExtension({ zone: zone("www.news.co.uk") });
  await onlyTransports(ext, [{ id: "t", port: 4801 }]);
  await ext.fail("https://www.news.co.uk/story", "net::ERR_CONNECTION_TIMED_OUT");
  assert.ok(await ext.policy("news.co.uk"), "policy keyed by the registrable domain");
  assert.equal(firstHop(await ext.route("https://static.news.co.uk/app.js")), "SOCKS5 127.0.0.1:4801");
  assert.equal(await ext.route("https://other.co.uk/"), "DIRECT");
  assert.ok(await ext.site("www.news.co.uk"), "the diagnosis stays per host");
});

test("routeScope=host keeps the policy to the exact host", async () => {
  const ext = await bootExtension({ zone: zone("www.exact.co.uk") });
  await onlyTransports(ext, [{ id: "t", port: 4802 }]);
  await ext.send("saveSettings", { patch: { routeScope: "host" } });
  await ext.fail("https://www.exact.co.uk/", "net::ERR_CONNECTION_TIMED_OUT");
  assert.ok(await ext.policy("www.exact.co.uk"));
  assert.equal(await ext.route("https://static.exact.co.uk/"), "DIRECT");
});

test("bundles: routing youtube.com also routes its video CDN; verification and removal follow", async () => {
  const ext = await bootExtension({ zone: zone("www.youtube.com") });
  await onlyTransports(ext, [{ id: "t", port: 4901 }]);
  await ext.fail("https://www.youtube.com/watch?v=x", "net::ERR_CONNECTION_RESET");
  assert.equal(firstHop(await ext.route("https://rr1---sn-abc.googlevideo.com/videoplayback")), "SOCKS5 127.0.0.1:4901");
  assert.equal(firstHop(await ext.route("https://i.ytimg.com/vi/x/hq.jpg")), "SOCKS5 127.0.0.1:4901");
  const sib = await ext.policy("googlevideo.com");
  assert.equal(sib.via, "bundle");
  assert.equal(sib.parent, "youtube.com");
  await ext.ok("https://www.youtube.com/watch?v=x");
  assert.equal((await ext.policy("googlevideo.com")).status, "fixed", "parent verified ⇒ bundle verified");
  await ext.send("clearDomain", { domain: "youtube.com" });
  assert.equal(await ext.policy("googlevideo.com"), null, "bundle members removed with their parent");
  assert.equal(await ext.site("www.youtube.com"), null, "diagnoses under the domain removed too");
  assert.equal(await ext.route("https://rr1---sn-abc.googlevideo.com/"), "DIRECT");
});

test("bundles can be turned off", async () => {
  const ext = await bootExtension({ zone: zone("x.com") });
  await onlyTransports(ext, [{ id: "t", port: 4902 }]);
  await ext.send("saveSettings", { patch: { bundles: false } });
  await ext.fail("https://x.com/", "net::ERR_CONNECTION_RESET");
  assert.equal(await ext.policy("twimg.com"), null);
});
