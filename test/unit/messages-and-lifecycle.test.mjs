import { test } from "node:test";
import assert from "node:assert/strict";
import { bootExtension, firstHop } from "../helpers/harness.mjs";

test("messages from content scripts / web pages are refused", async () => {
  const ext = await bootExtension();
  const fromPage = await ext.mock.sendMessage({ type: "clearAll" }, { id: "openroute-test-id", url: "https://evil.example/", tab: { id: 3 } });
  assert.equal(fromPage, undefined, "no handler answered");
  const otherExt = await ext.mock.sendMessage({ type: "getState" }, { id: "some-other-extension" });
  assert.equal(otherExt, undefined);
  const ours = await ext.send("getState");
  assert.equal(ours.ok, true);
});

test("unknown message types are ignored, not crashed on", async () => {
  const ext = await bootExtension();
  assert.equal(await ext.mock.sendMessage({ type: "toString" }), undefined);
  assert.equal(await ext.mock.sendMessage({ type: "nope" }), undefined);
  assert.equal(await ext.mock.sendMessage(null), undefined);
});

test("settings and transports are validated", async () => {
  const ext = await bootExtension();
  assert.equal((await ext.send("saveSettings", { patch: { autoRoute: "yes" } })).ok, false);
  assert.equal((await ext.send("saveSettings", { patch: { evil: true } })).ok, false);
  assert.equal((await ext.send("saveSettings", { patch: { dohProvider: "nowhere" } })).ok, false);
  assert.equal((await ext.send("saveSettings", { patch: { dohProvider: "quad9" } })).settings.dohProvider, "quad9");

  for (const bad of [
    { scheme: "ftp", host: "h", port: 1 }, { scheme: "socks5", host: "", port: 1 },
    { scheme: "socks5", host: "bad host", port: 1 }, { scheme: "socks5", host: "h", port: 70000 },
    { scheme: "socks5", host: "h", port: 1, id: "<script>" }
  ]) {
    assert.equal((await ext.send("addTransport", { transport: bad })).ok, false, JSON.stringify(bad));
  }
  const good = await ext.send("addTransport", { transport: { scheme: "socks5", host: "127.0.0.1", port: 1080, label: "x".repeat(200) } });
  assert.equal(good.ok, true);
  assert.ok(good.transport.id.startsWith("t-"), "generated id");
  assert.equal(good.transport.label.length, 60, "label capped");
});

test("getState exposes capabilities, routing engine status and a Secure DNS guide", async () => {
  const ext = await bootExtension({ flavor: "chromium" });
  const s = await ext.send("getState");
  assert.equal(s.capabilities.proxyEngine, "chromium");
  assert.equal(s.router.engine, "chromium-pac");
  assert.match(s.secureDns.url, /^chrome:\/\/settings/);
  const ff = await bootExtension({ flavor: "firefox" });
  const fs = await ff.send("getState");
  assert.equal(fs.capabilities.proxyEngine, "firefox");
  assert.equal(fs.secureDns.url, null, "Firefox can't open about:preferences from an extension");
  assert.ok(fs.secureDns.steps.length > 0);
});

test("another extension controlling the proxy is detected and reported", async () => {
  const ext = await bootExtension({
    zone: { "c.example": { A: ["93.184.215.14"] } },
    setup: (m) => { m.state.settings.proxy.levelOfControl = "controlled_by_other_extensions"; }
  });
  await ext.send("addTransport", { transport: { id: "v", scheme: "socks5", host: "127.0.0.1", port: 1081 } });
  await ext.fail("https://c.example/", "net::ERR_CONNECTION_TIMED_OUT");
  const s = await ext.send("getState");
  assert.equal(s.router.level, "controlled_by_other_extensions");
  assert.equal(s.router.applied, false);
});

test("Firefox: after the event page is suspended, routed domains still go through the proxy", async () => {
  const ext = await bootExtension({ flavor: "firefox", zone: { "wake.example": { A: ["93.184.215.14"] } } });
  await ext.send("addTransport", { transport: { id: "v", scheme: "socks5", host: "127.0.0.1", port: 1081 } });
  await ext.fail("https://wake.example/", "Error code 2152398862");
  await ext.restart(); // listeners re-registered by a fresh instance; table must load lazily
  const hop = firstHop(await ext.route("https://wake.example/"));
  assert.equal(hop?.type, "socks");
  assert.equal(hop?.port, 1081);
});

test("Chromium: a worker restart restores routing without re-setting an identical PAC", async () => {
  const ext = await bootExtension({ zone: { "keep.example": { A: ["93.184.215.14"] } } });
  await ext.send("addTransport", { transport: { id: "v", scheme: "socks5", host: "127.0.0.1", port: 1081 } });
  await ext.fail("https://keep.example/", "net::ERR_CONNECTION_TIMED_OUT");
  const sets = ext.state.settings.proxy.history.length;
  await ext.restart();
  assert.equal(firstHop(await ext.route("https://keep.example/")), "SOCKS5 127.0.0.1:1081");
  assert.equal(ext.state.settings.proxy.history.length, sets, "no redundant proxy.settings.set (it would reset connections)");
});

test("install opens onboarding; init survives a corrupt storage value", async () => {
  const ext = await bootExtension({ setup: (m) => m.api.storage.local._load({ policies: "garbage", schemaVersion: 2 }) });
  await ext.api.runtime.onInstalled._fire({ reason: "install" });
  await ext.mock.settle();
  assert.ok(ext.state.createdTabs.some((t) => /onboarding\.html$/.test(t.url)));
  const s = await ext.send("getState");
  assert.equal(s.ok, true);
});
