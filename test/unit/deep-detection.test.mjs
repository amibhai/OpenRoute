// Deep detection: block pages that "load", HTTP 451, blocked subresources —
// and the guards that keep normal setups (system proxies, Pi-hole, our own
// probes) from being mistaken for censorship.

import { test } from "node:test";
import assert from "node:assert/strict";
import { bootExtension, firstHop } from "../helpers/harness.mjs";

const PUBLIC = "93.184.215.14";

async function withTransport(ext, port = 5001) {
  for (const t of (await ext.view()).transports) await ext.send("removeTransport", { id: t.id });
  await ext.send("addTransport", { transport: { id: "t", scheme: "socks5", host: "127.0.0.1", port } });
}

async function response(ext, url, ip, extra = {}) {
  await ext.api.webRequest.onResponseStarted._fire({
    type: "main_frame", tabId: extra.tabId ?? 1, frameId: 0, url, ip, statusCode: extra.statusCode ?? 200, ...extra
  });
  await ext.mock.settle();
}

test("a block page served from an injected private address is detected and routed", async () => {
  const ext = await bootExtension({ zone: { "news.example": { A: [PUBLIC] } } });
  await withTransport(ext);
  await response(ext, "https://ok1.example/", "142.250.1.1");   // normal pages, public addresses
  await response(ext, "https://ok2.example/", "151.101.1.1");
  ext.mock.setFrame(7, 0, "https://news.example/");
  await response(ext, "https://news.example/", "10.10.34.36", { tabId: 7 }); // ISP block-page server
  const site = await ext.site("news.example");
  assert.equal(site?.type, "dns-blockpage");
  assert.equal((await ext.policy("news.example"))?.rung, "proxy");
  assert.equal(firstHop(await ext.route("https://news.example/")), "SOCKS5 127.0.0.1:5001");
});

test("guard: an address serving most pages is a (corporate) proxy, not DNS injection", async () => {
  const ext = await bootExtension({ zone: { "a.example": { A: [PUBLIC] }, "b.example": { A: [PUBLIC] }, "c.example": { A: [PUBLIC] } } });
  await withTransport(ext);
  for (const h of ["a.example", "b.example", "c.example"]) await response(ext, `https://${h}/`, "10.0.0.1");
  assert.equal(await ext.site("c.example"), null);
  assert.equal(await ext.policy("c.example"), null);
});

test("guard: loopback (local proxy, Pi-hole sinkhole) and first-ever page are never accused", async () => {
  const ext = await bootExtension({ zone: { "first.example": { A: [PUBLIC] }, "lo.example": { A: [PUBLIC] } } });
  await withTransport(ext);
  await response(ext, "https://first.example/", "10.10.34.36"); // no contrast yet
  assert.equal(await ext.site("first.example"), null);
  await response(ext, "https://ok.example/", "142.250.1.1");
  await response(ext, "https://lo.example/", "127.0.0.1");
  assert.equal(await ext.site("lo.example"), null);
});

test("guard: an injected-looking address that encrypted DNS also returns is not injection", async () => {
  const ext = await bootExtension({ zone: { "intranet.example": { A: ["10.1.2.3"] } } });
  await withTransport(ext);
  await response(ext, "https://ok.example/", "142.250.1.1");
  await response(ext, "https://intranet.example/", "10.1.2.3");
  assert.equal(await ext.policy("intranet.example"), null);
});

test("HTTP 451 (Unavailable For Legal Reasons) is routed", async () => {
  const ext = await bootExtension({ zone: { "legal.example": { A: [PUBLIC] } } });
  await withTransport(ext);
  await response(ext, "https://legal.example/", PUBLIC, { statusCode: 451 });
  assert.equal((await ext.site("legal.example"))?.type, "http-451");
  assert.equal(firstHop(await ext.route("https://legal.example/")), "SOCKS5 127.0.0.1:5001");
});

test("a routed site's own blocked CDN is routed along via the same transport", async () => {
  const ext = await bootExtension({ zone: { "site.example": { A: [PUBLIC] }, "cdn-site.example": { A: [PUBLIC] } } });
  await withTransport(ext);
  await ext.fail("https://site.example/", "net::ERR_CONNECTION_TIMED_OUT", { tabId: 9 });
  ext.mock.setFrame(9, 0, "https://site.example/");
  await ext.api.webRequest.onErrorOccurred._fire({
    type: "script", tabId: 9, frameId: 0, url: "https://cdn-site.example/app.js", error: "net::ERR_CONNECTION_RESET"
  });
  await ext.mock.settle();
  const sub = await ext.policy("cdn-site.example");
  assert.equal(sub?.via, "subresource");
  assert.equal(sub?.parent, "site.example");
  assert.equal(firstHop(await ext.route("https://cdn-site.example/app.js")), "SOCKS5 127.0.0.1:5001");
  await ext.send("clearDomain", { domain: "site.example" });
  assert.equal(await ext.policy("cdn-site.example"), null, "removed with its parent");
});

test("subresources of sites we're NOT routing, and the extension's own requests, are left alone", async () => {
  const ext = await bootExtension({ zone: { "ads.example": { A: [PUBLIC] } } });
  await withTransport(ext);
  ext.mock.setFrame(3, 0, "https://normal.example/");
  await ext.api.webRequest.onErrorOccurred._fire({ type: "script", tabId: 3, frameId: 0, url: "https://ads.example/x.js", error: "net::ERR_NAME_NOT_RESOLVED" });
  await ext.api.webRequest.onErrorOccurred._fire({ type: "xmlhttprequest", tabId: -1, frameId: -1, url: "https://ads.example/probe", error: "net::ERR_CONNECTION_RESET" });
  await ext.mock.settle();
  assert.equal(await ext.policy("ads.example"), null);
  assert.equal(await ext.site("ads.example"), null);
});

test("deep detection can be switched off", async () => {
  const ext = await bootExtension({ zone: { "off.example": { A: [PUBLIC] } } });
  await withTransport(ext);
  await ext.send("saveSettings", { patch: { deepDetection: false } });
  await response(ext, "https://ok.example/", "142.250.1.1");
  await response(ext, "https://off.example/", PUBLIC, { statusCode: 451 });
  assert.equal(await ext.site("off.example"), null);
});
