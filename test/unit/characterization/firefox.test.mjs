// Characterization tests for the Firefox port (desktop + Android share this
// path). Firefox exposes proxy.onRequest AND a proxy.settings object (which
// only accepts Firefox-format values), and reports navigation errors as
// nsresult codes ("Error code 2152398878") instead of net::ERR_* strings.

import { before, test } from "node:test";
import assert from "node:assert/strict";
import { bootExtension, firstHop, hasDirectFallback } from "../../helpers/harness.mjs";

const NS = {
  BINDING_ABORTED: "Error code 2152398850",   // 0x804B0002 — user stopped / navigated away
  UNKNOWN_HOST: "Error code 2152398878",      // 0x804B001E — DNS failure
  NET_TIMEOUT: "Error code 2152398862"        // 0x804B000E
};

const ZONE = {
  "ipblocked.example": { A: ["93.184.215.14"] },
  "dnsblocked.example": { A: ["93.184.215.16"] },
  "stopped.example": { A: ["93.184.215.17"] }
};

let ext;
before(async () => {
  ext = await bootExtension({ flavor: "firefox", zone: ZONE });
  await ext.send("addTransport", {
    transport: { id: "vps", label: "VPS", scheme: "socks5", host: "127.0.0.1", port: 1081, kind: "user" }
  });
  await ext.send("setActiveTransport", { id: "vps" });
});

test("A2 — Firefox routes through proxy.onRequest (not a Chromium PAC)", async () => {
  await ext.fail("https://ipblocked.example/", NS.NET_TIMEOUT);
  assert.ok(ext.api.proxy.onRequest.hasListeners(), "a proxy.onRequest listener is registered");
  const hop = firstHop(await ext.route("https://ipblocked.example/"));
  assert.equal(hop?.type, "socks");
  assert.equal(hop?.host, "127.0.0.1");
  assert.equal(hop?.port, 1081);
  assert.equal(hop?.proxyDNS, true, "DNS is resolved at the proxy, not locally");
  const other = await ext.route("https://unrelated.example/");
  assert.equal(firstHop(other)?.type, "direct", "split tunnel: other sites stay direct");
});

test("B9 — a routed Firefox domain never falls back to the censored direct path", async () => {
  const r = await ext.route("https://ipblocked.example/");
  assert.equal(hasDirectFallback(r), false, `descriptor chain was ${JSON.stringify(r)}`);
});

test("A3 — a user-aborted load (NS_BINDING_ABORTED) is ignored", async () => {
  await ext.fail("https://stopped.example/", NS.BINDING_ABORTED);
  assert.equal(await ext.policy("stopped.example"), null);
  assert.equal(await ext.site("stopped.example"), null);
});

test("A3 — NS_ERROR_UNKNOWN_HOST with a real DoH answer is classified as DNS tampering", async () => {
  await ext.fail("https://dnsblocked.example/", NS.UNKNOWN_HOST);
  assert.equal((await ext.site("dnsblocked.example"))?.type, "dns-tampering");
});
