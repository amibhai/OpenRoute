// Characterization tests for routing on Chromium (Chrome/Edge/Brave/Opera).
// Written in Phase 0 against the legacy code to pin down audit findings; each
// test names the finding it covers. They drive the extension only through
// browser events + the popup message API, so they survive refactors.

import { before, test } from "node:test";
import assert from "node:assert/strict";
import { bootExtension, firstHop, hasDirectFallback } from "../../helpers/harness.mjs";

const REAL_IP = "93.184.215.14";
const ZONE = Object.fromEntries([
  "dnstamper.example", "ipblocked.example", "dohblocked.example", "offline.example",
  "prerender.example", "ads.example", "sni.example", "rehome.example"
].map((h) => [h, { A: [REAL_IP] }]));

let ext;
before(async () => {
  ext = await bootExtension({ flavor: "chromium", zone: ZONE });
  await ext.send("addTransport", {
    transport: { id: "vps", label: "VPS", scheme: "socks5", host: "127.0.0.1", port: 1081, kind: "user", builtin: false }
  });
  await ext.send("setActiveTransport", { id: "vps" });
});

test("harness sanity — DNS tampering is diagnosed from a real DoH answer", async () => {
  await ext.fail("https://dnstamper.example/", "net::ERR_NAME_NOT_RESOLVED");
  assert.equal((await ext.site("dnstamper.example"))?.type, "dns-tampering");
});

test("A1 — a domain the ladder routes is actually routed by the PAC Chromium runs", async () => {
  await ext.fail("https://ipblocked.example/", "net::ERR_CONNECTION_TIMED_OUT", { tabId: 3 });
  assert.equal((await ext.policy("ipblocked.example"))?.rung, "proxy", "ladder chose the proxy rung");
  assert.equal(firstHop(await ext.route("https://ipblocked.example/")), "SOCKS5 127.0.0.1:1081");
  assert.equal(firstHop(await ext.route("https://cdn.ipblocked.example/x")), "SOCKS5 127.0.0.1:1081", "subdomains follow");
  assert.equal(hasDirectFallback(await ext.route("https://ipblocked.example/")), false, "no fallback to the censored path");
  assert.equal(await ext.route("https://unrelated.example/"), "DIRECT", "split tunnel: other sites stay direct");
});

test("B2 — when DoH itself is unreachable, a DNS failure is routed, not written off as NXDOMAIN", async () => {
  ext.doh.down = true;
  try {
    await ext.fail("https://dohblocked.example/", "net::ERR_NAME_NOT_RESOLVED");
  } finally {
    ext.doh.down = false;
  }
  assert.equal((await ext.policy("dohblocked.example"))?.rung, "proxy");
  assert.equal(firstHop(await ext.route("https://dohblocked.example/")), "SOCKS5 127.0.0.1:1081");
});

test("B3 — going offline never triggers routing", async () => {
  await ext.fail("https://offline.example/", "net::ERR_INTERNET_DISCONNECTED");
  assert.equal(await ext.policy("offline.example"), null);
  assert.equal(await ext.site("offline.example"), null);
});

test("B3 — errors from prerendered (not user-visible) navigations are ignored", async () => {
  await ext.fail("https://prerender.example/", "net::ERR_CONNECTION_RESET", { documentLifecycle: "prerender" });
  assert.equal(await ext.policy("prerender.example"), null);
});

test("B3 — an ad blocker's ERR_BLOCKED_BY_CLIENT is not censorship", async () => {
  await ext.fail("https://ads.example/", "net::ERR_BLOCKED_BY_CLIENT");
  assert.equal(await ext.policy("ads.example"), null);
  assert.equal(await ext.site("ads.example"), null);
});

test("B4 — a proxy failure doesn't overwrite the site's original diagnosis", async () => {
  await ext.fail("https://sni.example/", "net::ERR_CONNECTION_RESET");
  assert.equal((await ext.site("sni.example"))?.type, "sni-dpi");
  await ext.fail("https://sni.example/", "net::ERR_PROXY_CONNECTION_FAILED");
  assert.equal((await ext.site("sni.example"))?.type, "sni-dpi", "diagnosis kept after a transport failure");
});

test("B7 — removing a transport re-homes the domains it was carrying", async () => {
  await ext.send("addTransport", { transport: { id: "a", label: "A", scheme: "socks5", host: "127.0.0.1", port: 2001, kind: "user" } });
  await ext.send("addTransport", { transport: { id: "b", label: "B", scheme: "socks5", host: "127.0.0.1", port: 2002, kind: "user" } });
  await ext.send("setRung", { domain: "rehome.example", rung: "auto" });
  await ext.send("setActiveTransport", { id: "a" });
  await ext.fail("https://rehome.example/", "net::ERR_CONNECTION_TIMED_OUT");
  assert.equal((await ext.policy("rehome.example"))?.proxyId, "a");
  await ext.send("removeTransport", { id: "a" });
  const pol = await ext.policy("rehome.example");
  assert.notEqual(pol?.proxyId, "a", "policy no longer points at the removed transport");
  const hop = firstHop(await ext.route("https://rehome.example/"));
  assert.match(hop, /^SOCKS5 127\.0\.0\.1:(1081|2002)$/, `re-homed onto a live transport (got ${hop})`);
});
