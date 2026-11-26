// The generated PAC is executed in a VM that behaves like Chromium's PAC
// resolver, and cross-checked against the reference matcher Firefox uses.

import { test } from "node:test";
import assert from "node:assert/strict";
import { buildPac, pacDirective, PROBE_PARAM } from "../../src/background/routing/pac.js";
import { compileRoutes, matchRoute, firefoxDescriptor } from "../../src/background/routing/table.js";
import { compilePac, findProxy } from "../helpers/pac-vm.mjs";

const socks = (port, host = "127.0.0.1") => ({ id: `s${port}`, scheme: "socks5", host, port });
const T1 = socks(9150);
const T2 = { id: "h", scheme: "http", host: "proxy.example.net", port: 3128 };

const compiled = {
  routes: { "blocked.example": [T1], "deep.sub.other.example": [T2], "203.0.113.9": [T1], "chain.example": [T1, T2] },
  probes: { tor: [T1] }
};
const pac = buildPac(compiled);
const ctx = compilePac(pac);
const route = (url) => findProxy(ctx, url);

test("defines FindProxyForURL (the entry point Chromium calls)", () => {
  assert.equal(typeof ctx.FindProxyForURL, "function");
  assert.equal(typeof ctx.FindProxyForHost, "undefined");
});

test("routes a domain and all its subdomains, nothing else", () => {
  assert.equal(route("https://blocked.example/"), "SOCKS5 127.0.0.1:9150");
  assert.equal(route("https://www.blocked.example/path?q=1"), "SOCKS5 127.0.0.1:9150");
  assert.equal(route("https://a.b.c.blocked.example/"), "SOCKS5 127.0.0.1:9150");
  assert.equal(route("https://notblocked.example/"), "DIRECT", "suffix match is label-aligned");
  assert.equal(route("https://blocked.example.evil.net/"), "DIRECT");
  assert.equal(route("https://other.example/"), "DIRECT", "parent of a routed domain is not routed");
  assert.equal(route("https://x.deep.sub.other.example/"), "PROXY proxy.example.net:3128");
});

test("hosts are matched case-insensitively and without a trailing dot", () => {
  assert.equal(findProxy(ctx, "https://BLOCKED.Example/"), "SOCKS5 127.0.0.1:9150");
  assert.equal(ctx.FindProxyForURL("https://blocked.example./", "blocked.example."), "SOCKS5 127.0.0.1:9150");
});

test("IP literals match exactly, never by 'suffix'", () => {
  assert.equal(route("http://203.0.113.9/"), "SOCKS5 127.0.0.1:9150");
  assert.equal(route("http://1.203.0.113.9.nip.example/"), "DIRECT");
  assert.equal(route("http://103.0.113.9/"), "DIRECT");
});

test("local and private destinations always go direct", () => {
  for (const u of ["http://localhost:8080/", "http://127.0.0.1/", "http://10.1.2.3/", "http://192.168.1.1/",
    "http://172.20.0.5/", "http://printer.local/", "http://intranet/", "http://[::1]:3000/", "http://[fe80::1]/"]) {
    assert.equal(route(u), "DIRECT", u);
  }
});

test("failover chains are ordered and never end in DIRECT", () => {
  assert.equal(route("https://chain.example/"), "SOCKS5 127.0.0.1:9150; PROXY proxy.example.net:3128");
});

test("probe routes work for http:// only (Chromium strips https paths)", () => {
  assert.equal(route(`http://cp.cloudflare.com/generate_204?${PROBE_PARAM}=tor&n=1`), "SOCKS5 127.0.0.1:9150");
  assert.equal(route(`https://cp.cloudflare.com/generate_204?${PROBE_PARAM}=tor`), "DIRECT", "https probe can't be seen");
  assert.equal(route(`http://cp.cloudflare.com/?${PROBE_PARAM}=nope`), "DIRECT", "unknown probe id");
});

test("directives per scheme, with IPv6 hosts bracketed", () => {
  assert.equal(pacDirective({ scheme: "socks5", host: "127.0.0.1", port: 1080 }), "SOCKS5 127.0.0.1:1080");
  assert.equal(pacDirective({ scheme: "socks4", host: "h", port: 1 }), "SOCKS h:1");
  assert.equal(pacDirective({ scheme: "http", host: "h", port: 8080 }), "PROXY h:8080");
  assert.equal(pacDirective({ scheme: "https", host: "h", port: 443 }), "HTTPS h:443");
  assert.equal(pacDirective({ scheme: "socks5", host: "::1", port: 9050 }), "SOCKS5 [::1]:9050");
});

test("the PAC is pure ASCII (Chromium rejects anything else) even for hostile input", () => {
  assert.doesNotMatch(pac, /[\u0080-￿]/);
  const weird = buildPac({ routes: { "bücher.example": [T1], "例え.テスト": [T1], "emoji😀.example": [T1] } });
  assert.doesNotMatch(weird, /[\u0080-￿]/);
  const c = compilePac(weird);
  assert.equal(c.FindProxyForURL("https://bücher.example/", "bücher.example"), "SOCKS5 127.0.0.1:9150",
    "escaped keys still match the same characters");
});

test("an empty table is valid and routes everything direct", () => {
  const empty = compilePac(buildPac({ routes: {} }));
  assert.equal(findProxy(empty, "https://anything.example/"), "DIRECT");
});

test("full-tunnel default route sends everything (except local) through the transport", () => {
  const full = compilePac(buildPac({ routes: {}, defaultRoute: [T1] }));
  assert.equal(findProxy(full, "https://anything.example/"), "SOCKS5 127.0.0.1:9150");
  assert.equal(findProxy(full, "http://192.168.0.10/"), "DIRECT");
});

test("hostile domain keys can't break out of the PAC or hit prototype properties", () => {
  const nasty = buildPac({ routes: { '"; alert(1); //': [T1], "constructor": [T1], "__proto__": [T1] } });
  const c = compilePac(nasty);
  assert.equal(findProxy(c, "https://toString.example/"), "DIRECT");
  assert.equal(c.FindProxyForURL("https://constructor/", "constructor"), "DIRECT", "single-label → direct");
});

test("PAC and the Firefox reference matcher agree on random tables", () => {
  const labels = ["a", "b", "cdn", "www", "x1", "example", "test", "org"];
  const pick = (n) => Array.from({ length: n }, () => labels[Math.floor(Math.random() * labels.length)]).join(".");
  for (let round = 0; round < 40; round++) {
    const routes = {};
    for (let i = 0; i < 6; i++) routes[pick(2 + (i % 2))] = [socks(1000 + i)];
    const c = { routes };
    const p = compilePac(buildPac(c));
    for (let i = 0; i < 30; i++) {
      const host = pick(1 + (i % 4));
      const url = `https://${host}/`;
      const ref = matchRoute(c, url);
      const expected = ref ? ref.map(pacDirective).join("; ") : "DIRECT";
      assert.equal(findProxy(p, url), expected, `${host} with ${JSON.stringify(Object.keys(routes))}`);
    }
  }
});

test("compileRoutes skips exhausted, unrouted and ghost-transport policies", () => {
  const transports = [T1, { ...T2, enabled: false }];
  const policies = {
    "ok.example": { domain: "ok.example", rung: "proxy", proxyId: T1.id, status: "routing" },
    "gone.example": { domain: "gone.example", rung: "proxy", proxyId: "deleted", status: "routing" },
    "disabled.example": { domain: "disabled.example", rung: "proxy", proxyId: T2.id, status: "fixed" },
    "tired.example": { domain: "tired.example", rung: "proxy", proxyId: T1.id, status: "exhausted" },
    "dns.example": { domain: "dns.example", rung: "doh", proxyId: null, status: "needs-user" }
  };
  assert.deepEqual(Object.keys(compileRoutes({ policies, transports }).routes), ["ok.example"]);
});

test("Firefox descriptors resolve DNS at the proxy and carry auth correctly", () => {
  assert.deepEqual(firefoxDescriptor(T1), { type: "socks", host: "127.0.0.1", port: 9150, proxyDNS: true });
  assert.deepEqual(firefoxDescriptor({ scheme: "socks5", host: "h", port: 1, auth: { username: "u", password: "p" } }),
    { type: "socks", host: "h", port: 1, proxyDNS: true, username: "u", password: "p" });
  assert.equal(firefoxDescriptor({ scheme: "http", host: "h", port: 1, auth: { username: "u", password: "p" } }).proxyAuthorizationHeader,
    "Basic " + Buffer.from("u:p").toString("base64"));
});
