// DoH engine behavior: racing, failover, deadlines, second opinions, health.
// Uses a fake fetch where each resolver can be slow, down, or lie.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createWebExtMock } from "../helpers/webext-mock.mjs";
import { installFakeDoH } from "../helpers/fake-doh.mjs";
import { createDoH, createEndpointHealth, planEndpoints, RESOLVERS, RACE_ORDER } from "../../src/background/dns/doh.js";

const IP = "93.184.215.14";
const resolverOf = (url) => Object.entries(RESOLVERS).find(([, r]) => r.endpoints.some((e) => url.startsWith(e)))?.[0];

// A network where per-resolver behavior is scriptable: { cloudflare: { down, delayMs, zone } }.
function network(zone, behavior = {}) {
  const mock = createWebExtMock();
  const fakes = {};
  const log = [];
  for (const key of Object.keys(RESOLVERS)) {
    const m = createWebExtMock();
    fakes[key] = installFakeDoH(m, behavior[key]?.zone || zone);
    fakes[key].fetch = m.fetch;
  }
  const fetchImpl = async (url, init) => {
    const key = resolverOf(url);
    log.push(key);
    const b = behavior[key] || {};
    if (b.delayMs) {
      await new Promise((resolve, reject) => {
        const t = setTimeout(resolve, b.delayMs);
        init?.signal?.addEventListener("abort", () => { clearTimeout(t); reject(new DOMException("aborted", "AbortError")); }, { once: true });
      });
    }
    if (b.down) throw new TypeError("Failed to fetch");
    return fakes[key].fetch(url, init);
  };
  return { mock, fetchImpl, log };
}

const fast = { staggerMs: 30, attemptTimeoutMs: 400, deadlineMs: 900, confirmMs: 120 };

test("first answer wins; the preferred resolver is asked first", async () => {
  const { fetchImpl, log } = network({ "ok.example": { A: [IP] } });
  const doh = createDoH({ fetchImpl, getConfig: async () => ({ preferred: "quad9" }), timing: fast });
  const r = await doh.lookup("ok.example", 1);
  assert.equal(r.ok, true);
  assert.deepEqual(r.addresses, [IP]);
  assert.equal(log[0], "quad9");
  assert.equal(r.resolver, "quad9");
});

test("a dead preferred resolver costs one stagger interval, not a timeout", async () => {
  const { fetchImpl } = network({ "ok.example": { A: [IP] } }, { cloudflare: { delayMs: 10_000 } });
  const doh = createDoH({ fetchImpl, timing: fast });
  const t0 = Date.now();
  const r = await doh.lookup("ok.example", 1);
  assert.equal(r.ok, true);
  assert.notEqual(r.resolver, "cloudflare");
  assert.ok(Date.now() - t0 < 400, `took ${Date.now() - t0} ms`);
});

test("hard failures fall through immediately to the next endpoint", async () => {
  const { fetchImpl } = network({ "ok.example": { A: [IP] } }, { cloudflare: { down: true }, google: { down: true } });
  const doh = createDoH({ fetchImpl, timing: { ...fast, staggerMs: 5000 } }); // stagger never fires
  const t0 = Date.now();
  const r = await doh.lookup("ok.example", 1);
  assert.equal(r.resolver, "quad9");
  assert.ok(Date.now() - t0 < 300, `took ${Date.now() - t0} ms`);
});

test("nobody reachable → unreachable within the deadline (never NXDOMAIN)", async () => {
  const down = Object.fromEntries(Object.keys(RESOLVERS).map((k) => [k, { down: true }]));
  const { fetchImpl } = network({}, down);
  const doh = createDoH({ fetchImpl, timing: fast });
  const d = await doh.diagnose("x.example");
  assert.equal(d.unreachable, true);
  assert.equal(d.status, null);
  assert.equal(d.ok, false);
});

test("a hung network is cut off by the deadline", async () => {
  const slow = Object.fromEntries(Object.keys(RESOLVERS).map((k) => [k, { delayMs: 60_000 }]));
  const { fetchImpl } = network({ "ok.example": { A: [IP] } }, slow);
  const doh = createDoH({ fetchImpl, timing: fast });
  const t0 = Date.now();
  assert.equal(await doh.lookup("ok.example", 1), null);
  assert.ok(Date.now() - t0 < fast.deadlineMs + 200);
});

test("second opinion: one resolver's NXDOMAIN is overruled by another's real answer", async () => {
  const { fetchImpl } = network({ "split.example": { A: [IP] } }, { cloudflare: { zone: { "split.example": "NXDOMAIN" } } });
  const doh = createDoH({ fetchImpl, timing: fast });
  const r = await doh.lookup("split.example", 1);
  assert.equal(r.ok, true, "the real answer wins");
  assert.equal(r.consensus.disagreement, true);
  assert.ok(r.consensus.resolvers >= 2);
});

test("second opinion: an injected (bogon) answer is overruled too", async () => {
  const { fetchImpl } = network({ "lie.example": { A: [IP] } }, { cloudflare: { zone: { "lie.example": { A: ["10.10.34.36"] } } } });
  const doh = createDoH({ fetchImpl, timing: fast });
  const d = await doh.diagnose("lie.example");
  assert.equal(d.ok, true);
  assert.equal(d.injected, false);
});

test("a confirmed NXDOMAIN is reported as NXDOMAIN", async () => {
  const { fetchImpl } = network({});
  const doh = createDoH({ fetchImpl, timing: fast });
  const d = await doh.diagnose("nope.example");
  assert.equal(d.status, 3);
  assert.equal(d.unreachable, false);
});

test("IPv6-only hosts and real ECH are diagnosed from AAAA / HTTPS records", async () => {
  const { fetchImpl } = network({ "v6.example": { AAAA: ["2606:4700::1111"], HTTPS: [{ ech: true, alpn: ["h2", "h3"] }] } });
  const doh = createDoH({ fetchImpl, timing: fast });
  const d = await doh.diagnose("v6.example");
  assert.equal(d.ok, true);
  assert.deepEqual(d.addresses, ["2606:4700::1111"]);
  assert.equal(d.echLikely, true);
  assert.deepEqual(d.alpn, ["h2", "h3"]);
});

test("a recently-failed endpoint is demoted within its resolver (IP literal goes first)", () => {
  const health = createEndpointHealth();
  health.fail("https://cloudflare-dns.com/dns-query");
  const plan = planEndpoints(RACE_ORDER, health);
  assert.equal(plan[0].url, "https://1.1.1.1/dns-query", "the preferred resolver keeps first place via its IP endpoint");
  const cf = plan.filter((e) => e.resolver === "cloudflare").map((e) => e.url);
  assert.equal(cf[cf.length - 1], "https://cloudflare-dns.com/dns-query", "the failed endpoint is its resolver's last resort");
  health.ok("https://cloudflare-dns.com/dns-query", 20);
  assert.equal(planEndpoints(RACE_ORDER, health)[0].url, "https://cloudflare-dns.com/dns-query", "recovers after a success");
});

test("a custom resolver URL is tried first", () => {
  const plan = planEndpoints(RACE_ORDER, createEndpointHealth(), "https://doh.example.net/dns-query");
  assert.equal(plan[0].url, "https://doh.example.net/dns-query");
  assert.equal(plan[0].resolver, "custom");
});

test("malformed / wrong-content-type responses are ignored, not trusted", async () => {
  const { fetchImpl: base } = network({ "ok.example": { A: [IP] } });
  const fetchImpl = async (url, init) => {
    if (resolverOf(url) === "cloudflare") return new Response("<html>blocked</html>", { status: 200, headers: { "content-type": "text/html" } });
    if (resolverOf(url) === "google") return new Response(new Uint8Array([1, 2, 3]), { status: 200, headers: { "content-type": "application/dns-message" } });
    return base(url, init);
  };
  const doh = createDoH({ fetchImpl, timing: fast });
  const r = await doh.lookup("ok.example", 1);
  assert.equal(r.ok, true);
  assert.equal(r.resolver, "quad9");
});
