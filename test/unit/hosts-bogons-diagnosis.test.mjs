import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeHost, hostFromUrl, isLocalHost, selfAndParents, lookupDomain, isValidHostname } from "../../src/shared/hosts.js";
import { isBogon } from "../../src/background/dns/bogons.js";
import { classify, startRung, TYPES } from "../../src/background/diagnosis.js";
import { KIND } from "../../src/background/errors.js";

test("host normalization", () => {
  assert.equal(normalizeHost(" WWW.Example.COM. "), "www.example.com");
  assert.equal(normalizeHost("[2001:db8::1]"), "2001:db8::1");
  assert.equal(hostFromUrl("https://Sub.Example.org:8443/x"), "sub.example.org");
  assert.equal(hostFromUrl("not a url"), null);
});

test("local hosts are never treated as censorship targets", () => {
  for (const h of ["localhost", "app.localhost", "printer.local", "nas", "router.lan", "x.home.arpa", "svc.internal",
    "127.0.0.1", "10.0.0.8", "192.168.1.1", "172.16.0.1", "169.254.1.1", "100.64.0.1", "::1", "fe80::1", "fd12::1", ""]) {
    assert.equal(isLocalHost(h), true, h);
  }
  for (const h of ["example.com", "8.8.8.8", "2606:4700::1111", "1.1.1.1"]) assert.equal(isLocalHost(h), false, h);
});

test("parent-domain walking and lookup", () => {
  assert.deepEqual(selfAndParents("a.b.example.com"), ["a.b.example.com", "b.example.com", "example.com", "com"]);
  assert.deepEqual(selfAndParents("1.2.3.4"), ["1.2.3.4"]);
  assert.equal(lookupDomain("cdn.x.example.com", { "example.com": 1 }), "example.com");
  assert.equal(lookupDomain("example.com", { "cdn.example.com": 1 }), null);
  assert.equal(lookupDomain("toString", {}), null, "no prototype hits");
});

test("hostname validation", () => {
  for (const h of ["example.com", "a-b.example", "xn--bcher-kva.example", "127.0.0.1", "::1", "_dmarc.example.com"]) assert.ok(isValidHostname(h), h);
  for (const h of ["", "-bad.example", "a..b", "bad host", "x".repeat(254), "999.1.1.1.1"]) assert.equal(isValidHostname(h), false, h);
});

test("bogon detection covers IANA special-purpose ranges", () => {
  for (const ip of ["0.1.2.3", "10.10.34.36", "127.0.0.1", "100.100.1.1", "169.254.169.254", "172.31.255.255",
    "192.0.0.8", "192.0.2.1", "192.168.0.1", "198.18.0.5", "198.19.255.1", "198.51.100.7", "203.0.113.200",
    "224.0.0.1", "255.255.255.255", "::", "::1", "fe80::1", "fd00::1", "ff02::1", "2001:db8::5",
    "::ffff:10.0.0.1", "64:ff9b::a00:1", "not-an-ip:"]) {
    assert.equal(isBogon(ip), true, ip);
  }
  for (const ip of ["93.184.215.14", "1.1.1.1", "8.8.8.8", "172.32.0.1", "198.20.0.1", "2606:4700:4700::1111", "::ffff:93.184.215.14", "64:ff9b::808:808"]) {
    assert.equal(isBogon(ip), false, ip);
  }
});

test("classification table", () => {
  const ok = { ok: true, status: 0 };
  const nx = { ok: false, status: 3 };
  const down = { ok: false, status: null, unreachable: true };
  const poisoned = { ok: false, status: 0, injected: true };
  assert.equal(classify(KIND.DNS, ok), TYPES.DNS_TAMPERING);
  assert.equal(classify(KIND.DNS, nx), TYPES.NXDOMAIN);
  assert.equal(classify(KIND.DNS, down), TYPES.DNS_UNVERIFIED, "unreachable DoH is not NXDOMAIN");
  assert.equal(classify(KIND.DNS, poisoned), TYPES.DNS_POISONED);
  assert.equal(classify(KIND.RESET, ok), TYPES.SNI_DPI);
  assert.equal(classify(KIND.TLS, down), TYPES.SNI_DPI);
  assert.equal(classify(KIND.CERT, ok), TYPES.TLS_MITM);
  assert.equal(classify(KIND.TIMEOUT, ok), TYPES.IP_BLOCK);
  assert.equal(classify(KIND.REFUSED, down), TYPES.UNREACHABLE);
  assert.equal(classify(KIND.TIMEOUT, poisoned), TYPES.DNS_POISONED);
  assert.equal(classify(KIND.POLICY, ok), TYPES.POLICY);
  assert.equal(classify(KIND.UNKNOWN, ok), TYPES.UNKNOWN);
});

test("starting rungs", () => {
  assert.equal(startRung(TYPES.DNS_TAMPERING), "doh");
  assert.equal(startRung(TYPES.SNI_DPI, { echLikely: true }), "ech");
  assert.equal(startRung(TYPES.SNI_DPI, { echLikely: false }), "proxy");
  assert.equal(startRung(TYPES.DNS_UNVERIFIED), "proxy");
  assert.equal(startRung(TYPES.NXDOMAIN), "fallback");
  for (const t of [TYPES.DNS_POISONED, TYPES.TLS_MITM, TYPES.IP_BLOCK, TYPES.UNREACHABLE, TYPES.UNKNOWN]) assert.equal(startRung(t), "proxy", t);
});
