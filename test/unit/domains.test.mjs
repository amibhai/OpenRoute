// Registrable domains (official PSL test vectors) and site bundles.

import { test } from "node:test";
import assert from "node:assert/strict";
import { registrableDomain, publicSuffix } from "../../src/background/domains/psl.js";
import { bundleFor, BUNDLES } from "../../src/background/domains/bundles.js";

// From https://publicsuffix.org/list/tests.txt (punycoded where needed).
const VECTORS = [
  ["com", null], ["example.com", "example.com"], ["WwW.example.COM", "example.com"],
  ["b.example.com", "example.com"], ["a.b.example.com", "example.com"],
  ["example", null], ["example.example", "example.example"], ["a.b.example.example", "example.example"],
  ["biz", null], ["domain.biz", "domain.biz"], ["a.b.domain.biz", "domain.biz"],
  ["uk.com", null], ["example.uk.com", "example.uk.com"], ["a.b.example.uk.com", "example.uk.com"],
  ["test.ac", "test.ac"],
  ["jp", null], ["test.jp", "test.jp"], ["www.test.jp", "test.jp"], ["ac.jp", null],
  ["test.ac.jp", "test.ac.jp"], ["www.test.ac.jp", "test.ac.jp"], ["kyoto.jp", null],
  ["test.kyoto.jp", "test.kyoto.jp"], ["ide.kyoto.jp", null], ["b.ide.kyoto.jp", "b.ide.kyoto.jp"],
  ["a.b.ide.kyoto.jp", "b.ide.kyoto.jp"], ["c.kobe.jp", null], ["b.c.kobe.jp", "b.c.kobe.jp"],
  ["a.b.c.kobe.jp", "b.c.kobe.jp"], ["city.kobe.jp", "city.kobe.jp"], ["www.city.kobe.jp", "city.kobe.jp"],
  ["ck", null], ["test.ck", null], ["b.test.ck", "b.test.ck"], ["a.b.test.ck", "b.test.ck"],
  ["www.ck", "www.ck"], ["www.www.ck", "www.ck"],
  ["us", null], ["test.us", "test.us"], ["www.test.us", "test.us"], ["ak.us", null],
  ["test.ak.us", "test.ak.us"], ["www.test.ak.us", "test.ak.us"], ["k12.ak.us", null],
  ["test.k12.ak.us", "test.k12.ak.us"], ["www.test.k12.ak.us", "test.k12.ak.us"],
  ["xn--85x722f.com.cn", "xn--85x722f.com.cn"], ["xn--85x722f.xn--55qx5d.cn", "xn--85x722f.xn--55qx5d.cn"],
  ["www.xn--85x722f.xn--55qx5d.cn", "xn--85x722f.xn--55qx5d.cn"], ["shishi.xn--55qx5d.cn", "shishi.xn--55qx5d.cn"],
  ["xn--55qx5d.cn", null], ["xn--85x722f.xn--fiqs8s", "xn--85x722f.xn--fiqs8s"],
  ["www.xn--85x722f.xn--fiqs8s", "xn--85x722f.xn--fiqs8s"], ["shishi.xn--fiqs8s", "shishi.xn--fiqs8s"], ["xn--fiqs8s", null]
];

test("registrable domains match the official PSL test vectors", () => {
  for (const [host, expected] of VECTORS) assert.equal(registrableDomain(host), expected, host);
});

test("private-section suffixes keep users apart (github.io, blogspot, …)", () => {
  assert.equal(registrableDomain("alice.github.io"), "alice.github.io");
  assert.equal(registrableDomain("cdn.alice.github.io"), "alice.github.io");
  assert.equal(registrableDomain("github.io"), null);
  assert.equal(publicSuffix("alice.github.io"), "github.io");
  assert.equal(registrableDomain("www.bbc.co.uk"), "bbc.co.uk");
});

test("IP literals and malformed names are handled", () => {
  assert.equal(registrableDomain("93.184.215.14"), "93.184.215.14");
  assert.equal(registrableDomain("2001:db8::1"), "2001:db8::1");
  assert.equal(registrableDomain(".com"), null);
  assert.equal(registrableDomain("a..b.com"), null);
  assert.equal(registrableDomain(""), null);
});

test("bundles: members resolve to their bundle, including subdomains", () => {
  assert.equal(bundleFor("www.youtube.com")?.name, "youtube");
  assert.equal(bundleFor("rr3---sn-abc.googlevideo.com")?.name, "youtube");
  assert.equal(bundleFor("pbs.twimg.com")?.name, "x");
  assert.equal(bundleFor("example.com"), null);
  const seen = new Map();
  for (const [name, members] of Object.entries(BUNDLES)) {
    for (const m of members) {
      assert.ok(!seen.has(m), `${m} is in both ${seen.get(m)} and ${name}`);
      seen.set(m, name);
    }
  }
});
