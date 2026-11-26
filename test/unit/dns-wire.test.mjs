// DNS wire codec: RFC 8484 golden vector, real responses captured from
// Cloudflare's resolver (test/fixtures/dns/*.hex), and hostile input.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { encodeQuery, decodeMessage, toBase64Url, fromBase64Url, TYPE, RCODE } from "../../src/background/dns/wire.js";

const fixture = (name) => Uint8Array.from(Buffer.from(readFileSync(new URL(`../fixtures/dns/${name}.hex`, import.meta.url), "utf8").trim(), "hex"));

test("encodes the RFC 8484 §4.1 example query byte-for-byte", () => {
  const q = encodeQuery("www.example.com", TYPE.A, { pad: false });
  assert.equal(toBase64Url(q), "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB");
});

test("padded queries are a multiple of 128 bytes regardless of name length (RFC 8467)", () => {
  for (const name of ["a.io", "example.com", "a-much-longer-subdomain.with-many.labels.example.org", "x".repeat(60) + ".example"]) {
    const q = encodeQuery(name, TYPE.HTTPS);
    assert.equal(q.length % 128, 0, `${name} → ${q.length}`);
    const m = decodeMessage(q);
    assert.equal(m.questions[0].name, name);
    assert.equal(m.questions[0].type, TYPE.HTTPS);
  }
});

test("rejects names DNS can't carry", () => {
  assert.throws(() => encodeQuery("a".repeat(64) + ".example"), /label/);
  assert.throws(() => encodeQuery("a..b"), /label/);
  assert.throws(() => encodeQuery("example.com", "BOGUS"), /type/);
});

test("decodes real A answers", () => {
  const m = decodeMessage(fixture("example_com.A"));
  assert.equal(m.qr, true);
  assert.equal(m.rcode, RCODE.NOERROR);
  assert.equal(m.questions[0].name, "example.com");
  const ips = m.answers.filter((a) => a.type === TYPE.A).map((a) => a.data);
  assert.ok(ips.length > 0 && ips.every((ip) => /^\d+\.\d+\.\d+\.\d+$/.test(ip)), JSON.stringify(ips));
});

test("decodes real AAAA answers with RFC 5952 formatting", () => {
  const m = decodeMessage(fixture("example_com.AAAA"));
  const ips = m.answers.filter((a) => a.type === TYPE.AAAA).map((a) => a.data);
  assert.ok(ips.length > 0);
  for (const ip of ips) {
    assert.match(ip, /^[0-9a-f:]+$/);
    assert.ok(!/(^|:)0[0-9a-f]/.test(ip), `no leading zeros: ${ip}`);
  }
});

test("decodes a real CNAME chain (name compression)", () => {
  const m = decodeMessage(fixture("www_wikipedia_org.A"));
  const cname = m.answers.find((a) => a.type === TYPE.CNAME);
  assert.ok(cname && /wikimedia\.org$/.test(cname.data), JSON.stringify(m.answers));
  assert.ok(m.answers.some((a) => a.type === TYPE.A));
});

test("decodes a real NXDOMAIN", () => {
  const m = decodeMessage(fixture("does_not_exist_openroute_fixture_example.A"));
  assert.equal(m.rcode, RCODE.NXDOMAIN);
  assert.equal(m.answers.length, 0);
});

test("detects ECH from a real HTTPS record (SvcParamKey 5)", () => {
  const m = decodeMessage(fixture("crypto_cloudflare_com.HTTPS"));
  const rr = m.answers.find((a) => a.type === TYPE.HTTPS);
  assert.ok(rr, "an HTTPS record");
  assert.ok(rr.data.params.ech > 0, `ech present: ${JSON.stringify(rr.data)}`);
  assert.ok(Array.isArray(rr.data.params.alpn));
});

test("base64url round-trips", () => {
  const bytes = Uint8Array.from({ length: 300 }, (_, i) => (i * 37) & 0xff);
  assert.deepEqual(fromBase64Url(toBase64Url(bytes)), bytes);
});

test("hostile input: pointer loops, truncation and garbage never hang or crash oddly", () => {
  // Header + a question whose name is a pointer to itself (offset 12).
  const loop = Uint8Array.from([0, 0, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1]);
  assert.throws(() => decodeMessage(loop), /pointer/);
  const real = fixture("example_com.A");
  for (let cut = 0; cut < real.length - 1; cut++) {
    try { decodeMessage(real.subarray(0, cut)); } catch (e) { assert.ok(e instanceof Error); }
  }
  for (let i = 0; i < 2000; i++) {
    const junk = Uint8Array.from({ length: (i % 90) + 1 }, () => Math.floor(Math.random() * 256));
    try { decodeMessage(junk); } catch (e) { assert.ok(e instanceof Error); }
  }
});
