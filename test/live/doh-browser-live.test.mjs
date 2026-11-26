// Live, authoritative resolver check: every DoH endpoint in the catalog is
// queried from INSIDE the extension's service worker in real Chromium — the
// browser's network stack (HTTP/2, ALPN) and the manifest's host permissions,
// exactly what the extension uses. (Node's fetch speaks HTTP/1.1 only, which
// e.g. Quad9 refuses with 505, so Node is not the right place to judge this.)
//
//   npm run test:live            (needs internet)

import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { encodeQuery, toBase64Url, decodeMessage, TYPE } from "../../src/background/dns/wire.js";
import { RESOLVERS } from "../../src/background/dns/doh.js";
import { launchWithExtension } from "../e2e/helpers/chromium.mjs";

let browser;
before(async () => { browser = await launchWithExtension(); });
after(async () => { await browser?.close(); });

const query = toBase64Url(encodeQuery("example.com", TYPE.A));

async function queryFromWorker(endpoint) {
  return browser.worker.evaluate(async ([ep, q]) => {
    const t0 = Date.now();
    try {
      const r = await fetch(`${ep}?dns=${q}`, { headers: { accept: "application/dns-message" }, cache: "no-store", credentials: "omit" });
      return { status: r.status, type: r.headers.get("content-type"), bytes: [...new Uint8Array(await r.arrayBuffer())], ms: Date.now() - t0 };
    } catch (e) {
      return { error: String(e), ms: Date.now() - t0 };
    }
  }, [endpoint, query]);
}

for (const [key, r] of Object.entries(RESOLVERS)) {
  test(`${r.label}: at least one endpoint answers from the extension (browser stack)`, async (t) => {
    const results = [];
    for (const ep of r.endpoints) {
      const res = await queryFromWorker(ep);
      let verdict = res.error || `HTTP ${res.status}`;
      if (res.status === 200 && /dns-message/.test(res.type || "")) {
        const m = decodeMessage(Uint8Array.from(res.bytes));
        verdict = `rcode ${m.rcode}, ${m.answers.length} answers`;
        results.push({ ep, ok: m.rcode === 0 && m.answers.length > 0, verdict, ms: res.ms });
      } else {
        results.push({ ep, ok: false, verdict, ms: res.ms });
      }
    }
    for (const x of results) t.diagnostic(`${x.ok ? "ok  " : "FAIL"} ${x.ep} — ${x.verdict} (${x.ms} ms)`);
    assert.ok(results.some((x) => x.ok), `${key}: no endpoint answered`);
  });
}

test("the extension's own pipeline: ECH and NXDOMAIN come back right over real DoH", async () => {
  const state = await browser.send("recheck", { host: "crypto.cloudflare.com" }).catch((e) => ({ error: String(e) }));
  assert.ok(state?.ok, JSON.stringify(state));
  assert.equal(state.diag.ok, true);
  assert.equal(state.diag.echLikely, true, "real HTTPS record carries ech");
  const nx = await browser.send("recheck", { host: "no-such-host.openroute-live-test.example" });
  assert.equal(nx.diag.status, 3);
  assert.equal(nx.diag.unreachable, false);
});
