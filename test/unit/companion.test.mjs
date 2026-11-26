// Extension ↔ companion: registration of the transports the companion runs,
// and keeping them in sync with what its daemon actually serves.

import { test } from "node:test";
import assert from "node:assert/strict";
import { bootExtension, firstHop } from "../helpers/harness.mjs";

function fakeCompanion(state = {}) {
  const s = { pool: 31080, dpiRecord: 31081, dpiSegment: 31082, tor: 31090, hasPool: false, hasDpi: false, hasTor: false, ...state };
  const transports = () => [
    ...(s.hasPool ? [{ id: "companion", label: "VPS", port: s.pool }] : []),
    ...(s.hasDpi ? [{ id: "companion-dpi-record", label: "DPI bypass · TLS records", port: s.dpiRecord }, { id: "companion-dpi-segment", label: "DPI bypass · TCP segments", port: s.dpiSegment }] : []),
    ...(s.hasTor ? [{ id: "companion-tor", label: "Tor (snowflake)", port: s.tor }] : [])
  ];
  const handler = async (msg) => {
    switch (msg.cmd) {
      case "ping": return { ok: true, cmd: "pong", version: "1.0.0" };
      case "connect": s.hasPool = true; return { ok: true, socksPort: s.pool, id: "companion", count: msg.links.length };
      case "connectDpi": s.hasDpi = true; return { ok: true, transports: transports().filter((t) => t.id.startsWith("companion-dpi")) };
      case "connectTor": s.hasTor = true; return { ok: true, socksPort: s.tor, id: "companion-tor", mode: msg.mode };
      case "disconnect":
        if (!msg.kind || msg.kind === "dpi") s.hasDpi = false;
        if (!msg.kind || msg.kind === "tor") s.hasTor = false;
        if (!msg.kind || msg.kind === "singbox") s.hasPool = false;
        return { ok: true };
      case "transports": return { ok: true, transports: transports() };
      case "health": return { ok: true, transports: transports().map((t) => ({ id: t.id, health: "up", latencyMs: 40 })) };
      default: return { ok: false, error: "unknown cmd" };
    }
  };
  return { s, handler };
}

test("connecting through the companion registers and routes its transports", async () => {
  const c = fakeCompanion();
  const ext = await bootExtension({ zone: { "vps.example": { A: ["93.184.215.14"] } }, setup: (m) => m.setNativeHost("com.openroute.host", c.handler) });
  const r = await ext.send("companionConnect", { links: ["ss://x@1.2.3.4:443"], label: "VPS" });
  assert.equal(r.result.ok, true);
  const t = (await ext.view()).transports.find((x) => x.id === "companion");
  assert.equal(t.port, 31080);
  assert.equal((await ext.view()).raw.activeTransportId, "companion");
  await ext.fail("https://vps.example/", "net::ERR_CONNECTION_TIMED_OUT");
  assert.equal(firstHop(await ext.route("https://vps.example/")), "SOCKS5 127.0.0.1:31080");
});

test("DPI bypass adds two serverless transports the ladder can escalate between", async () => {
  const c = fakeCompanion();
  const ext = await bootExtension({ setup: (m) => m.setNativeHost("com.openroute.host", c.handler) });
  const r = await ext.send("companionConnectDpi");
  assert.equal(r.result.ok, true);
  const ids = (await ext.view()).transports.map((t) => t.id);
  assert.ok(ids.includes("companion-dpi-record") && ids.includes("companion-dpi-segment"), ids.join());
  await ext.send("companionDisconnect", { kind: "dpi" });
  assert.ok(!(await ext.view()).transports.some((t) => t.id.startsWith("companion-dpi")));
});

test("maintenance follows the daemon: changed ports are picked up, vanished transports removed", async () => {
  const c = fakeCompanion();
  const ext = await bootExtension({ zone: { "p.example": { A: ["93.184.215.14"] } }, setup: (m) => m.setNativeHost("com.openroute.host", c.handler) });
  await ext.send("companionConnect", { links: ["ss://x@1.2.3.4:443"] });
  await ext.send("companionConnectTor", { mode: "snowflake" });
  await ext.fail("https://p.example/", "net::ERR_CONNECTION_TIMED_OUT");

  c.s.pool = 32080;      // the daemon had to move to another port after a reboot
  c.s.hasTor = false;    // and Tor was stopped elsewhere
  await ext.mock.fireAllAlarms();
  await ext.mock.settle();
  const ts = (await ext.view()).transports;
  assert.equal(ts.find((t) => t.id === "companion").port, 32080);
  assert.ok(!ts.some((t) => t.id === "companion-tor"), "stale Tor transport removed");
  assert.equal(firstHop(await ext.route("https://p.example/")), "SOCKS5 127.0.0.1:32080", "routes follow the new port");
});

test("without a companion, everything degrades gracefully", async () => {
  const ext = await bootExtension();
  const s = await ext.send("getState");
  assert.equal(s.companion.available, false);
  const r = await ext.send("companionConnectDpi");
  assert.equal(r.ok, false);
  await ext.mock.fireAllAlarms(); // maintenance must not throw
});
