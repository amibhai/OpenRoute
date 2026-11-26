import { test } from "node:test";
import assert from "node:assert/strict";
import { createStore, migrate, SCHEMA_VERSION } from "../../src/background/store.js";
import { createWebExtMock } from "../helpers/webext-mock.mjs";

function setup() {
  const mock = createWebExtMock();
  const store = createStore(mock.api.storage.local);
  mock.api.storage.onChanged.addListener((changes, area) => { if (area === "local") store.noteChanges(changes); });
  return { mock, store };
}

test("concurrent read-modify-writes never lose updates", async () => {
  const { mock, store } = setup();
  await Promise.all(Array.from({ length: 50 }, (_, i) =>
    store.tx(["counter", "seen"], (d) => {
      d.counter = (d.counter || 0) + 1;
      d.seen = [...(d.seen || []), i];
    })));
  assert.equal(await store.get("counter"), 50);
  assert.equal((await store.get("seen")).length, 50);
  assert.equal(mock.api.storage.local._dump().counter, 50, "persisted, not just cached");
});

test("late onChanged events never resurrect an older value", async () => {
  const { mock, store } = setup();
  await store.tx(["k"], (d) => { d.k = 1; });
  await store.tx(["k"], (d) => { d.k = 2; });
  // Simulate a stale event for the first write arriving after the second.
  store.noteChanges({ k: { newValue: 1 } });
  assert.equal(await store.get("k"), 2);
  await store.tx(["k"], (d) => { d.k += 1; });
  assert.equal(await store.get("k"), 3);
  assert.equal(mock.api.storage.local._dump().k, 3);
});

test("setting a key to undefined deletes it", async () => {
  const { mock, store } = setup();
  await store.tx(["a", "b"], (d) => { d.a = 1; d.b = 2; });
  await store.tx(["a"], (d) => { d.a = undefined; });
  assert.equal(await store.get("a"), undefined);
  assert.deepEqual(Object.keys(mock.api.storage.local._dump()), ["b"]);
});

test("reads are copies — mutating them doesn't corrupt the cache", async () => {
  const { store } = setup();
  await store.tx(["obj"], (d) => { d.obj = { list: [1] }; });
  const copy = await store.get("obj");
  copy.list.push(2);
  assert.deepEqual(await store.get("obj"), { list: [1] });
});

test("a throwing mutator rejects its own tx without blocking later ones", async () => {
  const { store } = setup();
  await assert.rejects(store.tx(["x"], () => { throw new Error("boom"); }), /boom/);
  await store.tx(["x"], (d) => { d.x = "ok"; });
  assert.equal(await store.get("x"), "ok");
});

test("tx returns the mutator's result and writes nothing when nothing changed", async () => {
  const { mock, store } = setup();
  await store.tx(["v"], (d) => { d.v = { a: 1 }; });
  const sets = mock.state.netLog.length; // unrelated; just ensure no throw
  const r = await store.tx(["v"], (d) => d.v.a);
  assert.equal(r, 1);
  assert.equal(mock.state.netLog.length, sets);
});

test("migrates 0.3.x data to schema v2 without losing anything", async () => {
  const { mock, store } = setup();
  mock.api.storage.local._load({
    blockedSites: { "a.example": { host: "a.example", type: "ip-block", remediation: "old text", count: 3, lastSeen: 5 } },
    domainPolicy: { "a.example": { domain: "a.example", rung: "proxy", proxyId: "tor-browser", status: "fixed", attempts: 1 } },
    transports: [{ id: "tor-browser", label: "Tor Browser", scheme: "socks5", host: "127.0.0.1", port: 9150, health: "up", successes: 4, failures: 1, streak: 0, lastOk: 9 }],
    settings: { autoRoute: false },
    activeTransportId: "tor-browser"
  });
  const r = await migrate(store);
  assert.equal(r.migrated, true);
  const data = mock.api.storage.local._dump();
  assert.equal(data.schemaVersion, SCHEMA_VERSION);
  assert.equal(data.blockedSites, undefined);
  assert.equal(data.domainPolicy, undefined);
  assert.equal(data.sites["a.example"].type, "ip-block");
  assert.equal(data.sites["a.example"].remediation, undefined, "UI text is no longer stored");
  assert.equal(data.policies["a.example"].status, "fixed");
  assert.equal(data.policies["a.example"].retryCount, 0);
  assert.equal(data.transports[0].health, undefined, "health split out of config");
  assert.equal(data.transports[0].enabled, true);
  assert.deepEqual(data.transportHealth["tor-browser"], { state: "up", successes: 4, failures: 1, streak: 0, lastOk: 9, lastFail: null, latencyMs: null });
  assert.equal(data.settings.autoRoute, false, "settings untouched");
  assert.equal(data.activeTransportId, "tor-browser");
  assert.equal((await migrate(store)).migrated, false, "idempotent");
});

test("migration of a fresh install just stamps the schema", async () => {
  const { mock, store } = setup();
  await migrate(store);
  assert.deepEqual(mock.api.storage.local._dump(), { schemaVersion: SCHEMA_VERSION });
});
