// Boots the OpenRoute background against the webext mock so tests can drive
// it purely through browser events and the popup message API (black-box):
//
//   const ext = await bootExtension({ flavor: "firefox", zone: {...} });
//   await ext.fail("https://blocked.example/", "net::ERR_CONNECTION_RESET");
//   assert.equal(await ext.route("https://blocked.example/"), "SOCKS5 127.0.0.1:9150");
//
// The entry module is configurable so the same tests run against the legacy
// layout (Phase 0) and the src/ layout (Phase 1+).

import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createWebExtMock } from "./webext-mock.mjs";
import { installFakeDoH } from "./fake-doh.mjs";
import { installNetSim } from "./net-sim.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CANDIDATE_ENTRIES = [join(ROOT, "src", "background", "index.js"), join(ROOT, "background.js")];
export const ENTRY = process.env.OPENROUTE_ENTRY || CANDIDATE_ENTRIES.find((p) => existsSync(p));

let bootCount = 0;

export async function bootExtension({ flavor = "chromium", zone = {}, dohDown = false, setup } = {}) {
  const mock = createWebExtMock({ flavor }).install();
  const net = installNetSim(mock);
  const doh = installFakeDoH(mock, zone, { down: dohDown });
  if (setup) await setup(mock, net);
  await importEntry();
  await mock.settle();
  return wrap(mock, doh, net);
}

async function importEntry() {
  // A unique query defeats the ESM cache so each boot re-runs the entry's
  // top-level code (listener registration, init) like a fresh worker start.
  await import(`${pathToFileURL(ENTRY).href}?boot=${++bootCount}`);
}

function wrap(mock, doh, net) {
  const ext = {
    mock,
    doh,
    net,
    api: mock.api,
    state: mock.state,

    async fail(url, error, opts = {}) {
      await mock.navigateFail({ url, error, tabId: opts.tabId ?? 1, ...opts });
      await mock.settle();
    },

    async ok(url, opts = {}) {
      await mock.navigateOk({ url, tabId: opts.tabId ?? 1, ...opts });
      await mock.settle();
    },

    async send(type, extra = {}) {
      const res = await mock.sendMessage({ type, ...extra });
      await mock.settle();
      return res;
    },

    // Normalized view of the background state across schema versions.
    async view() {
      const s = (await mock.sendMessage({ type: "getState" })) || {};
      return {
        raw: s,
        policies: s.policies ?? s.policy ?? {},
        sites: s.sites ?? {},
        transports: s.transports ?? [],
        settings: s.settings ?? {}
      };
    },

    async policy(domain) { return (await ext.view()).policies[domain] ?? null; },
    async site(host) { return (await ext.view()).sites[host] ?? null; },

    // What the browser would do with this URL right now (PAC string on
    // Chromium, onRequest descriptor on Firefox).
    async route(url) { return mock.resolveProxy(url); },

    reloadsFor(tabId) {
      return mock.state.reloads.filter((r) => r.tabId === tabId).length +
             mock.state.tabUpdates.filter((u) => u.tabId === tabId && u.url).length;
    },

    // Simulate the MV3 worker being killed and restarted (state persists).
    async restart() {
      mock.restartWorker();
      await importEntry();
      await mock.settle();
      return ext;
    }
  };
  return ext;
}

// First proxy descriptor/directive in a route result, normalized for asserts.
export function firstHop(route) {
  if (typeof route === "string") return route.split(";")[0].trim();
  if (Array.isArray(route)) return route[0];
  return route;
}

export function hasDirectFallback(route) {
  if (typeof route === "string") return route.split(";").some((p) => p.trim() === "DIRECT");
  if (Array.isArray(route)) return route.some((d) => d && d.type === "direct");
  return !!route && route.type === "direct";
}
