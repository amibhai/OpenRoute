// The background half of the UX: the popup's "this site" state, routing a
// site from the popup / context menu / keyboard shortcut, per-tab badges,
// site grouping, backup and reset, and the shareable diagnostics report.

import { test } from "node:test";
import assert from "node:assert/strict";
import { bootExtension, firstHop } from "../helpers/harness.mjs";
import { groupSites } from "../../src/background/messages.js";

const IP = "93.184.215.14";
const zone = (...hosts) => Object.fromEntries(hosts.map((h) => [h, { A: [IP] }]));

async function onlyTransport(ext, port = 3101) {
  for (const t of (await ext.view()).transports) await ext.send("removeTransport", { id: t.id });
  if (port) await ext.send("addTransport", { transport: { id: `p${port}`, label: `Proxy ${port}`, scheme: "socks5", host: "127.0.0.1", port } });
}
const badge = (ext, tabId) => ext.state.badges.get(tabId)?.text;

test("tabState describes the tab's site: routed or not, through what, under which rule", async () => {
  const ext = await bootExtension({ zone: zone("www.tab.example") });
  await onlyTransport(ext);
  await ext.fail("https://www.tab.example/a", "net::ERR_CONNECTION_TIMED_OUT", { tabId: 3 });
  await ext.ok("https://www.tab.example/a", { tabId: 3 });

  let s = await ext.send("tabState", { url: "https://www.tab.example/a" });
  assert.deepEqual([s.ok, s.web, s.host, s.domain, s.routed], [true, true, "www.tab.example", "tab.example", true]);
  assert.equal(s.policy.status, "fixed");
  assert.equal(s.transport.label, "Proxy 3101");

  // By tab alone: Firefox for Android's popup can't see the page's URL.
  s = await ext.send("tabState", { tabId: 3 });
  assert.equal(s.host, "www.tab.example");
  assert.equal((await ext.send("tabState", { url: "chrome://settings/" })).web, false);

  await ext.send("setRule", { domain: "tab.example", list: "never" });
  s = await ext.send("tabState", { url: "https://www.tab.example/" });
  assert.deepEqual([s.rule, s.ruleDomain], ["never", "tab.example"]);
});

test("toggleSite routes a site through the best transport, then stops routing it", async () => {
  const ext = await bootExtension({ zone: zone("toggle.example") });
  await onlyTransport(ext);
  let r = (await ext.send("toggleSite", { url: "https://toggle.example/x", tabId: 7 })).result;
  assert.deepEqual([r.done, r.routed, r.domain, r.via], [true, true, "toggle.example", "p3101"]);
  assert.equal(firstHop(await ext.route("https://toggle.example/")), "SOCKS5 127.0.0.1:3101");
  assert.ok(ext.state.reloads.some((x) => x.tabId === 7), "the tab reloads onto its new route");

  r = (await ext.send("toggleSite", { url: "https://toggle.example/x", tabId: 7 })).result;
  assert.deepEqual([r.done, r.routed], [true, false]);
  assert.equal(await ext.route("https://toggle.example/"), "DIRECT");
  assert.equal(await ext.policy("toggle.example"), null, "back to automatic, not pinned direct");

  assert.equal((await ext.send("toggleSite", { url: "about:blank" })).result.reason, "not-a-website");
});

test("with no transport, routing a site opens the dashboard on Transports instead", async () => {
  const ext = await bootExtension();
  await onlyTransport(ext, 0);
  const r = (await ext.send("toggleSite", { url: "https://lonely.example/" })).result;
  assert.equal(r.reason, "no-transport");
  assert.ok(ext.state.createdTabs.some((t) => /src\/ui\/options\.html#transports$/.test(t.url)), JSON.stringify(ext.state.createdTabs));
  assert.equal((await ext.send("routeSite", { domain: "lonely.example" })).ok, false, "routeSite says why");
});

test("the context menu and the keyboard shortcut route the page they were used on", async () => {
  const ext = await bootExtension({ zone: zone("menu.example", "key.example") });
  await onlyTransport(ext);
  await ext.api.runtime.onInstalled._fire({ reason: "update" });
  await ext.mock.settle();
  assert.deepEqual(ext.state.menus.map((m) => m.id).sort(), ["openroute-dashboard", "openroute-never", "openroute-toggle"]);
  assert.ok(ext.state.menus.every((m) => m.title), "menus are titled from the messages");

  await ext.api.contextMenus.onClicked._fire({ menuItemId: "openroute-toggle", pageUrl: "https://menu.example/p" }, { id: 9, url: "https://menu.example/p" });
  await ext.mock.settle();
  assert.equal(firstHop(await ext.route("https://menu.example/")), "SOCKS5 127.0.0.1:3101");

  await ext.api.commands.onCommand._fire("toggle-route", { id: 10, url: "https://key.example/" });
  await ext.mock.settle();
  assert.equal(firstHop(await ext.route("https://key.example/")), "SOCKS5 127.0.0.1:3101");

  await ext.api.contextMenus.onClicked._fire({ menuItemId: "openroute-never", pageUrl: "https://menu.example/p" }, { id: 9 });
  await ext.mock.settle();
  assert.equal(await ext.route("https://menu.example/"), "DIRECT");
  assert.deepEqual((await ext.view()).raw.rules.never, ["menu.example"]);

  await ext.api.contextMenus.onClicked._fire({ menuItemId: "openroute-dashboard" }, {});
  await ext.mock.settle();
  assert.ok(ext.state.createdTabs.some((t) => /src\/ui\/options\.html$/.test(t.url)));
});

test("each tab's badge shows how its own site is doing", async () => {
  const ext = await bootExtension({ zone: zone("badge.example") });
  await onlyTransport(ext);
  await ext.fail("https://badge.example/", "net::ERR_CONNECTION_TIMED_OUT", { tabId: 4 });
  assert.equal(badge(ext, 4), "…", "being routed");
  await ext.ok("https://badge.example/", { tabId: 4 });
  assert.equal(badge(ext, 4), "✓", "routed and working");
  assert.match(ext.state.badges.get(4).title, /badgeRouted/);
  // A refresh with nothing changed doesn't re-send this tab's badge.
  const real = ext.api.action.setBadgeText;
  let calls = 0;
  ext.api.action.setBadgeText = (d) => {
    if (d.tabId === 4) calls++;
    return real(d);
  };
  await ext.mock.fireAllAlarms();
  await ext.mock.settle();
  assert.equal(calls, 0, "unchanged badges aren't rewritten");
  ext.api.action.setBadgeText = real;

  await ext.ok("https://elsewhere.example/", { tabId: 4 });
  assert.equal(badge(ext, 4), null, "a site OpenRoute doesn't handle shows the global badge");

  const stuck = await bootExtension({ zone: zone("stuck.example") });
  await onlyTransport(stuck, 0);
  await stuck.fail("https://stuck.example/", "net::ERR_CONNECTION_TIMED_OUT", { tabId: 2 });
  assert.equal(badge(stuck, 2), "!", "blocked with no way through");
  await stuck.api.tabs.onRemoved._fire(2, {});
  await stuck.mock.settle();
  assert.equal((await stuck.send("tabState", { tabId: 2 })).web, false, "a closed tab is forgotten");
});

test("sites are grouped by the domain that's routed, with what rides along", () => {
  const policies = {
    "x.com": { domain: "x.com", status: "fixed", updatedAt: 5 },
    "twimg.com": { domain: "twimg.com", via: "bundle", parent: "x.com", status: "fixed", updatedAt: 4 },
    "old.example": { domain: "old.example", status: "exhausted", updatedAt: 1 }
  };
  const sites = {
    "www.x.com": { host: "www.x.com", lastSeen: 9 },
    "pbs.twimg.com": { host: "pbs.twimg.com", lastSeen: 3 },
    "news.bbc.co.uk": { host: "news.bbc.co.uk", lastSeen: 2 }
  };
  const groups = groupSites(policies, sites);
  assert.deepEqual(groups.map((g) => g.domain), ["x.com", "bbc.co.uk", "old.example"], "most recent first");
  assert.deepEqual(groups[0].members, ["twimg.com"]);
  assert.deepEqual(groups[0].hosts.sort(), ["pbs.twimg.com", "www.x.com"]);
  assert.equal(groups[1].policy, null, "a diagnosed site without a policy groups under its registrable domain");
});

test("a backup restores settings, rules and transports; passwords only when asked", async () => {
  const ext = await bootExtension();
  await ext.send("addTransport", { transport: { id: "vps", label: "VPS", scheme: "http", host: "203.0.113.9", port: 3128, auth: { username: "u", password: "s3cret" } } });
  await ext.send("setRule", { domain: "keep.example", list: "always" });
  await ext.send("saveSettings", { patch: { mode: "full", bundles: false } });

  const plain = (await ext.send("exportData", {})).data;
  assert.equal(plain.format, "openroute-backup");
  assert.ok(!JSON.stringify(plain).includes("s3cret"), "no password unless asked");
  const full = (await ext.send("exportData", { includeSecrets: true })).data;
  assert.equal(full.transports.find((t) => t.id === "vps").auth.password, "s3cret");

  await ext.send("resetAll");
  let v = await ext.view();
  assert.deepEqual([v.settings.mode, v.settings.bundles], ["smart", true]);
  assert.ok(!v.transports.some((t) => t.id === "vps"));
  assert.ok(v.transports.some((t) => t.id === "tor-browser"), "the presets come back");
  assert.deepEqual(v.raw.rules, {});

  const r = (await ext.send("importData", { data: plain })).report;
  assert.equal(r.rules, 1);
  assert.ok(r.settings > 0 && r.transports > 0, JSON.stringify(r));
  assert.deepEqual(r.needsPassword, ["VPS"]);
  v = await ext.view();
  assert.equal(v.settings.mode, "full");
  assert.deepEqual(v.raw.rules.always, ["keep.example"]);
  assert.equal(v.transports.find((t) => t.id === "vps").auth.username, "u");

  assert.equal((await ext.send("importData", { data: { format: "something-else" } })).ok, false);
  const bad = { ...plain, rules: { always: ["ok.example", "not a domain!"] }, settings: { mode: "warp", autoReload: false } };
  const r2 = (await ext.send("importData", { data: bad })).report;
  assert.ok(r2.skipped.some((s) => s.includes("not a domain")), JSON.stringify(r2.skipped));
  assert.ok(r2.skipped.includes("setting mode"), "invalid values are skipped, not applied");
  assert.equal((await ext.view()).settings.autoReload, false, "the valid rest is applied");
});

test("reset keeps what the companion still runs", async () => {
  const ext = await bootExtension({ setup: (m) => m.setNativeHost("com.openroute.host", async (msg) => msg.cmd === "connectDpi"
    ? { ok: true, transports: [{ id: "companion-dpi-record", label: "DPI", port: 31081 }] }
    : { ok: true, cmd: "pong" }) });
  await ext.send("companionConnectDpi");
  await ext.send("resetAll");
  const ids = (await ext.view()).transports.map((t) => t.id);
  assert.ok(ids.includes("companion-dpi-record") && ids.includes("tor-browser"), ids.join());
});

test("the diagnostics report hides site names, proxy addresses and credentials", async () => {
  const ext = await bootExtension({ zone: zone("secret-site.example") });
  await ext.send("addTransport", { transport: { id: "vps", label: "Home VPS", scheme: "http", host: "198.51.100.77", port: 3128, auth: { username: "alice", password: "pw-123" } } });
  await ext.fail("https://secret-site.example/", "net::ERR_CONNECTION_TIMED_OUT", { tabId: 2 });

  const report = (await ext.send("diagnosticsReport", {})).report;
  const text = JSON.stringify(report);
  for (const leak of ["secret-site", "198.51.100.77", "alice", "pw-123", "Home VPS"]) assert.ok(!text.includes(leak), `the report leaks ${leak}`);
  assert.ok(Object.keys(report.policies).length > 0 && Object.keys(report.policies).every((k) => /^site-\d+$/.test(k)), Object.keys(report.policies).join());
  assert.ok(report.events.length > 0);

  const open = JSON.stringify((await ext.send("diagnosticsReport", { redactDomains: false })).report);
  assert.ok(open.includes("secret-site.example"), "site names on request");
  for (const leak of ["198.51.100.77", "alice", "pw-123"]) assert.ok(!open.includes(leak), `never ${leak}, even unredacted`);
});

test("openDashboard only opens known sections", async () => {
  const ext = await bootExtension();
  await ext.send("openDashboard", { section: "dns" });
  await ext.send("openDashboard", { section: "../../evil" });
  const urls = ext.state.createdTabs.map((t) => t.url);
  assert.ok(urls.some((u) => u.endsWith("src/ui/options.html#dns")));
  assert.ok(urls.some((u) => u.endsWith("src/ui/options.html")) && !urls.some((u) => u.includes("evil")));
});
