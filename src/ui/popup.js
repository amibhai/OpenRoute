// OpenRoute popup: what's happening on this tab, the routing mode, the
// transports' health and the latest sites. Everything else is on the
// dashboard (options page). All dynamic content is inserted as text.

import { $, $$, el, setChildren, relTime, busy } from "./shared/dom.js";
import { send, getApi } from "./shared/messaging.js";
import { t, localize, locale } from "./shared/i18n.js";
import { STATUS, STATUS_SEEN, EXHAUSTED, RUNG, HEALTH, DNS_TYPES, typeOf } from "./labels.js";

const api = getApi();
let STATE = null;
let TAB = null;
let INFO = null;

const chip = (tone, text) => el("span", { class: `chip ${tone}`, text });
const button = (text, onclick, cls = "btn small") => el("button", { class: cls, type: "button", text, onclick });

function banner(text, tone = "warn", action = null) {
  const b = $("#banner");
  if (!text) {
    b.hidden = true;
    return;
  }
  b.className = `banner ${tone}`;
  setChildren(b, el("span", { text }), action && button(action.label, action.onClick, "btn small"));
  b.hidden = false;
}

function note(text, tone = "") {
  const n = $("#tabNote");
  n.textContent = text || "";
  n.className = `note small ${tone}`;
}

// The page the user is looking at. Firefox for Android shows the popup as a
// tab of its own; then it's the page they came from.
async function currentTab() {
  const tabs = await api.tabs.query({ currentWindow: true }).catch(() => []);
  const own = api.runtime.getURL("");
  const active = tabs.find((x) => x.active);
  if (active && !(active.url || "").startsWith(own)) return active;
  return tabs.filter((x) => !x.active).sort((a, b) => (b.lastAccessed || 0) - (a.lastAccessed || 0))[0] || active || null;
}

async function refresh() {
  const [state, tab] = await Promise.all([send("getState"), currentTab()]);
  if (!state?.ok) {
    banner(t("errorBackground", { error: state?.error || "" }), "bad");
    return;
  }
  STATE = state;
  TAB = tab;
  INFO = tab ? await send("tabState", { url: tab.url, tabId: tab.id }) : { ok: true, web: false };
  render();
}

async function act(type, extra) {
  const res = await send(type, extra);
  if (!res?.ok) banner(res?.error || t("errorGeneric"), "bad");
  await refresh();
  return res;
}

function openDashboard(section) {
  send("openDashboard", { section }).finally(() => window.close());
}

const transportName = (id) => STATE.transports.find((x) => x.id === id)?.label || id;
const latency = (tr) => (tr?.latencyMs ? t("latencyMs", { ms: Math.round(tr.latencyMs) }) : "");

// ---- this site --------------------------------------------------------------

async function toggleSite(btn) {
  const res = await busy(btn, t("working"), () => send("toggleSite", { url: TAB?.url || INFO?.url, tabId: TAB?.id }));
  if (!res?.ok) return note(res?.error || t("errorGeneric"), "bad");
  const r = res.result || {};
  if (r.reason === "no-transport") return window.close(); // the dashboard opened on Transports
  await refresh();
  if (r.done) note(r.routed ? t("noteRouted", { domain: r.domain }) : t("noteUnrouted", { domain: r.domain }), "good");
}

async function openSecureDns(btn) {
  const res = await busy(btn, null, () => send("openSecureDnsSettings"));
  if (res?.opened) return window.close();
  const g = res?.guide;
  if (g) note([g.copyUrl && t("openUrl", { url: g.copyUrl }), ...(g.steps || [])].filter(Boolean).join(" → "));
}

function renderTab() {
  const status = $("#tabStatus");
  const detail = $("#tabDetail");
  const actions = $("#tabActions");
  if (!INFO?.ok || !INFO.web) {
    $("#tabHost").textContent = t("tabNotWebsite");
    setChildren(status);
    detail.textContent = "";
    setChildren(actions);
    return;
  }
  $("#tabHost").textContent = INFO.host;
  const s = STATE.settings || {};
  const pol = INFO.policy;
  const site = INFO.site;
  const toggle = (label, primary = false) => button(label, (e) => toggleSite(e.currentTarget), `btn small${primary ? " primary" : ""}`);
  const line = [];
  const buttons = [];
  let text;

  if (s.mode === "off") {
    line.push(chip("muted", t("statusOff")));
    text = t("tabModeOff");
    buttons.push(button(t("turnOnSmart"), () => act("saveSettings", { patch: { mode: "smart" } }), "btn small primary"));
  } else if (INFO.rule === "never") {
    line.push(chip("muted", t("statusNever")));
    text = t("tabNever", { domain: INFO.ruleDomain || INFO.domain });
    buttons.push(button(t("removeRule"), () => act("setRule", { domain: INFO.ruleDomain || INFO.domain, list: null })));
  } else if (s.mode === "full" && !pol?.pinned) {
    line.push(chip("good", t("statusFullTunnel")));
    text = t("tabFullTunnel");
  } else if (!pol) {
    line.push(chip("muted", t("statusDirect")));
    text = t("tabDirect");
    buttons.push(toggle(t("routeThisSite")));
  } else {
    const [key, tone] = STATUS[pol.status] || STATUS.blocked;
    line.push(chip(tone, t(key)));
    if (pol.pinned) line.push(chip("muted", t("pinned")));
    const via = INFO.transport?.label || (pol.proxyId ? transportName(pol.proxyId) : "");
    switch (pol.status) {
      case "fixed":
        if (!INFO.routed) text = t("tabWorksOn", { rung: t(RUNG[pol.rung] || "rungDirect") });
        else if (INFO.transport?.latencyMs) text = t("tabRoutedViaLatency", { via, latency: latency(INFO.transport) });
        else text = t("tabRoutedVia", { via });
        if (INFO.routed || pol.pinned) buttons.push(toggle(t("stopRouting")));
        break;
      case "routing":
        text = t("tabRoutingVia", { via });
        buttons.push(button(t("reloadPage"), () => { api.tabs.reload(TAB.id); window.close(); }, "btn small primary"), toggle(t("stopRouting")));
        break;
      case "exhausted":
        text = [t(EXHAUSTED[pol.exhaustedReason] || "exhaustedAllFailed"), pol.retryAt ? t("retryingAt", { when: relTime(pol.retryAt, locale()) }) : ""].filter(Boolean).join(" ");
        if (STATE.transports.length) buttons.push(button(t("tryAgainNow"), () => act("routeSite", { domain: pol.domain }), "btn small primary"));
        buttons.push(button(t("addTransport"), () => openDashboard("transports")));
        break;
      case "manual":
        text = t("tabManual", { rung: t(RUNG[pol.rung] || "rungDirect") });
        buttons.push(button(t("backToAuto"), () => act("setRung", { domain: pol.domain, rung: "auto" })));
        break;
      default: { // blocked, needs-user
        const dns = site?.type && DNS_TYPES.has(site.type);
        text = site?.type ? t(typeOf(site.type)[1]) : t("tabBlocked");
        if (dns) buttons.push(button(t("turnOnSecureDns"), (e) => openSecureDns(e.currentTarget), "btn small primary"));
        buttons.push(toggle(t("routeThisSite"), !dns));
      }
    }
  }
  if (site?.type && pol && pol.status !== "fixed") {
    const [label, , tone] = typeOf(site.type);
    line.push(chip(tone, t(label)));
  }
  setChildren(status, line);
  detail.textContent = text;
  setChildren(actions, buttons);
}

// ---- transports & sites --------------------------------------------------------

function renderTransports() {
  const list = STATE.transports || [];
  $("#transportEmpty").hidden = list.length > 0;
  setChildren($("#transportList"), list.slice(0, 5).map((tr) => {
    const [hk, tone] = HEALTH[tr.health] || HEALTH.unknown;
    return el("li", {},
      el("span", { class: `dot ${tone}`, role: "img", "aria-label": t(hk) }),
      el("span", { class: "tl", text: tr.label, title: tr.label }),
      tr.id === STATE.activeTransportId && chip("muted", t("preferred")),
      el("span", { class: "tm", text: tr.health === "up" && tr.latencyMs ? latency(tr) : t(hk) }));
  }));
}

function renderSites() {
  const groups = (STATE.groups || []).filter((g) => g.policy || g.hosts.length);
  $("#siteCount").textContent = groups.length ? String(groups.length) : "";
  $("#sitesEmpty").hidden = groups.length > 0;
  setChildren($("#siteList"), groups.slice(0, 5).map((g) => {
    const [key, tone] = g.policy ? STATUS[g.policy.status] || STATUS.blocked : STATUS_SEEN;
    const via = g.policy?.proxyId ? transportName(g.policy.proxyId) : "";
    return el("li", {}, el("button", {
      type: "button", onclick: () => openDashboard("sites"),
      "aria-label": t("siteRowLabel", { domain: g.domain, status: t(key) })
    },
    el("span", { class: "sd", text: g.domain }),
    via && el("span", { class: "sv", text: via }),
    chip(tone, t(key))));
  }));
}

// permissions.request has to run inside the click (a user gesture).
async function requestPermissions(perms) {
  try {
    await api.permissions.request(perms);
  } catch (e) {
    banner(t("errorPermission", { error: e?.message || String(e) }), "bad");
  }
  refresh();
}

function renderBanner() {
  const access = STATE.access || {};
  const caps = STATE.capabilities || {};
  const r = STATE.router || {};
  if (caps.needsHostAccessToRoute && access.hostAccess === false) {
    banner(t("bannerNeedsHostAccess"), "bad", { label: t("allow"), onClick: () => requestPermissions({ origins: ["<all_urls>"] }) });
  } else if (r.level === "controlled_by_other_extensions") {
    banner(t("bannerOtherExtension"), "bad");
  } else if (r.engine === "none") {
    banner(t("bannerNoProxyApi"), "warn");
  } else if (r.level === "not_controllable") {
    banner(t("bannerPolicyLocked"), "bad");
  } else if (r.error) {
    banner(t("bannerRoutingError", { error: r.error }), "bad");
  } else {
    banner("");
  }
}

function render() {
  const mode = STATE.settings?.mode || "smart";
  for (const r of $$('input[name="mode"]')) r.checked = r.value === mode;
  renderBanner();
  renderTab();
  renderTransports();
  renderSites();
}

function init() {
  localize();
  for (const r of $$('input[name="mode"]')) {
    r.addEventListener("change", (e) => {
      if (e.target.checked) act("saveSettings", { patch: { mode: e.target.value } });
    });
  }
  $("#openOptions").addEventListener("click", () => openDashboard(""));
  $("#manageTransports").addEventListener("click", () => openDashboard("transports"));
  $("#manageSites").addEventListener("click", () => openDashboard("sites"));
  $("#discover").addEventListener("click", async (e) => {
    const out = $("#discoverResult");
    const res = await busy(e.currentTarget, t("searching"), () => send("discoverLocalProxies"));
    if (!res?.ok || res.error) {
      out.textContent = res?.error || t("errorGeneric");
      out.className = "note small bad";
    } else if (res.found?.length) {
      out.textContent = t("discoverFound", { list: res.found.map((f) => `${f.label} (${f.port})`).join(", ") });
      out.className = "note small good";
    } else {
      out.textContent = t("discoverNone", { count: res.tested });
      out.className = "note small";
    }
    await refresh();
  });

  let timer = null;
  api.storage.onChanged.addListener((_c, area) => {
    if (area !== "local") return;
    clearTimeout(timer);
    timer = setTimeout(refresh, 150); // live, but debounced
  });
  refresh();
}

init();
