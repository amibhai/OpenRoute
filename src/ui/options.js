// OpenRoute dashboard: sites, transports (and the companion), DNS, rules,
// settings and diagnostics. Reads state from the background, changes it only
// through validated messages, and inserts everything dynamic as text.

import { $, $$, el, setChildren, relTime, busy, downloadJson } from "./shared/dom.js";
import { send, getApi } from "./shared/messaging.js";
import { t, localize, locale } from "./shared/i18n.js";
import { STATUS, EXHAUSTED, RUNG, HEALTH, RESOLVER_NAMES, EVENT, TOR_MODES, TOR_MODE, MODE_HELP, ENGINE, CONTROL, STATUS_SEEN, EVENT_MANUAL, typeOf } from "./labels.js";

const api = getApi();
const SECTIONS = ["sites", "transports", "dns", "rules", "settings", "diagnostics"];
let STATE = null;
let EVENTS = [];

const chip = (tone, text) => el("span", { class: `chip ${tone}`, text });
const button = (text, onclick, cls = "btn small") => el("button", { class: cls, type: "button", text, onclick });
const when = (ts) => relTime(ts, locale());
const transportName = (id) => STATE.transports.find((x) => x.id === id)?.label || id || "";

function say(target, text, tone = "") {
  const n = typeof target === "string" ? $(target) : target;
  n.textContent = text || "";
  n.className = `note ${tone}`.trim();
}

function banner(text, tone = "warn", action = null) {
  const b = $("#banner");
  if (!text) {
    b.hidden = true;
    return;
  }
  b.className = `banner ${tone}`;
  setChildren(b, el("span", { text }), action && button(action.label, action.onClick));
  b.hidden = false;
}

async function refresh() {
  const [res, log] = await Promise.all([send("getState"), send("getEventLog", { limit: 300 })]);
  if (!res?.ok) {
    banner(t("errorBackground", { error: res?.error || "" }), "bad");
    return;
  }
  STATE = res;
  EVENTS = log?.ok ? log.events : [];
  render();
}

// Runs a message; reports failure in `out` (or the banner) and refreshes.
async function act(type, extra, out) {
  const res = await send(type, extra);
  if (!res?.ok) {
    if (out) say(out, res?.error || t("errorGeneric"), "bad");
    else banner(res?.error || t("errorGeneric"), "bad");
  }
  await refresh();
  return res;
}

// permissions.request has to run inside the click (a user gesture).
async function requestPermissions(perms) {
  try {
    return await api.permissions.request(perms);
  } catch (e) {
    banner(t("errorPermission", { error: e?.message || String(e) }), "bad");
    return false;
  }
}

// ---- navigation ---------------------------------------------------------------

function showSection() {
  const id = SECTIONS.includes(location.hash.slice(1)) ? location.hash.slice(1) : "sites";
  for (const s of SECTIONS) $(`#${s}`).hidden = s !== id;
  for (const a of $$(".side a")) {
    if (a.getAttribute("href") === `#${id}`) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  }
}

// ---- sites ----------------------------------------------------------------------

function groupMatches(g, query, filter) {
  const p = g.policy;
  if (query && ![g.domain, ...g.hosts, ...g.members].some((d) => d.includes(query))) return false;
  if (filter === "attention") return !p || ["blocked", "needs-user", "exhausted"].includes(p.status);
  if (filter === "routed") return !!p && p.rung === "proxy" && !!p.proxyId;
  if (filter === "working") return p?.status === "fixed";
  return true;
}

function routeSelect(g) {
  const p = g.policy;
  const value = !p || !p.pinned ? "auto" : p.rung === "proxy" && p.proxyId ? `proxy:${p.proxyId}` : p.rung;
  const sel = el("select", { "aria-label": t("routeFor", { domain: g.domain }) },
    el("option", { value: "auto", text: t("routeAuto") }),
    el("option", { value: "direct", text: t("rungDirect") }),
    STATE.transports.map((tr) => el("option", { value: `proxy:${tr.id}`, text: t("routeVia", { via: tr.label }) })),
    el("option", { value: "fallback", text: t("rungFallback") }));
  sel.value = value;
  sel.addEventListener("change", () => {
    const v = sel.value;
    if (v.startsWith("proxy:")) act("setRung", { domain: g.domain, rung: "proxy", proxyId: v.slice(6) }, "#sitesResult");
    else act("setRung", { domain: g.domain, rung: v }, "#sitesResult");
  });
  return el("label", { class: "field" }, el("span", { text: t("route") }), sel);
}

function hostRow(host) {
  const d = STATE.sites[host] || {};
  const [label, remedy, tone] = typeOf(d.type);
  const bits = [];
  if (d.echLikely) bits.push(t("diagEch"));
  else if (d.hasHTTPS) bits.push(t("diagHttpsRecord"));
  if (d.injected) bits.push(t("diagInjected"));
  if (d.localInjected) bits.push(t("diagLocalInjected", { ips: (d.localIPs || []).join(", ") }));
  if (d.dohUnreachable) bits.push(t("diagDohUnreachable"));
  if (d.dohSkipped === "consent") bits.push(t("diagDohSkipped"));
  if (d.dohProvider) bits.push(t("diagVia", { resolver: RESOLVER_NAMES[d.dohProvider] || d.dohProvider }));
  const url = d.url || `https://${host}/`;
  return el("li", { class: "hostrow" },
    el("div", { class: "hhead" },
      el("span", { class: "hname", text: host }),
      d.type && chip(tone, t(label)),
      d.count > 1 && el("span", { class: "muted small", text: t("seenTimes", { count: d.count }) }),
      d.lastSeen && el("span", { class: "muted small", text: when(d.lastSeen) })),
    d.type && el("p", { class: "small", text: t(remedy) }),
    bits.length > 0 && el("p", { class: "muted small", text: bits.join(" · ") }),
    d.resolvedIPs?.length > 0 && el("p", { class: "muted small mono wrap-anywhere", text: t("realAddress", { ips: d.resolvedIPs.join(", ") }) }),
    el("div", { class: "actions" },
      button(t("open"), () => api.tabs.create({ url })),
      button(t("recheck"), (e) => busy(e.currentTarget, t("working"), () => act("recheck", { host }, "#sitesResult"))),
      button(t("wayback"), () => api.tabs.create({ url: `https://web.archive.org/web/2/${url}` })),
      button(t("readerView"), () => api.tabs.create({ url: `https://r.jina.ai/${url}` }))));
}

function groupTimeline(g) {
  const mine = new Set([g.domain, ...g.members]);
  const items = EVENTS.filter((e) => mine.has(e.domain) || mine.has(e.parent)).slice(-8).reverse();
  if (!items.length) return null;
  return el("div", {},
    el("h4", { text: t("history") }),
    el("ol", { class: "gtimeline" }, items.map((e) => el("li", {}, `${when(e.at)} — ${eventText(e)}`))));
}

function renderSites() {
  const query = $("#siteSearch").value.trim().toLowerCase();
  const filter = $("#siteFilter").value;
  const groups = (STATE.groups || []).filter((g) => groupMatches(g, query, filter));
  $("#groupsEmpty").hidden = groups.length > 0;
  const open = new Set($$("#groupList details[open]").map((d) => d.dataset.domain));
  setChildren($("#groupList"), groups.map((g) => {
    const p = g.policy;
    const [key, tone] = p ? STATUS[p.status] || STATUS.blocked : STATUS_SEEN;
    const via = p?.proxyId ? t("viaTransport", { via: transportName(p.proxyId) }) : p?.rung && p.rung !== "proxy" ? t(RUNG[p.rung] || "rungDirect") : "";
    const reason = p?.status === "exhausted"
      ? [t(EXHAUSTED[p.exhaustedReason] || "exhaustedAllFailed"), p.retryAt ? t("retryingAt", { when: when(p.retryAt) }) : ""].filter(Boolean).join(" ")
      : "";
    return el("li", {}, el("details", { class: "group", dataset: { domain: g.domain }, open: open.has(g.domain) },
      el("summary", {},
        el("span", { class: "gdomain", text: g.domain }),
        chip(tone, t(key)),
        p?.pinned && chip("muted", t("pinned")),
        via && el("span", { class: "gvia", text: via }),
        g.lastActivity > 0 && el("span", { class: "gwhen", text: when(g.lastActivity) })),
      el("div", { class: "gbody" },
        reason && el("p", { class: "small", text: reason }),
        g.members.length > 0 && el("p", { class: "muted small", text: t("routedAlong", { domains: g.members.join(", ") }) }),
        el("div", { class: "row" },
          routeSelect(g),
          button(t("routeNow"), () => act("routeSite", { domain: g.domain }, "#sitesResult")),
          button(t("alwaysRoute"), () => act("setRule", { domain: g.domain, list: "always" }, "#sitesResult")),
          button(t("neverRoute"), () => act("setRule", { domain: g.domain, list: "never" }, "#sitesResult")),
          button(t("forget"), () => act("clearDomain", { domain: g.domain }, "#sitesResult"), "btn small danger")),
        g.hosts.length > 0 && el("ul", { class: "stack" }, g.hosts.map(hostRow)),
        groupTimeline(g))));
  }));
}

// ---- transports & companion ------------------------------------------------------------

function endpointOf(tr) {
  return tr.kind === "companion" ? t("endpointCompanion", { port: tr.port }) : `${tr.scheme}://${tr.host}:${tr.port}`;
}

function renderTransports() {
  const list = STATE.transports || [];
  $("#transportsEmpty").hidden = list.length > 0;
  setChildren($("#transportCards"), list.map((tr) => {
    const [hk, tone] = HEALTH[tr.health] || HEALTH.unknown;
    const out = el("p", { class: "note", role: "status", "aria-live": "polite" });
    const facts = [
      tr.latencyMs && t("latencyMs", { ms: Math.round(tr.latencyMs) }),
      tr.lastOk && t("lastOk", { when: when(tr.lastOk) }),
      tr.lastFail && t("lastFail", { when: when(tr.lastFail) }),
      tr.auth?.username && t("loginAs", { user: tr.auth.username })
    ].filter(Boolean);
    return el("li", { class: "card tcard" },
      el("div", { class: "card-head" },
        el("span", { class: `dot ${tone}`, "aria-hidden": "true" }),
        el("span", { class: "tname", text: tr.label }),
        tr.id === STATE.activeTransportId && chip("muted", t("preferred")),
        el("span", { class: "spacer" }),
        chip(tone, t(hk))),
      el("p", { class: "muted small mono wrap-anywhere", text: endpointOf(tr) }),
      tr.note && el("p", { class: "muted small", text: tr.note }),
      facts.length > 0 && el("p", { class: "muted small", text: facts.join(" · ") }),
      el("div", { class: "actions" },
        button(t("test"), (e) => busy(e.currentTarget, t("testing"), async () => {
          const res = await send("probeTransport", { id: tr.id });
          const r = res?.result;
          await refresh();
          say(out, r?.ok ? t("testOk", { ms: Math.round(r.latencyMs || 0) }) : t("testFailed", { error: r?.error || res?.error || "" }), r?.ok ? "good" : "bad");
        })),
        tr.id !== STATE.activeTransportId && button(t("makePreferred"), () => act("setActiveTransport", { id: tr.id })),
        button(t("remove"), () => {
          if (confirm(t("confirmRemoveTransport", { name: tr.label }))) act("removeTransport", { id: tr.id });
        }, "btn small danger")),
      out);
  }));
}

function renderCompanion() {
  const c = STATE.companion || {};
  const chipEl = $("#companionChip");
  chipEl.className = `chip ${c.available ? "good" : "muted"}`;
  chipEl.textContent = !c.supported ? t("companionUnsupported") : c.available ? t("companionConnected") : t("companionMissing");
  $("#companionHelp").textContent = !c.supported ? t("companionUnsupportedHelp") : c.available ? t("companionHelp") : t("companionInstallHelp");
  $("#companionControls").hidden = !c.supported;
  for (const b of $$("#companionControls button")) b.disabled = !c.available;
  $("#cCheck").disabled = false;
}

async function companionCall(btn, type, extra, okText) {
  const res = await busy(btn, t("working"), () => send(type, extra));
  const inner = res?.result;
  if (res?.ok && inner?.ok !== false) say("#cResult", okText(inner || {}), "good");
  else say("#cResult", t("companionFailed", { error: inner?.error || res?.error || t("companionMissing") }), "bad");
  await refresh();
}

// ---- DNS, rules, settings --------------------------------------------------------------------

function renderDns() {
  const s = STATE.settings;
  const sel = $("#dohProvider");
  if (!sel.options.length) {
    setChildren(sel, (STATE.resolvers || Object.keys(RESOLVER_NAMES)).map((r) => el("option", { value: r, text: RESOLVER_NAMES[r] || r })));
  }
  sel.value = s.dohProvider;
  if (document.activeElement !== $("#customDoH")) $("#customDoH").value = s.customDoH || "";
  $("#remoteDiagnosis").checked = s.remoteDiagnosis !== false;
  const a = STATE.access || {};
  $("#consentRow").hidden = !(STATE.capabilities?.dataCollectionConsent && a.dataConsent === false && s.remoteDiagnosis !== false);
}

function renderRules() {
  const rules = STATE.rules || {};
  for (const list of ["always", "never"]) {
    const items = rules[list] || [];
    setChildren($(`#${list}List`), items.length
      ? items.map((d) => el("li", {}, el("span", { class: "wrap-anywhere", text: d }),
        button(t("remove"), () => act("setRule", { domain: d, list: null }, "#rulesResult"))))
      : el("li", { class: "muted small", text: t("rulesNone") }));
  }
}

function renderSettings() {
  const s = STATE.settings;
  for (const r of $$('input[name="mode"]')) r.checked = r.value === s.mode;
  $("#modeHelp").textContent = t(MODE_HELP[s.mode] || "modeSmartHelp");
  $("#routeScope").value = s.routeScope;
  for (const k of ["bundles", "autoRoute", "autoReload", "detectionEnabled", "deepDetection", "webrtcProtection"]) $(`#${k}`).checked = !!s[k];
  // Deep detection reads responses on every site, which Chromium only allows
  // with site access (Firefox already has it for routing).
  const needsAccess = STATE.capabilities?.proxyEngine === "chromium" && STATE.access?.hostAccess === false;
  $("#deepAccessRow").hidden = !(s.deepDetection && needsAccess);
}

// ---- diagnostics ------------------------------------------------------------------------------------

function eventText(e) {
  const name = (id) => (RUNG[id] ? t(RUNG[id]) : transportName(id));
  let key = EVENT[e.event];
  if (e.event === "manual") key = EVENT_MANUAL[e.rung] || EVENT_MANUAL.other;
  if (!key) return e.event;
  return t(key, {
    domain: e.domain || "", parent: e.parent || "", via: name(e.via || e.proxyId), from: name(e.from), to: name(e.to),
    type: e.type ? t(typeOf(e.type)[0]) : "", error: e.error || "",
    reason: EXHAUSTED[e.reason] ? t(EXHAUSTED[e.reason]) : e.reason || "",
    rung: e.rung ? t(RUNG[e.rung] || "rungDirect") : "",
    added: (e.added || []).join(", "),
    found: Array.isArray(e.found) && e.found.length ? e.found.join(", ") : t("none"),
    tested: e.tested ?? "", id: e.id || "", port: e.port || "", step: e.step || "", where: e.where || ""
  });
}

function yesNo(v) {
  return v == null ? t("unknown") : v ? t("yes") : t("no");
}

function renderDiagnostics() {
  const r = STATE.router || {};
  const b = STATE.browser || {};
  const a = STATE.access || {};
  const c = STATE.capabilities || {};
  const rows = [
    [t("statusVersion"), STATE.version || "?"],
    [t("statusBrowser"), [b.name, b.version, b.mobile ? t("mobile") : ""].filter(Boolean).join(" ") || t("unknown")],
    [t("statusEngine"), t(ENGINE[r.engine] || ENGINE.none)],
    [t("statusControl"), t(CONTROL[r.level] || "unknown")],
    [t("statusRoutes"), String(r.count ?? 0)],
    r.error && [t("statusRouterError"), r.error],
    [t("statusSiteAccess"), yesNo(a.hostAccess)],
    c.dataCollectionConsent && [t("statusDataConsent"), yesNo(a.dataConsent)],
    a.privateWindows != null && [t("statusPrivate"), yesNo(a.privateWindows)],
    [t("statusCompanion"), !STATE.companion?.supported ? t("companionUnsupported") : yesNo(STATE.companion.available)]
  ].filter(Boolean);
  setChildren($("#statusList"), rows.flatMap(([k, v]) => [el("dt", { text: k }), el("dd", { text: v })]));

  const filter = $("#eventFilter");
  const kinds = [...new Set(EVENTS.map((e) => e.event))].sort();
  const current = filter.value || "all";
  setChildren(filter, el("option", { value: "all", text: t("filterAllEvents") }), kinds.map((k) => el("option", { value: k, text: k })));
  filter.value = kinds.includes(current) ? current : "all";
  const shown = EVENTS.filter((e) => filter.value === "all" || e.event === filter.value).slice().reverse();
  $("#timelineEmpty").hidden = shown.length > 0;
  setChildren($("#timeline"), shown.map((e) => el("li", {},
    el("time", { datetime: new Date(e.at).toISOString(), title: new Date(e.at).toLocaleString(locale()), text: when(e.at) }),
    el("span", { text: eventText(e) }))));
}

function render() {
  $("#version").textContent = STATE.version ? t("versionLabel", { version: STATE.version }) : "";
  const r = STATE.router || {};
  if (STATE.capabilities?.needsHostAccessToRoute && STATE.access?.hostAccess === false) {
    banner(t("bannerNeedsHostAccess"), "bad", { label: t("allow"), onClick: async () => { await requestPermissions({ origins: ["<all_urls>"] }); refresh(); } });
  } else if (r.level === "controlled_by_other_extensions") banner(t("bannerOtherExtension"), "bad");
  else if (r.engine === "none") banner(t("bannerNoProxyApi"), "warn");
  else if (r.level === "not_controllable") banner(t("bannerPolicyLocked"), "bad");
  else banner("");
  renderSites();
  renderTransports();
  renderCompanion();
  renderDns();
  renderRules();
  renderSettings();
  renderDiagnostics();
}

// ---- wiring --------------------------------------------------------------------------------------------

function init() {
  localize();
  setChildren($("#cTorMode"), TOR_MODES.map((m) => el("option", { value: m, text: t(TOR_MODE[m]) })));
  window.addEventListener("hashchange", showSection);
  showSection();

  $("#siteSearch").addEventListener("input", () => STATE && renderSites());
  $("#siteFilter").addEventListener("change", () => STATE && renderSites());
  $("#clearAll").addEventListener("click", () => {
    if (confirm(t("confirmClearAll"))) act("clearAll", {}, "#sitesResult");
  });

  $("#discover").addEventListener("click", async (e) => {
    const res = await busy(e.currentTarget, t("searching"), () => send("discoverLocalProxies"));
    if (!res?.ok || res.error) say("#discoverResult", res?.error || t("errorGeneric"), "bad");
    else if (res.found?.length) say("#discoverResult", t("discoverFound", { list: res.found.map((f) => `${f.label} (${f.port})`).join(", ") }), "good");
    else say("#discoverResult", t("discoverNone", { count: res.tested }));
    await refresh();
  });

  $("#addForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const user = $("#tUser").value.trim();
    const pass = $("#tPass").value;
    const transport = {
      label: $("#tLabel").value.trim(), scheme: $("#tScheme").value,
      host: $("#tHost").value.trim(), port: Number.parseInt($("#tPort").value.trim(), 10), kind: "user",
      ...(user || pass ? { auth: { username: user, password: pass } } : {})
    };
    const res = await busy(e.submitter || $("#addForm button[type=submit]"), t("testing"), () => send("addTransport", { transport }));
    if (!res?.ok) return say("#addResult", res?.error || t("errorGeneric"), "bad");
    for (const id of ["tLabel", "tHost", "tPort", "tUser", "tPass"]) $(`#${id}`).value = "";
    say("#addResult", res.probe?.ok ? t("addedWorking", { ms: Math.round(res.probe.latencyMs || 0) }) : t("addedNotReachable"), res.probe?.ok ? "good" : "");
    await refresh();
  });

  $("#cConnect").addEventListener("click", (e) => {
    const links = $("#cLinks").value.split("\n").map((s) => s.trim()).filter(Boolean);
    if (!links.length) return $("#cLinks").focus();
    companionCall(e.currentTarget, "companionConnect", { links, label: $("#cLabel").value.trim() }, (r) => {
      $("#cLinks").value = "";
      return t("companionConnectedPool", { count: r.count || links.length, port: r.socksPort });
    });
  });
  $("#cDpi").addEventListener("click", (e) => companionCall(e.currentTarget, "companionConnectDpi", {}, (r) => t("dpiConnected", { count: (r.transports || []).length })));
  $("#cTor").addEventListener("click", (e) => {
    const bridges = $("#cBridges").value.split("\n").map((s) => s.trim()).filter(Boolean);
    companionCall(e.currentTarget, "companionConnectTor", { mode: $("#cTorMode").value, bridges: bridges.length ? bridges : undefined },
      (r) => t("torStarting", { mode: t(TOR_MODE[r.mode] || TOR_MODE[$("#cTorMode").value] || "torMode_auto") }));
  });
  $("#cNewIdentity").addEventListener("click", (e) => companionCall(e.currentTarget, "companionNewIdentity", {}, () => t("torNewIdentityDone")));
  $("#cRefreshBridges").addEventListener("click", (e) => companionCall(e.currentTarget, "companionRefreshBridges", {}, () => t("torBridgesRefreshed")));
  for (const [id, kind] of [["#cDisconnectServer", "singbox"], ["#cDisconnectDpi", "dpi"], ["#cDisconnectTor", "tor"]]) {
    $(id).addEventListener("click", (e) => companionCall(e.currentTarget, "companionDisconnect", { kind }, () => t("disconnected")));
  }
  $("#cCheck").addEventListener("click", async (e) => {
    const res = await busy(e.currentTarget, t("working"), () => send("companionStatus"));
    const s = res?.status;
    if (!s?.ok) return say("#cResult", t("companionFailed", { error: s?.error || res?.error || t("companionMissing") }), "bad");
    const sb = s.singbox || {};
    const tor = s.tor || {};
    const problem = sb.error || sb.lastError || tor.error || tor.lastError || "";
    say("#cResult", t("companionStatusLine", {
      version: s.version || "?",
      singbox: sb.running ? t("runningVersion", { version: sb.binary?.version || "?" }) : t("stopped"),
      tor: tor.running ? (tor.bootstrap != null ? t("runningBootstrap", { percent: tor.bootstrap }) : t("running")) : t("stopped"),
      error: problem || t("none")
    }), problem ? "bad" : "good");
  });

  $("#openDns").addEventListener("click", async () => {
    const res = await send("openSecureDnsSettings");
    const g = res?.guide;
    const steps = $("#dnsSteps");
    if (res?.opened || !g) {
      steps.hidden = true;
      return;
    }
    setChildren(steps, [g.copyUrl && t("openUrl", { url: g.copyUrl }), ...(g.steps || [])].filter(Boolean).map((s) => el("li", { text: s })));
    steps.hidden = false;
  });
  $("#remoteDiagnosis").addEventListener("change", (e) => act("saveSettings", { patch: { remoteDiagnosis: e.target.checked } }, "#dohResult"));
  $("#grantConsent").addEventListener("click", async () => {
    await requestPermissions({ data_collection: ["browsingActivity"] });
    refresh();
  });
  $("#dohProvider").addEventListener("change", (e) => act("saveSettings", { patch: { dohProvider: e.target.value } }, "#dohResult"));
  $("#saveDoh").addEventListener("click", async () => {
    const v = $("#customDoH").value.trim();
    const res = await act("saveSettings", { patch: { customDoH: v || null } }, "#dohResult");
    if (res?.ok) say("#dohResult", v ? t("customDohSaved") : t("customDohCleared"), "good");
  });

  for (const list of ["always", "never"]) {
    $(`#${list}Form`).addEventListener("submit", async (e) => {
      e.preventDefault();
      const input = $(`#${list}Input`);
      const res = await act("setRule", { domain: input.value.trim(), list }, "#rulesResult");
      if (res?.ok) {
        input.value = "";
        say("#rulesResult", "");
      }
    });
  }

  for (const r of $$('input[name="mode"]')) {
    r.addEventListener("change", (e) => e.target.checked && act("saveSettings", { patch: { mode: e.target.value } }));
  }
  $("#routeScope").addEventListener("change", (e) => act("saveSettings", { patch: { routeScope: e.target.value } }));
  for (const k of ["bundles", "autoRoute", "autoReload", "detectionEnabled"]) {
    $(`#${k}`).addEventListener("change", (e) => act("saveSettings", { patch: { [k]: e.target.checked } }));
  }
  $("#deepDetection").addEventListener("change", async (e) => {
    const on = e.target.checked;
    if (on && STATE.capabilities?.proxyEngine === "chromium" && STATE.access?.hostAccess === false) await requestPermissions({ origins: ["<all_urls>"] });
    act("saveSettings", { patch: { deepDetection: on } });
  });
  $("#grantDeep").addEventListener("click", async () => {
    await requestPermissions({ origins: ["<all_urls>"] });
    refresh();
  });
  $("#webrtcProtection").addEventListener("change", async (e) => {
    const on = e.target.checked;
    if (on && !(await requestPermissions({ permissions: ["privacy"] }))) {
      e.target.checked = false;
      return say("#webrtcResult", t("webrtcNeedsPermission"), "bad");
    }
    const res = await act("saveSettings", { patch: { webrtcProtection: on } }, "#webrtcResult");
    if (res?.ok) say("#webrtcResult", res.webrtc?.applied === false ? t("webrtcNotApplied") : on ? t("webrtcOn") : t("webrtcOff"), res.webrtc?.applied === false ? "bad" : "good");
  });

  $("#exportBtn").addEventListener("click", async () => {
    const res = await send("exportData", { includeSecrets: $("#includeSecrets").checked });
    if (!res?.ok) return say("#backupResult", res?.error || t("errorGeneric"), "bad");
    downloadJson(`openroute-backup-${new Date().toISOString().slice(0, 10)}.json`, res.data);
    say("#backupResult", t("backupSaved"), "good");
  });
  $("#importBtn").addEventListener("click", () => $("#importFile").click());
  $("#importFile").addEventListener("change", async (e) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    let data;
    try {
      data = JSON.parse(await file.text());
    } catch {
      return say("#backupResult", t("importNotJson"), "bad");
    }
    const res = await act("importData", { data }, "#backupResult");
    if (!res?.ok) return;
    const r = res.report;
    say("#backupResult", [
      t("importDone", { settings: r.settings, rules: r.rules, transports: r.transports }),
      r.needsPassword.length && t("importNeedsPassword", { names: r.needsPassword.join(", ") }),
      r.skipped.length && t("importSkipped", { items: r.skipped.join("; ") })
    ].filter(Boolean).join(" "), r.skipped.length ? "" : "good");
  });
  $("#resetBtn").addEventListener("click", () => {
    if (confirm(t("confirmReset"))) act("resetAll", {}, "#backupResult");
  });

  $("#eventFilter").addEventListener("change", () => STATE && renderDiagnostics());
  $("#reportBtn").addEventListener("click", async (e) => {
    const res = await busy(e.currentTarget, t("working"), () => send("diagnosticsReport", { redactDomains: $("#redactDomains").checked }));
    if (res?.ok) downloadJson(`openroute-report-${new Date().toISOString().slice(0, 10)}.json`, res.report);
    else banner(res?.error || t("errorGeneric"), "bad");
  });

  let timer = null;
  api.storage.onChanged.addListener((_c, area) => {
    if (area !== "local") return;
    clearTimeout(timer);
    timer = setTimeout(refresh, 250);
  });
  refresh();
}

init();
