// OpenRoute popup. Reads all state from the background (getState) and drives
// it through typed messages. All dynamic content is inserted as text.

import { $, el, setChildren, relTime } from "./shared/dom.js";
import { send, getApi } from "./shared/messaging.js";
import { BADGES, REMEDIATION, STATUS, EXHAUSTED_REASON, RUNG_LABEL, HEALTH_CLS, RESOLVER_LABELS } from "./labels.js";

const api = getApi();
let STATE = { policies: {}, transports: [], settings: {}, activeTransportId: null, companion: {}, sites: {} };

function banner(text, cls = "warn", action = null) {
  const b = $("#banner");
  if (!text) { b.hidden = true; return; }
  b.className = `banner ${cls}`;
  setChildren(b, el("span", { text }), action && el("button", {
    class: "btn tiny", type: "button", text: action.label, onclick: action.onClick
  }));
  b.hidden = false;
}

// permissions.request must run inside the click handler (a user gesture).
async function requestPermissions(perms) {
  try {
    await api.permissions.request(perms);
  } catch (e) {
    banner(`The browser refused: ${e?.message || e}`, "bad");
  }
  refresh();
}

async function refresh() {
  const res = await send("getState");
  if (!res?.ok) {
    banner(`Can't reach the OpenRoute background: ${res?.error || "unknown error"}`, "bad");
    return;
  }
  STATE = res;
  renderAll();
}

async function act(type, extra, { quiet = false } = {}) {
  const res = await send(type, extra);
  if (!res?.ok && !quiet) banner(res?.error || "Something went wrong", "bad");
  await refresh();
  return res;
}

// ---- transports -------------------------------------------------------------

function endpointOf(t) {
  return t.kind === "companion" ? `companion · 127.0.0.1:${t.port}` : `${t.scheme}://${t.host}:${t.port}`;
}

function renderTransports() {
  const items = STATE.transports.map((t) => {
    const radio = el("input", {
      type: "radio", name: "activeT", class: "tactive", checked: t.id === STATE.activeTransportId,
      "aria-label": `Prefer ${t.label}`,
      onchange: () => act("setActiveTransport", { id: t.id })
    });
    const health = el("span", {
      class: `thealth ${HEALTH_CLS[t.health] || "muted"}`,
      title: `health: ${t.health}${t.latencyMs ? ` · ${t.latencyMs} ms` : ""}`,
      role: "img", "aria-label": `health ${t.health}`
    });
    const meta = el("div", { class: "tmeta" },
      el("span", { class: "tlabel", text: t.label }),
      el("span", { class: "tendpoint muted small", text: endpointOf(t) + (t.note ? ` — ${t.note}` : "") }));
    const remove = el("button", {
      class: "btn tiny ghost tremove", type: "button", title: `Remove ${t.label}`, "aria-label": `Remove ${t.label}`,
      text: "✕", onclick: () => act("removeTransport", { id: t.id })
    });
    return el("li", { class: "titem" }, el("label", { class: "tradio" }, radio), health, meta, remove);
  });
  setChildren($("#transportList"), items);

  const c = STATE.companion || {};
  const pill = $("#companionPill");
  pill.textContent = !c.supported ? "companion: not supported here" : c.available ? "companion: connected" : "companion: not installed";
  pill.className = "pill " + (c.available ? "good" : "muted");
  $("#companionBox").hidden = c.supported === false;
}

// ---- sites ------------------------------------------------------------------

function transportLabel(id) {
  return STATE.transports.find((t) => t.id === id)?.label || id;
}

function rungSelect(host, pol) {
  const value = !pol || !pol.pinned ? "auto" : pol.rung === "proxy" && pol.proxyId ? `proxy:${pol.proxyId}` : pol.rung;
  const options = [
    el("option", { value: "auto", text: "Auto" }),
    el("option", { value: "direct", text: "Direct" }),
    ...STATE.transports.map((t) => el("option", { value: `proxy:${t.id}`, text: `via ${t.label}` })),
    el("option", { value: "fallback", text: "Read-only" })
  ];
  const sel = el("select", { class: "rungSelect", "aria-label": `Route for ${host}` }, options);
  sel.value = value;
  sel.addEventListener("change", () => {
    const v = sel.value;
    if (v.startsWith("proxy:")) act("setRung", { domain: host, rung: "proxy", proxyId: v.slice(6) });
    else act("setRung", { domain: host, rung: v });
  });
  return el("label", { class: "rungpick small" }, "route ", sel);
}

function statusLine(pol) {
  if (!pol) return [el("span", { class: "chip muted", text: "not routed" })];
  const s = STATUS[pol.status] || { label: pol.status, cls: "muted" };
  const via = pol.rung === "proxy" && pol.proxyId ? ` via ${transportLabel(pol.proxyId)}` : "";
  const parts = [
    el("span", { class: `chip ${s.cls}`, text: s.label + (pol.pinned ? " · pinned" : "") }),
    el("span", { class: "muted", text: ` ${RUNG_LABEL[pol.rung] || pol.rung}${via}` })
  ];
  if (pol.status === "exhausted") {
    const why = EXHAUSTED_REASON[pol.exhaustedReason] || "";
    const when = pol.retryAt ? ` Retrying ${relTime(pol.retryAt)}.` : "";
    parts.push(el("div", { class: "muted small", text: `${why}${when}`.trim() }));
  } else if (pol.status === "needs-user" && EXHAUSTED_REASON[pol.exhaustedReason]) {
    parts.push(el("div", { class: "muted small", text: EXHAUSTED_REASON[pol.exhaustedReason] }));
  }
  return parts;
}

function renderSites() {
  const sites = STATE.sites || {};
  const policies = STATE.policies || {};
  const hosts = [...new Set([...Object.keys(sites), ...Object.keys(policies)])];
  const rows = hosts.map((h) => ({ host: h, diag: sites[h] || {}, pol: policies[h] || null }))
    .sort((a, b) => (b.diag.lastSeen || b.pol?.updatedAt || 0) - (a.diag.lastSeen || a.pol?.updatedAt || 0));

  $("#count").textContent = String(rows.length);
  $("#empty").hidden = rows.length > 0;

  setChildren($("#list"), rows.map(({ host, diag, pol }) => {
    const url = diag.url || `https://${host}/`;
    const badge = BADGES[diag.type] || (diag.type ? BADGES.unknown : null);
    const bits = [];
    if (diag.echLikely) bits.push("ECH available");
    else if (diag.hasHTTPS) bits.push("HTTPS record");
    if (diag.injected) bits.push("⚠ injected answer");
    if (diag.localInjected) bits.push(`⚠ your resolver answered ${(diag.localIPs || []).join(", ")}`);
    if (diag.dohUnreachable) bits.push("encrypted DNS unreachable");
    if (diag.dohSkipped === "consent") bits.push("encrypted-DNS check off");
    if (diag.dohProvider) bits.push(`via ${RESOLVER_LABELS[diag.dohProvider] || diag.dohProvider}`);

    const actions = el("div", { class: "actions" },
      rungSelect(host, pol),
      el("button", { class: "btn small", type: "button", text: "Retry", onclick: () => api.tabs.create({ url }) }),
      el("button", {
        class: "btn small", type: "button", text: "Recheck",
        onclick: async (e) => {
          const b = e.currentTarget; const old = b.textContent;
          b.textContent = "…"; b.disabled = true;
          await act("recheck", { host });
          b.textContent = old; b.disabled = false;
        }
      }),
      el("button", { class: "btn small", type: "button", text: "Wayback", onclick: () => api.tabs.create({ url: "https://web.archive.org/web/2/" + url }) }),
      el("button", { class: "btn small", type: "button", text: "Reader", onclick: () => api.tabs.create({ url: "https://r.jina.ai/" + url }) }),
      el("button", { class: "btn small ghost", type: "button", text: "Remove", onclick: () => act("clearDomain", { domain: host }) }));

    return el("li", { class: "item" },
      el("div", { class: "item-top" },
        el("span", { class: "host", text: host }),
        badge && el("span", { class: `badge ${badge.cls}`, text: badge.label })),
      el("div", { class: "statusline small" }, statusLine(pol)),
      diag.type && el("p", { class: "remedy muted small", text: REMEDIATION[diag.type] || REMEDIATION.unknown }),
      bits.length && el("div", { class: "diag muted small", text: bits.join(" · ") }),
      diag.resolvedIPs?.length && el("div", { class: "ips muted small", text: `Real IP via DoH: ${diag.resolvedIPs.join(", ")}` }),
      actions);
  }));
}

// ---- controls ---------------------------------------------------------------

function renderControls() {
  const s = STATE.settings || {};
  $("#autoRoute").checked = s.autoRoute !== false;
  $("#autoReload").checked = s.autoReload !== false;
  $("#detectionToggle").checked = s.detectionEnabled !== false;
  $("#providerSelect").value = s.dohProvider || "cloudflare";
  $("#remoteDiagnosis").checked = s.remoteDiagnosis !== false;

  const access = STATE.access || {};
  const caps = STATE.capabilities || {};
  $("#consentNote").hidden = !(access.dataConsent === false && s.remoteDiagnosis !== false);

  const r = STATE.router || {};
  if (caps.needsHostAccessToRoute && access.hostAccess === false) {
    banner("OpenRoute needs access to all sites to route the blocked ones (it never reads page content).", "bad", {
      label: "Allow",
      onClick: () => requestPermissions({ origins: ["<all_urls>"] })
    });
  } else if (r.level === "controlled_by_other_extensions") {
    banner("Another extension controls your proxy settings, so OpenRoute can't route sites. Disable the other proxy/VPN extension.", "bad");
  } else if (r.engine === "none") {
    banner("This browser has no proxy API: OpenRoute can diagnose blocks and suggest fixes, but can't route sites.", "warn");
  } else if (r.level === "not_controllable") {
    banner("Your proxy settings are locked by a policy on this device, so OpenRoute can't route sites.", "bad");
  } else if (r.error) {
    banner(`Routing error: ${r.error}`, "bad");
  } else {
    banner("");
  }
}

function renderAll() {
  renderTransports();
  renderSites();
  renderControls();
}

function initControls() {
  const save = (patch) => act("saveSettings", { patch });
  $("#autoRoute").addEventListener("change", (e) => save({ autoRoute: e.target.checked }));
  $("#autoReload").addEventListener("change", (e) => save({ autoReload: e.target.checked }));
  $("#detectionToggle").addEventListener("change", (e) => save({ detectionEnabled: e.target.checked }));
  $("#providerSelect").addEventListener("change", (e) => save({ dohProvider: e.target.value }));
  $("#remoteDiagnosis").addEventListener("change", (e) => save({ remoteDiagnosis: e.target.checked }));
  $("#grantConsent").addEventListener("click", () => requestPermissions({ data_collection: ["browsingActivity"] }));
  $("#clearAll").addEventListener("click", () => act("clearAll"));

  $("#openDns").addEventListener("click", async () => {
    const res = await send("openSecureDnsSettings");
    const guide = res?.guide;
    const steps = $("#dnsSteps");
    if (res?.opened || !guide) { steps.hidden = true; return; }
    setChildren(steps, (guide.copyUrl ? [`Open ${guide.copyUrl}`] : []).concat(guide.steps || []).map((s) => el("li", { text: s })));
    steps.hidden = false;
  });

  $("#addTransportForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const err = $("#tError");
    err.hidden = true;
    const transport = {
      label: $("#tLabel").value.trim(),
      scheme: $("#tScheme").value,
      host: $("#tHost").value.trim(),
      port: Number.parseInt($("#tPort").value.trim(), 10),
      kind: "user"
    };
    const res = await send("addTransport", { transport });
    if (!res?.ok) {
      err.textContent = res?.error || "Couldn't add that transport";
      err.hidden = false;
      return;
    }
    $("#tLabel").value = $("#tHost").value = $("#tPort").value = "";
    refresh();
  });

  $("#cConnect").addEventListener("click", async () => {
    const links = $("#cLink").value.split("\n").map((s) => s.trim()).filter(Boolean);
    const label = $("#cLabel").value.trim();
    const status = $("#cStatus");
    if (!links.length) { $("#cLink").focus(); return; }
    const btn = $("#cConnect"); const old = btn.textContent;
    btn.textContent = "Connecting…"; btn.disabled = true; status.textContent = "";
    const res = await send("companionConnect", { links, label });
    btn.textContent = old; btn.disabled = false;
    const inner = res?.result;
    if (inner?.ok) {
      const pool = inner.count > 1 ? ` · pool of ${inner.count}` : "";
      status.textContent = `Connected · SOCKS 127.0.0.1:${inner.socksPort}${pool}`;
      $("#cLink").value = "";
    } else {
      status.textContent = "Failed: " + (inner?.error || res?.error || "companion not installed");
    }
    refresh();
  });

  $("#cTor").addEventListener("click", async () => {
    const mode = $("#cTorMode").value;
    const status = $("#cStatus");
    const btn = $("#cTor"); const old = btn.textContent;
    btn.textContent = "Starting Tor…"; btn.disabled = true; status.textContent = "";
    const res = await send("companionConnectTor", { mode });
    btn.textContent = old; btn.disabled = false;
    const inner = res?.result;
    status.textContent = inner?.ok
      ? `Tor (${inner.mode}) starting · SOCKS 127.0.0.1:${inner.socksPort} — bootstrap may take a moment`
      : "Tor failed: " + (inner?.error || res?.error || "companion not installed");
    refresh();
  });

  $("#cDisconnect").addEventListener("click", async () => {
    await send("companionDisconnect", {});
    $("#cStatus").textContent = "Disconnected";
    refresh();
  });
}

let refreshTimer = null;
api.storage.onChanged.addListener((_c, area) => {
  if (area !== "local") return;
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(refresh, 150); // debounce live updates
});

initControls();
refresh();
