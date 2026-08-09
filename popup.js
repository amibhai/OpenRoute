// OpenRoute dashboard. Reads all state from the background control plane
// (getState) and drives it through typed messages. Classic script — no imports.

const $ = (sel, root = document) => root.querySelector(sel);

const BADGES = {
  "dns-tampering": { label: "DNS tampering", cls: "good" },
  "dns-nxdomain":  { label: "NXDOMAIN", cls: "warn" },
  "doh-tampered":  { label: "DNS poisoned", cls: "bad" },
  "sni-dpi":       { label: "SNI / DPI", cls: "warn" },
  "ip-block":      { label: "IP block", cls: "bad" },
  "unreachable":   { label: "Unreachable", cls: "warn" },
  "policy-block":  { label: "Policy block", cls: "warn" },
  "unknown":       { label: "Unknown", cls: "warn" }
};

// How each ladder status reads to a human, and its colour class.
const STATUS = {
  blocked:     { label: "blocked", cls: "bad" },
  routing:     { label: "routing…", cls: "warn" },
  verifying:   { label: "verifying…", cls: "warn" },
  fixed:       { label: "✓ working", cls: "good" },
  "needs-user":{ label: "needs you", cls: "warn" },
  exhausted:   { label: "no route left", cls: "bad" }
};

const HEALTH_CLS = { up: "good", degraded: "warn", down: "bad", unknown: "muted" };
const RESOLVER_LABELS = { cloudflare: "Cloudflare", google: "Google", quad9: "Quad9" };

let STATE = { policy: {}, transports: [], settings: {}, activeTransportId: null, companion: {}, sites: {} };

function send(type, extra = {}) {
  return new Promise((resolve) => chrome.runtime.sendMessage({ type, ...extra }, resolve));
}

async function refresh() {
  const res = await send("getState");
  if (res?.ok) { STATE = res; renderAll(); }
}

// ---- transports ------------------------------------------------------------

function endpointOf(t) {
  return t.kind === "companion" ? "companion" : `${t.scheme}://${t.host}:${t.port}`;
}

function renderTransports() {
  const ul = $("#transportList");
  ul.innerHTML = "";
  const tpl = $("#transportTpl");
  for (const t of STATE.transports) {
    const node = tpl.content.cloneNode(true);
    const radio = $(".tactive", node);
    radio.checked = t.id === STATE.activeTransportId;
    radio.onchange = async () => { await send("setActiveTransport", { id: t.id }); refresh(); };

    const dot = $(".thealth", node);
    dot.classList.add(HEALTH_CLS[t.health] || "muted");
    dot.title = `health: ${t.health}${t.latencyMs ? ` · ${t.latencyMs}ms` : ""}`;

    $(".tlabel", node).textContent = t.label;
    $(".tendpoint", node).textContent = endpointOf(t) + (t.note ? ` — ${t.note}` : "");

    const rm = $(".tremove", node);
    if (t.builtin) rm.style.display = "none";
    rm.onclick = async () => { await send("removeTransport", { id: t.id }); refresh(); };

    ul.appendChild(node);
  }

  const c = STATE.companion || {};
  const pill = $("#companionPill");
  pill.textContent = c.available ? "companion: connected" : "companion: not installed";
  pill.className = "pill " + (c.available ? "good" : "muted");
}

// ---- sites -----------------------------------------------------------------

function rungOptions(pol) {
  // Auto + Direct + one option per transport + Read-only. Selected reflects policy.
  const opts = [`<option value="auto">Auto</option>`, `<option value="direct">Direct</option>`];
  for (const t of STATE.transports) {
    opts.push(`<option value="proxy:${t.id}">via ${escapeHtml(t.label)}</option>`);
  }
  opts.push(`<option value="fallback">Read-only</option>`);
  return opts.join("");
}

function selectedRungValue(pol) {
  if (!pol) return "auto";
  if (!pol.pinned) return "auto";
  if (pol.rung === "proxy" && pol.proxyId) return `proxy:${pol.proxyId}`;
  return pol.rung;
}

function renderSites() {
  const list = $("#list");
  // Union of diagnosed sites and policy domains.
  const domains = new Set([...Object.keys(STATE.sites || {}), ...Object.keys(STATE.policy || {})]);
  const rows = [...domains].map((d) => ({
    host: d,
    diag: STATE.sites[d] || {},
    pol: STATE.policy[d] || null
  })).sort((a, b) => (b.diag.lastSeen || 0) - (a.diag.lastSeen || 0));

  $("#count").textContent = rows.length;
  $("#empty").style.display = rows.length ? "none" : "block";
  list.innerHTML = "";
  const tpl = $("#itemTpl");

  for (const { host, diag, pol } of rows) {
    const node = tpl.content.cloneNode(true);
    const url = diag.url || `https://${host}/`;

    $(".host", node).textContent = host;

    const bmeta = BADGES[diag.type] || BADGES.unknown;
    const badge = $(".badge", node);
    badge.textContent = bmeta.label;
    badge.classList.add(bmeta.cls);

    // Status line: rung + status + which transport is carrying it.
    const sl = $(".statusline", node);
    if (pol) {
      const smeta = STATUS[pol.status] || { label: pol.status, cls: "muted" };
      const via = pol.rung === "proxy" && pol.proxyId
        ? ` via ${transportLabel(pol.proxyId)}` : "";
      sl.innerHTML = `<span class="chip ${smeta.cls}">${smeta.label}</span>` +
        `<span class="muted"> ${rungLabel(pol.rung)}${via}</span>`;
    } else {
      sl.innerHTML = `<span class="chip muted">not routed</span>`;
    }

    $(".remedy", node).textContent = diag.remediation || "";

    const bits = [];
    if (diag.echLikely) bits.push("ECH available");
    else if (diag.hasHTTPS) bits.push("HTTPS record");
    if (diag.injected) bits.push("⚠ injected answer");
    if (diag.dohProvider) bits.push(`via ${RESOLVER_LABELS[diag.dohProvider] || diag.dohProvider}`);
    $(".diag", node).textContent = bits.join(" · ");

    $(".ips", node).textContent = diag.resolvedIPs?.length
      ? `Real IP via DoH: ${diag.resolvedIPs.join(", ")}` : "";

    // Rung override.
    const sel = $(".rungSelect", node);
    sel.innerHTML = rungOptions(pol);
    sel.value = selectedRungValue(pol);
    sel.onchange = async () => {
      const v = sel.value;
      if (v.startsWith("proxy:")) await send("setRung", { domain: host, rung: "proxy", proxyId: v.slice(6) });
      else await send("setRung", { domain: host, rung: v });
      refresh();
    };

    $(".retry", node).onclick = () => chrome.tabs.create({ url });
    $(".recheck", node).onclick = async (e) => {
      const b = e.currentTarget; const old = b.textContent;
      b.textContent = "…"; b.disabled = true;
      await send("recheck", { host }); refresh();
      b.textContent = old; b.disabled = false;
    };
    $(".wayback", node).onclick = () => chrome.tabs.create({ url: "https://web.archive.org/web/2/" + url });
    $(".reader", node).onclick = () => chrome.tabs.create({ url: "https://r.jina.ai/" + url });
    $(".remove", node).onclick = async () => { await send("clearDomain", { domain: host }); refresh(); };

    list.appendChild(node);
  }
}

function transportLabel(id) {
  return STATE.transports.find((t) => t.id === id)?.label || id;
}
function rungLabel(rung) {
  return { direct: "Direct", doh: "Secure DNS", ech: "Secure DNS+ECH", proxy: "Proxy", fallback: "Read-only" }[rung] || rung;
}
function escapeHtml(s) { return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }

// ---- controls --------------------------------------------------------------

function renderControls() {
  const s = STATE.settings || {};
  $("#autoRoute").checked = s.autoRoute !== false;
  $("#autoReload").checked = s.autoReload !== false;
  $("#detectionToggle").checked = s.detectionEnabled !== false;
  $("#providerSelect").value = s.dohProvider || "cloudflare";
}

function renderAll() { renderTransports(); renderSites(); renderControls(); }

// ---- wiring ----------------------------------------------------------------

function initControls() {
  $("#autoRoute").onchange = (e) => send("saveSettings", { patch: { autoRoute: e.target.checked } });
  $("#autoReload").onchange = (e) => send("saveSettings", { patch: { autoReload: e.target.checked } });
  $("#detectionToggle").onchange = (e) => send("saveSettings", { patch: { detectionEnabled: e.target.checked } });
  $("#providerSelect").onchange = (e) => send("saveSettings", { patch: { dohProvider: e.target.value } });
  $("#openDns").onclick = () => chrome.tabs.create({ url: "chrome://settings/security" });
  $("#clearAll").onclick = async () => { await send("clearAllPolicy"); await chrome.storage.local.set({ blockedSites: {} }); refresh(); };

  $("#tAdd").onclick = async () => {
    const label = $("#tLabel").value.trim() || "Proxy";
    const scheme = $("#tScheme").value;
    const host = $("#tHost").value.trim();
    const port = parseInt($("#tPort").value.trim(), 10);
    if (!host || !port) { $("#tHost").focus(); return; }
    const id = `user-${host}-${port}`.replace(/[^a-z0-9-]/gi, "");
    await send("addTransport", { transport: { id, label, scheme, host, port, kind: "user", builtin: false } });
    $("#tLabel").value = $("#tHost").value = $("#tPort").value = "";
    refresh();
  };

  $("#cConnect").onclick = async () => {
    const link = $("#cLink").value.trim();
    const label = $("#cLabel").value.trim();
    const status = $("#cStatus");
    if (!link) { $("#cLink").focus(); return; }
    const btn = $("#cConnect"); const old = btn.textContent;
    btn.textContent = "Connecting…"; btn.disabled = true;
    status.textContent = "";
    const res = await send("companionConnect", { link, label });
    btn.textContent = old; btn.disabled = false;
    const inner = res?.result;
    if (inner?.ok) { status.textContent = `Connected · SOCKS 127.0.0.1:${inner.socksPort}`; $("#cLink").value = ""; }
    else { status.textContent = "Failed: " + (inner?.error || res?.error || "companion not installed"); }
    refresh();
  };
  $("#cDisconnect").onclick = async () => {
    await send("companionDisconnect");
    $("#cStatus").textContent = "Disconnected";
    refresh();
  };
}

let refreshTimer = null;
chrome.storage.onChanged.addListener((_c, area) => {
  if (area !== "local") return;
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(refresh, 150); // debounce live updates
});

initControls();
refresh();
