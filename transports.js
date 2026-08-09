// Transport registry — the set of proxy backends the router can route through.
//
// Phase A ships the transports an extension can reach on its own: any SOCKS5/
// HTTP proxy the user already runs, with a one-click preset for the Tor Browser
// SOCKS port. Phase B's native companion registers itself here as another
// transport (kind: "companion") exposing Shadowsocks/Reality/Tor/Snowflake — so
// nothing above the transport layer has to change when it lands.

const TRANSPORTS_KEY = "transports";
const ACTIVE_KEY = "activeTransportId";

// Health is scored from real routing outcomes (see health.js), not guessed.
export const HEALTH = { UP: "up", DEGRADED: "degraded", DOWN: "down", UNKNOWN: "unknown" };

function preset(id, label, scheme, host, port, kind, note) {
  return {
    id, label, scheme, host, port, kind,
    note: note || "",
    health: HEALTH.UNKNOWN,
    successes: 0,
    failures: 0,
    lastOk: null,
    builtin: true
  };
}

// Sensible defaults so the tool is useful the moment it's installed. The Tor
// preset only works if the user is running Tor Browser (SOCKS on 9150) or a
// standalone tor (9050) — the popup says so.
export function defaults() {
  return [
    preset("tor-browser", "Tor Browser", "socks5", "127.0.0.1", 9150, "tor",
      "Requires Tor Browser running. Strong, slower."),
    preset("tor-daemon", "Tor (daemon)", "socks5", "127.0.0.1", 9050, "tor",
      "Requires a standalone tor service.")
  ];
}

export async function list() {
  const { [TRANSPORTS_KEY]: t } = await chrome.storage.local.get(TRANSPORTS_KEY);
  return Array.isArray(t) && t.length ? t : defaults();
}

export async function save(transports) {
  await chrome.storage.local.set({ [TRANSPORTS_KEY]: transports });
}

export async function get(id) {
  return (await list()).find((t) => t.id === id) || null;
}

export async function upsert(t) {
  const all = await list();
  const i = all.findIndex((x) => x.id === t.id);
  if (i >= 0) all[i] = { ...all[i], ...t };
  else all.push({ health: HEALTH.UNKNOWN, successes: 0, failures: 0, ...t });
  await save(all);
  return all;
}

export async function remove(id) {
  const all = (await list()).filter((t) => t.id !== id);
  await save(all);
}

// Record a real routing outcome for a transport and rescore its health from
// recent history. Health is earned from what actually happened, never guessed.
export async function recordOutcome(id, ok) {
  const all = await list();
  const t = all.find((x) => x.id === id);
  if (!t) return;

  t.successes = (t.successes || 0) + (ok ? 1 : 0);
  t.failures = (t.failures || 0) + (ok ? 0 : 1);
  // Rolling recent-failure streak drives the DOWN verdict quickly.
  t.streak = ok ? 0 : (t.streak || 0) + 1;
  if (ok) t.lastOk = Date.now();

  if (t.streak >= 3) t.health = HEALTH.DOWN;
  else if (t.streak >= 1) t.health = HEALTH.DEGRADED;
  else if (t.successes > 0) t.health = HEALTH.UP;
  else t.health = HEALTH.UNKNOWN;

  await save(all);
  return t;
}

export async function getActiveId() {
  const { [ACTIVE_KEY]: id } = await chrome.storage.local.get(ACTIVE_KEY);
  return id || null;
}

export async function setActiveId(id) {
  await chrome.storage.local.set({ [ACTIVE_KEY]: id });
}

// Pick the transport the ladder should try first: the user's active choice if
// it's usable, otherwise the healthiest available, preferring non-DOWN ones.
export async function pickBest(excludeIds = []) {
  const all = (await list()).filter((t) => !excludeIds.includes(t.id));
  if (!all.length) return null;

  const activeId = await getActiveId();
  const active = all.find((t) => t.id === activeId);
  if (active && active.health !== HEALTH.DOWN) return active;

  const rank = { [HEALTH.UP]: 0, [HEALTH.UNKNOWN]: 1, [HEALTH.DEGRADED]: 2, [HEALTH.DOWN]: 3 };
  return [...all].sort((a, b) => (rank[a.health] ?? 1) - (rank[b.health] ?? 1))[0];
}

// PAC directive for a transport, e.g. "SOCKS5 127.0.0.1:9150" or "PROXY host:port".
// A trailing "; DIRECT" is intentionally *omitted* — we never want a blocked
// domain to silently fall back to the censored direct path mid-session; the
// ladder handles failure explicitly instead.
export function pacDirective(t) {
  if (!t) return "DIRECT";
  if (t.scheme === "http" || t.scheme === "https") return `PROXY ${t.host}:${t.port}`;
  if (t.scheme === "socks4") return `SOCKS ${t.host}:${t.port}`;
  return `SOCKS5 ${t.host}:${t.port}`; // SOCKS5 → Chrome resolves DNS proxy-side
}
