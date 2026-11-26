// Transport registry — the proxy backends the router can send a domain
// through: any SOCKS5/SOCKS4/HTTP(S) proxy the user runs, the Tor presets, and
// transports the native companion registers.

import { HEALTH, blankHealth } from "./health.js";
import { isValidHostname, normalizeHost } from "../../shared/hosts.js";

export const SCHEMES = Object.freeze(["socks5", "socks4", "http", "https"]);

export function presets() {
  return [
    {
      id: "tor-browser", label: "Tor Browser", scheme: "socks5", host: "127.0.0.1", port: 9150,
      kind: "tor", builtin: true, enabled: true, note: "Requires Tor Browser running. Strong, slower."
    },
    {
      id: "tor-daemon", label: "Tor (daemon)", scheme: "socks5", host: "127.0.0.1", port: 9050,
      kind: "tor", builtin: true, enabled: true, note: "Requires a standalone tor service."
    }
  ];
}

function newId() {
  return "t-" + (globalThis.crypto?.randomUUID?.() || `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`);
}

// Validate + normalize untrusted input (popup, imports, companion replies).
export function validateTransport(input) {
  if (!input || typeof input !== "object") return { error: "transport must be an object" };
  const scheme = String(input.scheme || "socks5").toLowerCase();
  if (!SCHEMES.includes(scheme)) return { error: `unsupported scheme "${scheme}"` };
  const host = normalizeHost(input.host);
  if (!isValidHostname(host)) return { error: "invalid host" };
  const port = Number(input.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return { error: "port must be 1–65535" };
  const id = input.id == null || input.id === "" ? newId() : String(input.id);
  if (!/^[A-Za-z0-9._:-]{1,64}$/.test(id)) return { error: "invalid id" };
  const label = String(input.label || "").trim().slice(0, 60) || `${scheme}://${host}:${port}`;
  let auth = null;
  if (input.auth && (input.auth.username || input.auth.password)) {
    const username = String(input.auth.username ?? "");
    const password = String(input.auth.password ?? "");
    if (!username) return { error: "a username is required with a password" };
    if (username.length > 256 || password.length > 256) return { error: "credentials too long" };
    auth = { username, password };
  }
  return {
    value: {
      id, label, scheme, host, port,
      kind: ["user", "tor", "companion", "discovered"].includes(input.kind) ? input.kind : "user",
      builtin: !!input.builtin,
      enabled: input.enabled !== false,
      note: String(input.note || "").slice(0, 120),
      createdAt: Number(input.createdAt) || Date.now(),
      ...(auth ? { auth } : {})
    }
  };
}

const RANK = { [HEALTH.UP]: 0, [HEALTH.UNKNOWN]: 1, [HEALTH.DEGRADED]: 2 };

// One ranking for everything (pickBest, failover chains): the user's active
// choice first, then measured-good before unknown before degraded, user
// transports before built-in presets, then by latency, then by age.
export function rankTransports(list, healthMap = {}, activeId = null) {
  const score = (t) => {
    const h = healthMap[t.id] || blankHealth();
    return (t.id === activeId ? -100 : 0) + (RANK[h.state] ?? 1) * 10 + (t.builtin ? 1 : 0);
  };
  return [...list].sort((a, b) =>
    score(a) - score(b) ||
    ((healthMap[a.id]?.latencyMs ?? 1e9) - (healthMap[b.id]?.latencyMs ?? 1e9)) ||
    ((a.createdAt || 0) - (b.createdAt || 0)));
}

export function createTransports({ store, health, caps = {} }) {
  async function configs() {
    const t = await store.get("transports");
    // Absent (first run) → presets. An intentionally emptied list stays empty.
    return Array.isArray(t) ? t : presets();
  }

  async function list() {
    const [all, hs] = await Promise.all([configs(), health.getAll()]);
    return all.map((t) => {
      const h = hs[t.id] || blankHealth();
      // Never hand passwords to pages; they only need to know one is set.
      const auth = t.auth ? { username: t.auth.username, hasPassword: !!t.auth.password } : undefined;
      return { ...t, auth, health: h.state, latencyMs: h.latencyMs, lastOk: h.lastOk, lastFail: h.lastFail, successes: h.successes, failures: h.failures };
    });
  }

  async function get(id) {
    return (await configs()).find((t) => t.id === id) || null;
  }

  async function upsert(input) {
    const existing = input?.id ? await get(input.id) : null;
    const merged = { ...(existing || {}), ...input };
    // Editing without re-typing the password keeps the stored one.
    if (input?.auth && input.auth.password === undefined && existing?.auth) {
      merged.auth = { ...input.auth, password: existing.auth.password };
    }
    const { value, error } = validateTransport(merged);
    if (error) throw new Error(error);
    if (value.auth && caps.proxyEngine === "chromium" && (value.scheme === "socks5" || value.scheme === "socks4")) {
      throw new Error("Chromium browsers can't log in to SOCKS proxies. Use an HTTP(S) proxy, or the companion (it bridges authenticated SOCKS).");
    }
    await store.tx(["transports"], (d) => {
      const all = Array.isArray(d.transports) ? d.transports : presets();
      const i = all.findIndex((x) => x.id === value.id);
      if (i >= 0) all[i] = { ...all[i], ...value };
      else all.push(value);
      d.transports = all;
    });
    return value;
  }

  async function remove(id) {
    await store.tx(["transports", "activeTransportId"], (d) => {
      const all = Array.isArray(d.transports) ? d.transports : presets();
      d.transports = all.filter((t) => t.id !== id);
      if (d.activeTransportId === id) d.activeTransportId = undefined;
    });
    await health.forget(id);
  }

  async function getActiveId() {
    return (await store.get("activeTransportId")) || null;
  }

  async function setActiveId(id) {
    if (id != null && !(await get(id))) throw new Error(`no transport "${id}"`);
    await store.tx(["activeTransportId"], (d) => { d.activeTransportId = id ?? undefined; });
  }

  // The transport a domain should try next: the user's active choice when it
  // is usable, else the healthiest enabled one. DOWN transports are skipped
  // (their breaker is open); null when nothing is usable.
  async function pickBest(excludeIds = []) {
    const exclude = new Set(excludeIds);
    const [all, hs, activeId] = await Promise.all([configs(), health.getAll(), getActiveId()]);
    const usable = all.filter((t) => t.enabled !== false && !exclude.has(t.id) && (hs[t.id]?.state ?? HEALTH.UNKNOWN) !== HEALTH.DOWN);
    return usable.length ? rankTransports(usable, hs, activeId)[0] : null;
  }

  return { configs, list, get, upsert, remove, getActiveId, setActiveId, pickBest };
}
