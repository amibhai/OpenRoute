// Active probes.
//
// A probe is one small plain-HTTP request carrying "__openroute_probe=<id>".
// The routing table maps that id to a specific transport (or to DIRECT), so
// the request travels exactly the path being tested:
//   * Chromium hands http:// URLs to the PAC in full (https ones are stripped
//     to the origin), so the marker is visible there;
//   * Firefox's proxy.onRequest sees every URL.
// That gives health checks for every transport — and discovery of proxies
// already running on this machine — with no native helper and before any
// real site is ever sent down a dead path.

import { PROBE_PARAM } from "./routing/pac.js";

// The operating systems' own captive-portal checks: they MUST stay plain HTTP
// (that's their whole job), so the browser never upgrades them to https —
// which matters because an https URL reaches the PAC without its query, and
// the probe marker would vanish. (cp.cloudflare.com, for one, is caught by
// cloudflare.com's HSTS preload in Chromium — verified in the e2e suite.)
// A wrong answer means something on the path intercepted the request.
export const PROBE_TARGETS = Object.freeze([
  { url: "http://connectivitycheck.gstatic.com/generate_204", check: async (r) => r.status === 204 },
  { url: "http://detectportal.firefox.com/success.txt", check: async (r) => r.status === 200 && (await r.text()).trim() === "success" },
  { url: "http://captive.apple.com/hotspot-detect.html", check: async (r) => r.status === 200 && /Success/.test(await r.text()) }
]);

// Local proxies people commonly already run. Defaults per each project's
// documentation; anything listening that speaks the protocol and actually
// reaches the internet is offered as a transport.
export const DISCOVERY_CANDIDATES = Object.freeze([
  { port: 9150, scheme: "socks5", label: "Tor Browser", kind: "tor" },
  { port: 9050, scheme: "socks5", label: "Tor / Orbot", kind: "tor" },
  { port: 10808, scheme: "socks5", label: "v2rayN / v2rayNG", kind: "discovered" },
  { port: 10809, scheme: "http", label: "v2rayN (HTTP)", kind: "discovered" },
  { port: 7890, scheme: "socks5", label: "Clash / Mihomo", kind: "discovered" },
  { port: 7897, scheme: "socks5", label: "Clash Verge", kind: "discovered" },
  { port: 2080, scheme: "socks5", label: "NekoBox / NekoRay", kind: "discovered" },
  { port: 12334, scheme: "socks5", label: "Hiddify", kind: "discovered" },
  { port: 1080, scheme: "socks5", label: "Local SOCKS5 (1080)", kind: "discovered" },
  { port: 8118, scheme: "http", label: "Privoxy / Orbot HTTP", kind: "discovered" }
]);

export const probeIds = Object.freeze({
  transport: (id) => `t-${id}`,
  candidate: (c) => `c-${c.port}-${c.scheme}`,
  direct: "direct"
});

export function candidateTransport(c) {
  return { id: `local-${c.port}${c.scheme === "socks5" ? "" : `-${c.scheme}`}`, label: c.label, scheme: c.scheme, host: "127.0.0.1", port: c.port, kind: c.kind };
}

export function probeUrl(target, id) {
  const sep = target.includes("?") ? "&" : "?";
  return `${target}${sep}${PROBE_PARAM}=${encodeURIComponent(id)}&n=${Math.random().toString(36).slice(2, 10)}`;
}

export function createProber({ fetchImpl, timeoutMs = 8000 } = {}) {
  const doFetch = (...a) => (fetchImpl || globalThis.fetch)(...a);

  async function once(id, target, timeout) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeout);
    const started = Date.now();
    try {
      const res = await doFetch(probeUrl(target.url, id), {
        cache: "no-store", credentials: "omit", redirect: "manual", referrerPolicy: "no-referrer", signal: ctrl.signal
      });
      // An opaque redirect means the browser rewrote the URL before routing
      // it (HSTS / HTTPS-upgrade): this target can't carry a marker here.
      if (res.type === "opaqueredirect") return { upgraded: true };
      const ok = await target.check(res).catch(() => false);
      return { ok, latencyMs: Date.now() - started, status: res.status, intercepted: !ok };
    } catch {
      return { ok: false, latencyMs: Date.now() - started, error: ctrl.signal.aborted ? "timeout" : "unreachable" };
    } finally {
      clearTimeout(timer);
    }
  }

  /** → { ok, latencyMs, status?, intercepted?, error? }  Never rejects. */
  async function run(id, { targets = PROBE_TARGETS, timeout = timeoutMs } = {}) {
    for (const target of targets) {
      const r = await once(id, target, timeout);
      if (!r.upgraded) return r;
    }
    return { ok: false, latencyMs: 0, error: "no-usable-target" };
  }

  // A site reachability check through a chosen path ("direct" or a transport
  // probe id). Opaque (no-cors) — any HTTP answer at all means "reachable".
  async function reach(url, id, { timeout = timeoutMs } = {}) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeout);
    const started = Date.now();
    try {
      await doFetch(probeUrl(url, id), { mode: "no-cors", cache: "no-store", credentials: "omit", redirect: "manual", referrerPolicy: "no-referrer", signal: ctrl.signal });
      return { ok: true, latencyMs: Date.now() - started };
    } catch {
      return { ok: false, latencyMs: Date.now() - started, error: ctrl.signal.aborted ? "timeout" : "unreachable" };
    } finally {
      clearTimeout(timer);
    }
  }

  return { run, reach };
}
