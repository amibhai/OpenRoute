// DNS-over-HTTPS engine (RFC 8484 wire format).
//
//   * Fast       — endpoints are raced happy-eyeballs style: a new attempt
//                  starts every STAGGER_MS until one answers, failures fall
//                  through immediately, and a hard deadline caps the lookup.
//   * Resilient  — several independent, NON-filtering resolvers, each by
//                  hostname and by IP literal (certs carry IP SANs), so a
//                  poisoned resolver hostname doesn't matter. Endpoints that
//                  failed recently are tried last.
//   * Honest     — answers are validated (bogons ⇒ "injected"), suspicious
//                  answers (NXDOMAIN / bogons) get a second opinion from a
//                  different resolver, and "nobody answered" is reported as
//                  unreachable — never as NXDOMAIN.

import { encodeQuery, decodeMessage, toBase64Url, TYPE, RCODE } from "./wire.js";
import { isBogon } from "./bogons.js";

// Filtering resolvers (ad/malware blocking) are deliberately excluded: their
// "blocked" answers would look exactly like censorship to the classifier.
export const RESOLVERS = Object.freeze({
  cloudflare: { label: "Cloudflare", endpoints: ["https://cloudflare-dns.com/dns-query", "https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query"] },
  google: { label: "Google", endpoints: ["https://dns.google/dns-query", "https://8.8.8.8/dns-query", "https://8.8.4.4/dns-query"] },
  quad9: { label: "Quad9", endpoints: ["https://dns.quad9.net/dns-query", "https://9.9.9.9/dns-query", "https://149.112.112.112/dns-query"] },
  adguard: { label: "AdGuard (unfiltered)", endpoints: ["https://unfiltered.adguard-dns.com/dns-query"] },
  mullvad: { label: "Mullvad", endpoints: ["https://dns.mullvad.net/dns-query"] },
  nextdns: { label: "NextDNS", endpoints: ["https://dns.nextdns.io/dns-query"] },
  dnssb: { label: "DNS.SB", endpoints: ["https://doh.dns.sb/dns-query", "https://185.222.222.222/dns-query"] }
});

export const RACE_ORDER = ["cloudflare", "google", "quad9", "dnssb", "mullvad", "nextdns", "adguard"];
export const RESOLVER_HOSTS = [...new Set(Object.values(RESOLVERS).flatMap((r) => r.endpoints.map((u) => new URL(u).hostname)))];

export const TIMING = Object.freeze({
  staggerMs: 250,          // start the next endpoint if nothing answered yet
  attemptTimeoutMs: 3000,  // one endpoint
  deadlineMs: 5000,        // the whole lookup
  confirmMs: 600,          // wait this long for a second opinion on a suspicious answer
  maxEndpoints: 6          // per lookup
});
const FAIL_COOLDOWN_MS = 5 * 60 * 1000;

export function createEndpointHealth(now = () => Date.now()) {
  const m = new Map();
  return {
    ok(url, ms) {
      const h = m.get(url) || { fails: 0 };
      h.lastOk = now();
      h.fails = 0;
      h.ewmaMs = h.ewmaMs == null ? ms : Math.round(h.ewmaMs * 0.7 + ms * 0.3);
      m.set(url, h);
    },
    fail(url) {
      const h = m.get(url) || { fails: 0 };
      h.lastFail = now();
      h.fails += 1;
      m.set(url, h);
    },
    coolingDown(url) {
      const h = m.get(url);
      return !!h && h.fails > 0 && now() - h.lastFail < FAIL_COOLDOWN_MS;
    },
    snapshot() { return Object.fromEntries(m); }
  };
}

// Interleave resolvers (preferred first) so one resolver's slow endpoints
// never starve the others. A recently-failed endpoint is demoted *within its
// resolver*: when "cloudflare-dns.com" is blocked by DNS/SNI, its IP-literal
// sibling 1.1.1.1 is exactly what tends to get through, so it moves up.
export function planEndpoints(resolverKeys, health, customUrl) {
  const lists = resolverKeys.filter((k) => RESOLVERS[k]).map((k) => {
    const eps = RESOLVERS[k].endpoints.map((url) => ({ url, resolver: k }));
    return [...eps.filter((e) => !health.coolingDown(e.url)), ...eps.filter((e) => health.coolingDown(e.url))];
  });
  if (customUrl) lists.unshift([{ url: customUrl, resolver: "custom" }]);
  const flat = [];
  for (let i = 0; lists.some((l) => i < l.length); i++) for (const l of lists) if (i < l.length) flat.push(l[i]);
  return flat;
}

async function queryEndpoint(fetchImpl, url, name, type, signal) {
  const q = encodeQuery(name, type);
  const res = await fetchImpl(`${url}${url.includes("?") ? "&" : "?"}dns=${toBase64Url(q)}`, {
    headers: { accept: "application/dns-message" },
    cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer", signal
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const ct = res.headers.get("content-type") || "";
  if (!ct.includes("application/dns-message")) throw new Error(`unexpected content-type "${ct}"`);
  const msg = decodeMessage(new Uint8Array(await res.arrayBuffer()));
  if (!msg.qr) throw new Error("not a DNS response");
  return msg;
}

function summarize(msg) {
  const addresses = msg.answers.filter((a) => (a.type === TYPE.A || a.type === TYPE.AAAA) && a.data).map((a) => a.data);
  const svcb = msg.answers.filter((a) => (a.type === TYPE.HTTPS || a.type === TYPE.SVCB) && a.data);
  const bogons = addresses.filter(isBogon);
  return {
    status: msg.rcode,
    addresses,
    bogons,
    injected: addresses.length > 0 && bogons.length === addresses.length,
    ok: msg.rcode === RCODE.NOERROR && addresses.length > bogons.length,
    hasHTTPS: svcb.length > 0,
    echLikely: svcb.some((r) => r.data.params?.ech > 0),
    alpn: [...new Set(svcb.flatMap((r) => r.data.params?.alpn || []))],
    cnames: msg.answers.filter((a) => a.type === TYPE.CNAME).map((a) => a.data)
  };
}

const authoritative = (s) => s.status === RCODE.NOERROR || s.status === RCODE.NXDOMAIN;
const suspicious = (s) => s.status === RCODE.NXDOMAIN || s.injected;

/** Race endpoints for one (name, type). Resolves to a summary or null; never rejects. */
export function raceLookup(name, type, { endpoints, fetchImpl, health, timing = TIMING }) {
  const t = { ...TIMING, ...timing };
  const list = endpoints.slice(0, t.maxEndpoints);
  return new Promise((resolve) => {
    const answers = [];
    const controllers = [];
    let next = 0;
    let inFlight = 0;
    let done = false;
    let staggerTimer = null;
    let confirmTimer = null;

    const choose = () => {
      if (!answers.length) return null;
      const good = answers.find((a) => a.ok); // a real answer outweighs NXDOMAIN/bogons from another resolver
      return {
        ...(good || answers[0]),
        consensus: {
          answers: answers.length,
          resolvers: new Set(answers.map((a) => a.resolver)).size,
          disagreement: answers.some((a) => a.ok) && answers.some((a) => !a.ok)
        }
      };
    };
    const finish = () => {
      if (done) return;
      done = true;
      clearTimeout(staggerTimer);
      clearTimeout(confirmTimer);
      clearTimeout(deadline);
      for (const c of controllers) c.abort();
      resolve(choose());
    };
    const onAnswer = (a) => {
      answers.push(a);
      if (!suspicious(a) || answers.some((x) => x.resolver !== a.resolver)) return finish();
      // Suspicious and unconfirmed: hurry a second opinion, but don't wait long.
      if (!confirmTimer) confirmTimer = setTimeout(finish, t.confirmMs);
      launch();
    };
    const launch = () => {
      clearTimeout(staggerTimer);
      if (done) return;
      if (next >= list.length) {
        if (inFlight === 0) finish();
        return;
      }
      const ep = list[next++];
      // Second opinions must come from a different resolver.
      if (answers.length && answers.every((a) => a.resolver === ep.resolver) && next < list.length) {
        launch();
        return;
      }
      const ctrl = new AbortController();
      controllers.push(ctrl);
      const attemptTimer = setTimeout(() => ctrl.abort(), t.attemptTimeoutMs);
      const started = Date.now();
      inFlight++;
      queryEndpoint(fetchImpl, ep.url, name, type, ctrl.signal)
        .then((msg) => {
          health.ok(ep.url, Date.now() - started);
          if (done) return;
          const s = summarize(msg);
          if (authoritative(s)) onAnswer({ ...s, resolver: ep.resolver, endpoint: ep.url });
        })
        .catch(() => { if (!done) health.fail(ep.url); })
        .finally(() => {
          clearTimeout(attemptTimer);
          inFlight--;
          if (done) return;
          if (inFlight === 0) launch(); // an attempt failed/answered unusably: move on now
        });
      staggerTimer = setTimeout(launch, t.staggerMs);
    };
    const deadline = setTimeout(finish, t.deadlineMs);
    launch();
  });
}

/**
 * The DoH client. getConfig() → { preferred, customUrl } (read per lookup so
 * settings changes apply immediately).
 */
export function createDoH({ fetchImpl, getConfig = async () => ({}), timing, health = createEndpointHealth() } = {}) {
  const doFetch = (...a) => (fetchImpl || globalThis.fetch)(...a);

  async function lookup(name, type) {
    const cfg = await getConfig();
    const preferred = RESOLVERS[cfg.preferred] ? cfg.preferred : "cloudflare";
    const keys = [preferred, ...RACE_ORDER.filter((k) => k !== preferred)];
    const endpoints = planEndpoints(keys, health, cfg.customUrl);
    return raceLookup(name, type, { endpoints, fetchImpl: doFetch, health, timing });
  }

  /** A + AAAA reachability and an HTTPS/SVCB lookup (ECH). Never rejects. */
  async function diagnose(hostname) {
    const [a, aaaa, https] = await Promise.all([
      lookup(hostname, TYPE.A), lookup(hostname, TYPE.AAAA), lookup(hostname, TYPE.HTTPS)
    ]);
    const answered = [a, aaaa].filter(Boolean);
    const addresses = [...new Set(answered.flatMap((r) => r.addresses))];
    const bogons = addresses.filter(isBogon);
    const status = answered.some((r) => r.status === RCODE.NOERROR) ? RCODE.NOERROR : (answered[0]?.status ?? null);
    return {
      hostname,
      ok: status === RCODE.NOERROR && addresses.length > bogons.length,
      status,
      addresses,
      bogons,
      injected: addresses.length > 0 && bogons.length === addresses.length,
      unreachable: answered.length === 0,
      resolver: (a || aaaa)?.resolver ?? null,
      endpoint: (a || aaaa)?.endpoint ?? null,
      consensus: (a || aaaa)?.consensus ?? null,
      hasHTTPS: !!https?.hasHTTPS,
      echLikely: !!https?.echLikely,
      alpn: https?.alpn || [],
      error: answered.length ? undefined : "no resolver answered",
      at: Date.now()
    };
  }

  return { lookup, diagnose, health };
}

// Short-lived cache in front of diagnose(), so a page retrying in a burst
// reuses one diagnosis instead of starting a lookup storm.
export function createDiagnoser({ doh, ttlMs = 30_000 }) {
  const cache = new Map();
  async function diagnoseCached(host, { fresh = false } = {}) {
    const hit = cache.get(host);
    if (!fresh && hit && Date.now() - hit.at < ttlMs) return hit.diag;
    const diag = await doh.diagnose(host);
    cache.set(host, { diag, at: Date.now() });
    if (cache.size > 256) cache.delete(cache.keys().next().value);
    return diag;
  }
  diagnoseCached.invalidate = (host) => (host ? cache.delete(host) : cache.clear());
  return diagnoseCached;
}
