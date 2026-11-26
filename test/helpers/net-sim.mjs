// A network simulator behind the webext mock's fetch. Every non-DoH request
// is routed the way the browser would route it RIGHT NOW (via the installed
// PAC on Chromium, or proxy.onRequest on Firefox), then delivered — or not —
// according to the simulated world:
//
//   sim.dead(1081)            the proxy on port 1081 refuses connections
//   sim.intercepting(1082)    a proxy that answers, but with a block page
//   sim.blockDirect(host)     the direct path to host is censored
//
// Proxies are alive by default. Failover chains behave like Chromium: a dead
// hop is skipped and the next one tried; a request with no live hop fails.

import { isResolverUrl } from "./fake-doh.mjs";

function hopsOf(route) {
  if (route == null) return [{ direct: true }];
  if (typeof route === "string") {
    return route.split(";").map((s) => s.trim()).filter(Boolean).map((h) => {
      if (h === "DIRECT") return { direct: true };
      const m = /^(SOCKS5|SOCKS|PROXY|HTTPS)\s+\[?([^\]\s]+?)\]?:(\d+)$/.exec(h);
      return m ? { host: m[2], port: Number(m[3]) } : { direct: true };
    });
  }
  const list = Array.isArray(route) ? route : [route];
  return list.map((d) => (!d || d.type === "direct" ? { direct: true } : { host: d.host, port: Number(d.port) }));
}

function answer(url) {
  const u = new URL(url);
  if (u.pathname === "/generate_204") return { status: 204 };
  if (u.pathname === "/success.txt") return { status: 200, body: "success\n" };
  return { status: 200, body: `ok from ${u.hostname}` };
}

export function installNetSim(mock) {
  const deadPorts = new Set();
  const interceptPorts = new Set();
  const blockedDirect = new Set();
  const log = [];
  const sim = {
    log,
    dead(...ports) { ports.forEach((p) => deadPorts.add(p)); return sim; },
    alive(...ports) { ports.forEach((p) => { deadPorts.delete(p); interceptPorts.delete(p); }); return sim; },
    intercepting(...ports) { ports.forEach((p) => interceptPorts.add(p)); return sim; },
    blockDirect(...hosts) { hosts.forEach((h) => blockedDirect.add(h)); return sim; },
    viaPort(port) { return log.filter((l) => l.via === port); }
  };
  mock.net.route((req) => !isResolverUrl(req.url), async (req) => {
    const host = new URL(req.url).hostname;
    const route = await mock.resolveProxy(req.url);
    for (const hop of hopsOf(route)) {
      if (hop.direct) {
        if ([...blockedDirect].some((b) => host === b || host.endsWith("." + b))) {
          log.push({ url: req.url, via: "direct", ok: false });
          throw new TypeError("Failed to fetch (net::ERR_CONNECTION_TIMED_OUT)");
        }
        log.push({ url: req.url, via: "direct", ok: true });
        return answer(req.url);
      }
      if (deadPorts.has(hop.port)) { log.push({ url: req.url, via: hop.port, ok: false }); continue; }
      log.push({ url: req.url, via: hop.port, ok: true });
      if (interceptPorts.has(hop.port)) return { status: 200, body: "<html>Access denied</html>" };
      return answer(req.url);
    }
    throw new TypeError("Failed to fetch (net::ERR_PROXY_CONNECTION_FAILED)");
  });
  return sim;
}
