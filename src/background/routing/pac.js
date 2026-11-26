// Chromium PAC generation.
//
// Chromium's resolver calls FindProxyForURL(url, host) — a script without it
// fails to load and, with mandatory:false, Chrome silently goes DIRECT. The
// generated script is plain ES5, never touches DNS (no dnsResolve/isInNet, so
// no local lookups leak or stall), and matches a host and each parent domain
// against an embedded table, so "cdn.example.com" follows "example.com".
//
// Probe routes let the extension health-check a specific transport: Chromium
// passes the full URL to the PAC only for http:// (https paths are stripped),
// so probes are plain-HTTP requests carrying "__openroute_probe=<id>".

export const PROBE_PARAM = "__openroute_probe";

export function hostPort(t) {
  const h = String(t.host);
  return h.includes(":") && !h.startsWith("[") ? `[${h}]:${t.port}` : `${h}:${t.port}`;
}

// PAC directive for one transport. No trailing "; DIRECT": a routed domain
// must never silently fall back to the censored direct path.
export function pacDirective(t) {
  if (!t) return "DIRECT";
  switch (t.scheme) {
    case "http": return `PROXY ${hostPort(t)}`;
    case "https": return `HTTPS ${hostPort(t)}`;
    case "socks4": return `SOCKS ${hostPort(t)}`;
    default: return `SOCKS5 ${hostPort(t)}`;
  }
}

export function chainDirective(transports) {
  const parts = transports.filter(Boolean).map(pacDirective);
  return parts.length ? parts.join("; ") : "DIRECT";
}

// compiled: { routes: {domain: [transport…]}, probes?: {id: [transport…]},
//             defaultRoute?: [transport…] (full-tunnel) }
export function buildPac(compiled) {
  const routes = {};
  for (const [domain, chain] of Object.entries(compiled.routes || {})) routes[domain] = chainDirective(chain);
  // Probe ids travel URL-encoded in the query string; key them that way.
  const probes = {};
  for (const [id, chain] of Object.entries(compiled.probes || {})) probes[encodeURIComponent(id)] = chainDirective(chain);
  const def = compiled.defaultRoute?.length ? chainDirective(compiled.defaultRoute) : "DIRECT";
  const lit = (o) => JSON.stringify(JSON.stringify(o));
  return asciiOnly(`// OpenRoute split-tunnel PAC (generated, do not edit)
var ROUTES = JSON.parse(${lit(routes)});
var PROBES = JSON.parse(${lit(probes)});
var DEFAULT_ROUTE = ${JSON.stringify(def)};
var PROBE_KEY = ${JSON.stringify(PROBE_PARAM + "=")};
var HAS = Object.prototype.hasOwnProperty;
var IPV4 = /^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$/;
var LOCAL = /^(localhost|127\\.|10\\.|192\\.168\\.|172\\.(1[6-9]|2\\d|3[01])\\.|169\\.254\\.|100\\.(6[4-9]|[7-9]\\d|1[01]\\d|12[0-7])\\.|0\\.|::1$|fe[89ab][0-9a-f]?:|f[cd][0-9a-f]{0,2}:)/i;

function FindProxyForURL(url, host) {
  host = String(host).toLowerCase();
  if (host.charAt(0) === "[") host = host.substring(1, host.length - 1);
  while (host.charAt(host.length - 1) === ".") host = host.substring(0, host.length - 1);

  var p = url.indexOf(PROBE_KEY);
  if (p !== -1 && url.substring(0, 7).toLowerCase() === "http://") {
    var id = url.substring(p + PROBE_KEY.length);
    var amp = id.indexOf("&");
    if (amp !== -1) id = id.substring(0, amp);
    if (HAS.call(PROBES, id)) return PROBES[id];
  }

  if (host === "" || host.indexOf(".") === -1 && host.indexOf(":") === -1) return "DIRECT";
  if (LOCAL.test(host) || /\\.(localhost|local|lan|home\\.arpa|internal)$/.test(host)) return "DIRECT";

  if (IPV4.test(host) || host.indexOf(":") !== -1) {
    return HAS.call(ROUTES, host) ? ROUTES[host] : DEFAULT_ROUTE;
  }
  var h = host;
  for (;;) {
    if (HAS.call(ROUTES, h)) return ROUTES[h];
    var dot = h.indexOf(".");
    if (dot === -1) return DEFAULT_ROUTE;
    h = h.substring(dot + 1);
  }
}
`);
}

// Chromium rejects pacScript.data containing any non-ASCII character
// ("supports only ASCII code"). Hostnames are punycode already; this is the
// guarantee for everything else. Inside string literals \uXXXX is the same
// character; elsewhere only comments could carry it.
export function asciiOnly(s) {
  // Per UTF-16 code unit, so astral characters become a valid surrogate pair.
  return s.replace(/[\u0080-￿]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
}
