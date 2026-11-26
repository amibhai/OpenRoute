// Hostname helpers shared by the background and the UI. Pure functions, no
// browser APIs, safe to unit-test directly.

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

export function normalizeHost(h) {
  if (h == null) return "";
  let s = String(h).trim().toLowerCase();
  if (s.startsWith("[") && s.endsWith("]")) s = s.slice(1, -1);
  while (s.endsWith(".")) s = s.slice(0, -1);
  return s;
}

export function hostFromUrl(url) {
  try {
    return normalizeHost(new URL(url).hostname) || null;
  } catch {
    return null;
  }
}

export function isIPv4(h) {
  const m = IPV4.exec(h);
  return !!m && m.slice(1).every((o) => Number(o) <= 255);
}

export function isIPv6(h) {
  return typeof h === "string" && h.includes(":");
}

export function isIpLiteral(h) {
  return isIPv4(h) || isIPv6(h);
}

function v4Octets(ip) {
  return ip.split(".").map(Number);
}

// Addresses that can only be the local machine or the local network.
export function isPrivateIPv4(ip) {
  if (!isIPv4(ip)) return false;
  const [a, b] = v4Octets(ip);
  return a === 0 || a === 10 || a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||  // CGNAT 100.64/10
    (a === 169 && b === 254) ||            // link-local
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168);
}

export function isPrivateIPv6(ip) {
  const s = normalizeHost(ip);
  return s === "::" || s === "::1" || /^fe[89ab][0-9a-f]?:/.test(s) || /^f[cd][0-9a-f]{0,2}:/.test(s) ||
    s.startsWith("::ffff:127.") || s.startsWith("::ffff:10.") || s.startsWith("::ffff:192.168.");
}

// Hosts that are never the target of network censorship: loopback, LAN,
// link-local, mDNS, single-label intranet names and special-use domains.
export function isLocalHost(h) {
  const s = normalizeHost(h);
  if (!s) return true;
  if (s === "localhost" || s.endsWith(".localhost")) return true;
  if (isIPv4(s)) return isPrivateIPv4(s);
  if (isIPv6(s)) return isPrivateIPv6(s);
  if (!s.includes(".")) return true;
  return /\.(local|lan|home\.arpa|internal|intranet|corp)$/.test(s);
}

// "a.b.example.com" → ["a.b.example.com", "b.example.com", "example.com", "com"]
export function selfAndParents(h) {
  const s = normalizeHost(h);
  if (!s) return [];
  if (isIpLiteral(s)) return [s];
  const out = [s];
  let rest = s;
  for (let dot = rest.indexOf("."); dot !== -1; dot = rest.indexOf(".")) {
    rest = rest.slice(dot + 1);
    out.push(rest);
  }
  return out;
}

// Look `host` (and each parent domain) up in a plain object keyed by domain.
export function lookupDomain(host, table) {
  for (const d of selfAndParents(host)) {
    if (Object.prototype.hasOwnProperty.call(table, d)) return d;
  }
  return null;
}

export function isValidHostname(h) {
  const s = normalizeHost(h);
  if (!s || s.length > 253) return false;
  if (isIPv6(s)) return /^[0-9a-f:.]+$/.test(s) && (s.match(/::/g) || []).length <= 1;
  const labels = s.split(".");
  // WHATWG URL rule: a host whose last label is numeric is parsed as IPv4 and
  // must then be a valid address ("999.1.1.1.1" is not a hostname).
  if (/^\d+$/.test(labels[labels.length - 1])) return isIPv4(s);
  return labels.every((label) => /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/.test(label));
}
