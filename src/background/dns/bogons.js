// Answer validation: addresses a public site's authoritative DNS answer must
// never contain. A "real" answer pointing into one of these ranges is an
// injected / block-page response (or fake-IP DNS like Clash's 198.18/15).
// Ranges per the IANA special-purpose registries (RFC 6890 et al.).

import { isIPv4 } from "../../shared/hosts.js";

function v4(ip) { return ip.split(".").map(Number); }

export function isBogonV4(ip) {
  if (!isIPv4(ip)) return false;
  const [a, b, c] = v4(ip);
  return (
    a === 0 || a === 10 || a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||   // CGNAT 100.64/10
    (a === 169 && b === 254) ||             // link-local
    (a === 172 && b >= 16 && b <= 31) ||    // 172.16/12
    (a === 192 && b === 0 && c === 0) ||    // IETF protocol assignments 192.0.0/24
    (a === 192 && b === 0 && c === 2) ||    // TEST-NET-1
    (a === 192 && b === 88 && c === 99) ||  // deprecated 6to4 relay
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) || // benchmarking 198.18/15 (fake-IP DNS)
    (a === 198 && b === 51 && c === 100) || // TEST-NET-2
    (a === 203 && b === 0 && c === 113) ||  // TEST-NET-3
    a >= 224                                // multicast, reserved, broadcast
  );
}

// Expand "::"-compressed IPv6 into 8 hextets (numbers), or null if malformed.
function hextets(ip) {
  let s = ip.toLowerCase();
  const lastColon = s.lastIndexOf(":");
  if (s.slice(lastColon + 1).includes(".")) {
    const tailV4 = s.slice(lastColon + 1);
    if (!isIPv4(tailV4)) return null;
    const [a, b, c, d] = v4(tailV4);
    s = `${s.slice(0, lastColon + 1)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  const parts = [...head, ...Array(Math.max(fill, 0)).fill("0"), ...tail];
  if (parts.length !== 8 || parts.some((p) => !/^[0-9a-f]{1,4}$/.test(p))) return null;
  return parts.map((p) => parseInt(p, 16));
}

export function isBogonV6(ip) {
  const h = hextets(ip);
  if (!h) return true; // unparseable answer → treat as bogus
  const allZero = h.slice(0, 7).every((x) => x === 0);
  if (allZero && (h[7] === 0 || h[7] === 1)) return true;           // :: and ::1
  // IPv4-mapped ::ffff:a.b.c.d and NAT64 64:ff9b::a.b.c.d → judge the embedded v4.
  const embedded = `${h[6] >> 8}.${h[6] & 0xff}.${h[7] >> 8}.${h[7] & 0xff}`;
  if (h.slice(0, 5).every((x) => x === 0) && h[5] === 0xffff) return isBogonV4(embedded);
  if (h[0] === 0x64 && h[1] === 0xff9b && h.slice(2, 6).every((x) => x === 0)) return isBogonV4(embedded);
  if ((h[0] & 0xfe00) === 0xfc00) return true;   // unique local fc00::/7
  if ((h[0] & 0xffc0) === 0xfe80) return true;   // link-local fe80::/10
  if ((h[0] & 0xff00) === 0xff00) return true;   // multicast ff00::/8
  if (h[0] === 0x2001 && h[1] === 0x0db8) return true;    // documentation 2001:db8::/32
  if (h[0] === 0x0100 && h.slice(1, 4).every((x) => x === 0)) return true; // discard 100::/64
  return false;
}

export function isBogon(ip) {
  const s = String(ip || "").trim();
  return s.includes(":") ? isBogonV6(s) : isBogonV4(s);
}
