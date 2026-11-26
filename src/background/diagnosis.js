// Turns (error kind, DoH diagnosis) into a block classification, and a
// classification into the ladder rung that should handle it first.

import { KIND } from "./errors.js";

export const TYPES = Object.freeze({
  DNS_TAMPERING: "dns-tampering",   // resolver lied/failed; DoH has the real IP
  DNS_POISONED: "doh-tampered",     // even DoH returned bogus (private/bogon) IPs
  DNS_UNVERIFIED: "dns-unverified", // DNS failed and no DoH resolver was reachable to check
  NXDOMAIN: "dns-nxdomain",         // DoH confirms the name doesn't exist
  SNI_DPI: "sni-dpi",               // connection reset/TLS failure — SNI/DPI filtering
  TLS_MITM: "tls-mitm",             // certificate invalid — interception/block page over TLS
  IP_BLOCK: "ip-block",             // DNS fine, packets to the server are dropped/refused
  UNREACHABLE: "unreachable",       // server unreachable and DNS couldn't be checked
  POLICY: "policy-block",           // a local policy/firewall, not the ISP
  UNKNOWN: "unknown"
});

export function classify(kind, diag) {
  const d = diag || {};
  switch (kind) {
    case KIND.DNS:
      if (d.injected) return TYPES.DNS_POISONED;
      if (d.ok) return TYPES.DNS_TAMPERING;
      if (d.status === 3) return TYPES.NXDOMAIN;
      return TYPES.DNS_UNVERIFIED;
    case KIND.RESET:
    case KIND.TLS:
      return TYPES.SNI_DPI;
    case KIND.CERT:
      return TYPES.TLS_MITM;
    case KIND.TIMEOUT:
    case KIND.REFUSED:
    case KIND.UNREACHABLE:
      if (d.injected) return TYPES.DNS_POISONED;
      return d.ok ? TYPES.IP_BLOCK : TYPES.UNREACHABLE;
    case KIND.POLICY:
      return TYPES.POLICY;
    default:
      return TYPES.UNKNOWN;
  }
}

// First rung for a fresh block. Guidance rungs (doh/ech) come first when
// they're the correct full-speed fix; the rest need routing.
export function startRung(type, diag) {
  switch (type) {
    case TYPES.DNS_TAMPERING: return "doh";
    case TYPES.SNI_DPI: return diag?.echLikely ? "ech" : "proxy";
    case TYPES.NXDOMAIN:
    case TYPES.POLICY: return "fallback";
    default: return "proxy";
  }
}
