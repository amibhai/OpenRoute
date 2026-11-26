// Human-readable labels shared by the popup and onboarding.

export const BADGES = {
  "dns-tampering": { label: "DNS tampering", cls: "good" },
  "dns-nxdomain": { label: "Doesn't exist", cls: "warn" },
  "dns-unverified": { label: "DNS blocked", cls: "bad" },
  "doh-tampered": { label: "DNS poisoned", cls: "bad" },
  "sni-dpi": { label: "SNI / DPI", cls: "warn" },
  "tls-mitm": { label: "TLS intercepted", cls: "bad" },
  "ip-block": { label: "IP block", cls: "bad" },
  "unreachable": { label: "Unreachable", cls: "warn" },
  "policy-block": { label: "Local policy", cls: "warn" },
  "unknown": { label: "Unknown", cls: "warn" }
};

export const REMEDIATION = {
  "dns-tampering": "Your resolver is faking DNS. Secure DNS fixes this at full speed; until then OpenRoute can route it.",
  "dns-nxdomain": "Encrypted DNS says this domain doesn't exist — check the address. Read-only copies may still work.",
  "dns-unverified": "DNS failed and encrypted DNS is unreachable too — likely deeper DNS blocking. OpenRoute routes it (the proxy resolves names).",
  "doh-tampered": "Even encrypted DNS returned a fake/private address. OpenRoute routes around it.",
  "sni-dpi": "The connection was reset during the TLS handshake — SNI/DPI filtering. ECH or a proxy defeats it.",
  "tls-mitm": "The certificate was invalid — something is intercepting the connection (often a block page). OpenRoute routes it.",
  "ip-block": "DNS is fine but packets to the server are dropped. Needs a proxy/tunnel — OpenRoute routes it.",
  "unreachable": "The server is unreachable and DNS couldn't be checked. It may be down or blocked at the IP level.",
  "policy-block": "Blocked by a policy or firewall on this device — not your ISP.",
  "unknown": "Couldn't classify the failure. OpenRoute will try routing it."
};

export const STATUS = {
  blocked: { label: "blocked", cls: "bad" },
  routing: { label: "routing…", cls: "warn" },
  fixed: { label: "✓ working", cls: "good" },
  "needs-user": { label: "needs you", cls: "warn" },
  exhausted: { label: "no route left", cls: "bad" },
  manual: { label: "manual", cls: "muted" }
};

export const EXHAUSTED_REASON = {
  "no-transport": "No transport to route through — add one above.",
  "all-transports-failed": "Every transport failed for this site.",
  "max-attempts": "Too many failed attempts.",
  "transport-removed": "Its transport was removed.",
  "auto-route-off": "Auto-route is off.",
  "no-proxy-api": "This browser can't route sites (no proxy API)."
};

export const RUNG_LABEL = { direct: "Direct", doh: "Secure DNS", ech: "Secure DNS + ECH", proxy: "Proxy", fallback: "Read-only" };
export const HEALTH_CLS = { up: "good", degraded: "warn", down: "bad", unknown: "muted" };
export const RESOLVER_LABELS = { cloudflare: "Cloudflare", google: "Google", quad9: "Quad9" };
