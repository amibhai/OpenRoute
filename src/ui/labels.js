// Message keys (see _locales/*/messages.json) and display classes for the
// background's vocabulary. Pages translate with t(key); nothing here is
// user-visible text itself.

// Diagnosis type → [label key, remedy key, tone]
export const TYPE = {
  "dns-tampering": ["typeDnsTampering", "remedyDnsTampering", "good"],
  "dns-nxdomain": ["typeDnsNxdomain", "remedyDnsNxdomain", "warn"],
  "dns-unverified": ["typeDnsUnverified", "remedyDnsUnverified", "bad"],
  "doh-tampered": ["typeDohTampered", "remedyDohTampered", "bad"],
  "sni-dpi": ["typeSniDpi", "remedySniDpi", "warn"],
  "tls-mitm": ["typeTlsMitm", "remedyTlsMitm", "bad"],
  "ip-block": ["typeIpBlock", "remedyIpBlock", "bad"],
  "unreachable": ["typeUnreachable", "remedyUnreachable", "warn"],
  "policy-block": ["typePolicyBlock", "remedyPolicyBlock", "warn"],
  "dns-blockpage": ["typeDnsBlockpage", "remedyDnsBlockpage", "bad"],
  "http-451": ["typeHttp451", "remedyHttp451", "bad"],
  "unknown": ["typeUnknown", "remedyUnknown", "warn"]
};
export const typeOf = (type) => TYPE[type] || TYPE.unknown;

// Blocks Secure DNS fixes at full speed.
export const DNS_TYPES = new Set(["dns-tampering", "dns-blockpage"]);

// Policy status → [label key, tone]
export const STATUS = {
  blocked: ["statusBlocked", "bad"],
  routing: ["statusRouting", "warn"],
  fixed: ["statusFixed", "good"],
  "needs-user": ["statusNeedsUser", "warn"],
  exhausted: ["statusExhausted", "bad"],
  manual: ["statusManual", "muted"]
};

// A site seen failing but not (or no longer) handled by a policy.
export const STATUS_SEEN = ["statusSeen", "muted"];

export const EXHAUSTED = {
  "no-transport": "exhaustedNoTransport",
  "all-transports-failed": "exhaustedAllFailed",
  "max-attempts": "exhaustedMaxAttempts",
  "transport-removed": "exhaustedTransportRemoved",
  "auto-route-off": "exhaustedAutoRouteOff",
  "no-proxy-api": "exhaustedNoProxyApi"
};

export const RUNG = { direct: "rungDirect", doh: "rungDoh", ech: "rungEch", proxy: "rungProxy", fallback: "rungFallback" };

// Transport health → [label key, tone]
export const HEALTH = {
  up: ["healthUp", "good"],
  degraded: ["healthDegraded", "warn"],
  down: ["healthDown", "bad"],
  unknown: ["healthUnknown", "muted"]
};

// Resolver names are brands: shown as-is in every language.
export const RESOLVER_NAMES = {
  cloudflare: "Cloudflare", google: "Google", quad9: "Quad9", adguard: "AdGuard (unfiltered)",
  mullvad: "Mullvad", nextdns: "NextDNS", dnssb: "DNS.SB"
};

export const EVENT = {
  blocked: "eventBlocked",
  routed: "eventRouted",
  verified: "eventVerified",
  "route-failed": "eventRouteFailed",
  exhausted: "eventExhausted",
  retry: "eventRetry",
  rehomed: "eventRehomed",
  demoted: "eventDemoted",
  "works-direct": "eventWorksDirect",
  manual: "eventManual",
  bundle: "eventBundle",
  "routed-subresource": "eventRoutedSubresource",
  "reload-skipped": "eventReloadSkipped",
  discovery: "eventDiscovery",
  "doh-via-transport": "eventDohViaTransport",
  "companion-port": "eventCompanionPort",
  "proxy-auth-rejected": "eventProxyAuthRejected",
  "init-error": "eventInitError",
  "router-error": "eventRouterError",
  error: "eventError"
};

// "manual" events by what the user chose.
export const EVENT_MANUAL = { proxy: "eventManualProxy", auto: "eventManualAuto", other: "eventManual" };

export const TOR_MODES = ["auto", "direct", "obfs4", "snowflake", "meek", "webtunnel"];
export const TOR_MODE = Object.fromEntries(TOR_MODES.map((m) => [m, `torMode_${m}`]));

export const MODE_HELP = { smart: "modeSmartHelp", full: "modeFullHelp", off: "modeOffHelp" };

export const ENGINE = { chromium: "engineChromium", firefox: "engineFirefox", none: "engineNone" };

// chrome.proxy levelOfControl → key
export const CONTROL = {
  controllable_by_this_extension: "controlFree",
  controlled_by_this_extension: "controlOurs",
  controlled_by_other_extensions: "controlOther",
  not_controllable: "controlLocked"
};
