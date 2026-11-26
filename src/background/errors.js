// Navigation-error taxonomy.
//
// Chromium reports "net::ERR_CONNECTION_RESET"; Firefox reports nsresult
// codes — as decimal numbers ("Error code 2152398878") or symbolic names
// ("NS_ERROR_UNKNOWN_HOST", "SSL_ERROR_…"). normalizeError() turns any of them
// into one {code, kind} so the rest of the extension never sees a browser
// dialect. `kind` decides what happens next:
//
//   ignore   user/browser initiated or local (abort, ad blocker, bad URL…)  → nothing
//   offline  no network at all / network changed                          → nothing
//   policy   blocked by a local policy or firewall, not the ISP            → log only
//   proxy    a proxy (ours or the system's) failed                         → transport failure
//   dns | reset | tls | cert | timeout | refused | unreachable | http | unknown
//            possible censorship                                          → diagnose

export const KIND = Object.freeze({
  IGNORE: "ignore",
  OFFLINE: "offline",
  POLICY: "policy",
  PROXY: "proxy",
  DNS: "dns",
  RESET: "reset",
  TLS: "tls",
  CERT: "cert",
  TIMEOUT: "timeout",
  REFUSED: "refused",
  UNREACHABLE: "unreachable",
  HTTP: "http",
  UNKNOWN: "unknown"
});

const K = KIND;

// Chromium net error names (without the "ERR_" prefix) → kind.
const CHROMIUM = new Map(Object.entries({
  [K.IGNORE]: [
    "ABORTED", "BLOCKED_BY_CLIENT", "BLOCKED_BY_RESPONSE", "BLOCKED_BY_CSP", "BLOCKED_BY_ORB",
    "BLOCKED_BY_FINGERPRINTING_PROTECTION", "BLOCKED_BY_PRIVATE_NETWORK_ACCESS_CHECKS",
    "BLOCKED_BY_LOCAL_NETWORK_ACCESS_CHECKS", "INVALID_URL", "DISALLOWED_URL_SCHEME",
    "UNKNOWN_URL_SCHEME", "FILE_NOT_FOUND", "ACCESS_DENIED", "UNSAFE_REDIRECT", "UNSAFE_PORT",
    "CACHE_MISS", "CACHE_READ_FAILURE", "CONTENT_DECODING_FAILED", "INVALID_ARGUMENT",
    "NOT_IMPLEMENTED", "INSUFFICIENT_RESOURCES", "OUT_OF_MEMORY", "UPLOAD_FILE_CHANGED",
    "ICANN_NAME_COLLISION", "HTTPS_UPGRADE_FALLBACK"
  ],
  [K.OFFLINE]: ["INTERNET_DISCONNECTED", "NETWORK_CHANGED", "NETWORK_IO_SUSPENDED", "ADDRESS_INVALID"],
  [K.POLICY]: ["BLOCKED_BY_ADMINISTRATOR", "NETWORK_ACCESS_DENIED"],
  [K.PROXY]: [
    "PROXY_CONNECTION_FAILED", "TUNNEL_CONNECTION_FAILED", "SOCKS_CONNECTION_FAILED",
    "SOCKS_CONNECTION_HOST_UNREACHABLE", "PROXY_AUTH_UNSUPPORTED", "PROXY_AUTH_REQUESTED",
    "PROXY_AUTH_REQUESTED_WITH_NO_CONNECTION", "UNEXPECTED_PROXY_AUTH", "PROXY_CERTIFICATE_INVALID",
    "PROXY_HTTP_1_1_REQUIRED", "PROXY_UNABLE_TO_CONNECT_TO_DESTINATION", "PAC_SCRIPT_FAILED",
    "PAC_NOT_IN_DHCP", "MANDATORY_PROXY_CONFIGURATION_FAILED", "NO_SUPPORTED_PROXIES",
    "PROXY_DELEGATE_CANCELED_CONNECT_REQUEST", "PROXY_DELEGATE_CANCELED_CONNECT_RESPONSE"
  ],
  [K.DNS]: ["NAME_NOT_RESOLVED", "NAME_RESOLUTION_FAILED"],
  [K.RESET]: [
    "CONNECTION_RESET", "CONNECTION_CLOSED", "CONNECTION_ABORTED", "EMPTY_RESPONSE",
    "SOCKET_NOT_CONNECTED", "HTTP2_PROTOCOL_ERROR", "HTTP2_PING_FAILED", "HTTP2_SERVER_REFUSED_STREAM",
    "HTTP2_STREAM_CLOSED", "HTTP2_FLOW_CONTROL_ERROR", "HTTP2_FRAME_SIZE_ERROR",
    "HTTP2_COMPRESSION_ERROR", "HTTP2_INADEQUATE_TRANSPORT_SECURITY", "QUIC_PROTOCOL_ERROR",
    "QUIC_HANDSHAKE_FAILED", "SPDY_PROTOCOL_ERROR", "INVALID_HTTP_RESPONSE",
    "RESPONSE_HEADERS_TRUNCATED", "CONTENT_LENGTH_MISMATCH", "INCOMPLETE_CHUNKED_ENCODING",
    "INVALID_CHUNKED_ENCODING"
  ],
  [K.TLS]: [
    "SSL_PROTOCOL_ERROR", "SSL_VERSION_OR_CIPHER_MISMATCH", "SSL_UNRECOGNIZED_NAME_ALERT",
    "SSL_BAD_RECORD_MAC_ALERT", "SSL_DECRYPT_ERROR_ALERT", "SSL_HANDSHAKE_NOT_COMPLETED",
    "BAD_SSL_CLIENT_AUTH_CERT", "SSL_CLIENT_AUTH_CERT_NEEDED", "ECH_NOT_NEGOTIATED",
    "ECH_FALLBACK_CERTIFICATE_INVALID", "SSL_OBSOLETE_CIPHER", "SSL_RENEGOTIATION_REQUESTED",
    "SSL_SERVER_CERT_CHANGED", "SSL_KEY_USAGE_INCOMPATIBLE"
  ],
  [K.CERT]: ["SSL_PINNED_KEY_NOT_IN_CERT_CHAIN", "CERTIFICATE_TRANSPARENCY_REQUIRED", "INSECURE_RESPONSE"],
  [K.TIMEOUT]: ["CONNECTION_TIMED_OUT", "TIMED_OUT"],
  [K.REFUSED]: ["CONNECTION_REFUSED"],
  [K.UNREACHABLE]: ["ADDRESS_UNREACHABLE", "CONNECTION_FAILED"],
  [K.HTTP]: [
    "TOO_MANY_REDIRECTS", "HTTP_RESPONSE_CODE_FAILURE", "INVALID_RESPONSE", "INVALID_REDIRECT",
    "RESPONSE_BODY_TOO_BIG_TO_DRAIN", "TOO_MANY_RETRIES"
  ]
}).flatMap(([kind, codes]) => codes.map((c) => [c, kind])));

function chromiumKind(code) {
  if (CHROMIUM.has(code)) return CHROMIUM.get(code);
  if (code.startsWith("CERT_")) return K.CERT;
  if (code.startsWith("SSL_")) return K.TLS;
  if (code.startsWith("DNS_")) return K.DNS;
  if (code.startsWith("PROXY_") || code.startsWith("SOCKS_")) return K.PROXY;
  if (code.startsWith("HTTP2_") || code.startsWith("QUIC_")) return K.RESET;
  if (code.startsWith("BLOCKED_BY_")) return K.IGNORE;
  return K.UNKNOWN;
}

// Firefox network-module nsresults (NS_ERROR_MODULE_NETWORK, 0x804Bxxxx).
const NS_NETWORK = new Map([
  [0x0002, ["NS_BINDING_ABORTED", K.IGNORE]],
  [0x0003, ["NS_BINDING_REDIRECTED", K.IGNORE]],
  [0x0004, ["NS_BINDING_RETARGETED", K.IGNORE]],
  [0x000A, ["NS_ERROR_MALFORMED_URI", K.IGNORE]],
  [0x000D, ["NS_ERROR_CONNECTION_REFUSED", K.REFUSED]],
  [0x000E, ["NS_ERROR_NET_TIMEOUT", K.TIMEOUT]],
  [0x0010, ["NS_ERROR_OFFLINE", K.OFFLINE]],
  [0x0012, ["NS_ERROR_UNKNOWN_PROTOCOL", K.IGNORE]],
  [0x0013, ["NS_ERROR_PORT_ACCESS_NOT_ALLOWED", K.IGNORE]],
  [0x0014, ["NS_ERROR_NET_RESET", K.RESET]],
  [0x001E, ["NS_ERROR_UNKNOWN_HOST", K.DNS]],
  [0x001F, ["NS_ERROR_REDIRECT_LOOP", K.HTTP]],
  [0x002A, ["NS_ERROR_UNKNOWN_PROXY_HOST", K.PROXY]],
  [0x0046, ["NS_ERROR_DOCUMENT_NOT_CACHED", K.IGNORE]],
  [0x0047, ["NS_ERROR_NET_INTERRUPT", K.RESET]],
  [0x0048, ["NS_ERROR_PROXY_CONNECTION_REFUSED", K.PROXY]],
  [0x004C, ["NS_ERROR_NET_PARTIAL_TRANSFER", K.RESET]]
]);

const NS_MODULE_NETWORK = 0x804B;
const NS_MODULE_SECURITY = 0x805A;   // NSS / PSM errors (TLS + certificates)
const NS_MODULE_URILOADER = 0x805C;  // content-blocking (tracking/malware/phishing)

function firefoxNumeric(n) {
  const mod = (n >>> 16) & 0xFFFF;
  const code = n & 0xFFFF;
  if (n === 0x80004004) return { code: "NS_ERROR_ABORT", kind: K.IGNORE };
  if (mod === NS_MODULE_NETWORK && NS_NETWORK.has(code)) {
    const [name, kind] = NS_NETWORK.get(code);
    return { code: name, kind };
  }
  if (mod === NS_MODULE_SECURITY) {
    // Low 16 bits are the negated NSS error. SSL_ERROR_* live at 11289–12288
    // (protocol problems, except SSL_ERROR_BAD_CERT_DOMAIN = 12276); SEC_ERROR_*
    // and MOZILLA_PKIX_ERROR_* (6193–8192) are certificate verdicts.
    if (code >= 11289 && code <= 12288 && code !== 12276) return { code: `NSS_${code}`, kind: K.TLS };
    return { code: `NSS_${code}`, kind: K.CERT };
  }
  if (mod === NS_MODULE_URILOADER) return { code: `NS_URILOADER_${code}`, kind: K.IGNORE };
  if (mod === NS_MODULE_NETWORK) return { code: `NS_NETWORK_${code}`, kind: K.UNKNOWN };
  return { code: `NS_${n.toString(16)}`, kind: K.UNKNOWN };
}

function firefoxSymbolic(name) {
  if (/^NS_BINDING_/.test(name) || name === "NS_ERROR_ABORT") return K.IGNORE;
  if (/MALWARE|PHISHING|TRACKING|UNWANTED|HARMFUL|FINGERPRINTING|CRYPTOMINING|SOCIALTRACKING|BLOCKED_URI|CONTENT_BLOCKED/.test(name)) return K.IGNORE;
  if (/OFFLINE/.test(name)) return K.OFFLINE;
  if (/PROXY/.test(name)) return K.PROXY;
  if (/UNKNOWN_HOST|DNS|NET_ON_RESOLV/.test(name)) return K.DNS;
  if (/CONNECTION_REFUSED/.test(name)) return K.REFUSED;
  if (/NET_TIMEOUT|NET_ON_CONNECTING|NET_ON_WAITING/.test(name)) return K.TIMEOUT;
  if (/NET_RESET|NET_INTERRUPT|PARTIAL_TRANSFER|NET_ON_SENDING|NET_ON_RECEIVING|NET_EMPTY_RESPONSE/.test(name)) return K.RESET;
  if (/NET_ON_TLS/.test(name)) return K.TLS;
  if (/^SSL_ERROR_BAD_CERT_DOMAIN/.test(name)) return K.CERT;
  if (/^SSL_ERROR_/.test(name)) return K.TLS;
  if (/^(SEC_ERROR_|MOZILLA_PKIX_ERROR_)/.test(name)) return K.CERT;
  if (/REDIRECT_LOOP/.test(name)) return K.HTTP;
  if (/MALFORMED_URI|UNKNOWN_PROTOCOL|PORT_ACCESS_NOT_ALLOWED|DOCUMENT_NOT_CACHED/.test(name)) return K.IGNORE;
  return K.UNKNOWN;
}

export function normalizeError(raw) {
  const s = String(raw ?? "").trim();
  if (!s) return { raw: s, code: "UNKNOWN", kind: K.UNKNOWN, source: "unknown" };

  const chromium = /(?:^|net::)ERR_([A-Z0-9_]+)/.exec(s);
  if (chromium) return { raw: s, code: chromium[1], kind: chromiumKind(chromium[1]), source: "chromium" };

  const numeric = /Error code (\d+)/i.exec(s) || /^(\d{9,10})$/.exec(s) || /^0x([0-9a-f]{8})$/i.exec(s);
  if (numeric) {
    const n = numeric[0].toLowerCase().startsWith("0x") ? parseInt(numeric[1], 16) : Number(numeric[1]);
    return { raw: s, ...firefoxNumeric(n >>> 0), source: "firefox" };
  }

  const symbolic = /\b((?:NS|SSL|SEC|MOZILLA_PKIX)_[A-Z0-9_]+)\b/.exec(s);
  if (symbolic) return { raw: s, code: symbolic[1], kind: firefoxSymbolic(symbolic[1]), source: "firefox" };

  return { raw: s, code: s.toUpperCase().replace(/\W+/g, "_").slice(0, 64), kind: K.UNKNOWN, source: "unknown" };
}

// Kinds that may indicate censorship and are worth a diagnosis.
export function isCandidate(kind) {
  return ![K.IGNORE, K.OFFLINE, K.POLICY, K.PROXY].includes(kind);
}
