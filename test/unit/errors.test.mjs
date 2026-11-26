import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeError, KIND, isCandidate } from "../../src/background/errors.js";

const kindOf = (s) => normalizeError(s).kind;

test("Chromium net errors map to the right kind", () => {
  const cases = {
    "net::ERR_ABORTED": KIND.IGNORE,
    "net::ERR_BLOCKED_BY_CLIENT": KIND.IGNORE,
    "net::ERR_INTERNET_DISCONNECTED": KIND.OFFLINE,
    "net::ERR_NETWORK_CHANGED": KIND.OFFLINE,
    "net::ERR_BLOCKED_BY_ADMINISTRATOR": KIND.POLICY,
    "net::ERR_PROXY_CONNECTION_FAILED": KIND.PROXY,
    "net::ERR_TUNNEL_CONNECTION_FAILED": KIND.PROXY,
    "net::ERR_SOCKS_CONNECTION_FAILED": KIND.PROXY,
    "net::ERR_NAME_NOT_RESOLVED": KIND.DNS,
    "net::ERR_DNS_TIMED_OUT": KIND.DNS,
    "net::ERR_CONNECTION_RESET": KIND.RESET,
    "net::ERR_EMPTY_RESPONSE": KIND.RESET,
    "net::ERR_HTTP2_PROTOCOL_ERROR": KIND.RESET,
    "net::ERR_SSL_PROTOCOL_ERROR": KIND.TLS,
    "net::ERR_SSL_UNRECOGNIZED_NAME_ALERT": KIND.TLS,
    "net::ERR_SSL_SOMETHING_NEW": KIND.TLS,
    "net::ERR_CERT_AUTHORITY_INVALID": KIND.CERT,
    "net::ERR_CERT_KNOWN_INTERCEPTION_BLOCKED": KIND.CERT,
    "net::ERR_CONNECTION_TIMED_OUT": KIND.TIMEOUT,
    "net::ERR_CONNECTION_REFUSED": KIND.REFUSED,
    "net::ERR_ADDRESS_UNREACHABLE": KIND.UNREACHABLE,
    "net::ERR_TOO_MANY_REDIRECTS": KIND.HTTP,
    "net::ERR_FAILED": KIND.UNKNOWN,
    "ERR_CONNECTION_RESET": KIND.RESET // without the net:: prefix
  };
  for (const [raw, kind] of Object.entries(cases)) assert.equal(kindOf(raw), kind, raw);
});

test("Firefox decimal nsresult codes decode (network module)", () => {
  const cases = {
    "Error code 2152398850": ["NS_BINDING_ABORTED", KIND.IGNORE],
    "Error code 2152398878": ["NS_ERROR_UNKNOWN_HOST", KIND.DNS],
    "Error code 2152398861": ["NS_ERROR_CONNECTION_REFUSED", KIND.REFUSED],
    "Error code 2152398862": ["NS_ERROR_NET_TIMEOUT", KIND.TIMEOUT],
    "Error code 2152398864": ["NS_ERROR_OFFLINE", KIND.OFFLINE],
    "Error code 2152398868": ["NS_ERROR_NET_RESET", KIND.RESET],
    "Error code 2152398919": ["NS_ERROR_NET_INTERRUPT", KIND.RESET],
    "Error code 2152398920": ["NS_ERROR_PROXY_CONNECTION_REFUSED", KIND.PROXY],
    "Error code 2152398890": ["NS_ERROR_UNKNOWN_PROXY_HOST", KIND.PROXY],
    "Error code 2147500036": ["NS_ERROR_ABORT", KIND.IGNORE]
  };
  for (const [raw, [code, kind]] of Object.entries(cases)) {
    const e = normalizeError(raw);
    assert.equal(e.code, code, raw);
    assert.equal(e.kind, kind, raw);
    assert.equal(e.source, "firefox");
  }
});

test("Firefox security-module codes split into TLS protocol vs certificate", () => {
  const nss = (neg) => String((0x805A0000 + neg) >>> 0);
  assert.equal(kindOf(`Error code ${nss(12286)}`), KIND.TLS, "SSL_ERROR_NO_CYPHER_OVERLAP");
  assert.equal(kindOf(`Error code ${nss(12276)}`), KIND.CERT, "SSL_ERROR_BAD_CERT_DOMAIN");
  assert.equal(kindOf(`Error code ${nss(8179)}`), KIND.CERT, "SEC_ERROR_UNKNOWN_ISSUER");
  assert.equal(kindOf(`Error code ${nss(7184)}`), KIND.CERT, "MOZILLA_PKIX range");
});

test("Firefox symbolic names are understood", () => {
  assert.equal(kindOf("NS_ERROR_UNKNOWN_HOST"), KIND.DNS);
  assert.equal(kindOf("NS_ERROR_NET_ON_RESOLVED"), KIND.DNS);
  assert.equal(kindOf("NS_ERROR_TRACKING_URI"), KIND.IGNORE);
  assert.equal(kindOf("NS_ERROR_PHISHING_URI"), KIND.IGNORE);
  assert.equal(kindOf("SSL_ERROR_BAD_CERT_DOMAIN"), KIND.CERT);
  assert.equal(kindOf("SSL_ERROR_HANDSHAKE_FAILURE_ALERT"), KIND.TLS);
  assert.equal(kindOf("SEC_ERROR_EXPIRED_CERTIFICATE"), KIND.CERT);
  assert.equal(kindOf("NS_BINDING_REDIRECTED"), KIND.IGNORE);
});

test("garbage never throws and is a diagnosable unknown", () => {
  for (const raw of [undefined, null, "", "weird", 42, {}]) {
    const e = normalizeError(raw);
    assert.equal(typeof e.kind, "string");
  }
  assert.equal(kindOf("something odd happened"), KIND.UNKNOWN);
});

test("only possible-censorship kinds are candidates for diagnosis", () => {
  for (const k of [KIND.IGNORE, KIND.OFFLINE, KIND.POLICY, KIND.PROXY]) assert.equal(isCandidate(k), false, k);
  for (const k of [KIND.DNS, KIND.RESET, KIND.TLS, KIND.CERT, KIND.TIMEOUT, KIND.REFUSED, KIND.UNREACHABLE, KIND.HTTP, KIND.UNKNOWN]) {
    assert.equal(isCandidate(k), true, k);
  }
});
