// Evaluates a PAC script the way Chromium's proxy resolver does, so tests
// exercise the *generated* PAC rather than trusting it:
//   * the entry point must be FindProxyForURL(url, host) — a script without it
//     fails to load (Chromium's proxy_resolver_v8 rejects it);
//   * https:// and wss:// URLs are stripped to scheme://host:port/ before the
//     call (Chromium hides paths/queries of secure URLs from PAC scripts);
//   * `host` is passed without IPv6 brackets.
// The standard PAC helper functions are provided (DNS helpers are inert —
// generated PACs must not depend on local DNS).

import vm from "node:vm";

function shExpMatch(str, pattern) {
  const re = new RegExp("^" + String(pattern).replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$");
  return re.test(String(str));
}

const BUILTINS = {
  isPlainHostName: (h) => String(h).indexOf(".") === -1,
  dnsDomainIs: (h, d) => String(h).length >= String(d).length && String(h).endsWith(String(d)),
  localHostOrDomainIs: (h, hd) => h === hd || (String(h).indexOf(".") === -1 && String(hd).startsWith(h + ".")),
  isResolvable: () => false,
  isInNet: () => false,
  dnsResolve: () => null,
  myIpAddress: () => "127.0.0.1",
  dnsDomainLevels: (h) => String(h).split(".").length - 1,
  shExpMatch,
  weekdayRange: () => true,
  dateRange: () => true,
  timeRange: () => true,
  alert: () => {}
};

export function compilePac(source) {
  const ctx = vm.createContext({ ...BUILTINS });
  vm.runInContext(String(source), ctx, { timeout: 1000, filename: "openroute.pac" });
  if (typeof ctx.FindProxyForURL !== "function") {
    throw new Error("PAC script defines no FindProxyForURL(url, host) — Chromium refuses to load it");
  }
  return ctx;
}

export function pacUrlFor(url) {
  const u = new URL(url);
  if (u.protocol === "https:" || u.protocol === "wss:") return `${u.protocol}//${u.host}/`;
  return u.href;
}

export function pacHostFor(url) {
  return new URL(url).hostname.replace(/^\[|\]$/g, "");
}

export function findProxy(source, url) {
  const ctx = typeof source === "string" ? compilePac(source) : source;
  return ctx.FindProxyForURL(pacUrlFor(url), pacHostFor(url));
}
