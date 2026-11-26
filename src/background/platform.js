// Platform layer: one place that knows which browser we're in and what it can
// do. Everything else asks this module instead of sniffing APIs ad hoc.
//
//   * api  — promise-based extension namespace (`browser` on Firefox,
//            `chrome` on Chromium; both are promise-based under MV3).
//   * capabilities — feature detection, never user-agent guessing. The proxy
//     engine is decided by *which* API exists: Firefox also has a
//     proxy.settings object (Firefox-format only), so the presence of
//     proxy.onRequest is what identifies the Firefox engine.

export function getApi() {
  return globalThis.browser ?? globalThis.chrome;
}

export function detectCapabilities(api) {
  const proxyEngine = api?.proxy?.onRequest ? "firefox"
    : (api?.proxy?.settings && typeof api.proxy.settings.set === "function") ? "chromium"
      : "none";
  return Object.freeze({
    proxyEngine,
    canRoute: proxyEngine !== "none",
    nativeMessaging: typeof api?.runtime?.connectNative === "function",
    webRequest: !!api?.webRequest?.onErrorOccurred,
    dnsApi: typeof api?.dns?.resolve === "function",
    sessionStorage: !!api?.storage?.session,
    privacy: !!api?.privacy?.network?.webRTCIPHandlingPolicy,
    menus: !!(api?.menus ?? api?.contextMenus),
    permissions: !!api?.permissions
  });
}

// Best-effort browser identity for UI copy and deep links. Never used to
// decide behavior — capabilities do that.
export async function detectBrowser(api) {
  const ua = globalThis.navigator?.userAgent || "";
  const mobile = /Android|Mobile/i.test(ua);
  if (typeof api?.runtime?.getBrowserInfo === "function") {
    try {
      const info = await api.runtime.getBrowserInfo();
      return { family: "firefox", name: info?.name || "Firefox", version: info?.version || "", mobile };
    } catch { /* fall through */ }
  }
  if (/Firefox\//.test(ua)) return { family: "firefox", name: "Firefox", version: (/Firefox\/([\d.]+)/.exec(ua) || [])[1] || "", mobile };

  const brands = (globalThis.navigator?.userAgentData?.brands || []).map((b) => b.brand);
  const version = (/Chrome\/([\d.]+)/.exec(ua) || [])[1] || "";
  let name = "Chromium";
  if (brands.includes("Microsoft Edge") || /Edg\//.test(ua)) name = "Edge";
  else if (brands.includes("Opera") || brands.includes("Opera GX") || /OPR\//.test(ua)) name = "Opera";
  else if (brands.includes("Brave") || globalThis.navigator?.brave) name = "Brave";
  else if (/Vivaldi/.test(ua) || brands.includes("Vivaldi")) name = "Vivaldi";
  else if (/YaBrowser/.test(ua) || brands.includes("Yandex")) name = "Yandex";
  else if (brands.includes("Google Chrome")) name = "Chrome";
  return { family: "chromium", name, version, mobile };
}

// Where (and how) to turn on the browser's encrypted DNS. Chromium browsers
// let an extension open their settings page; Firefox does not allow opening
// about:preferences from an extension, so it gets copyable steps instead.
export function secureDnsGuide(browser) {
  const name = browser?.name || "Chrome";
  if (browser?.family === "firefox") {
    return {
      url: null,
      copyUrl: "about:preferences#privacy",
      steps: browser.mobile
        ? ["Open Firefox Settings", "Tap Privacy & security → DNS over HTTPS", "Choose Increased or Max protection"]
        : ["Open about:preferences#privacy in a new tab", "Scroll to DNS over HTTPS", "Choose Increased or Max Protection (provider: Cloudflare or NextDNS)"]
    };
  }
  const pages = {
    Edge: "edge://settings/privacy",
    Brave: "brave://settings/security",
    Opera: "opera://settings/security",
    Vivaldi: "chrome://settings/security"
  };
  return {
    url: pages[name] || "chrome://settings/security",
    copyUrl: null,
    steps: ["Turn on “Use secure DNS”", "Pick Cloudflare (1.1.1.1) or Google as the provider"]
  };
}
