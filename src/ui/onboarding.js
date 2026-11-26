// Onboarding: shows only the permissions this browser still needs, opens the
// right Secure DNS settings page (or shows steps where an extension can't
// open settings, e.g. Firefox), finds proxies already running here, and says
// whether the companion is installed.

import { $, el, setChildren, busy } from "./shared/dom.js";
import { send, getApi } from "./shared/messaging.js";
import { t, localize } from "./shared/i18n.js";

const api = getApi();

function setRow(id, show, granted) {
  const row = $(id);
  row.hidden = !show;
  if (!show) return;
  row.classList.toggle("done", !!granted);
  row.querySelector(".state").textContent = granted ? "✓" : "•";
  const btn = row.querySelector("button");
  if (btn) btn.hidden = !!granted;
}

async function render() {
  const s = await send("getState");
  if (!s?.ok) return;
  const a = s.access || {};
  const caps = s.capabilities || {};
  const needHost = caps.needsHostAccessToRoute;
  const needConsent = caps.dataCollectionConsent && a.dataConsent !== null;
  const showPrivate = s.browser?.family === "firefox" && a.privateWindows === false;
  setRow("#rowHost", needHost, a.hostAccess);
  setRow("#rowConsent", needConsent, a.dataConsent);
  setRow("#rowPrivate", showPrivate, false);
  $("#accessCard").hidden = !(needHost || needConsent || showPrivate);

  $("#step1Text").textContent = t("onbStep1Text", { browser: s.browser?.name || t("yourBrowser") });
  const c = s.companion || {};
  $("#companionLine").textContent = !c.supported ? t("onbCompanionUnsupported") : c.available ? t("onbCompanionFound") : t("onbCompanionMissing");
}

// permissions.request must be called from the click itself (user gesture).
$("#grantHost").addEventListener("click", async () => {
  await api.permissions.request({ origins: ["<all_urls>"] }).catch(() => false);
  render();
});
$("#grantConsent").addEventListener("click", async () => {
  await api.permissions.request({ data_collection: ["browsingActivity"] }).catch(() => false);
  render();
});

$("#openDns").addEventListener("click", async () => {
  const res = await send("openSecureDnsSettings");
  const guide = res?.guide;
  const steps = $("#dnsSteps");
  if (res?.opened || !guide) {
    steps.hidden = true;
    return;
  }
  setChildren(steps, [guide.copyUrl && t("openUrl", { url: guide.copyUrl }), ...(guide.steps || [])].filter(Boolean).map((x) => el("li", { text: x })));
  steps.hidden = false;
});

$("#discover").addEventListener("click", async (e) => {
  const out = $("#discoverResult");
  const res = await busy(e.currentTarget, t("searching"), () => send("discoverLocalProxies"));
  if (!res?.ok || res.error) {
    out.textContent = res?.error || t("errorGeneric");
    out.className = "note bad";
  } else if (res.found?.length) {
    out.textContent = t("discoverFound", { list: res.found.map((f) => `${f.label} (${f.port})`).join(", ") });
    out.className = "note good";
  } else {
    out.textContent = t("discoverNone", { count: res.tested });
    out.className = "note";
  }
});
$("#openTransports").addEventListener("click", () => send("openDashboard", { section: "transports" }));

$("#done").addEventListener("click", async () => {
  const tab = await api.tabs.getCurrent();
  if (tab?.id != null) api.tabs.remove(tab.id);
  else window.close();
});

localize();
render();
