// Onboarding: shows only the permissions this browser still needs, opens the
// right Secure DNS settings page (or shows steps where an extension can't
// open settings, e.g. Firefox), and reports whether the companion is present.

import { $, el, setChildren } from "./shared/dom.js";
import { send, getApi } from "./shared/messaging.js";

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

  if (s.browser?.name) $("#browserName").textContent = s.browser.name;
  const c = s.companion || {};
  $("#companionLine").textContent = !c.supported
    ? "This browser can't talk to the companion app — use a proxy or Tor you already run."
    : c.available
      ? "✓ Companion detected — connect a transport from the popup."
      : "Companion not installed yet. Setup guide: companion/README.md · server/README.md.";
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
  if (res?.opened || !guide) { steps.hidden = true; return; }
  setChildren(steps, (guide.copyUrl ? [`Open ${guide.copyUrl}`] : []).concat(guide.steps || []).map((s) => el("li", { text: s })));
  steps.hidden = false;
});

$("#done").addEventListener("click", async () => {
  const tab = await api.tabs.getCurrent();
  if (tab?.id != null) api.tabs.remove(tab.id);
  else window.close();
});

render();
