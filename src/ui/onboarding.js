// Onboarding page: opens the right Secure-DNS settings page for this browser
// (or shows the steps where an extension can't open settings, e.g. Firefox).

import { $, el, setChildren } from "./shared/dom.js";
import { send, getApi } from "./shared/messaging.js";

const api = getApi();

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
