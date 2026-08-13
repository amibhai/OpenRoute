// Onboarding page logic. Deep-links to Secure DNS and closes when done.
const $ = (s) => document.querySelector(s);

$("#openDns").addEventListener("click", () => {
  chrome.tabs.create({ url: "chrome://settings/security" });
});

$("#done").addEventListener("click", async () => {
  const tab = await chrome.tabs.getCurrent();
  if (tab?.id != null) chrome.tabs.remove(tab.id);
});
