// Drives the installed Firefox through geckodriver (from .tools/) and installs
// the built Firefox package as a temporary add-on.

import { existsSync } from "node:fs";
import { join } from "node:path";
import { Builder, By } from "selenium-webdriver";
import firefoxPkg from "selenium-webdriver/firefox.js";
import { build, GECKO_ID } from "../../../scripts/build.mjs";
import { ROOT } from "./chromium.mjs";

const { Options, ServiceBuilder } = firefoxPkg;

export const FIREFOX_BINARY = process.env.OPENROUTE_FIREFOX ||
  ["C:/Program Files/Mozilla Firefox/firefox.exe", "/usr/bin/firefox", "/Applications/Firefox.app/Contents/MacOS/firefox"].find(existsSync);
const GECKODRIVER = [
  join(ROOT, ".tools", "geckodriver", "geckodriver.exe"),
  join(ROOT, ".tools", "geckodriver", "geckodriver")
].find(existsSync);

export const firefoxAvailable = () => !!(FIREFOX_BINARY && GECKODRIVER);

// Fixed internal UUID so the test can open the extension's own pages.
const UUID = "3f6a9c3e-0a7b-4f7e-9a1c-0e6d5b2c4a11";

export async function launchFirefox({ localDomains = [], idleTimeoutMs = 3000, prefs = {} } = {}) {
  const { zipPath } = build("firefox");
  const options = new Options()
    .setBinary(FIREFOX_BINARY)
    .addArguments("-headless")
    .setPreference("network.dns.localDomains", localDomains.join(","))
    .setPreference("extensions.background.idle.timeout", idleTimeoutMs)
    .setPreference("extensions.webextensions.uuids", JSON.stringify({ [GECKO_ID]: UUID }))
    .setPreference("browser.shell.checkDefaultBrowser", false)
    .setPreference("datareporting.policy.dataSubmissionEnabled", false)
    .setPreference("network.trr.mode", 5); // keep Firefox's own DoH out of the test
  for (const [k, v] of Object.entries(prefs)) options.setPreference(k, v);

  const driver = await new Builder()
    .forBrowser("firefox")
    .setFirefoxOptions(options)
    .setFirefoxService(new ServiceBuilder(GECKODRIVER))
    .build();
  await driver.installAddon(zipPath, true);
  const base = `moz-extension://${UUID}`;

  async function openControl() {
    await driver.get(`${base}/src/ui/popup.html`);
  }
  await openControl();

  // runtime.sendMessage from the extension's own page (a trusted sender).
  async function send(type, extra = {}) {
    const res = await driver.executeAsyncScript(
      "const [msg, done] = [arguments[0], arguments[arguments.length - 1]];" +
      "browser.runtime.sendMessage(msg).then(done, (e) => done({ ok: false, error: String(e) }));",
      { type, ...extra });
    return res;
  }

  async function gotoAllowingError(url) {
    try { await driver.get(url); } catch { /* "Reached error page" is expected for blocked sites */ }
  }

  async function textOf(id) {
    try { return await (await driver.findElement(By.id(id))).getText(); } catch { return null; }
  }

  return {
    driver, base, send, openControl, gotoAllowingError, textOf,
    async close() { await driver.quit().catch(() => {}); }
  };
}
