/* global chrome -- evaluated inside the extension page, not in Node */
// Launches Playwright's bundled Chromium with the unpacked extension loaded.
// (Branded Chrome 137+ ignores --load-extension; Chromium and Chrome for
// Testing still honor it.)

import { chromium } from "playwright";
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

export function tempDir(prefix) {
  return mkdtempSync(join(process.env.OPENROUTE_E2E_TMP || tmpdir(), prefix));
}

// Copy just what the extension ships (no node_modules/.tools) into a temp dir.
// allUrls grants site access up front — what a user does when opting in to
// deep detection or proxy logins on Chromium (a test can't click the prompt).
export function stageExtension({ allUrls = false } = {}) {
  const dir = tempDir("openroute-ext-");
  for (const p of ["manifest.json", "src", "icons", "LICENSE"]) cpSync(join(ROOT, p), join(dir, p), { recursive: true });
  if (allUrls) {
    const m = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
    m.host_permissions = [...new Set([...(m.host_permissions || []), "<all_urls>"])];
    writeFileSync(join(dir, "manifest.json"), JSON.stringify(m, null, 2));
  }
  return dir;
}

// OPENROUTE_E2E_BROWSER picks the Chromium-family browser under test.
// Branded Chrome 137+ ignores --load-extension; Edge and Brave (and
// Playwright's Chromium) still honor it. Branded builds run headful but
// off-screen, since their headless mode may not load extensions.
const CHROMIUM_FAMILY = {
  chromium: { channel: "chromium", headless: true },
  edge: { executablePath: ["C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe", "/usr/bin/microsoft-edge", "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"] },
  brave: { executablePath: ["C:/Program Files/BraveSoftware/Brave-Browser/Application/brave.exe", "/usr/bin/brave-browser", "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"] }
};

export function browserUnderTest() {
  const name = process.env.OPENROUTE_E2E_BROWSER || "chromium";
  const spec = CHROMIUM_FAMILY[name];
  if (!spec) return { name, launch: { executablePath: name, headless: false } }; // a path
  if (!spec.executablePath) return { name, launch: spec };
  const exe = spec.executablePath.find((p) => existsSync(p));
  return { name, launch: exe ? { executablePath: exe, headless: false } : null };
}

export async function launchWithExtension({ hostRules = [], extraArgs = [], allUrls = false } = {}) {
  const extDir = stageExtension({ allUrls });
  const profile = tempDir("openroute-profile-");
  const target = browserUnderTest();
  if (!target.launch) throw new Error(`browser "${target.name}" is not installed`);
  const args = [
    `--disable-extensions-except=${extDir}`,
    `--load-extension=${extDir}`,
    "--no-first-run",
    "--no-default-browser-check",
    ...(target.launch.headless === false ? ["--window-position=-2400,-2400"] : []),
    ...(hostRules.length ? [`--host-resolver-rules=${hostRules.join(", ")}`] : []),
    ...extraArgs
  ];
  const context = await chromium.launchPersistentContext(profile, { ...target.launch, args });
  let worker = context.serviceWorkers().find((w) => w.url().startsWith("chrome-extension://"));
  if (!worker) worker = await context.waitForEvent("serviceworker", { timeout: 15000 });
  const extensionId = new URL(worker.url()).host;

  // A page inside the extension: its runtime.sendMessage is a trusted sender.
  const control = await context.newPage();
  await control.goto(`chrome-extension://${extensionId}/src/ui/popup.html`);
  const send = (type, extra = {}) => control.evaluate(([t, e]) => chrome.runtime.sendMessage({ type: t, ...e }), [type, extra]);

  return {
    context, worker, extensionId, control, send,
    async close() {
      await context.close().catch(() => {});
      for (const d of [extDir, profile]) rmSync(d, { recursive: true, force: true, maxRetries: 3 });
    }
  };
}

export async function waitFor(fn, { timeout = 15000, interval = 200, message = "condition" } = {}) {
  const start = Date.now();
  let last;
  while (Date.now() - start < timeout) {
    try {
      last = await fn();
      if (last) return last;
    } catch (e) { last = e; }
    await new Promise((r) => setTimeout(r, interval));
  }
  throw new Error(`timed out waiting for ${message} (last: ${last instanceof Error ? last.message : JSON.stringify(last)})`);
}
