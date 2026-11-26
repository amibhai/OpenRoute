/* global chrome -- evaluated inside the extension page, not in Node */
// Launches Playwright's bundled Chromium with the unpacked extension loaded.
// (Branded Chrome 137+ ignores --load-extension; Chromium and Chrome for
// Testing still honor it.)

import { chromium } from "playwright";
import { cpSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

export function tempDir(prefix) {
  return mkdtempSync(join(process.env.OPENROUTE_E2E_TMP || tmpdir(), prefix));
}

// Copy just what the extension ships (no node_modules/.tools) into a temp dir.
export function stageExtension() {
  const dir = tempDir("openroute-ext-");
  for (const p of ["manifest.json", "src", "icons", "LICENSE"]) cpSync(join(ROOT, p), join(dir, p), { recursive: true });
  return dir;
}

export async function launchWithExtension({ hostRules = [], extraArgs = [] } = {}) {
  const extDir = stageExtension();
  const profile = tempDir("openroute-profile-");
  const args = [
    `--disable-extensions-except=${extDir}`,
    `--load-extension=${extDir}`,
    "--no-first-run",
    "--no-default-browser-check",
    ...(hostRules.length ? [`--host-resolver-rules=${hostRules.join(", ")}`] : []),
    ...extraArgs
  ];
  const context = await chromium.launchPersistentContext(profile, { channel: "chromium", headless: true, args });
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
