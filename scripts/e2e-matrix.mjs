#!/usr/bin/env node
// Runs the end-to-end suites against every browser installed on this machine:
// the Chromium-family suite on Playwright's Chromium, Edge and Brave (branded
// Chrome 137+ can't load unpacked extensions from the command line), and the
// Firefox suite on Firefox. Browsers that aren't installed are skipped.
//
//   node scripts/e2e-matrix.mjs

import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { browserUnderTest } from "../test/e2e/helpers/chromium.mjs";
import { firefoxAvailable } from "../test/e2e/helpers/firefox.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const runs = [];
for (const name of ["chromium", "edge", "brave"]) {
  process.env.OPENROUTE_E2E_BROWSER = name;
  if (!browserUnderTest().launch) { runs.push([name, "skipped (not installed)"]); continue; }
  const r = spawnSync(process.execPath, ["--test", "--test-reporter=dot", "test/e2e/chromium-routing.test.mjs"], {
    cwd: ROOT, stdio: "inherit", env: { ...process.env, OPENROUTE_E2E_BROWSER: name }
  });
  runs.push([name, r.status === 0 ? "pass" : "FAIL"]);
}
if (firefoxAvailable()) {
  const r = spawnSync(process.execPath, ["--test", "--test-reporter=dot", "test/e2e/firefox-routing.test.mjs"], { cwd: ROOT, stdio: "inherit" });
  runs.push(["firefox", r.status === 0 ? "pass" : "FAIL"]);
} else {
  runs.push(["firefox", "skipped (Firefox or geckodriver missing)"]);
}
console.log("\nE2E browser matrix:");
for (const [name, result] of runs) console.log(`  ${name.padEnd(9)} ${result}`);
process.exit(runs.some(([, r]) => r === "FAIL") ? 1 : 0);
