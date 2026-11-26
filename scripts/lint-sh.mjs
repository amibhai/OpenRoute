#!/usr/bin/env node
// shellcheck over every shell script in the repo, using the project-local
// binary from scripts/setup-tools.mjs when present (else one on PATH). Each
// script is checked in the dialect its shebang names.

import { spawnSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const local = join(ROOT, ".tools", "shellcheck", process.platform === "win32" ? "shellcheck.exe" : "shellcheck");
const bin = existsSync(local) ? local : "shellcheck";
const fakes = "test/server/fakes";
const files = [
  "server/install-server.sh",
  "companion/install/install-unix.sh",
  "build.sh",
  ...readdirSync(join(ROOT, fakes)).filter((f) => f !== "README.md").map((f) => `${fakes}/${f}`)
];

const r = spawnSync(bin, ["-S", "style", ...files], { cwd: ROOT, stdio: "inherit" });
if (r.error) {
  console.error(`shellcheck isn't available (${r.error.code}); get it with: npm run setup-tools -- shellcheck`);
  process.exit(1);
}
if (r.status === 0) console.log(`shellcheck: ${files.length} scripts clean`);
process.exit(r.status ?? 1);
