#!/usr/bin/env node
// actionlint over the GitHub workflows: syntax, expressions, action inputs,
// and shellcheck over every run: block (with the project-local shellcheck on
// PATH). Both come from scripts/setup-tools.mjs, else from PATH.

import { spawnSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import { delimiter, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const exe = (n) => (process.platform === "win32" ? `${n}.exe` : n);
const local = join(ROOT, ".tools", "actionlint", exe("actionlint"));
const bin = existsSync(local) ? local : "actionlint";
const workflows = readdirSync(join(ROOT, ".github", "workflows")).filter((f) => /\.ya?ml$/.test(f)).map((f) => `.github/workflows/${f}`);

const env = { ...process.env, PATH: [join(ROOT, ".tools", "shellcheck"), process.env.PATH].join(delimiter) };
const r = spawnSync(bin, ["-no-color", ...workflows], { cwd: ROOT, stdio: "inherit", env });
if (r.error) {
  console.error(`actionlint isn't available (${r.error.code}); get it with: npm run setup-tools -- actionlint shellcheck`);
  process.exit(1);
}
if (r.status === 0) console.log(`actionlint: ${workflows.length} workflows clean`);
process.exit(r.status ?? 1);
