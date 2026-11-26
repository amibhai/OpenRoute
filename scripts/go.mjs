#!/usr/bin/env node
// Runs Go in companion/ with the project-local toolchain from
// scripts/setup-tools.mjs (else the go on PATH), keeping its caches inside
// .tools/ so nothing lands in your home directory.
//
//   node scripts/go.mjs                # go vet ./... && go test ./...
//   node scripts/go.mjs test -run X ./...

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const TOOLS = join(ROOT, ".tools");
const localGo = join(TOOLS, "go", "bin", process.platform === "win32" ? "go.exe" : "go");
const go = existsSync(localGo) ? localGo : "go";
const env = {
  ...process.env,
  GOTOOLCHAIN: "local",
  GOTELEMETRY: "off",
  ...(go === localGo ? { GOCACHE: join(TOOLS, "gocache"), GOPATH: join(TOOLS, "gopath") } : {})
};

function run(args) {
  const r = spawnSync(go, args, { cwd: join(ROOT, "companion"), env, stdio: "inherit" });
  if (r.error) {
    console.error(`go isn't available (${r.error.code}); get it with: npm run setup-tools -- go`);
    return 1;
  }
  return r.status ?? 1;
}

const args = process.argv.slice(2);
process.exit(args.length ? run(args) : run(["vet", "./..."]) || run(["test", "-count=1", "./..."]));
