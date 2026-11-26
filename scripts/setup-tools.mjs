#!/usr/bin/env node
// Downloads the toolchain used to *verify* OpenRoute (not to run it) into the
// project-local, gitignored `.tools/` directory. Every archive is checked
// against a published SHA-256 before it is extracted; nothing is installed
// system-wide.
//
//   node scripts/setup-tools.mjs                 # everything
//   node scripts/setup-tools.mjs go sing-box     # a subset
//   node scripts/setup-tools.mjs --force         # re-download even if present
//
// Sources and their checksums:
//   go           go.dev/dl/?mode=json                      (sha256 per file)
//   sing-box     GitHub releases (latest + newest 1.12.x)   (asset "digest")
//   tor          dist.torproject.org Tor Expert Bundle      (sha256sums-signed-build.txt)
//   geckodriver  GitHub releases                            (asset "digest")
//   shellcheck   GitHub releases                            (asset "digest")
//   actionlint   GitHub releases                            (asset "digest")

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const TOOLS = join(ROOT, ".tools");
const CACHE = join(TOOLS, "downloads");
const UA = { "user-agent": "openroute-setup-tools" };

const args = process.argv.slice(2);
const FORCE = args.includes("--force");
const wanted = args.filter((a) => !a.startsWith("--"));
const ALL = ["go", "sing-box", "tor", "geckodriver", "shellcheck", "actionlint"];
const targets = wanted.length ? wanted : ALL;

const OS = { win32: "windows", darwin: "darwin", linux: "linux" }[process.platform];
const ARCH = { x64: "amd64", arm64: "arm64" }[process.arch];
if (!OS || !ARCH) {
  console.error(`unsupported platform ${process.platform}/${process.arch}`);
  process.exit(1);
}

// ---- helpers ---------------------------------------------------------------

async function getJSON(url) {
  const r = await fetch(url, { headers: { ...UA, accept: "application/json" } });
  if (!r.ok) throw new Error(`GET ${url} → HTTP ${r.status}`);
  return r.json();
}

async function getText(url) {
  const r = await fetch(url, { headers: UA });
  if (!r.ok) throw new Error(`GET ${url} → HTTP ${r.status}`);
  return r.text();
}

async function download(url, expectedSha256, name) {
  mkdirSync(CACHE, { recursive: true });
  const dest = join(CACHE, name);
  if (existsSync(dest) && sha256(readFileSync(dest)) === expectedSha256) return dest;
  process.stdout.write(`  downloading ${name} … `);
  const r = await fetch(url, { headers: UA, redirect: "follow" });
  if (!r.ok) throw new Error(`GET ${url} → HTTP ${r.status}`);
  const buf = Buffer.from(await r.arrayBuffer());
  const got = sha256(buf);
  if (got !== expectedSha256) {
    throw new Error(`checksum mismatch for ${name}: expected ${expectedSha256}, got ${got}`);
  }
  writeFileSync(dest, buf);
  console.log(`ok (${(buf.length / 1048576).toFixed(1)} MiB, sha256 verified)`);
  return dest;
}

function sha256(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

// Windows ships bsdtar (handles .zip and .tar.gz); Git-Bash's GNU tar can't do
// zip, so call the system one explicitly there.
function extract(archive, into) {
  mkdirSync(into, { recursive: true });
  const tar = process.platform === "win32"
    ? join(process.env.SystemRoot || "C:\\Windows", "System32", "tar.exe")
    : "tar";
  let res;
  if (archive.endsWith(".zip") && process.platform !== "win32") {
    res = spawnSync("unzip", ["-q", "-o", archive, "-d", into], { stdio: "inherit" });
  } else {
    res = spawnSync(tar, ["-xf", archive, "-C", into], { stdio: "inherit" });
  }
  if (res.status !== 0) throw new Error(`failed to extract ${archive}`);
}

function findFile(dir, fileName) {
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) {
      const hit = findFile(p, fileName);
      if (hit) return hit;
    } else if (entry === fileName) {
      return p;
    }
  }
  return null;
}

function marker(dir) { return join(dir, ".openroute-tool.json"); }
function installedVersion(dir) {
  try { return JSON.parse(readFileSync(marker(dir), "utf8")).version; } catch { return null; }
}
function markInstalled(dir, info) {
  writeFileSync(marker(dir), JSON.stringify({ ...info, installedAt: new Date().toISOString() }, null, 2));
}

const exe = (n) => (process.platform === "win32" ? `${n}.exe` : n);

// ---- tools -----------------------------------------------------------------

async function setupGo() {
  const releases = await getJSON("https://go.dev/dl/?mode=json");
  const rel = releases.find((r) => r.stable);
  const kind = OS === "windows" ? ".zip" : ".tar.gz";
  const file = rel.files.find((f) => f.os === OS && f.arch === ARCH && f.kind === "archive" && f.filename.endsWith(kind));
  if (!file) throw new Error(`no Go archive for ${OS}/${ARCH}`);
  const dir = join(TOOLS, "go");
  if (!FORCE && installedVersion(dir) === rel.version) return report("go", rel.version, join(dir, "bin", exe("go")));
  const archive = await download(`https://go.dev/dl/${file.filename}`, file.sha256, file.filename);
  rmSync(dir, { recursive: true, force: true });
  extract(archive, TOOLS); // archive's top-level folder is "go/"
  markInstalled(dir, { version: rel.version, sha256: file.sha256 });
  report("go", rel.version, join(dir, "bin", exe("go")));
}

async function setupSingBox() {
  // sing-box publishes dozens of alpha/beta tags per minor, so the newest
  // 1.12.x stable can sit several pages deep — page until we have it.
  const releases = [];
  for (let page = 1; page <= 10; page++) {
    const batch = await getJSON(`https://api.github.com/repos/SagerNet/sing-box/releases?per_page=100&page=${page}`);
    releases.push(...batch);
    if (batch.length < 100 || releases.some((r) => /^v1\.12\.\d+$/.test(r.tag_name) && !r.prerelease)) break;
  }
  const stable = releases.filter((r) => !r.prerelease && !r.draft && /^v\d+\.\d+\.\d+$/.test(r.tag_name));
  const byVer = (a, b) => cmpVer(b.tag_name.slice(1), a.tag_name.slice(1));
  stable.sort(byVer);
  const latest = stable[0];
  const min = stable.find((r) => r.tag_name.startsWith("v1.12."));
  for (const rel of [min, latest].filter(Boolean)) {
    const ver = rel.tag_name.slice(1);
    const ext = OS === "windows" ? "zip" : "tar.gz";
    const name = `sing-box-${ver}-${OS}-${ARCH}.${ext}`;
    const asset = rel.assets.find((a) => a.name === name);
    if (!asset) throw new Error(`sing-box ${ver}: asset ${name} not found`);
    const digest = (asset.digest || "").replace(/^sha256:/, "");
    if (!/^[0-9a-f]{64}$/.test(digest)) throw new Error(`sing-box ${ver}: release has no sha256 digest to verify against`);
    const dir = join(TOOLS, `sing-box-${ver}`);
    if (!FORCE && installedVersion(dir) === ver) { report("sing-box", ver, findFile(dir, exe("sing-box"))); continue; }
    const archive = await download(asset.browser_download_url, digest, name);
    rmSync(dir, { recursive: true, force: true });
    extract(archive, dir);
    markInstalled(dir, { version: ver, sha256: digest });
    report("sing-box", ver, findFile(dir, exe("sing-box")));
  }
}

async function setupTor() {
  const info = await getJSON("https://aus1.torproject.org/torbrowser/update_3/release/downloads.json");
  const ver = info.version;
  const torOs = { windows: "windows", darwin: "macos", linux: "linux" }[OS];
  const torArch = { amd64: "x86_64", arm64: "aarch64" }[ARCH];
  const name = `tor-expert-bundle-${torOs}-${torArch}-${ver}.tar.gz`;
  const base = `https://dist.torproject.org/torbrowser/${ver}`;
  const sums = await getText(`${base}/sha256sums-signed-build.txt`);
  const line = sums.split(/\r?\n/).find((l) => l.trim().endsWith(name));
  if (!line) throw new Error(`tor ${ver}: ${name} not listed in sha256sums-signed-build.txt`);
  const digest = line.trim().split(/\s+/)[0].toLowerCase();
  const dir = join(TOOLS, "tor");
  if (!FORCE && installedVersion(dir) === ver) return report("tor", ver, findFile(dir, exe("tor")));
  const archive = await download(`${base}/${name}`, digest, name);
  rmSync(dir, { recursive: true, force: true });
  extract(archive, dir);
  markInstalled(dir, { version: ver, sha256: digest });
  report("tor", ver, findFile(dir, exe("tor")));
}

async function setupGeckodriver() {
  const rel = await getJSON("https://api.github.com/repos/mozilla/geckodriver/releases/latest");
  const suffix = {
    "windows/amd64": "win64.zip", "windows/arm64": "win-aarch64.zip",
    "darwin/amd64": "macos.tar.gz", "darwin/arm64": "macos-aarch64.tar.gz",
    "linux/amd64": "linux64.tar.gz", "linux/arm64": "linux-aarch64.tar.gz"
  }[`${OS}/${ARCH}`];
  const asset = rel.assets.find((a) => a.name.endsWith(suffix) && !a.name.endsWith(".asc"));
  if (!asset) throw new Error(`geckodriver: no asset for ${OS}/${ARCH}`);
  const digest = (asset.digest || "").replace(/^sha256:/, "");
  if (!/^[0-9a-f]{64}$/.test(digest)) throw new Error("geckodriver: release has no sha256 digest to verify against");
  const ver = rel.tag_name;
  const dir = join(TOOLS, "geckodriver");
  if (!FORCE && installedVersion(dir) === ver) return report("geckodriver", ver, findFile(dir, exe("geckodriver")));
  const archive = await download(asset.browser_download_url, digest, asset.name);
  rmSync(dir, { recursive: true, force: true });
  extract(archive, dir);
  markInstalled(dir, { version: ver, sha256: digest });
  report("geckodriver", ver, findFile(dir, exe("geckodriver")));
}

async function setupShellcheck() {
  const rel = await getJSON("https://api.github.com/repos/koalaman/shellcheck/releases/latest");
  const ver = rel.tag_name;
  const name = {
    "windows/amd64": `shellcheck-${ver}.zip`,
    "linux/amd64": `shellcheck-${ver}.linux.x86_64.tar.gz`, "linux/arm64": `shellcheck-${ver}.linux.aarch64.tar.gz`,
    "darwin/amd64": `shellcheck-${ver}.darwin.x86_64.tar.gz`, "darwin/arm64": `shellcheck-${ver}.darwin.aarch64.tar.gz`
  }[`${OS}/${ARCH}`];
  const asset = rel.assets.find((a) => a.name === name);
  if (!asset) throw new Error(`shellcheck: no asset for ${OS}/${ARCH}`);
  const digest = (asset.digest || "").replace(/^sha256:/, "");
  if (!/^[0-9a-f]{64}$/.test(digest)) throw new Error("shellcheck: release has no sha256 digest to verify against");
  const dir = join(TOOLS, "shellcheck");
  if (!FORCE && installedVersion(dir) === ver) return report("shellcheck", ver, findFile(dir, exe("shellcheck")));
  const archive = await download(asset.browser_download_url, digest, asset.name);
  rmSync(dir, { recursive: true, force: true });
  extract(archive, dir);
  markInstalled(dir, { version: ver, sha256: digest });
  report("shellcheck", ver, findFile(dir, exe("shellcheck")));
}

async function setupActionlint() {
  const rel = await getJSON("https://api.github.com/repos/rhysd/actionlint/releases/latest");
  const ver = rel.tag_name.replace(/^v/, "");
  const name = `actionlint_${ver}_${OS}_${ARCH}${OS === "windows" ? ".zip" : ".tar.gz"}`;
  const asset = rel.assets.find((a) => a.name === name);
  if (!asset) throw new Error(`actionlint: no asset ${name}`);
  const digest = (asset.digest || "").replace(/^sha256:/, "");
  if (!/^[0-9a-f]{64}$/.test(digest)) throw new Error("actionlint: release has no sha256 digest to verify against");
  const dir = join(TOOLS, "actionlint");
  if (!FORCE && installedVersion(dir) === ver) return report("actionlint", ver, findFile(dir, exe("actionlint")));
  const archive = await download(asset.browser_download_url, digest, asset.name);
  rmSync(dir, { recursive: true, force: true });
  extract(archive, dir);
  markInstalled(dir, { version: ver, sha256: digest });
  report("actionlint", ver, findFile(dir, exe("actionlint")));
}

function cmpVer(a, b) {
  const pa = a.split(".").map(Number), pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
  return 0;
}

function report(tool, version, path) {
  console.log(`✓ ${tool} ${version}${path ? `  →  ${path}` : ""}`);
}

// ---- main ------------------------------------------------------------------

const RUNNERS = { go: setupGo, "sing-box": setupSingBox, tor: setupTor, geckodriver: setupGeckodriver, shellcheck: setupShellcheck, actionlint: setupActionlint };
mkdirSync(TOOLS, { recursive: true });
let failed = 0;
for (const t of targets) {
  const run = RUNNERS[t];
  if (!run) { console.error(`unknown tool "${t}" (choose from ${ALL.join(", ")})`); failed++; continue; }
  try {
    console.log(`→ ${t}`);
    await run();
  } catch (e) {
    failed++;
    console.error(`✗ ${t}: ${e.message}`);
  }
}
process.exit(failed ? 1 : 0);
