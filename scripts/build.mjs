#!/usr/bin/env node
// Builds per-browser packages from the single source tree (zero dependencies).
//
//   node scripts/build.mjs                    # every target
//   node scripts/build.mjs chromium firefox   # a subset
//   node scripts/build.mjs --no-zip           # unpacked folders only
//
// Output (dist/ is gitignored):
//   dist/<target>/                         unpacked, ready for "Load unpacked" /
//                                          Firefox "Load Temporary Add-on"
//   dist/openroute-<target>-<version>.zip  deterministic, store-ready archive
//   dist/SHA256SUMS                        checksums of every zip
//
// Targets:
//   chromium        Chrome, Edge, Brave, Opera, Vivaldi, Arc, Yandex — keeps the
//                   manifest "key", so the unpacked extension ID is stable
//                   (the companion pre-authorizes it).
//   chromium-store  same, without "key" — for Chrome Web Store / Edge Add-ons /
//                   Opera add-ons uploads (the store assigns the ID).
//   firefox         Firefox desktop + Android (AMO): event-page background,
//                   gecko id, built-in data-collection consent, dns API.
//   test            chromium + localhost permissions for hermetic e2e (no zip).

import { createHash } from "node:crypto";
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { createZip, listZip } from "./lib/zip.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DIST = join(ROOT, "dist");
const SHIP = ["src", "icons", "LICENSE"];
export const GECKO_ID = "openroute@openroute.app";

const base = JSON.parse(readFileSync(join(ROOT, "manifest.json"), "utf8"));

const clone = (o) => structuredClone(o);

export const TARGETS = {
  chromium: { zip: true, manifest: (m) => m },
  "chromium-store": {
    zip: true,
    manifest: (m) => { delete m.key; return m; }
  },
  firefox: {
    zip: true,
    manifest: (m) => {
      delete m.key;
      delete m.minimum_chrome_version;
      m.background = { scripts: [m.background.service_worker], type: "module" };
      // proxy.onRequest only sees requests to hosts we have permission for.
      m.host_permissions = ["<all_urls>"];
      // Firefox authenticates proxies through onRequest descriptors instead.
      m.permissions = [...new Set([...m.permissions.filter((p) => p !== "webRequestAuthProvider"), "dns"])];
      if (m.optional_host_permissions) delete m.optional_host_permissions;
      m.browser_specific_settings = {
        gecko: {
          id: GECKO_ID,
          strict_min_version: "140.0",
          // Diagnosing a block sends the failing site's domain to an encrypted
          // DNS resolver; that's optional, the rest works without it.
          data_collection_permissions: { required: ["none"], optional: ["browsingActivity"] }
        },
        gecko_android: { strict_min_version: "142.0" }
      };
      return m;
    }
  },
  test: {
    zip: false,
    manifest: (m) => {
      m.host_permissions = [...new Set([...(m.host_permissions || []), "http://127.0.0.1/*", "http://localhost/*", "https://127.0.0.1/*"])];
      m.name = `${m.name} (test build)`;
      return m;
    }
  }
};

function walk(dir) {
  const out = [];
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

// Every file the manifest or an HTML page references must exist.
function verify(stage, manifest) {
  const refs = new Set();
  const add = (p) => p && refs.add(String(p).replace(/^\//, ""));
  add(manifest.background?.service_worker);
  (manifest.background?.scripts || []).forEach(add);
  add(manifest.action?.default_popup);
  add(manifest.options_ui?.page);
  add(manifest.options_page);
  Object.values(manifest.icons || {}).forEach(add);
  Object.values(manifest.action?.default_icon || {}).forEach(add);
  for (const f of walk(stage).filter((f) => f.endsWith(".html"))) {
    const html = readFileSync(f, "utf8");
    for (const m of html.matchAll(/\b(?:src|href)="([^"#?:]+)"/g)) {
      add(relative(stage, join(dirname(f), m[1])).split(sep).join("/"));
    }
  }
  for (const f of walk(stage).filter((f) => f.endsWith(".js"))) {
    const js = readFileSync(f, "utf8");
    for (const m of js.matchAll(/\bfrom\s+["'](\.{1,2}\/[^"']+)["']/g)) {
      add(relative(stage, join(dirname(f), m[1])).split(sep).join("/"));
    }
  }
  const missing = [...refs].filter((r) => !existsSync(join(stage, r)));
  if (missing.length) throw new Error(`missing files referenced by the extension:\n  ${missing.join("\n  ")}`);
  return refs.size;
}

export function build(target, { zip = true } = {}) {
  const spec = TARGETS[target];
  if (!spec) throw new Error(`unknown target "${target}" (choose: ${Object.keys(TARGETS).join(", ")})`);
  const manifest = spec.manifest(clone(base));
  const stage = join(DIST, target);
  rmSync(stage, { recursive: true, force: true });
  mkdirSync(stage, { recursive: true });
  for (const item of SHIP) cpSync(join(ROOT, item), join(stage, item), { recursive: true, filter: (src) => !/make-icons\.mjs$/.test(src) });
  writeFileSync(join(stage, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
  const refs = verify(stage, manifest);

  let zipPath = null;
  if (zip && spec.zip) {
    const entries = walk(stage).map((f) => ({ name: relative(stage, f).split(sep).join("/"), data: readFileSync(f) }));
    const buf = createZip(entries);
    zipPath = join(DIST, `openroute-${target}-${manifest.version}.zip`);
    writeFileSync(zipPath, buf);
    const names = listZip(buf);
    if (!names.includes("manifest.json")) throw new Error("zip is missing manifest.json");
  }
  return { target, stage, zipPath, refs, version: manifest.version };
}

function sha256File(p) {
  return createHash("sha256").update(readFileSync(p)).digest("hex");
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);
  const noZip = args.includes("--no-zip");
  const names = args.filter((a) => !a.startsWith("--"));
  const targets = names.length ? names : Object.keys(TARGETS);
  mkdirSync(DIST, { recursive: true });
  console.log(`Building OpenRoute ${base.version}`);
  const results = [];
  for (const t of targets) {
    const r = build(t, { zip: !noZip });
    results.push(r);
    const size = r.zipPath ? ` · ${(statSync(r.zipPath).size / 1024).toFixed(1)} KB` : "";
    console.log(`  ✓ ${t.padEnd(15)} dist/${t}/ (${r.refs} references verified)${r.zipPath ? ` → ${relative(ROOT, r.zipPath).split(sep).join("/")}` : ""}${size}`);
  }
  const zips = results.filter((r) => r.zipPath);
  if (zips.length) {
    const sums = readdirSync(DIST).filter((f) => f.endsWith(".zip") && f.includes(`-${base.version}.`))
      .sort().map((f) => `${sha256File(join(DIST, f))}  ${f}`).join("\n") + "\n";
    writeFileSync(join(DIST, "SHA256SUMS"), sums);
    console.log("  ✓ dist/SHA256SUMS");
  }
}
