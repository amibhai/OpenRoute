// Live: the SagerNet key embedded in server/install-server.sh is the one
// that actually signs SagerNet's apt and rpm repositories today. If SagerNet
// rotates its key, this fails before a user's install does.
//
//   npm run test:live

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { findBash, SCRIPT } from "../server/harness.mjs";

const FPR = "2C317FBD5D886B4E89BAE8DA6D9152172A2B2F0C";
const bash = findBash();
const hasGpg = bash && spawnSync(bash, ["-c", "command -v gpg"]).status === 0;
const slash = (p) => p.replace(/\\/g, "/");

async function fetchTo(url, path) {
  const r = await fetch(url, { headers: { "user-agent": "openroute-tests" } });
  assert.equal(r.status, 200, `${url} → HTTP ${r.status}`);
  writeFileSync(path, Buffer.from(await r.arrayBuffer()));
}

// Imports the script's embedded key into a scratch keyring and verifies a
// signature over files in dir; returns the fingerprint gpg reports for the
// signing key. (Git Bash's gpg is an MSYS program: it needs /c/… paths.)
function signer(dir, ...files) {
  const r = spawnSync(bash, ["-c", `set -e
    G=$1; shift
    if command -v cygpath >/dev/null 2>&1; then G=$(cygpath -u "$G"); fi
    mkdir -p "$G/gnupg"
    chmod 700 "$G/gnupg" 2>/dev/null || true # Windows temp dirs refuse; gpg only warns
    args=(); for f; do args+=("$G/$f"); done
    source <(sed -n '/^sagernet_key() {/,/^}/p' "$SCRIPT_PATH")
    sagernet_key >"$G/key.asc"
    gpg --homedir "$G/gnupg" --batch --quiet --import "$G/key.asc" 2>/dev/null
    gpg --homedir "$G/gnupg" --batch --status-fd 1 --verify "\${args[@]}" 2>/dev/null | awk '$2 == "VALIDSIG" { print $3 }'`,
  "verify", slash(dir), ...files], { encoding: "utf8", env: { ...process.env, SCRIPT_PATH: slash(SCRIPT) } });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout.trim();
}

test("deb.sagernet.org's InRelease is signed by the embedded key", { skip: !hasGpg && "needs bash and gpg" }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "sagernet-"));
  try {
    // apt asks for dists/*/InRelease, a literal "*" (the repo is on Gemfury).
    await fetchTo("https://deb.sagernet.org/dists/*/InRelease", join(dir, "InRelease"));
    assert.equal(signer(dir, "InRelease"), FPR);
    // Negative control: one changed byte and nothing verifies.
    const text = readFileSync(join(dir, "InRelease"), "utf8");
    const tampered = text.replace(/^Date: (.)/m, (_, c) => `Date: ${c === "X" ? "Y" : "X"}`);
    assert.notEqual(tampered, text);
    writeFileSync(join(dir, "Tampered"), tampered);
    assert.equal(signer(dir, "Tampered"), "");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("rpm.sagernet.org's repomd.xml is signed by the embedded key", { skip: !hasGpg && "needs bash and gpg" }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "sagernet-"));
  try {
    await fetchTo("https://rpm.sagernet.org/repodata/repomd.xml", join(dir, "repomd.xml"));
    await fetchTo("https://rpm.sagernet.org/repodata/repomd.xml.asc", join(dir, "repomd.xml.asc"));
    assert.equal(signer(dir, "repomd.xml.asc", "repomd.xml"), FPR);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
