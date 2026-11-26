// Runs server/install-server.sh for real against a scratch root
// ($OPENROUTE_ROOT) with the stand-ins in ./fakes ahead of everything on
// PATH, so systemctl, ufw, useradd, apt-get & co. are simulated while
// sing-box, openssl and coreutils are the real ones.

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..");
export const SCRIPT = join(REPO, "server", "install-server.sh");
const slash = (p) => p.replace(/\\/g, "/");

export function findBash() {
  if (process.platform === "win32") {
    // Git for Windows' bash; System32\bash.exe would be WSL, another OS.
    for (const base of [process.env.ProgramFiles, process.env.ProgramW6432, "C:\\Program Files"]) {
      if (base && existsSync(join(base, "Git", "bin", "bash.exe"))) return join(base, "Git", "bin", "bash.exe");
    }
    return null;
  }
  const r = spawnSync("bash", ["-c", "command -v bash"], { encoding: "utf8" });
  return r.status === 0 ? r.stdout.trim() : null;
}

function findFile(dir, name) {
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) {
      const hit = findFile(p, name);
      if (hit) return hit;
    } else if (entry === name) {
      return p;
    }
  }
  return null;
}

// The project-local sing-box from scripts/setup-tools.mjs.
export function findSingBox(minor = "1.14") {
  const tools = join(REPO, ".tools");
  if (!existsSync(tools)) return null;
  const exe = process.platform === "win32" ? "sing-box.exe" : "sing-box";
  for (const d of readdirSync(tools).filter((n) => n.startsWith(`sing-box-${minor}.`)).sort().reverse()) {
    const hit = findFile(join(tools, d), exe);
    if (hit) return slash(hit);
  }
  return null;
}

// The candidates "--sni auto" tries, as the script lists them.
export function sniCandidates() {
  return readFileSync(SCRIPT, "utf8").match(/^readonly SNI_CANDIDATES="([^"]+)"/m)[1].split(" ");
}

// V4 OpenPGP fingerprint of an armored public key: SHA-1 over 0x99, the
// two-byte length and the body of its first (primary key) packet.
export function openpgpFingerprint(armored) {
  const b64 = armored.replace(/\r/g, "").split("\n")
    .filter((l) => l && !l.startsWith("-----") && !l.startsWith("=") && !/^[A-Za-z-]+: /.test(l))
    .join("");
  const buf = Buffer.from(b64, "base64");
  let len, off;
  if (buf[0] & 0x40) { // new packet format
    const l0 = buf[1];
    if (l0 < 192) [len, off] = [l0, 2];
    else if (l0 < 224) [len, off] = [((l0 - 192) << 8) + buf[2] + 192, 3];
    else [len, off] = [buf.readUInt32BE(2), 6];
  } else { // old format: the low two bits give the length's size
    [len, off] = [[buf[1], buf.readUInt16BE(1), buf.readUInt32BE(1)][buf[0] & 3], [2, 3, 5][buf[0] & 3]];
  }
  return createHash("sha1").update(Buffer.from([0x99, len >> 8, len & 0xff])).update(buf.subarray(off, off + len)).digest("hex").toUpperCase();
}

// Prepends the stand-ins to PATH inside bash (Git Bash puts its own dirs
// first otherwise) and remembers the real openssl for the fake to defer to.
const BOOT = [
  'export REAL_OPENSSL="$(command -v openssl)"',
  "FAKE_BIN_POSIX=$FAKE_BIN",
  'if command -v cygpath >/dev/null 2>&1; then FAKE_BIN_POSIX=$(cygpath -u "$FAKE_BIN"); fi',
  'export FAKE_BIN_POSIX PATH="$FAKE_BIN_POSIX:$PATH"',
  'exec bash "$0" "$@"'
].join("\n");

export function fakeSystem({ bash, singBox = "", ufw = false, firewalld = false, iptablesReject = false } = {}) {
  const base = mkdtempSync(join(tmpdir(), "openroute-server-"));
  const root = join(base, "root"), fake = join(base, "fake"), bin = join(base, "bin");
  // run/systemd/system marks a systemd host; /proc says BBR and IPv6 exist.
  for (const d of [fake, bin, ...["run/systemd/system", "proc/sys/net/ipv4", "proc/net", "etc"].map((d) => join(root, d))]) {
    mkdirSync(d, { recursive: true });
  }
  writeFileSync(join(root, "proc/sys/net/ipv4/tcp_available_congestion_control"), "reno cubic bbr\n");
  writeFileSync(join(root, "proc/net/if_inet6"), "00000000000000000000000000000001 01 80 10 80       lo\n");
  writeFileSync(join(root, "etc/os-release"), 'PRETTY_NAME="Debian GNU/Linux 12 (test double)"\n');
  for (const f of readdirSync(join(HERE, "fakes"))) {
    if (f === "README.md") continue;
    copyFileSync(join(HERE, "fakes", f), join(bin, f));
  }
  copyFileSync(join(bin, "iptables"), join(bin, "ip6tables"));
  copyFileSync(join(bin, "iptables-save"), join(bin, "ip6tables-save"));
  for (const f of readdirSync(bin)) chmodSync(join(bin, f), 0o755);
  if (ufw) writeFileSync(join(fake, "ufw-active"), "");
  if (firewalld) writeFileSync(join(fake, "firewalld-active"), "");
  if (iptablesReject) writeFileSync(join(fake, "iptables-reject"), "");

  const env = {
    OPENROUTE_ROOT: slash(root), FAKE_DIR: slash(fake), FAKE_BIN: bin, REAL_SINGBOX: singBox,
    // v0.3's environment variables must not leak in from the test runner.
    REALITY_SNI: "", SERVER_IP: "", VLESS_PORT: "", SS_PORT: ""
  };
  const fakeLines = (name) => (existsSync(join(fake, name)) ? readFileSync(join(fake, name), "utf8").split("\n").filter(Boolean) : []);

  return {
    root,
    run(args, extra = {}) {
      const r = spawnSync(bash, ["-c", BOOT, slash(SCRIPT), ...args], {
        env: { ...process.env, ...env, ...extra }, encoding: "utf8", timeout: 180_000
      });
      return { code: r.status, out: r.stdout, err: r.stderr, all: `${r.stdout}\n${r.stderr}${r.error ? `\n${r.error}` : ""}` };
    },
    state() {
      const p = join(root, "etc/openroute-server/state.env");
      if (!existsSync(p)) return null;
      const s = {};
      for (const line of readFileSync(p, "utf8").split("\n")) {
        const m = line.match(/^([A-Z0-9_]+)='(.*)'$/);
        if (m) s[m[1]] = m[2];
      }
      return s;
    },
    links: () => readFileSync(join(root, "etc/openroute-server/links.txt"), "utf8").split("\n").filter(Boolean),
    read: (rel) => readFileSync(join(root, rel), "utf8"),
    write: (rel, text) => { mkdirSync(dirname(join(root, rel)), { recursive: true }); writeFileSync(join(root, rel), text); },
    exists: (rel) => existsSync(join(root, rel)),
    log: () => fakeLines("log"),
    fakeLines,
    fakeExists: (name) => existsSync(join(fake, name)),
    setFake: (name, text = "") => writeFileSync(join(fake, name), text),
    clearFake: (name) => rmSync(join(fake, name), { force: true }),
    ufwRules: () => fakeLines("ufw-rules").map((l) => l.split(" ")[0]),
    cleanup: () => rmSync(base, { recursive: true, force: true })
  };
}
