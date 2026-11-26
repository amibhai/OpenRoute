// install-server.sh's install / re-install / rotate / doctor / uninstall
// flows, run for real against a scratch root with stand-ins for the system
// tools (see ./fakes). Every config it writes is checked by real sing-box,
// and every pin is recomputed here from the certificate itself.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { fakeSystem, findBash, findSingBox, openpgpFingerprint, sniCandidates } from "./harness.mjs";

const bash = findBash();
const singBox = findSingBox("1.14");
const skip = !bash ? "needs bash" : !singBox ? "needs sing-box in .tools (npm run setup-tools -- sing-box)" : false;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const BASE = ["--host", "203.0.113.7", "--sni", "www.example.com", "--no-qr"];
const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");

function withSystem(opts, fn) {
  const sys = fakeSystem({ bash, singBox, ...opts });
  try {
    return fn(sys);
  } finally {
    sys.cleanup();
  }
}
function ok(r) {
  assert.equal(r.code, 0, `expected success, got exit ${r.code}\n${r.all}`);
  return r;
}
function fails(r, re) {
  assert.notEqual(r.code, 0, `expected a failure\n${r.all}`);
  assert.match(r.all, re);
  return r;
}

test("install, re-run, add Hysteria2, rotate, move ports, doctor, uninstall", { skip }, () => withSystem({ ufw: true }, (sys) => {
  // A fresh install.
  let r = ok(sys.run(["install", ...BASE, "--sing-box", singBox]));
  const s1 = sys.state();
  assert.match(s1.UUID, UUID);
  assert.equal(s1.VLESS_PORT, "443");
  assert.equal(s1.HY2, "0");
  assert.equal(s1.SB_SOURCE, "existing");
  assert.equal(s1.SB_PATH, singBox);
  assert.equal(s1.FW_KIND, "ufw");
  const ss = s1.SS_PORT;
  assert.ok(+ss >= 20000 && +ss < 40000, ss);
  assert.deepEqual(sys.ufwRules(), ["443/tcp", `${ss}/tcp`, `${ss}/udp`]);

  const links1 = sys.links();
  assert.equal(links1.length, 2);
  assert.match(links1[0], /^vless:\/\/[0-9a-f-]{36}@203\.0\.113\.7:443\?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www\.example\.com&fp=chrome&pbk=[\w-]{43}&sid=[0-9a-f]{16}&type=tcp#OpenRoute%20Reality$/);
  const ssLink = links1[1].match(/^ss:\/\/2022-blake3-aes-128-gcm:([^@]+)@203\.0\.113\.7:(\d+)#OpenRoute%20SS-2022$/);
  assert.ok(ssLink, links1[1]);
  assert.equal(decodeURIComponent(ssLink[1]), s1.SS_PSK, "SIP002: the 2022 key is percent-encoded, not base64-wrapped");
  for (const l of links1) assert.ok(r.out.includes(l), "the links are printed");

  const unit = sys.read("etc/systemd/system/openroute-server.service");
  assert.match(unit, /^User=openroute$/m);
  assert.match(unit, /^ExecStartPre=.* check -c \/etc\/openroute-server\/config\.json$/m);
  assert.match(unit, /^ExecStart=.* run -D \/var\/lib\/openroute-server -c \/etc\/openroute-server\/config\.json$/m);
  assert.match(unit, /^CapabilityBoundingSet=CAP_NET_BIND_SERVICE$/m);
  assert.match(unit, /^NoNewPrivileges=yes$/m);
  assert.match(sys.read("etc/sysctl.d/90-openroute-server.conf"), /^net\.ipv4\.tcp_congestion_control = bbr$/m);
  const log = sys.log();
  assert.ok(log.includes("systemctl restart openroute-server"));
  assert.ok(log.some((l) => /^useradd .*openroute$/.test(l)), "runs as its own system user");
  assert.ok(!log.some((l) => l.startsWith("curl ")), "no network when --host is given");
  assert.ok(!log.some((l) => l.startsWith("apt-get ")), "an existing sing-box is used as is");

  // Running it again changes nothing a client depends on.
  ok(sys.run(["install", "--no-qr"]));
  assert.deepEqual(sys.links(), links1);

  // Adding Hysteria2 leaves the existing links alone.
  ok(sys.run(["install", "--hysteria2", "--no-qr"]));
  const s3 = sys.state();
  const links3 = sys.links();
  assert.equal(links3.length, 3);
  assert.equal(links3[0], links1[0]);
  assert.equal(links3[2], links1[1]);
  assert.match(links3[1], new RegExp(`^hysteria2://[0-9a-f]{32}@203\\.0\\.113\\.7:${s3.HY2_PORT}/\\?sni=www\\.example\\.com&obfs=salamander&obfs-password=[0-9a-f]{32}&pinSHA256=${s3.HY2_CERT_SHA256}&pinPublicKeySHA256=${s3.HY2_PIN}#OpenRoute%20Hysteria2$`));
  // The pins are what a client will compute from the certificate it's shown.
  const cert = new X509Certificate(sys.read("etc/openroute-server/hysteria2.crt"));
  assert.equal(sha256(cert.publicKey.export({ type: "spki", format: "der" })), s3.HY2_PIN);
  assert.equal(sha256(cert.raw), s3.HY2_CERT_SHA256);
  assert.ok(cert.checkHost("www.example.com"), "the certificate is for the name the link sends");
  assert.ok(sys.ufwRules().includes(`${s3.HY2_PORT}/udp`));

  // Rotating changes every secret and nothing else.
  r = ok(sys.run(["rotate", "--no-qr"]));
  const s4 = sys.state();
  for (const k of ["UUID", "SS_PSK", "SHORT_ID", "REALITY_PRIVATE", "REALITY_PUBLIC", "HY2_PASSWORD", "HY2_OBFS", "HY2_PIN"]) {
    assert.notEqual(s4[k], s3[k], `${k} should change`);
  }
  for (const k of ["VLESS_PORT", "SS_PORT", "HY2_PORT", "REALITY_SNI", "HOST"]) assert.equal(s4[k], s3[k], `${k} should stay`);
  assert.match(r.out, /old links no longer work/);

  // --new-ports moves the Shadowsocks and Hysteria2 ports; the firewall follows.
  ok(sys.run(["rotate", "--new-ports", "--no-qr"]));
  const s5 = sys.state();
  assert.notEqual(s5.SS_PORT, s4.SS_PORT);
  assert.notEqual(s5.HY2_PORT, s4.HY2_PORT);
  assert.deepEqual(sys.ufwRules().sort(), ["443/tcp", `${s5.SS_PORT}/tcp`, `${s5.SS_PORT}/udp`, `${s5.HY2_PORT}/udp`].sort());

  r = ok(sys.run(["doctor"]));
  assert.match(r.out, /no problems found/);

  // Uninstalling leaves nothing behind.
  ok(sys.run(["uninstall", "--yes"]));
  for (const p of ["etc/openroute-server", "etc/systemd/system/openroute-server.service", "etc/sysctl.d/90-openroute-server.conf"]) {
    assert.ok(!sys.exists(p), `${p} should be gone`);
  }
  assert.deepEqual(sys.ufwRules(), []);
  assert.ok(!sys.fakeExists("user-openroute"));
  assert.ok(!sys.fakeExists("active-openroute-server"));
}));

test("upgrades a v0.3 server in place, keeping its credentials so existing links keep working", { skip }, () => withSystem({}, (sys) => {
  const gen = (...a) => spawnSync(singBox, ["generate", ...a], { encoding: "utf8" }).stdout.trim();
  const uuid = gen("uuid"), psk = gen("rand", "16", "--base64"), sid = gen("rand", "8", "--hex");
  const kp = gen("reality-keypair");
  const priv = kp.match(/PrivateKey: (\S+)/)[1], pub = kp.match(/PublicKey: (\S+)/)[1];
  // Exactly what v0.3's installer wrote.
  sys.write("etc/sing-box/openroute.env", `UUID="${uuid}"\nSS_PSK="${psk}"\nSS_PORT="31337"\nVLESS_PORT="443"\nREALITY_SNI="www.microsoft.com"\nREALITY_PUBLIC="${pub}"\nSHORT_ID="${sid}"\nSERVER_IP="203.0.113.9"\n`);
  sys.write("etc/sing-box/config.json", `{
  "log": { "level": "warn", "timestamp": true },
  "inbounds": [
    { "type": "vless", "tag": "vless-in", "listen": "::", "listen_port": 443,
      "users": [ { "uuid": "${uuid}", "flow": "xtls-rprx-vision" } ],
      "tls": { "enabled": true, "server_name": "www.microsoft.com",
        "reality": { "enabled": true, "handshake": { "server": "www.microsoft.com", "server_port": 443 },
          "private_key": "${priv}", "short_id": [ "${sid}" ] } } },
    { "type": "shadowsocks", "tag": "ss-in", "listen": "::", "listen_port": 31337,
      "method": "2022-blake3-aes-128-gcm", "password": "${psk}" }
  ],
  "outbounds": [ { "type": "direct", "tag": "direct" }, { "type": "block", "tag": "block" } ],
  "route": { "rules": [ { "ip_is_private": true, "outbound": "block" } ], "final": "direct" }
}
`);
  sys.setFake("active-sing-box"); // v0.3 ran the package's own service

  const r = ok(sys.run(["install", "--sing-box", singBox, "--no-qr"]));
  const s = sys.state();
  assert.deepEqual(
    [s.UUID, s.SS_PSK, s.SS_PORT, s.VLESS_PORT, s.REALITY_SNI, s.REALITY_PRIVATE, s.REALITY_PUBLIC, s.SHORT_ID, s.HOST],
    [uuid, psk, "31337", "443", "www.microsoft.com", priv, pub, sid, "203.0.113.9"]
  );
  assert.match(r.out, /links you already use keep working/);
  assert.ok(sys.log().includes("systemctl disable --now sing-box"), "the old service is retired");
  assert.ok(!sys.exists("etc/sing-box/openroute.env") && sys.exists("etc/sing-box/openroute.env.migrated"));
  assert.ok(sys.exists("etc/sing-box/config.json.openroute-v0.3.bak"));
  assert.ok(sys.links()[0].startsWith(`vless://${uuid}@203.0.113.9:443?`) && sys.links()[0].includes(`pbk=${pub}&sid=${sid}`));
}));

test("iptables (Oracle Cloud style) and firewalld: opens our ports, then closes exactly those", { skip }, () => {
  withSystem({ iptablesReject: true }, (sys) => {
    sys.setFake("iptables-rules", "-p tcp --dport 22 -j ACCEPT\n"); // the user's own rule
    ok(sys.run(["install", ...BASE, "--sing-box", singBox]));
    const ss = sys.state().SS_PORT;
    assert.equal(sys.state().FW_KIND, "iptables");
    const ours = [["tcp", 443], ["tcp", ss], ["udp", ss]].map(([p, n]) => `-p ${p} --dport ${n} -m comment --comment openroute-server -j ACCEPT`);
    assert.deepEqual(sys.fakeLines("iptables-rules").sort(), ["-p tcp --dport 22 -j ACCEPT", ...ours].sort());
    assert.deepEqual(sys.fakeLines("ip6tables-rules").sort(), ours.sort());
    assert.ok(sys.fakeExists("netfilter-saved"), "the rules survive a reboot");
    ok(sys.run(["uninstall", "--yes"]));
    assert.deepEqual(sys.fakeLines("iptables-rules"), ["-p tcp --dport 22 -j ACCEPT"], "only our rules are removed");
    assert.deepEqual(sys.fakeLines("ip6tables-rules"), []);
  });
  withSystem({ firewalld: true }, (sys) => {
    ok(sys.run(["install", ...BASE, "--sing-box", singBox]));
    const ss = sys.state().SS_PORT;
    assert.deepEqual(sys.fakeLines("firewalld-ports").sort(), ["443/tcp", `${ss}/tcp`, `${ss}/udp`].sort());
    assert.ok(sys.log().includes("firewall-cmd --quiet --reload"));
    ok(sys.run(["uninstall", "--yes"]));
    assert.deepEqual(sys.fakeLines("firewalld-ports"), []);
  });
  withSystem({}, (sys) => {
    const r = ok(sys.run(["install", ...BASE, "--sing-box", singBox]));
    assert.match(r.out, /no active host firewall/);
    assert.equal(sys.state().FW_KIND, "");
  });
});

test("a port someone else holds is refused, naming who holds it", { skip }, () => withSystem({}, (sys) => {
  sys.setFake("busy", "tcp 443 nginx\n");
  fails(sys.run(["install", ...BASE, "--sing-box", singBox]), /port 443 is already in use by users:\(\("nginx"[\s\S]*--vless-port/);
  assert.equal(sys.state(), null, "nothing is written before the checks pass");
  ok(sys.run(["install", ...BASE, "--vless-port", "8443", "--sing-box", singBox]));
  assert.equal(sys.state().VLESS_PORT, "8443");
}));

test("--sni auto takes the fastest site that passes TLS 1.3 + HTTP/2; a failing pick is refused", { skip }, () => withSystem({}, (sys) => {
  for (const h of sniCandidates()) if (h !== "www.apple.com" && h !== "www.amazon.com") sys.setFake(`sni-fail-${h}`);
  sys.setFake("sni-delay-www.amazon.com", "0.8");
  ok(sys.run(["install", "--host", "203.0.113.7", "--sni", "auto", "--sing-box", singBox, "--no-qr"]));
  assert.equal(sys.state().REALITY_SNI, "www.apple.com");

  sys.setFake("sni-fail-bad.example");
  fails(sys.run(["install", "--sni", "bad.example", "--no-qr"]), /bad\.example doesn't offer TLS 1\.3/);
  assert.equal(sys.state().REALITY_SNI, "www.apple.com", "a refused change changes nothing");

  // The installed site failing later only warns: switching would break every link.
  sys.setFake("sni-fail-www.apple.com");
  const r = ok(sys.run(["install", "--no-qr"]));
  assert.match(r.err, /keeping it so your links stay valid/);
  assert.equal(sys.state().REALITY_SNI, "www.apple.com");
}));

test("finds its public IP, and follows it when it changes", { skip }, () => withSystem({}, (sys) => {
  ok(sys.run(["install", "--sni", "www.example.com", "--sing-box", singBox, "--no-qr"], { FAKE_CURL: "ip", FAKE_IP: "198.51.100.4" }));
  assert.equal(sys.state().HOST, "198.51.100.4");
  const r = ok(sys.run(["install", "--no-qr"], { FAKE_CURL: "ip", FAKE_IP: "198.51.100.77" }));
  assert.match(r.err, /public IP changed from 198\.51\.100\.4 to 198\.51\.100\.77/);
  assert.ok(sys.links()[0].includes("@198.51.100.77:443"));
  ok(sys.run(["install", "--no-qr"])); // offline now: keeps what it has
  assert.equal(sys.state().HOST, "198.51.100.77");
}));

test("installs sing-box from SagerNet's repository, trusting only the embedded key; --purge removes it all", { skip }, () => withSystem({}, (sys) => {
  ok(sys.run(["install", ...BASE])); // no sing-box anywhere yet
  assert.equal(sys.state().SB_SOURCE, "repo");
  const list = sys.read("etc/apt/sources.list.d/openroute-sagernet.sources");
  assert.match(list, /^URIs: https:\/\/deb\.sagernet\.org\/$/m);
  assert.match(list, /^Signed-By: \/etc\/apt\/keyrings\/openroute-sagernet\.asc$/m);
  assert.equal(openpgpFingerprint(sys.read("etc/apt/keyrings/openroute-sagernet.asc")), "2C317FBD5D886B4E89BAE8DA6D9152172A2B2F0C");
  assert.ok(sys.log().some((l) => /^apt-get install .*sing-box$/.test(l)));

  ok(sys.run(["uninstall", "--yes", "--purge"]));
  assert.ok(sys.log().some((l) => /^apt-get remove .*sing-box$/.test(l)));
  assert.ok(!sys.exists("etc/apt/sources.list.d/openroute-sagernet.sources"));
  assert.ok(!sys.exists("etc/apt/keyrings/openroute-sagernet.asc"));
}));

test("a repository set up from SagerNet's own instructions is reused, not duplicated", { skip }, () => withSystem({}, (sys) => {
  // apt refuses two entries for one repo with different Signed-By values.
  sys.write("etc/apt/sources.list.d/sagernet.sources", "Types: deb\nURIs: https://deb.sagernet.org/\nSuites: *\nComponents: *\nSigned-By: /etc/apt/keyrings/sagernet.asc\n");
  ok(sys.run(["install", ...BASE]));
  assert.ok(!sys.exists("etc/apt/sources.list.d/openroute-sagernet.sources"));
  assert.equal(sys.state().SB_SOURCE, "repo");
}));

test("a downloaded sing-box that doesn't match its pinned SHA-256 is never installed", { skip }, () => withSystem({}, (sys) => {
  fails(sys.run(["install", ...BASE, "--source", "release"], { FAKE_CURL: "junk" }), /doesn't match its pinned SHA-256/);
  assert.ok(!sys.exists("usr/local/bin/sing-box"));
}));

test("doctor names what's wrong", { skip }, () => withSystem({ ufw: true }, (sys) => {
  ok(sys.run(["install", ...BASE, "--sing-box", singBox]));
  const ss = sys.state().SS_PORT;
  sys.clearFake("active-openroute-server");
  sys.setFake("ufw-rules", "443/tcp openroute-server\n"); // someone deleted the Shadowsocks rules
  const r = sys.run(["doctor"], { FAKE_NTP: "no" });
  assert.equal(r.code, 1, r.all);
  assert.match(r.out, /openroute-server isn't running/);
  assert.match(r.out, new RegExp(`ufw doesn't allow ${ss}/tcp`));
  assert.match(r.out, /clock isn't NTP-synchronized/);
  assert.match(r.out, /\d problem\(s\) found/);
}));

test("if sing-box won't start, install says so and shows its log", { skip }, () => withSystem({}, (sys) => {
  sys.setFake("fail-start-openroute-server");
  const r = fails(sys.run(["install", ...BASE, "--sing-box", singBox]), /didn't come up/);
  assert.match(r.all, /fake journal/);
}));

test("rejects bad options before touching anything", { skip: !bash && "needs bash" }, () => withSystem({}, (sys) => {
  for (const [args, re] of [
    [["install", "--vless-port", "70000"], /must be a port number/],
    [["install", "--ss-port", "0443"], /must be a port number/],
    [["install", "--sni", "not a host"], /--sni must be a hostname/],
    [["install", "--host", "1.2.3.4;reboot"], /--host must be an IP address or a hostname/],
    // (Not a quote: MSYS's runtime eats quotes in a Windows command line.)
    [["install", "--name", "bad;name"], /--name/],
    [["install", "--source", "curl"], /--source must be/],
    [["install", "--reality-dest", "2001:db8::1:443"], /--reality-dest must be host:port/],
    [["install", "--bogus"], /unknown option/],
    [["generate", "--host", "1.2.3.4"], /generate needs --dir/]
  ]) fails(sys.run(args), re);
  assert.deepEqual(sys.log(), [], "nothing ran");
}));
