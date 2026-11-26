# OpenRoute server

One command turns a Linux VPS into a hardened [sing-box](https://sing-box.sagernet.org)
server and prints the share links you paste into OpenRoute. It's the strongest
rung of the ladder: a transport only you control.

```sh
curl -fsSLO https://raw.githubusercontent.com/amibhai/OpenRoute/main/server/install-server.sh
less install-server.sh          # it runs as root, so read it first; it's written to be read
sudo bash install-server.sh
```

You can also take `install-server.sh` from a [release](https://github.com/amibhai/OpenRoute/releases) and check
it against the release's `SHA256SUMS`.

Any systemd Linux works: Debian, Ubuntu, Fedora, RHEL / Alma / Rocky and others. Supported
architectures are amd64, arm64, armv7 and i386. A $5 box is plenty.

## What you get

| transport | port | why |
|---|---|---|
| **VLESS-Reality** | TCP 443 | Its handshake is a real TLS 1.3 handshake borrowed from a big site. To a censor's DPI, and to an active prober that connects itself, it looks like an ordinary visit to that site. No certificate to buy or leak. |
| **Shadowsocks-2022** | TCP+UDP, random 20000–39999 | Fast, simple, replay-protected AEAD on a second port, so one blocked port doesn't take you offline. |
| **Hysteria2** (`--hysteria2`) | UDP, random | QUIC with Salamander obfuscation. Much faster on lossy or long-distance links, and useful where TCP is throttled. |

Paste all the links into OpenRoute's popup (**Transports → Connect via companion**, one per line).
The companion runs them as a pool and fails over between them on its own.

## Commands

```sh
sudo bash install-server.sh               # install, or upgrade in place
sudo bash install-server.sh show          # print the links (and QR codes) again
sudo bash install-server.sh rotate        # new credentials; the old links stop working
sudo bash install-server.sh rotate --new-ports
sudo bash install-server.sh doctor        # check everything, explain what's wrong
sudo bash install-server.sh uninstall     # remove it (--purge: sing-box too)
```

Running `install` again is safe. It keeps every credential and port, so links already handed
out keep working. It also regenerates the config with whatever the current script knows, and
re-checks the firewall. Use it to upgrade, or to add or remove Hysteria2.

| option | default | |
|---|---|---|
| `--sni HOST\|auto` | `auto` | The site Reality impersonates. `auto` tests several big sites from the server and picks the fastest that passes the check below. |
| `--host ADDR` | detected public IP | The address put in the links. A domain name pointing at the server works too. |
| `--vless-port N` | 443 | Keep 443 so it looks like HTTPS. |
| `--ss-port N`, `--hy2-port N` | random | |
| `--hysteria2` / `--no-hysteria2` | off | |
| `--name NAME` | OpenRoute | The label client apps show. |
| `--source repo\|release\|existing` | `repo` on apt/dnf | Where sing-box comes from (see below). |
| `--no-firewall`, `--no-bbr`, `--no-qr` | | Skip those steps. |
| `--yes` | | Don't ask (uninstall). |

v0.3's environment variables (`REALITY_SNI`, `SERVER_IP`, `VLESS_PORT`, `SS_PORT`) still work.

## What it does to the machine

1. **Installs sing-box from a source it can verify.**
   - **`repo`:** SagerNet's apt or rpm repository, with its signing key embedded in the script (fingerprint
     `2C31 7FBD 5D88 6B4E 89BA E8DA 6D91 5217 2A2B 2F0C`). Packages must be signed by that key, and nothing is
     fetched to decide what to trust. If you already added SagerNet's repository yourself, the script reuses it.
   - **`release`:** the pinned sing-box 1.14.4 release. The download is checked against a SHA-256 built into
     the script; a mismatch means nothing gets installed.
   - **`existing`:** any sing-box 1.12 or newer already on the machine.
   - There's no `curl | sh` anywhere.
2. **Checks the Reality cover site.** It must offer TLS 1.3, HTTP/2 and X25519 with a valid certificate,
   tested from the server, because Reality needs all three. A site that fails is refused. If the site already
   installed stops passing, the script only warns, since changing it would change every link.
3. **Writes `/etc/openroute-server/`:**
   - `config.json`, validated by `sing-box check` before it's used;
   - the state file (root-only, mode 600);
   - the Hysteria2 certificate, if that's enabled.

   Every secret comes from `sing-box generate`, nothing is hard-coded, and logs stay at warning level, so
   destinations aren't recorded.
4. **Runs it as `openroute-server.service` under its own system user.**
   - The unit runs `sing-box check` before every start.
   - It's sandboxed: `ProtectSystem=strict`, `NoNewPrivileges`, a system-call filter, no capabilities except
     binding port 443, and so on.
   - It restarts on failure.
   - It uses its own unit and directory, because the sing-box package's own `/etc/sing-box/config.json` is a
     sample: an open proxy on port 8080 with a password published on GitHub. `doctor` warns if that sample is
     ever running.
5. **Opens exactly its ports**, and records them so it can close them again on uninstall or a port change:
   - **ufw**
   - **firewalld**
   - **iptables**, including Oracle Cloud's images, which ship with a REJECT rule that silently drops
     everything except SSH. The rules are saved so they survive a reboot.
   - **nftables:** it tells you what to allow rather than editing your ruleset.
6. **Turns on BBR** congestion control and bigger UDP buffers (for QUIC), in
   `/etc/sysctl.d/90-openroute-server.conf`, if the kernel has BBR.
7. **Turns on NTP.** Shadowsocks-2022 refuses clients whose clock is more than 30 seconds off.

**What clients can't reach through the server:**
- the server itself, its LAN, and cloud metadata services (`169.254.169.254`, `100.100.100.200`);
- any other private or reserved address;
- the same addresses reached **by name**. The server resolves names before it checks the address, so
  `localhost` or `metadata.google.internal` is refused too. v0.3 checked addresses only, so a name
  resolving to a private address got through.
- outbound port 25, so a leaked link can't be used to send spam, which gets VPS accounts closed.

## Hysteria2 in other apps

Hysteria2 runs on a self-signed certificate. That's why the link pins it, with two parameters:

- **`pinPublicKeySHA256`**: the SHA-256 of the certificate's public key. OpenRoute checks it instead of a CA
  (it needs sing-box 1.13 or newer; the companion says so if yours is older).
- **`pinSHA256`**: the standard Hysteria fingerprint of the whole certificate.

Apps that only understand `pinSHA256` usually also want `&insecure=1` added. Only do that in an app you know
checks `pinSHA256`: in an app that ignores the pin, `insecure=1` means no certificate check at all.

## Your provider's firewall

This is the most common reason a fresh server doesn't work, and the script can't see it from inside. AWS
security groups, Oracle Cloud security lists, GCP and Azure network rules all need to allow:
- TCP 443;
- TCP and UDP on the Shadowsocks port;
- UDP on the Hysteria2 port, if you enabled it.

`doctor` and `show` print the exact ports.

## Upgrading from v0.3

Run `sudo bash install-server.sh`. It finds the old `/etc/sing-box/openroute.env` and keeps its
credentials and ports, so your current links keep working. It then stops the old `sing-box`
service and moves the old files aside: `openroute.env.migrated` and
`config.json.openroute-v0.3.bak`.

## Troubleshooting

Start with `sudo bash install-server.sh doctor`. It checks each of these and says what to do:
- the sing-box version, and whether sing-box accepts the config;
- that the service is running and every port is listening;
- your firewall rules;
- that the cover site still passes its check;
- that the public IP still matches the links;
- clock sync;
- the vendor-sample hazard above.

## How it's tested

- **End to end, with real sing-box** (1.12 and 1.14, in `companion/server_e2e_test.go`).
  - **Positive phase:** the script's `generate` step writes a config, real sing-box serves it, and each printed
    link (VLESS-Reality, SS-2022, pinned Hysteria2) is parsed by the companion's own code. Traffic goes through
    each one.
  - **Negative phase:** the same tunnels must refuse a loopback target, both by address and by a name that
    resolves to one.
  - **Mutation check:** deleting the `resolve` rule, or the private-address rules, from the script makes the
    test fail.
- **Install flows** (`test/server/`, 12 tests).
  - **Lifecycles:** install, re-install, adding Hysteria2, rotate, port moves, doctor, uninstall, and the v0.3
    upgrade.
  - **Environments:** ufw, firewalld and iptables.
  - **Failure paths:** port conflicts, cover-site selection, IP changes, an unverifiable download, the package
    repository, and a service that won't start.
  - These run against stand-ins for systemctl, ufw, useradd and the rest (see `test/server/fakes/`); sing-box
    and openssl are real.
- **Live** (`npm run test:live`): the embedded key verifies today's signatures on SagerNet's apt and rpm
  repositories, and a tampered file fails.
- **shellcheck** at style level, over every shell script.

- **A real install, in CI.** On every change, a fresh Ubuntu runner with systemd goes through the full
  cycle:
  1. installs the pinned release;
  2. checks that the service runs sandboxed as its own user;
  3. runs `doctor`;
  4. pushes traffic through every printed link;
  5. confirms the server's loopback stays closed;
  6. re-installs, which must keep the links;
  7. rotates, which must change them;
  8. uninstalls, which must leave nothing behind.

**Not covered yet: other distributions on real systems.** Debian, Fedora and RHEL / Alma / Rocky run only
against the stand-ins. The systemd sandbox settings are standard, and a too-old systemd ignores the ones it
doesn't know rather than failing. Even so, if the service won't start on your distro, `doctor` and
`journalctl -u openroute-server` will say why. Please open an issue.

## Honest notes

- **This is circumvention, not anonymity.** A VPS is tied to your payment and identity. For anonymity, use Tor.
- **Your server's IP can be blocked.** No protocol saves an address a censor blocks outright. Rotating
  credentials doesn't help there; a new server (IP) does.
- **Pick the cover site with some care.** `auto` picks among big sites that are reachable in the countries
  OpenRoute is for. Stealthier still is a site hosted near your VPS; pass it with `--sni`.
