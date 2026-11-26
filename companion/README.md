# OpenRoute companion

The optional native helper that gives the extension transports a browser
can't run on its own:

- **your own server or a pool of them**: Shadowsocks-2022, VLESS-Reality, VMess, Trojan, Hysteria2, TUIC,
  WireGuard, plus authenticated SOCKS/HTTP upstreams, from share links or a subscription
- **serverless DPI bypass**: TLS ClientHello fragmentation, no server needed
- **Tor**: direct, obfs4, Snowflake, meek, WebTunnel, or *auto*

It orchestrates [`sing-box`](https://sing-box.sagernet.org) and
[`tor`](https://www.torproject.org) rather than reimplementing any crypto.

## How it fits together

```
browser ──native messaging──▶ openroute-companion (host)   ← started by the browser, stateless
                                   │ Unix-domain socket in your private data dir
                                   ▼
                              openroute-companion daemon   ← owns state, supervises children
                                   ├── sing-box  (pool · DPI-record · DPI-segment inbounds on 127.0.0.1)
                                   └── tor       (SOCKS on 127.0.0.1, cookie-authenticated control port)
```

- The **host** is what the browser launches. It checks that the caller is an extension it serves, then forwards each message to the daemon. If the daemon isn't running, the host starts it.
- The **daemon** keeps the *desired state* on disk and brings it back after a restart or reboot. It supervises its children and restarts them with backoff. If a child keeps crashing it gives up and reports why.
  - The children die with the daemon. On Windows this is a kill-on-close job object; on Linux, `Pdeathsig`; on macOS, process groups.
  - The daemon exits on its own when no browser has talked to it for 15 minutes.
- **No TCP control ports.** Host↔daemon IPC is a Unix-domain socket (supported on Windows 10 1803+).
  - sing-box's Clash API has a random secret.
  - Tor's control port uses cookie authentication.
- **Ports are picked free once and kept stable.** If one ever has to change, the extension notices on its next maintenance tick and follows it.

## Install

You need a [`sing-box`](https://github.com/SagerNet/sing-box/releases) binary, **1.12 or newer**. Put it on `PATH`,
pass it to the installer, or drop it in the data directory: `%APPDATA%\OpenRoute` on Windows, `~/.openroute` elsewhere.
Tor modes also need Tor Browser or the Tor Expert Bundle installed; the companion finds them on its own.

**Windows** (PowerShell, no admin):
```powershell
cd companion\install
.\install-windows.ps1 [-SingBox C:\path\to\sing-box.exe]
```

**macOS / Linux:**
```sh
cd companion/install
./install-unix.sh [--sing-box /path/to/sing-box]
```

The installer builds the companion (with Go 1.21+) or uses a prebuilt binary next to the script. It then registers the companion with every supported browser it finds:

- **Chromium family:** Chrome (including Beta, Dev and Canary), Chromium, Edge, Brave, Vivaldi, Opera, Arc, Yandex, Thorium.
- **Firefox family:** Firefox, LibreWolf, Waterfox, Floorp, Zen.

**No extension ID to copy:** the unpacked extension's ID is pinned by its manifest key and allowed out of the box. For a store build, add `--extension-id <id>`.

```sh
openroute-companion doctor      # what's installed, what's registered, is the daemon up
openroute-companion uninstall   # unregister from every browser
```

## The DPI-bypass rung, honestly

sing-box can split the TLS ClientHello so the server name isn't in one packet. It can split across **TLS records** (`dpi-record`) or across **TCP segments** (`dpi-segment`). Splitting defeats filters that match the plaintext SNI, at near-direct speed and with no server.

sing-box's own documentation says this is for **simple** filters, not sophisticated national DPI. The two are separate transports, so OpenRoute's ladder simply tries them and moves on to a real tunnel when they don't work for a site. (`tls_spoof` exists in sing-box 1.14 but needs administrator/root rights, so the companion doesn't use it.)

## Tor modes

| mode | what it does |
|---|---|
| `direct` | plain connection to the Tor network |
| `obfs4` | built-in obfs4 bridges (or your own `Bridge obfs4 …` lines) |
| `snowflake` | Snowflake. In current Tor bundles it runs through `lyrebird`, not a separate `snowflake-client` |
| `meek` | domain-fronted meek_lite |
| `webtunnel` | your own WebTunnel bridges (from bridges.torproject.org) |
| `auto` | tries direct, then obfs4, then Snowflake, then meek, until one bootstraps |

Plugin lines and built-in bridges come from the installed Tor's own
`pt_config.json`. Failing that, the companion uses a bundled snapshot or a fresh copy from Tor's Moat API (`refreshBridges`, optionally fetched *through* another transport when bridges.torproject.org is blocked).

## Self-signed servers: certificate pinning

A link can carry `pinPublicKeySHA256=<sha256 of the server certificate's public key>`, in hex or base64.
OpenRoute's server script prints this for its Hysteria2 certificate, and it works for any TLS-based link.

The companion turns it into sing-box's `certificate_public_key_sha256`. sing-box then checks that pin
*instead of* a CA, so no `insecure` is involved. Tested against the real binary: the right pin connects,
while a wrong pin and no pin are both refused. This needs sing-box 1.13 or newer, and the companion says so
on older versions.

The standard Hysteria `pinSHA256` fingerprints the whole certificate, which no stable sing-box can check. A
link that pairs it with `insecure=1` is refused rather than silently connected without any verification.

## Protocol

Messages are native-messaging JSON. Every reply carries `ok`, and failures add an `error` with the reason, never a secret.

| → `cmd` | ← reply |
|---|---|
| `ping` | `{cmd:"pong", version, singbox:{path,version,ok}, tor:{path}}` |
| `connect {links[] \| link \| subscription, id, label}` | `{socksPort, id, count}` |
| `connectDpi` | `{transports:[{id,label,port,note}…]}` |
| `connectTor {mode, bridges[]}` | `{socksPort, id:"companion-tor", mode}` |
| `disconnect {kind}` | `kind` = `singbox` \| `dpi` \| `tor` \| *(all)* |
| `transports` | what the extension should have registered right now |
| `health` | `[{id, health, latencyMs, bootstrap?}]` (Clash API delay test / Tor bootstrap %) |
| `status` | sing-box + tor process state, restarts, last error |
| `newIdentity` | Tor `SIGNAL NEWNYM` |
| `refreshBridges {viaSocks?}` | fetch current built-in bridges from Tor's Moat API |

## Tests

```sh
npm run setup-tools              # Go, sing-box 1.12.x + latest, Tor Expert Bundle… (checksum-verified, into .tools/)
npm run test:companion           # go vet + go test with that toolchain (or: cd companion && go test ./...)
```

The suite checks:

- **Configs:** every config shape the companion generates passes the **real `sing-box check`** on 1.12.x and the latest release.
- **torrc:** every Tor mode passes the **real `tor --verify-config`**.
- **Full chain:** browser-style host → daemon → sing-box → a real Shadowsocks-2022 server → a site. A negative control (server down, so the request must fail) proves the traffic really went through the tunnel.
- **Supervisor:** crash-loop give-up, plus orphan cleanup that never kills a reused PID.
- **Share-link parsing**, including the formats the old parser rejected, and certificate pins.
- **The server script, end to end.** `server/install-server.sh` generates a config, real sing-box serves it,
  and every link it prints carries traffic through a companion-built client. The same tunnels must also
  refuse private destinations, both by address and by name.

## Limits

- **Not anonymity.** A server you rent is tied to you. For anonymity use Tor Browser.
- **No guarantees.** Reality, SS-2022 and Hysteria2 defeat *current* DPI and active probing, but it's an arms race.
- **Windows needs 10 (1803) or newer** for Unix-domain sockets.
