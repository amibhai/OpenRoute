# OpenRoute companion (Phase B)

The native helper that gives the extension the transports a browser can't run on
its own. It's a Chrome **Native Messaging** host that speaks the length-prefixed
NM protocol on stdin/stdout and drives a local [`sing-box`](https://sing-box.sagernet.org)
subprocess exposing a SOCKS proxy on `127.0.0.1:1080`. The extension's
split-tunnel PAC then routes only blocked domains through it.

**Why sing-box?** The hard part — audited Shadowsocks-2022 / VLESS-Reality /
WireGuard / Tor crypto and transports — already exists and is battle-tested.
This companion *orchestrates* it (generates config, starts it, reads health from
its Clash API) rather than reimplementing anything security-critical.

## What it does

- Parses `ss://`, `vless://` (incl. TLS + **Reality**) share links, or a raw
  `{...}` sing-box outbound, into a working config.
- Runs sing-box with a `mixed` (SOCKS+HTTP) inbound + DNS-over-HTTPS **through the
  tunnel** (this is what an extension can't do — it closes the "Secure DNS is
  manual" gap).
- Reports live health/latency per transport back to the extension via the Clash
  API delay test.

## Requirements

- [Go](https://go.dev/dl/) 1.21+ to build the host (one static binary, std-lib only).
- A [`sing-box`](https://github.com/SagerNet/sing-box/releases) binary on `PATH`,
  or passed to the installer, or dropped in the data dir (`%APPDATA%\OpenRoute`
  on Windows, `~/.openroute` elsewhere).

## Install

Find your unpacked extension's ID at `chrome://extensions` (Developer mode).

**Windows** (PowerShell):
```powershell
cd companion\install
.\install-windows.ps1 -ExtId <extension-id> [-SingBox C:\path\to\sing-box.exe]
```

**macOS / Linux**:
```sh
cd companion/install
./install-unix.sh <extension-id> [/path/to/sing-box]
```

The installer runs `go build`, writes the NM host manifest to the browser's
`NativeMessagingHosts` directory (and, on Windows, the registry key for Chrome +
Edge), and optionally bundles your `sing-box`. Reload the extension; the popup's
companion pill should read **connected**.

## Use

In the popup → **Transports → Connect via companion**, paste a share link and hit
**Connect**. The companion brings up sing-box and registers a `companion`
transport; the ladder will route blocked domains through it.

## Protocol (NM messages)

| → to host | ← response |
|---|---|
| `{cmd:"ping"}` | `{ok, cmd:"pong", version}` |
| `{cmd:"status"}` | `{ok, running, socksPort, activeId, singboxOk}` |
| `{cmd:"connect", link, id, label}` | `{ok, socksPort, id}` or `{ok:false, error}` |
| `{cmd:"disconnect"}` | `{ok}` |
| `{cmd:"transports"}` | `{ok, transports:[…]}` |
| `{cmd:"health"}` | `{ok, transports:[{id, health, latencyMs}]}` |

## Test it end-to-end

```sh
go vet ./...
go build -o bin/openroute-host .
# smoke-test the NM framing without Chrome (4-byte LE length + JSON):
printf '\x0e\x00\x00\x00{"cmd":"ping"}' | ./bin/openroute-host   # writes a length-prefixed pong
```

Then, against a real endpoint: stand up a sing-box server (Phase D scripts, or
any Shadowsocks-2022/Reality server), paste its share link into the popup,
Connect, and load a blocked site — it should route through `127.0.0.1:1080`.

## Honest limits

- Not compiled/tested in this repo's CI — build it on your machine with the steps
  above. The code is std-lib only so `go build` needs no network.
- Reality/SS-2022 defeat *current* DPI + active probing; it's an arms race, never
  a guarantee. This is circumvention, **not anonymity** — a VPS you rent is tied
  to you.
