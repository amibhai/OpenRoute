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
- **Pools & rotation (Phase C):** pass several links and they're wrapped in a
  sing-box `urltest` group — it auto-selects the lowest-latency working node and
  re-tests every few minutes, so a pool of public/VPS proxies self-heals.
- **Tor (Phase C):** runs a detached `tor` with a dedicated SOCKS port (9250),
  in `direct`, `obfs4`, or `snowflake` mode — the free, no-server rung for when
  even a proxy IP is blocked. Health comes from Tor's control-port bootstrap %.
- Runs sing-box with a `mixed` (SOCKS+HTTP) inbound + DNS-over-HTTPS **through the
  tunnel** (this is what an extension can't do — it closes the "Secure DNS is
  manual" gap).
- Reports live health/latency per transport back to the extension via the Clash
  API delay test.

### Extra binaries for Tor modes

`tor` is required for any Tor mode; `obfs4` mode also needs **lyrebird** (or the
older `obfs4proxy`); `snowflake` mode needs **snowflake-client**. All three ship
inside Tor Browser — point the installer at them or drop them in the data dir.
`obfs4` mode also needs `Bridge obfs4 …` lines from <https://bridges.torproject.org>.

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
| `{cmd:"status"}` | `{ok, running, socksPort, activeId, singboxOk, tor:[…]}` |
| `{cmd:"connect", link\|links, id, label}` | `{ok, socksPort, id, count}` or `{ok:false, error}` |
| `{cmd:"connectTor", mode, label, bridges}` | `{ok, socksPort:9250, id:"companion-tor", mode}` |
| `{cmd:"disconnect", kind}` | `{ok}` — `kind` = `singbox` \| `tor` \| omit for both |
| `{cmd:"transports"}` | `{ok, transports:[…]}` (sing-box + Tor) |
| `{cmd:"health"}` | `{ok, transports:[{id, health, latencyMs, bootstrap?}]}` |

`connect` takes either a single `link` or a `links` array (pool). `mode` for
`connectTor` is `direct`, `obfs4`, or `snowflake`.

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
