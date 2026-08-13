# OpenRoute self-host server (Phase D)

One command turns a fresh VPS into a hardened [`sing-box`](https://sing-box.sagernet.org)
server speaking **Shadowsocks-2022** and **VLESS-Reality**, and prints the share
links you paste into the extension. This is the strongest, most reliable rung of
the ladder — a transport only you control.

## Use

On a fresh **Debian/Ubuntu** VPS (a $5/mo box is plenty), as root:

```sh
sudo bash install-server.sh
```

It installs sing-box, generates fresh credentials + a Reality keypair, writes a
hardened `/etc/sing-box/config.json`, starts the service, opens the firewall (if
`ufw` is active), and prints:

```
vless://…?security=reality&sni=…&pbk=…&sid=…&flow=xtls-rprx-vision#OpenRoute-Reality
ss://…@IP:PORT#OpenRoute-SS
```

Paste **both** into the popup's companion pool box (one per line) → **Connect**.
The companion runs them as an auto-failover pool. Re-print later with:

```sh
sudo bash install-server.sh --show
```

## Options (env vars)

| var | default | notes |
|---|---|---|
| `REALITY_SNI` | `www.microsoft.com` | the real TLS site Reality borrows; must support TLS 1.3 |
| `VLESS_PORT` | `443` | keep 443 so it looks like normal HTTPS |
| `SS_PORT` | random 20000–39999 | Shadowsocks-2022 port |
| `SERVER_IP` | auto-detected | set if detection is wrong (e.g. behind NAT) |

```sh
REALITY_SNI=www.apple.com SS_PORT=8443 sudo -E bash install-server.sh
```

## Why these two transports

- **VLESS-Reality** — no certificate to buy or leak; the TLS handshake is
  indistinguishable from a real visit to `REALITY_SNI`, which defeats SNI/DPI
  filtering and active probing far better than plain TLS proxies.
- **Shadowsocks-2022** — a fast, simple AEAD fallback on a second port, so one
  blocked port doesn't take you fully offline.

## Hardening applied

- Config + creds are `chmod 600`.
- A route rule **blocks private/link-local IPs** (`ip_is_private`), so the proxy
  can't be used to reach the box's LAN or the cloud metadata endpoint
  (`169.254.169.254`).
- Keys come from `openssl rand` / `sing-box generate` — never hardcoded.

Consider also: a non-root user, `fail2ban` for SSH, and keeping the box patched.

## Honest notes

- **Not run/tested from this repo** — there's no VPS in the build environment.
  It's plain, `bash -n`-clean POSIX-ish bash targeting Debian/Ubuntu; read it
  before running (it's short).
- It pipes the **official** `https://sing-box.app/install.sh` to `sh` for arch
  detection + the systemd unit. If you'd rather not, install sing-box yourself
  first (the script skips install when `sing-box` is already on `PATH`).
- Renting a VPS ties the endpoint to your identity/payment. This is
  **circumvention, not anonymity** — for anonymity use Tor (the free rung).
- Reality's borrowed SNI should be a site that's *not* itself blocked where you
  are and that you don't mind your traffic appearing to go to.
