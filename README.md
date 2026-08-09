# OpenRoute — Unblock & Route

A personal-use Chrome extension that detects when a site is blocked, works out
**how** it's being blocked, and then walks that one domain down a **failover
ladder** until something gets it through — at full speed for everyone else.

> **The honest headline:** nothing is "unblockable." Tor, every VPN, every proxy
> gets blocked somewhere. OpenRoute's job is to **stack enough independent
> fallbacks that, in practice, something almost always works**, and to be honest
> about the ceiling instead of pretending there isn't one. It gives you
> circumvention, **not anonymity** — a proxy you run is tied to you.

## Why this design

Most ISP restrictions are **DNS tampering** — the cheapest block to deploy and
the cheapest to defeat. Chrome's built-in **Secure DNS (DoH)** beats it with
essentially zero latency. So Stage 1 does the honest, high-value work:

1. **Detect** — watches for failed top-level navigations (debounced so a
   retrying page doesn't trigger a lookup storm), and serializes its writes so
   overlapping failures never corrupt the log.
2. **Diagnose** — runs a resilient DNS-over-HTTPS lookup and classifies the block:
   - `DNS tampering` — DoH finds a real IP but your resolver couldn't → **fixable at full speed** by enabling Secure DNS.
   - `DNS fully poisoned` — even DoH comes back with a private/bogon IP → poisoning upstream of the encrypted resolver; try another DoH provider.
   - `SNI / DPI` — the TLS handshake was reset → enable ECH + Secure DNS; the popup flags when the domain publishes an HTTPS record (so ECH should help).
   - `IP block` — the ISP drops packets to the server → needs a proxy (Stage 2).
   - `NXDOMAIN / unreachable / policy` — likely not an ISP block.
3. **Fix / fall back** — one click to the Secure DNS setting; **Recheck** re-runs
   the diagnosis on demand; for content you just need to read, open it via
   Wayback or a reader proxy (read-only).

### What makes the DoH engine resilient

- **Multiple independent resolvers** (Cloudflare, Google, Quad9): the preferred
  one is tried first; if it can't give an authoritative answer, the rest are
  raced and the first solid response wins.
- **IP-literal endpoints** (`https://1.1.1.1/…`, `8.8.8.8`, `9.9.9.9`): if a
  censor poisons the *resolver's hostname*, we still reach it by IP — those
  addresses serve certs with IP SANs, so TLS keeps validating.
- **Time-boxed + retried**: every request has an `AbortController` timeout and a
  retry, so a hung fetch can never wedge the background worker.
- **Answers are validated, not trusted**: private / loopback / CGNAT / bogon
  addresses are flagged as injected responses instead of being reported as the
  "real" IP.
- **ECH awareness**: an HTTPS/SVCB (type 65) lookup runs in parallel so the tool
  can tell you when Encrypted ClientHello is likely to defeat an SNI filter.

## The failover ladder (new in 0.3)

Each blocked domain is walked down a ladder, cheapest/fastest first, and the
winning rung is remembered per-domain and re-verified. A rung is only marked
**working** once a real navigation through it actually succeeds.

| Rung | Method | Beats |
|---|---|---|
| Secure DNS | DoH (you toggle it once) | DNS tampering — at full speed |
| Secure DNS + ECH | Encrypted ClientHello | SNI/DPI where the domain supports it |
| Proxy | split-tunnel via SOCKS/HTTP (your VPS, Tor, …) | IP blocks + DPI |
| Read-only | Wayback / Reader | "at least let me read it" |

**Split tunnel:** only blocked domains detour through a proxy (a generated PAC
script); everything else stays direct and full-speed. When a proxy fails to
deliver a page, OpenRoute automatically tries the next transport, then the next
rung — with a hard attempt cap so it can never loop.

**Transports** are anything the browser can reach: any SOCKS5/HTTP proxy you run
(one-click preset for Tor Browser on `127.0.0.1:9150`). The upcoming native
companion registers itself here to add built-in Shadowsocks-2022 / VLESS-Reality
/ Tor / Snowflake without changing anything above the transport layer.

> **Honest scope:** the extension alone can only *route to* a proxy — it can't
> *be* one. Beating IP/DPI blocks needs somewhere unblocked to route through
> (your VPS, Tor, a peer network). That transport layer is the native companion
> + self-host scripts still to come; today OpenRoute fully unblocks DNS at full
> speed and routes everything else through whatever proxy/Tor you point it at.

## Install (Developer mode)

1. Open `chrome://extensions`
2. Toggle **Developer mode** (top-right)
3. Click **Load unpacked** and select this `openroute-extension` folder
4. Pin the OpenRoute icon; the badge shows how many blocks were detected

## Try it

- Turn on **Secure DNS** from the popup — the full-speed fix for DNS blocks.
- Visit a domain that fails to load; it appears in the popup, diagnosed, with a
  live status chip (blocked → routing → ✓ working).
- Add a transport (run Tor Browser and pick it, or add any SOCKS/HTTP proxy).
  With **Auto-route** on, IP/DPI-blocked domains detour through it automatically
  and the tab reloads itself.
- Use the per-site **route** dropdown to pin a domain to Auto / Direct / a
  specific transport / Read-only.

## Testing the ladder locally

- **DNS block:** add a line like `127.0.0.1 example.com` to your hosts file →
  the browser fails to resolve, DoH still finds the real IP → diagnosed as
  *DNS tampering*, remedy prompts Secure DNS.
- **IP block:** block a site's IP at your OS firewall, add a working proxy/Tor
  transport, enable Auto-route → the domain flips to *routing* then *✓ working*
  and loads through the proxy while other sites stay direct.
- **Split-tunnel proof:** with a domain routed, compare the exit IP it sees
  (via an IP-echo page on that domain vs. a non-routed one) — only the routed
  domain shows the proxy's IP.
- **Failover:** point a transport at a dead port → watch it score DOWN and the
  ladder cascade to the next transport, then to Read-only when exhausted.

> Known Phase-A limitation: if an ISP serves a **block page** with HTTP 200, the
> verifier can read that as "working." The DoH diagnosis catches the injected-IP
> variant; full block-page detection needs a content script (later phase).

## Privacy

- DoH lookups go to your chosen provider (Cloudflare, Google, or Quad9); on
  failure the others may be queried as a fallback.
- "Wayback" and "Reader" send the page URL to those third-party services.
- Everything else stays local in `chrome.storage.local` (capped to the 200 most
  recent entries).

## Roadmap

- **Phase A (done)** — failover ladder + split-tunnel proxy routing
  (`chrome.proxy` + PAC), per-domain policy, verifier, transport health.
- **Phase B** — native companion (Go + sing-box) exposing built-in
  Shadowsocks-2022 / VLESS-Reality / WireGuard, DNS-through-companion, health API.
- **Phase C** — free-network fallbacks: Tor (+ obfs4/Snowflake bridges),
  Snowflake, health-checked public-proxy pool with rotation.
- **Phase D** — one-command self-host for a hardened VPS (sing-box + Reality),
  multi-region failover, one-click share-link/QR import.
- **Phase E** — onboarding, cross-browser (Firefox/Edge), packaging, docs.

## Legality

Circumventing censorship is legal in most places but restricted in a few.
Know your jurisdiction. This is a personal-use tool.
