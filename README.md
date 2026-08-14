# OpenRoute — Unblock & Route

**A free, open-source browser extension.** It detects when a site is blocked, works
out **how** it's being blocked, and then walks that one domain down a **failover
ladder** until something gets it through — at full speed for everyone else.

Works on **Chrome, Edge, Brave** (and experimentally Firefox). No account, no
signup, no telemetry, no server required to get started.

👉 **[Jump straight to install instructions](#install--3-minutes)**

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
(one-click preset for Tor Browser on `127.0.0.1:9150`). The optional
[native companion](companion/) registers itself here to add Shadowsocks-2022 /
VLESS-Reality / Tor / Snowflake without changing anything above the transport layer.

> **Honest scope:** the extension alone can only *route to* a proxy — it can't
> *be* one. Beating IP/DPI blocks needs somewhere unblocked to route through
> (your VPS, Tor, a peer network) — that's what the [companion](companion/) and
> [self-host server](server/) provide. Out of the box, with no extra setup,
> OpenRoute fully unblocks **DNS-based** blocking at full speed and routes
> everything else through whatever proxy/Tor you point it at.

## Install — 3 minutes

There's **nothing to compile** and no dependencies. The extension is plain
JavaScript; you download the folder and load it. It is **not on the Chrome Web
Store**, so you install it in developer mode — this is normal and takes 3 clicks.

### Step 1 — Download the code

**Option A — download the ZIP (easiest, no tools needed)**

1. Go to **<https://github.com/amibhai/OpenRoute>**
2. Click the green **`< > Code`** button → **Download ZIP**
3. **Extract/unzip** the file somewhere permanent (e.g. `Documents\OpenRoute`)
   — ⚠️ *don't* leave it inside the `.zip`, and don't delete this folder later:
   the browser loads the extension from it every time it starts.

**Option B — clone with git**

```sh
git clone https://github.com/amibhai/OpenRoute.git
```

You'll end up with a folder containing `manifest.json`, `background.js`, `popup.html`,
and an `icons/` folder. **That folder is the extension.**

### Step 2 — Load it into your browser

<details open>
<summary><b>Chrome, Edge, Brave, Opera (Chromium browsers)</b></summary>

1. Open your browser and go to:
   - Chrome → `chrome://extensions`
   - Edge → `edge://extensions`
   - Brave → `brave://extensions`
2. Turn on **Developer mode** (toggle in the top-right corner; on Edge it's on the left)
3. Click **Load unpacked**
4. Select the folder from Step 1 — the one that **directly contains `manifest.json`**
   (if you see a `manifest.json` inside when you open it, that's the right folder)
5. Done. A welcome page opens automatically.

**Pin it:** click the puzzle-piece 🧩 icon in the toolbar → pin **OpenRoute** so the
badge is always visible.
</details>

<details>
<summary><b>Firefox (experimental)</b></summary>

Firefox needs its own manifest, so build the packaged version first:

```sh
./build.sh          # macOS / Linux  (needs `zip`)
# or on Windows:
powershell -ExecutionPolicy Bypass -File build.ps1
```

Then extract `dist/openroute-firefox-<version>.zip` and:

1. Go to `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on…**
3. Select the `manifest.json` inside the extracted folder

⚠️ Temporary add-ons are removed when Firefox restarts. Firefox support is
experimental and hasn't had a full end-to-end run — see the table below.
</details>

### Step 3 — Turn on Secure DNS (the actual fix for most blocks)

The welcome page walks you through this, or do it manually:

1. Open `chrome://settings/security`
2. Turn on **Use secure DNS**
3. Choose **Cloudflare (1.1.1.1)** or **Google**

That single toggle defeats the most common form of blocking (DNS tampering) at
**full speed**. Most people need nothing else.

### Step 4 (optional) — Beat IP blocks and DPI

If a site is blocked at the IP level, the extension needs somewhere unblocked to
route through. Pick whichever fits you:

| You have… | Do this |
|---|---|
| Tor Browser installed | Just run it — OpenRoute has a built-in preset for `127.0.0.1:9150` |
| Any SOCKS5/HTTP proxy | Popup → **Transports** → add host + port |
| A VPS (~$5/mo) | Run [`server/install-server.sh`](server/install-server.sh) on it, then install the [companion](companion/) and paste the link it prints |
| Nothing, and you want free | Install the [companion](companion/) and use its built-in **Tor / Snowflake** mode |

### Updating

Pull the latest code, then click the **↻ reload** icon on the OpenRoute card at
`chrome://extensions`:

```sh
git pull        # or download + extract the new ZIP over the old folder
```

### Troubleshooting

| Problem | Fix |
|---|---|
| *"Manifest file is missing or unreadable"* | You selected the wrong folder. Pick the one that **directly** contains `manifest.json` (a ZIP often nests a second folder inside). |
| Extension disappears after restart | On Chromium you probably deleted/moved the folder — it must stay put. On Firefox, temporary add-ons are removed by design. |
| No icon in the toolbar | Click the 🧩 puzzle-piece and pin OpenRoute. |
| Nothing gets detected | Detection only fires on **failed** page loads. Check **Detect** is on in the popup. |
| A site still won't load | Open the popup and read the diagnosis — if it says *IP block*, you need Step 4. |

### Browser support

| Browser | Status | Proxy engine |
|---|---|---|
| Chrome | ✅ supported | `chrome.proxy` PAC |
| Edge | ✅ supported (Chromium) | `chrome.proxy` PAC |
| Brave / Opera / Vivaldi | ✅ should work (Chromium) | `chrome.proxy` PAC |
| Firefox | 🧪 experimental | `proxy.onRequest` adapter — use `manifest.firefox.json` |
| Safari | ❌ not supported | different extension platform |

The router auto-detects the engine, so the same code drives both. Firefox needs the
companion's Firefox NM manifest (`allowed_extensions`, see `companion/host/`) and hasn't
had a full end-to-end run yet.

### Building distributable zips

`powershell -File build.ps1` (Windows) or `./build.sh` (macOS/Linux) produces
`dist/openroute-chrome-<ver>.zip` and `dist/openroute-firefox-<ver>.zip`, ready for
the Chrome Web Store / Firefox AMO.

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

- **Phase A (done, tested)** — failover ladder + split-tunnel proxy routing
  (`chrome.proxy` + PAC), per-domain policy, verifier, transport health.
  Logic covered by a Node harness (32 assertions).
- **Phase B (scaffolded)** — native companion (Go + sing-box) exposing
  Shadowsocks-2022 / VLESS-Reality via `ss://`/`vless://` links, DNS-through-
  companion, health API, cross-OS installers. See [`companion/`](companion/).
  Build & end-to-end test on your machine (`go build`; needs a `sing-box` binary).
- **Phase C (scaffolded)** — free-network fallbacks in the companion: **Tor**
  (`direct`/`obfs4`/`snowflake`, control-port bootstrap health) and **auto-rotating
  pools** (multiple upstreams wrapped in a sing-box `urltest` group). Popup gains
  a Tor-mode selector and a multi-link pool field.
- **Phase D (scaffolded)** — one-command self-host: [`server/install-server.sh`](server/install-server.sh)
  stands up a hardened sing-box VPS (Shadowsocks-2022 + VLESS-Reality) and prints
  the `ss://`/`vless://` links the companion consumes. Paste both into the pool box
  for multi-transport failover. Still to come: multi-region, one-click QR import.
- **Phase E (scaffolded)** — first-run onboarding wizard, real icons, Edge support +
  experimental Firefox port (`manifest.firefox.json` + `proxy.onRequest` adapter), and
  `build.ps1`/`build.sh` packaging into store-ready zips.

## Contributing

Issues and pull requests are welcome at
**<https://github.com/amibhai/OpenRoute>**.

Especially useful right now:

- **Real-world reports** — what blocking you hit, what OpenRoute diagnosed, and
  whether the ladder got you through. Diagnosis accuracy improves with real data.
- **Firefox testing** — the port is written but unproven.
- **End-to-end companion/server runs** on real hardware (see each README).

If you're reporting a bug, please include your browser + version, what the popup
diagnosed, and anything in the service-worker console
(`chrome://extensions` → **service worker**).

## Legality & responsible use

Circumventing censorship is **legal in most countries** and is a recognised part
of the right to access information — but a few jurisdictions restrict or ban it,
and some networks (schools, employers) prohibit it by policy even where it's
legal. **Know the rules that apply to you before using it**; that judgement is
yours to make, and the risk is yours to carry.

Please also understand what this tool is *not*:

- **It is not anonymity.** A proxy or VPS you run is tied to you and your payment
  method. If you need anonymity, use [Tor Browser](https://www.torproject.org/) —
  which OpenRoute can also route through, but is not a substitute for.
- **It is not a guarantee.** See the honest headline at the top: everything gets
  blocked somewhere. OpenRoute stacks fallbacks; it doesn't work miracles.
- **It is not for attacking anyone.** Use it to reach information, not to evade
  security controls you're accountable to.

If you're in a genuinely high-risk situation (a place where being caught
circumventing carries real consequences), please rely on tools with formal
security audits and a threat model built for that — Tor Browser, or the guidance
at [accessnow.org/help](https://www.accessnow.org/help/). This project has not
been independently audited.

## License

[MIT](LICENSE) — use it, fork it, modify it, ship it, commercially or otherwise.
Just keep the copyright notice. No warranty.

**Third-party components** are *not* bundled — the installers locate or fetch
them, and they keep their own licenses:

| Component | License | How it's used |
|---|---|---|
| [sing-box](https://github.com/SagerNet/sing-box) | GPL-3.0-or-later | run as a **separate process** by the companion |
| [Tor](https://www.torproject.org/) + pluggable transports | BSD-3-Clause | run as a **separate process** by the companion |

Running these as subprocesses doesn't make OpenRoute a derivative work, so the
MIT license here stands. But if you **redistribute a bundle** that includes the
sing-box binary, GPL-3.0 obligations attach to that bundle — ship it separately
or comply. *(Not legal advice.)*
