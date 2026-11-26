# OpenRoute — Unblock & Route

**A free, open-source browser extension for getting around censorship.** When a
site fails to load, OpenRoute works out *how* it's being blocked, then routes
**only that site** around the block. Every other site stays direct and
full-speed.

Works in **Chrome, Edge, Brave and the other Chromium browsers**, and in
**Firefox** (desktop and Android). No account, no telemetry, nothing to sign up
for.

> **The honest headline:** nothing is unblockable. Every VPN, proxy and Tor
> bridge gets blocked somewhere. OpenRoute stacks independent ways around a
> block so that, in practice, one of them usually works, and it tells you which
> one did. It gives you circumvention, **not anonymity**: a server you rent is
> tied to you.

## How it works

1. **It notices.** A page that fails to load is caught as it fails. With *deep
   detection* on, so are block pages, HTTP 451 answers and a routed site's
   blocked images and scripts.
2. **It diagnoses.** The failing domain is looked up over encrypted DNS (DNS
   over HTTPS, RFC 8484) and compared with what your network said. That tells
   apart:
   - DNS tampering and DNS poisoning;
   - filtering by site name (SNI / DPI);
   - an intercepted TLS connection;
   - an address (IP) block;
   - a legal (451) block;
   - a block page;
   - a block on your own device or network;
   - a site that is simply down.
3. **It routes, cheapest fix first.** Each blocked site walks a ladder:

   | rung | what it is | beats |
   |---|---|---|
   | Secure DNS | your browser's own encrypted DNS (one toggle) | DNS tampering, at full speed |
   | Secure DNS + ECH | Encrypted Client Hello, where the site supports it | filtering by site name |
   | DPI bypass | a split TLS handshake, no server needed ([companion](companion/)) | simple name filters |
   | Your server or proxy | a proxy you run, or your own server through the [companion](companion/) | address blocks and DPI |
   | Tor | the free network, with bridges ([companion](companion/) or Tor Browser) | blocks even your own server hits |
   | Read-only | a Wayback or reader copy | "at least let me read it" |

4. **It keeps working.** These all happen without you:
   - Routed sites get a failover chain (primary + 2), and they never fall back
     to your direct connection.
   - Transports are tested before they carry a site, and their health is kept
     up to date.
   - Each routed site is re-checked on its direct path every few days and goes
     back to direct once that works again.
   - A site with no working route is retried on a backoff schedule instead of
     being given up on.

Only blocked sites detour (*Smart* mode). You can also send *All sites* through
your best transport, or turn routing *Off*, from the popup.

## Install

OpenRoute isn't in the browser stores yet, so you install a release build
yourself. It takes a few clicks.

**Chrome, Edge, Brave, Opera, Vivaldi and other Chromium browsers**

1. Download `openroute-chromium-<version>.zip` from
   [Releases](https://github.com/amibhai/OpenRoute/releases) and unzip it somewhere permanent. The browser
   loads the extension from that folder every time it starts.
2. Open `chrome://extensions` (`edge://extensions`, `brave://extensions`, and
   so on) and turn on **Developer mode**.
3. Click **Load unpacked** and pick the unzipped folder, the one with
   `manifest.json` directly inside.

You can also load a clone of this repository directly: the repository root is
the extension.

**Checking a download.** Each release lists the SHA-256 of every file in
`SHA256SUMS`, and carries signed build provenance:

```sh
gh attestation verify openroute-chromium-1.0.0.zip --repo amibhai/OpenRoute
```

**Firefox**

Until OpenRoute is on addons.mozilla.org, Firefox's release builds only accept
it as a *temporary* add-on, which is removed when Firefox restarts:

1. Download `openroute-firefox-<version>.zip` from
   [Releases](https://github.com/amibhai/OpenRoute/releases).
2. Open `about:debugging#/runtime/this-firefox`, click **Load Temporary
   Add-on…** and pick the zip.

Firefox asks for two things, and the welcome page walks you through both:
- **Access to all sites**, which it needs to route anything.
- *Optionally*, consent for the encrypted-DNS check. Without it, no domain
  leaves your browser and routing still works.

**Then:**

1. **Turn on Secure DNS** in your browser. The welcome page opens the right
   settings, or shows the steps where it can't. That one toggle beats the most
   common kind of blocking at full speed.
2. **Add a way through, for blocks DNS can't fix:**
   - **A proxy you already run.** OpenRoute's **Find local proxies** detects
     Tor Browser, Tor, v2rayN, Clash, NekoBox, Hiddify and others on their
     usual ports.
   - **Any SOCKS or HTTP proxy.** Add it under *Transports*, with a login if it
     needs one.
   - **Your own server.** One command on a cheap VPS ([server/](server/)) sets
     up VLESS-Reality, Shadowsocks-2022 and optionally Hysteria2. The
     [companion app](companion/) then runs it for the browser, along with DPI
     bypass and Tor in every bridge mode.

## Using it

- **The popup** shows the site you're on: whether it's routed, through what,
  and how fast. It has one button for what to do next (route it, stop routing,
  turn on Secure DNS, try again), plus the mode switch and your transports'
  health.
- **The badge on each tab:** ✓ means routed and working, … means being routed,
  and ! means blocked. With no tab badge, the number counts sites that need
  you.
- **Right-click a page**, or press **Alt+Shift+O**, to route that site or stop
  routing it.
- **The dashboard**, the gear icon in the popup, holds everything else:
  - **Sites:** each one's diagnosis and history, with per-site routing, rules
    and a read-only copy.
  - **Transports:** test them, set the preferred one, add proxies, connect the
    companion.
  - **DNS:** encrypted-DNS settings.
  - **Rules:** sites to always route or never route.
  - **Settings:** including deep detection, WebRTC leak protection, and backup
    and restore.
  - **Diagnostics:** a timeline of what happened and why, and a bug-report
    download with site names hidden.

## Browser support

| browser | routing | companion | tested end to end |
|---|---|---|---|
| Chromium, Edge, Brave | `chrome.proxy` (PAC) | ✓ | ✓ every change, in real browsers (Chromium, Edge 158, Brave 158) |
| Chrome | `chrome.proxy` (PAC) | ✓ | same engine; Chrome itself can't be automated with extensions |
| Opera, Vivaldi, Arc, Yandex | `chrome.proxy` (PAC) | ✓ | not yet: Chromium-based, should behave the same |
| Firefox 140+ | `proxy.onRequest` | ✓ | ✓ every change, in real Firefox (146) |
| LibreWolf, Waterfox, Floorp, Zen | `proxy.onRequest` | ✓ | not yet: Firefox-based |
| Firefox for Android 142+ | `proxy.onRequest` | — (no native apps) | builds and passes Mozilla's linter; not run on a device yet |
| Safari | — | — | not supported (no proxy API for extensions) |

Where a browser can't route, OpenRoute still diagnoses blocks and tells you
how to fix them.

## Privacy

There is no telemetry, no analytics, no account, and no remote configuration.
What OpenRoute sends, and when:
- the domain of a page that **failed to load**, to an encrypted-DNS resolver
  (Cloudflare by default; Firefox asks first);
- small plain-HTTP health checks through your own transports;
- the URL, to Wayback or the reader proxy, **only when you click** those
  buttons.

Everything else stays in your browser. [PRIVACY.md](PRIVACY.md) lists every
request OpenRoute, the companion and the server script make.

## Security

See [SECURITY.md](SECURITY.md) for the threat model, and to report a
vulnerability privately.

## For developers

```sh
npm ci                 # dev tools only; the extension has no runtime dependencies
npm run setup-tools    # project-local, checksum-verified Go, sing-box, Tor, … in .tools/
npm test               # unit tests
npm run test:e2e       # real Chromium and Firefox
```

- [CONTRIBUTING.md](CONTRIBUTING.md): setup, every command, and how to add a
  language.
- [docs/architecture.md](docs/architecture.md): how the pieces fit together.
- [docs/testing.md](docs/testing.md): what's tested, how, and what isn't yet.
- [CHANGELOG.md](CHANGELOG.md): what changed in each release.

## Legality and responsible use

Circumventing censorship is legal in most countries and part of the right to
access information. Some places restrict it, and schools or employers may
forbid it on their networks. **Know the rules that apply to you**; that
judgement, and its risk, are yours.

- **Not anonymity.** A proxy or VPS you run is tied to you. For anonymity, use
  [Tor Browser](https://www.torproject.org/).
- **Not a guarantee.** Everything gets blocked somewhere.
- **Not audited.** If being caught carries real danger where you are, use
  tools with formal security audits and a threat model built for that, such as
  Tor Browser, or see [accessnow.org/help](https://www.accessnow.org/help/).

## License

[MIT](LICENSE): use it, fork it, ship it. Keep the copyright notice; no
warranty.

Other licenses involved:

| component | license | how it's used |
|---|---|---|
| [Public Suffix List](https://publicsuffix.org) | MPL-2.0 | data bundled in the extension (`src/background/domains/psl-data.js`, notice kept in the file) |
| [sing-box](https://github.com/SagerNet/sing-box) | GPL-3.0-or-later | run as a separate program by the companion and on your server; not bundled |
| [Tor](https://www.torproject.org/) and its pluggable transports | BSD-3-Clause | run as a separate program by the companion; not bundled |

Running sing-box as a separate program doesn't make OpenRoute a derivative
work. But if you **redistribute a bundle that includes the sing-box binary**,
GPL-3.0 applies to that bundle. *(This is not legal advice.)*
