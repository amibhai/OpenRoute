# OpenRoute — Unblock & Route

**A free, open-source browser extension for getting around censorship.** When a
site fails to load, OpenRoute works out *how* it's being blocked, then routes
**only that site** around the block. Every other site stays direct and
full-speed.

Works in **Chrome, Edge, Brave, Opera, Vivaldi** and other Chromium browsers,
and in **Firefox**. No account, no telemetry, nothing to sign up for.

> **The honest headline:** nothing is unblockable. Every VPN, proxy and Tor
> bridge gets blocked somewhere. OpenRoute stacks independent ways around a
> block so that, in practice, one of them usually works, and it tells you which
> one did. It gives you circumvention, **not anonymity**: a server you rent is
> tied to you.

**Jump to:**
- [How it works](#how-it-works)
- [Install, step by step](#install-step-by-step)
- [The first five minutes](#the-first-five-minutes)
- [Getting past address blocks](#getting-past-address-blocks)
- [Using OpenRoute day to day](#using-openroute-day-to-day)
- [Updating](#updating) · [Uninstalling](#uninstalling) · [Troubleshooting](#troubleshooting)
- [Browser support](#browser-support) · [Privacy](#privacy) · [For developers](#for-developers)

## How it works

1. **It notices.** A page that fails to load is caught as it fails. With *deep
   detection* on, so are block pages, HTTP 451 answers and a routed site's
   blocked images and scripts.
2. **It diagnoses.** The failing domain is looked up over encrypted DNS (DNS
   over HTTPS) and compared with what your network said. That tells apart:
   - DNS tampering and DNS poisoning;
   - filtering by site name (SNI / DPI);
   - an intercepted connection;
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
   | DPI bypass | a split TLS handshake, no server needed ([companion app](companion/)) | simple name filters |
   | Your server or proxy | a proxy you run, or your own server through the [companion app](companion/) | address blocks and DPI |
   | Tor | the free network, with bridges (Tor Browser or the companion app) | blocks even your own server hits |
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

---

## Install, step by step

OpenRoute isn't in the browser stores yet, so you install a release build
yourself. It takes about three minutes.

**Every download is on the [Releases page](https://github.com/amibhai/OpenRoute/releases),** under **Assets**:

| file | for |
|---|---|
| `openroute-chromium-<version>.zip` | Chrome, Edge, Brave, Opera, Vivaldi, Arc, Yandex |
| `openroute-firefox-<version>.zip` | Firefox and Firefox-based browsers |
| `openroute-companion-<version>-<system>.zip` / `.tar.gz` | the optional companion app (see [Getting past address blocks](#getting-past-address-blocks)) |
| `install-server.sh` | the optional script for your own server |
| `SHA256SUMS` | checksums of all of the above |

<details>
<summary><b>Checking a download (optional)</b></summary>

Compare the file's SHA-256 with its line in `SHA256SUMS`:

- **Windows (PowerShell):** `Get-FileHash .\openroute-chromium-1.0.0.zip`
- **macOS:** `shasum -a 256 openroute-chromium-1.0.0.zip`
- **Linux:** `sha256sum openroute-chromium-1.0.0.zip`

With the [GitHub CLI](https://cli.github.com) you can also verify that the
file was built by this repository's release workflow:

```sh
gh attestation verify openroute-chromium-1.0.0.zip --repo amibhai/OpenRoute
```
</details>

### Chrome, Edge, Brave, Opera, Vivaldi

**1. Download** `openroute-chromium-<version>.zip` from the
[Releases page](https://github.com/amibhai/OpenRoute/releases).

**2. Unzip it somewhere permanent,** for example `Documents\OpenRoute` or
`~/OpenRoute`:
- **Windows:** right-click the zip → **Extract All…**
- **macOS:** double-click the zip.
- **Linux:** `unzip openroute-chromium-*.zip -d ~/OpenRoute`

⚠️ The browser loads the extension from this folder every time it starts, so
don't delete or move it later. Open the folder and check that you can see
`manifest.json` directly inside it.

**3. Open your browser's extensions page** by typing its address in the address
bar:

| browser | address | where the **Developer mode** switch is |
|---|---|---|
| Chrome | `chrome://extensions` | top right |
| Edge | `edge://extensions` | left sidebar |
| Brave | `brave://extensions` | top right |
| Opera | `opera://extensions` | top right |
| Vivaldi | `vivaldi://extensions` | top right |

**4. Turn on Developer mode.** New buttons appear.

**5. Click Load unpacked** and choose the folder from step 2, the one with
`manifest.json` directly inside.

**6. Pin the button to your toolbar** so its badge is always visible:
- **Chrome, Brave:** click the puzzle-piece icon 🧩, then the pin next to
  OpenRoute.
- **Edge:** click the puzzle-piece icon, then the eye icon (**Show in
  toolbar**).
- **Opera:** click the cube icon, then the pin.

**7. A welcome page opens.** Continue with [The first five minutes](#the-first-five-minutes).

> Some browsers occasionally remind you that a "developer mode extension" is
> installed. That's expected for extensions installed this way: keep it
> enabled.

### Firefox (desktop)

Firefox normally installs only add-ons signed by Mozilla. Until OpenRoute is on
addons.mozilla.org, pick one of these:

**Option A: temporary install (any Firefox; removed when Firefox restarts)**

1. Download `openroute-firefox-<version>.zip` from the
   [Releases page](https://github.com/amibhai/OpenRoute/releases).
2. Type `about:debugging#/runtime/this-firefox` in the address bar.
3. Click **Load Temporary Add-on…** and choose the zip file.
4. The welcome page opens. Go on to [step 1 of The first five
   minutes](#the-first-five-minutes) and allow **Access to all sites**:
   Firefox needs it before OpenRoute can route anything.
5. Pin it: click the puzzle-piece icon, then the gear next to OpenRoute, then
   **Pin to Toolbar**.

After a restart, repeat steps 2–3. Your settings are kept.

**Option B: permanent install (Firefox Developer Edition, Nightly or ESR only)**

1. Type `about:config` in the address bar and accept the warning.
2. Search for `xpinstall.signatures.required` and set it to **false**.
3. Rename the downloaded `openroute-firefox-<version>.zip` to
   `openroute-firefox-<version>.xpi`.
4. Open `about:addons`, click the gear ⚙, choose **Install Add-on From File…**,
   pick the `.xpi`, and click **Add**.
5. Allow **Access to all sites** when the welcome page asks, and pin the button
   as in option A.

(Regular Firefox ignores step 2 by design. Use option A there.)

### Firefox for Android

This version builds and passes Mozilla's checks. However, Firefox for Android
installs add-ons from addons.mozilla.org, so it becomes a one-tap install once
OpenRoute is listed there. On Android, OpenRoute can route through Orbot or
v2rayNG running on the phone. The companion app is desktop-only.

### Safari

It isn't supported: Safari gives extensions no way to route traffic.

---

## The first five minutes

**1. Allow what the welcome page asks for.**
- **Firefox** needs **Access to all sites**, required to route the blocked
  ones. OpenRoute never reads page content.
- **Firefox also offers the encrypted-DNS check** (optional): when a site
  fails, its domain is checked with an encrypted resolver to tell DNS tampering
  from other blocks. Without it, nothing leaves your browser and routing still
  works.
- **Chromium browsers** need nothing extra to start.

**2. Turn on Secure DNS.** This is the single most effective step, because DNS
tampering is the most common block and this fixes it at full speed for every
site. The welcome page's **Open Secure DNS settings** button takes you there.
By hand:

| browser | where | what to choose |
|---|---|---|
| Chrome | `chrome://settings/security` | **Use secure DNS** → on → *Cloudflare (1.1.1.1)* or *Google (Public DNS)* |
| Edge | `edge://settings/privacy/security` | **Use secure DNS…** → on → **Choose a service provider** → Cloudflare |
| Brave | `brave://settings/security` | **Use secure DNS** → on → Cloudflare |
| Opera | `opera://settings/security` | **Use DNS-over-HTTPS** → on → Cloudflare |
| Vivaldi | `chrome://settings/security` (Vivaldi keeps Chromium's page) | **Use secure DNS** → on → Cloudflare |
| Firefox | `about:preferences#privacy` → **DNS over HTTPS** | **Increased Protection** or **Max Protection**, provider Cloudflare or NextDNS |

On a work or school computer, this setting may be locked by your administrator.

**3. Check that it works.** Open any website and click the OpenRoute button.
The **This site** card should say **Direct**: the site loads directly, and
OpenRoute steps in only if a site fails.

That's enough for most people. If a site is blocked by its address, read on.

---

## Getting past address blocks

Some blocks, by IP address or deep inspection, can't be fixed by DNS. For
those, OpenRoute needs **somewhere unblocked to route through**, called a
*transport*. Choose whichever suits you. You can add several, and OpenRoute
fails over between them.

### Option 1: Tor Browser (free, nothing to configure)

1. Install [Tor Browser](https://www.torproject.org/download/) and start it.
   Keep it running in the background.
2. In OpenRoute's popup, click **Find local proxies**. It should report *Tor
   Browser (9150)*.

Tor is slower, but free and hard to block. If Tor itself is blocked where you
are, choose a bridge in Tor Browser's connection settings.

### Option 2: a proxy app you already use

v2rayN, Clash / Clash Verge / Mihomo, NekoBox, Hiddify, Orbot (Android) and
plain SOCKS or Privoxy setups are all found automatically on their usual
ports. Start the app, then click **Find local proxies** in the popup.

### Option 3: any SOCKS5 or HTTP(S) proxy

1. In the popup, click **Add or manage transports**. The dashboard opens on
   **Transports**.
2. Under **Add a proxy**, fill in:
   - **Name:** anything, e.g. *My VPS*.
   - **Type:** SOCKS5, HTTP, HTTPS or SOCKS4.
   - **Host** and **Port.**
   - If it needs one, a **Login (optional)**: username and password.
3. Click **Add a transport**. It's tested right away, and you're told whether it
   works and how fast it is.

Chromium browsers can log in only to HTTP(S) proxies; they ask for site access
the first time. For a SOCKS proxy with a login, use the companion app.

### Option 4: your own server, through the companion app (strongest)

**Your own server.** On a cheap VPS, run the [server script](server/):

```sh
curl -fsSLO https://github.com/amibhai/OpenRoute/releases/latest/download/install-server.sh
sudo bash install-server.sh
```

It sets up VLESS-Reality, Shadowsocks-2022 and optionally Hysteria2, then prints
**share links**. The [server guide](server/) explains every option.

**The companion app** runs those tunnels for your browser. It also runs DPI
bypass and Tor:

1. Download the archive for your computer from the
   [Releases page](https://github.com/amibhai/OpenRoute/releases), for example
   `…-windows-amd64.zip`, `…-darwin-arm64.tar.gz` (Apple silicon) or
   `…-linux-amd64.tar.gz`, and unpack it.
2. Get [sing-box](https://github.com/SagerNet/sing-box/releases), version 1.12
   or newer:
   - **Windows:** the `windows-amd64` zip.
   - **macOS:** `brew install sing-box`.
   - **Linux:** your package manager, or the release archive.
3. Run the installer from the unpacked folder:
   - **Windows (PowerShell):**
     `powershell -ExecutionPolicy Bypass -File .\install-windows.ps1 -SingBox C:\path\to\sing-box.exe`
   - **macOS / Linux:** `./install-unix.sh --sing-box /path/to/sing-box`

   It registers the companion with every browser it finds and finishes with a
   self-check. If Windows SmartScreen warns about the program, click **More
   info → Run anyway**. On macOS, if it's blocked, allow it under **System
   Settings → Privacy & Security**.
4. Restart your browser. In the dashboard, under **Transports → Companion
   app**:
   - paste your share links under **Your server, or a pool** (one per line) →
     **Connect**;
   - or click **Turn on DPI bypass** (no server needed);
   - or choose a **Mode** under **Tor** → **Start Tor**. *Automatic* tries each
     bridge type in turn.

Details: [companion guide](companion/) · [server guide](server/).

---

## Using OpenRoute day to day

**Just browse.** When a site fails to load, OpenRoute diagnoses it, routes it if
it can, and reloads the tab. You don't have to do anything.

**The popup**, opened by clicking the toolbar button:

- **This site** shows how OpenRoute is handling the page you're on, with one
  button for what to do next:

  | status | meaning | buttons |
  |---|---|---|
  | **Direct** | loads normally; OpenRoute isn't involved | **Route this site** to send it through a transport anyway |
  | **Routing…** | just routed; not yet confirmed working | **Reload page**, **Stop routing** |
  | **Working** | works, e.g. *Working through My VPS, 84 ms away* | **Stop routing** |
  | **Blocked** / **Needs you** | diagnosed, with the fix explained | **Turn on Secure DNS** (DNS blocks), **Route this site** |
  | **No route left** | every transport failed; retried automatically | **Try again now**, **Add a transport** |
  | **Manual** | you chose its route by hand | **Back to automatic** |
  | **Never routed** | you told OpenRoute to leave it alone | **Remove that rule** |

- **The mode switch:**
  - **Smart:** route only blocked sites. This is the default.
  - **All sites:** route everything through your best transport, like a VPN.
  - **Off:** route nothing.
- **Transports:** each one's health and speed, plus **Find local proxies**.
- **Sites:** recent blocked sites. **Manage** opens them in the dashboard.

**The badge on each tab:**
- **✓** means this site is routed and working.
- **…** means it's being routed.
- **!** means it's blocked.
- **No badge, or a number,** means OpenRoute isn't handling this site. The
  number counts sites that need you.

**Shortcuts:** right-click any page → **Route this site through OpenRoute (or
stop)** or **Never route this site**. Or press **Alt+Shift+O** to route or stop
routing the current site. To change the key, go to `chrome://extensions/shortcuts`,
or in Firefox to `about:addons` → gear ⚙ → **Manage Extension Shortcuts**.

**The dashboard**, the gear ⚙ in the popup:

| section | what you can do |
|---|---|
| **Sites** | search and filter every blocked site. Open one for its diagnosis, history and real address, choose its **Route**, **Route now**, add **Always route** or **Never route**, **Forget** it, or open a **Wayback copy** or **Reader view** |
| **Transports** | **Test** each transport, **Make preferred**, **Remove**, add a proxy, find local ones, and control the companion app (your server, DPI bypass, Tor: new identity, refresh bridges, status) |
| **DNS** | open Secure DNS settings, pick the resolver for diagnosis (or your own DoH endpoint), turn the encrypted-DNS check on or off |
| **Rules** | domains to **Always route** or **Never route**, covering everything under them |
| **Settings** | mode; whether to route the whole site or only the exact host; routing a site's own CDNs with it; automatic routing and reloading; deep detection; WebRTC leak protection; **Export backup** / **Import backup**; **Reset everything** |
| **Diagnostics** | the routing engine's status, a **Timeline** of what happened and why, and **Download report** for bug reports, with site names hidden by default and addresses and passwords never included |

**When a site still won't load:**
1. Open the popup or **Dashboard → Sites** and read the diagnosis.
2. If it says the block is by address, add a transport (see [above](#getting-past-address-blocks)), or try another with **Route** in its row.
3. If every transport fails, try Tor. For reading only, use **Wayback copy** or
   **Reader view**.
4. Still stuck? Send a bug report with **Diagnostics → Download report**.

---

## Updating

- **Chrome, Edge, Brave, Opera, Vivaldi:** download the new zip and unzip it
  **over the same folder**, replacing the files. Then open the extensions page
  and click **Reload** (↻) on OpenRoute. Your settings are kept: they live in the
  browser, not the folder.
- **Firefox, temporary install:** load the new zip in `about:debugging`.
  **Permanent install:** install the new `.xpi` the same way you did the first.
- **Companion app:** unpack the new archive and run its installer again.
- **Your server:** run `sudo bash install-server.sh` again. It upgrades in place
  and keeps your links.

## Uninstalling

- **The extension:** on the extensions page, click **Remove**. This deletes all
  its data too.
- **The companion app:** the installer keeps a copy of the program in
  `%APPDATA%\OpenRoute` on Windows and `~/.openroute` elsewhere.
  1. Run `openroute-companion uninstall` from that folder, or from the unpacked
     archive. It unregisters the companion from every browser.
  2. Delete that folder.
- **Your server:** run `sudo bash install-server.sh uninstall`. Add `--purge` to
  remove sing-box too.

## Troubleshooting

| problem | fix |
|---|---|
| "Manifest file is missing or unreadable" | You picked the wrong folder. Choose the one with `manifest.json` **directly** inside (zips sometimes add an extra folder level). |
| The extension is gone after a restart | Chromium: the folder was moved or deleted; it must stay put. Firefox: temporary add-ons are removed on restart by design (see option B). |
| No button in the toolbar | Pin it: puzzle-piece icon → pin. |
| "Another extension controls the proxy settings" | Turn off other VPN or proxy extensions. Only one extension can control the proxy at a time. |
| Firefox: "needs access to all sites" | Click **Allow** in the popup, or in `about:addons` → OpenRoute → **Permissions**, turn on access to all websites. |
| A site stays blocked | See [When a site still won't load](#using-openroute-day-to-day). |
| Companion shows **Not installed** | Run the companion's installer again (it ends with a self-check) and restart the browser. For the checklist on its own, run `openroute-companion doctor` from `%APPDATA%\OpenRoute` or `~/.openroute`. |
| Alt+Shift+O does nothing | Another extension may use that shortcut. Pick another (see Shortcuts above). |
| Secure DNS setting is greyed out | Your administrator manages it. OpenRoute still routes blocked sites through your transports. |

---

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

Where a browser can't route, OpenRoute still diagnoses blocks and tells you how
to fix them.

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

To run from source, load this repository's root folder as an unpacked
extension.

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
