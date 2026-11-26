# Changelog

Notable changes to OpenRoute. Versions follow [Semantic Versioning](https://semver.org).

## [Unreleased]

## [1.0.0] — 2026-11-26

A rebuild of the extension, the companion and the server script. 0.3
diagnosed blocks, but most of its routing didn't work. 1.0 routes reliably in
every Chromium browser and in Firefox, and is tested end to end in real
browsers against real sing-box and Tor.

### Fixed — broken in 0.3

- **Chromium routed nothing.**
  - **Cause:** the generated PAC defined `FindProxyForHost`, which Chromium
    never calls, so every request silently went direct.
  - **Fix:** routing now uses `FindProxyForURL`, with ASCII-only scripts.
    Chromium rejects anything else.
- **Firefox routed nothing.** The proxy engine was picked wrongly, and every
  Firefox network error was classified as "unknown".
- **The companion and the server wrote configs that current sing-box rejects.**
  The companion also reported success when sing-box never started.
- **The maintenance timer was reset on every wake** of a busy browser, so
  health checks never ran.
- **Routing mistakes:**
  - a reload loop for a pinned site whose proxy was down;
  - an unreachable encrypted-DNS resolver read as "domain doesn't exist";
  - offline, aborted, ad-blocked and prerendered loads were routed;
  - proxy errors overwrote a site's diagnosis.
- **Routes were permanent:**
  - a site that ran out of routes stayed that way for good;
  - routes never expired;
  - removing a transport stranded its sites.
- **Security:**
  - **SSRF on the server.** A client could reach the server's own network
    and cloud metadata services by *hostname*. The server now resolves names
    before checking addresses.
  - **The companion killed by PID file,** so after a reboot it could kill an
    unrelated process.
  - **Tor's control port was unauthenticated.**
  - **The popup inserted transport names as HTML.**
  - **Page messages weren't validated.**
  - **Installs used `curl | sh`.**
- **Store blocker.** The store description was 175 characters; the Chrome Web
  Store allows 132.

### Added

**Detection and diagnosis**
- **Encrypted DNS** now uses RFC 8484 wire format with padding, across seven
  resolvers that race each other, with second opinions on suspicious answers.
- **ECH detection** reads the site's HTTPS record.
- **Encrypted DNS through a transport** where it's blocked.
- **Firefox local-resolver evidence,** and Firefox's built-in data consent:
  without it, no domain leaves the browser.
- **Deep detection** catches block pages served from injected addresses,
  HTTP 451, and blocked resources of routed sites.

**Routing**
- **Active probes.** No site is sent down an untested transport, and probes,
  not page failures, decide health.
- **Failover chains** (primary + 2), never ending in a direct connection.
- **Health checks** on transports that carry traffic.
- **Discovery** of local proxies: Tor Browser, Tor, v2rayN, Clash, NekoBox,
  Hiddify and others.
- **Registrable-domain routing** via the Public Suffix List, and site bundles
  (a site's own CDNs ride along).
- **Modes:** Smart, All sites, Off. **Rules:** always and never route.
- **De-escalation:** routed sites go back to direct once they work directly
  again.
- **Proxy logins** for HTTP(S) proxies, and optional WebRTC leak protection.

**Companion**
- **A supervised daemon** behind a stateless native-messaging host, talking
  over a Unix socket. No TCP control ports.
- **sing-box 1.12+ configs,** checked by sing-box before every start.
- **Share links:** SS-2022 (the SIP002 form), VLESS-Reality, VMess, Trojan,
  Hysteria2, TUIC, WireGuard, logins and subscriptions.
- **Certificate pinning** for self-signed servers.
- **A serverless DPI-bypass rung** (TLS record or TCP-segment splitting).
- **Tor:** direct, obfs4, Snowflake (via lyrebird), meek, WebTunnel and auto,
  with built-in or fresh bridges and new identity.
- **One-command install** for every Chromium-family and Firefox-family browser
  on Windows, macOS and Linux.

**Server**
- **Commands:** `install` (an idempotent upgrade), `show`, `rotate`, `doctor`,
  `uninstall` and `generate`.
- **Verified sing-box:** from SagerNet's signed repository with an embedded,
  fingerprint-checked key, or from a release pinned to its SHA-256.
- **Sandboxed** under its own user and unit.
- **Reality** with an automatically chosen, checked cover site, plus optional
  pinned Hysteria2.
- **Firewall handling:** ufw, firewalld and iptables, including Oracle Cloud's
  images. Also BBR and clock sync.
- **Upgrades a 0.3 server in place,** keeping its links.

**Interface**
- **Popup:** built around the site you're on, with a mode switch and
  transport health.
- **Dashboard:** Sites, Transports with the companion, DNS, Rules, Settings
  (including backup and restore) and Diagnostics (a timeline, and a redacted
  report).
- **Per-tab badges,** the right-click "Route this site", and Alt+Shift+O.
- **Every string localizable;** the layout handles right-to-left languages.
  Audited in a real browser for accessible names and WCAG AA contrast, in
  light and dark mode.

**Builds, tests and releases**
- **Per-browser packages** from one manifest, as deterministic zips.
- **Tests:**
  - 156 unit tests, 17 real-browser e2e tests (12 Chromium, 5 Firefox) and
    22 Go tests against real sing-box and Tor;
  - server-script tests, plus a matrix on Chromium, Edge, Brave and Firefox.
- **CI on three operating systems,** including a real server install.
- **Releases** with checksums and SLSA build provenance.

### Removed

- `manifest.firefox.json`. The Firefox manifest is now generated by
  `scripts/build.mjs`.
- The companion's old line protocol. The companion's README describes the
  current protocol.

## [0.3.0]

The first public version: block detection and DoH diagnosis, a popup, an early
failover ladder, and scaffolding for the companion and the server script.
