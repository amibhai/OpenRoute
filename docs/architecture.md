# Architecture

OpenRoute is three programs. Each works without the next.

```
 browser extension ──── routes blocked sites through ───▶ transports
  (src/, every browser)                                    │
        │ native messaging (optional)                      ├─ any SOCKS/HTTP proxy you run (Tor Browser, v2rayN, Clash…)
        ▼                                                  ├─ the companion's local SOCKS ports
 companion app ── runs sing-box and tor ───────────────────┤    (your server pool, DPI bypass, Tor)
  (companion/, Go)                                         └─ …which reach your own server
                                                                (server/install-server.sh on a VPS)
```

## The extension

The extension is plain ES modules with no runtime dependencies. The
background runs as an MV3 service worker in Chromium and as an event page in
Firefox. `createBackground()` builds a self-contained instance with no
module-level state, so a worker restart, or a test, always starts clean.
Listeners are registered synchronously at start-up, because a listener added
later doesn't wake a suspended worker.

```
src/background/
  index.js           entry: create, register listeners, init
  background.js      wiring: navigation → diagnosis → ladder → router; per-tab badges,
                     context menu, keyboard command, maintenance alarm (5 min)
  platform.js        capability detection (proxy.onRequest → Firefox engine,
                     proxy.settings → Chromium PAC, neither → diagnose-only),
                     browser identity, Secure DNS guidance, permission status
  store.js           one serialized transaction queue over storage.local/session;
                     schema migration from 0.3
  errors.js          Chromium net::ERR_* and Firefox nsresult/NSS codes → one taxonomy
                     (ignore / offline / DNS / TLS / connection / proxy / policy …)
  diagnosis.js       error kind + DoH evidence → block type (dns-tampering, sni-dpi,
                     ip-block, http-451, dns-blockpage …) and the first rung to try
  dns/wire.js        RFC 8484 wire format: padded queries; A/AAAA/CNAME/HTTPS/SVCB answers
  dns/doh.js         7 resolvers × hostname and IP-literal endpoints; staggered racing
                     (250 ms, 5 s cap); second opinions for NXDOMAIN or bogon answers;
                     per-endpoint health; ECH detection (SvcParam 5)
  dns/bogons.js      every IANA special-purpose range
  ladder.js          per-domain policy state machine (below); bounded auto-reload;
                     backoff retries; de-escalation; re-homing when a transport goes
  policy.js          rungs, statuses, backoff schedule, caps (300 sites, 500 policies)
  probe.js           active probes: a plain-HTTP request carrying a marker that the
                     routing table sends through one specific transport; local discovery
  transports/        registry (validation, ranking, presets) and health (EWMA latency,
                     circuit breaker that recovers)
  routing/table.js   policies + rules + health → routes: failover chains (primary + 2),
                     never DIRECT for a routed domain
  routing/pac.js     Chromium PAC (FindProxyForURL, ASCII-only, probe markers)
  routing/engines.js Chromium (PAC, held only while something is routed) and Firefox
                     (proxy.onRequest; returns nothing for traffic that isn't ours)
  routing/router.js  serialized applies, probe and exclusion windows, DoH through a
                     transport when encrypted DNS is blocked
  detect/requests.js deep detection: block pages from injected private addresses,
                     HTTP 451, blocked subresources of routed sites
  domains/           Public Suffix List (registrable-domain routing) and site bundles
  companion.js       native-messaging client
  messages.js        the API the pages use, every request validated; site grouping,
                     backup/import, reset, redacted diagnostics report
  eventlog.js        ring buffer of the last 300 decisions, with reasons
src/shared/          hostnames (validation, suffix lookup), i18n lookup
src/ui/              popup, dashboard (options), onboarding; shared design tokens and DOM helpers
_locales/en/         every user-visible string
```

### A blocked page, step by step

1. `webNavigation.onErrorOccurred` fires for a top-level frame. Aborts, offline
   errors, ad blockers, prerenders and subframes are dropped.
2. If the domain is already routed, its route failed. `onRouteFailure` decides,
   using Chromium's real failover semantics, which transports the browser has
   already tried. The site's diagnosis stays as it was.
3. Otherwise the host is diagnosed:
   - a DoH lookup (with the user's consent in Firefox);
   - Firefox's own resolver with TRR off, as local evidence;
   - classification into a block type, recorded in `sites`.
4. The ladder picks a rung:
   - **guidance** (turn on Secure DNS) for DNS blocks Secure DNS fixes;
   - **proxy** through the best *verified* transport: a fresh probe runs first,
     so a site is never sent down a dead tunnel;
   - **exhausted**, with a retry time, when nothing works.
5. The router compiles the table and installs it, as a PAC in Chromium or a
   lookup table in Firefox. The tab reloads at most three times per domain
   every two minutes, and only while it still shows the failed site.
6. `webNavigation.onCompleted` on the new route marks the policy **fixed**. The
   tab's badge turns to ✓.

### Policy states

```
blocked ──▶ routing ──▶ fixed ──(direct works again ×2)──▶ removed
   │           │
   │           └─(every transport failed)──▶ exhausted ──(backoff 10 min…24 h,
   │                                                       or a new or recovered transport)──▶ routing
   └─(only the user can fix it)──▶ needs-user
manual: the user pinned a rung by hand.  Rules: always / never route.
```

### Storage

- **`storage.local`** holds:
  - `settings`, `rules`, `transports`, `activeTransportId`;
  - `policies`, `sites`, `transportHealth`;
  - `eventLog`, `schemaVersion`.
- **`storage.session`** holds:
  - `tabHosts`: which site each tab shows, for its badge;
  - `reloads`: the reload budget;
  - `dohVia`: encrypted DNS reached through a transport.

### Pages

The pages never write storage. They send messages and re-render on
`storage.onChanged`.

- **Popup:** the tab's site and its one next action, the mode switch, transports,
  and recent sites.
- **Dashboard:** Sites, Transports with the companion, DNS, Rules, Settings and
  Diagnostics.

**i18n.** Strings live in `_locales/*/messages.json`, with `{name}` placeholders
that `src/shared/i18n.js` fills. Pages carry `data-i18n` markers only. A page
takes its `lang` and `dir` from the messages actually shown.

**Design.** `src/ui/shared/base.css` holds the tokens, which meet WCAG AA in
light and dark mode. Layout uses logical properties, so right-to-left just
works.

## The companion

One Go binary, standard library only:

```
browser ─native messaging─▶ host (per message, stateless; checks the caller's extension ID)
                              │ Unix-domain socket in the user's private data directory
                              ▼
                            daemon (desired state on disk; idle exit after 15 min)
                              ├─ sing-box: pool (urltest), DPI-record, DPI-segment inbounds on 127.0.0.1
                              └─ tor: SocksPort, cookie-authenticated control port, bridges via lyrebird
```

- **Child processes.** They're supervised: restarts back off, and a crash loop
  is given up on with the reason reported. They die with the daemon (a Windows
  job object, Linux `Pdeathsig`, process groups elsewhere).
- **Before sing-box starts,** every config passes `sing-box check`. The start
  only counts once its ports listen.
- **Share links** become sing-box outbounds:
  - Shadowsocks (SIP002, 2022 and legacy), VLESS (Reality and TLS), VMess,
    Trojan, Hysteria2, TUIC, WireGuard, SOCKS/HTTP with logins, raw JSON, and
    subscriptions;
  - certificate pins map to `certificate_public_key_sha256`;
  - anything sing-box can't do is refused with a reason.
- **Each maintenance tick,** the extension syncs its transports with what the
  daemon runs.

## The server script

`server/install-server.sh` is one readable bash file. It provides the commands
`install` (an idempotent upgrade that keeps credentials), `show`, `rotate`,
`doctor`, `uninstall`, and `generate` (files only, no system changes; the
tests drive this one).

- **Paths and tests.** Every system path hangs off `$OPENROUTE_ROOT`, so the
  test suite runs the real flows against a scratch directory with stand-ins
  for systemctl & co.
- **State and config.** State lives in `/etc/openroute-server/state.env`,
  readable by root only, as plain key-value pairs that are parsed, never
  sourced. The sing-box config is generated from it and checked by sing-box
  before use.
- **The service** is its own unit, `openroute-server.service`, running as its
  own user in a systemd sandbox. The vendor's `sing-box.service` is left alone.

## Builds and releases

- **`scripts/build.mjs`** writes the browser packages:
  - `chromium`, which keeps the manifest `key`, so the unpacked ID is stable
    and pre-authorized by the companion;
  - `chromium-store`;
  - `firefox`: an event page, the gecko ID, the data-consent declaration and
    the `dns` API;
  - `test`.

  It checks every referenced file and every manifest message, and the zips are
  deterministic.
- **The release workflow** adds:
  - companion archives for six platforms;
  - the server script;
  - `SHA256SUMS`;
  - SLSA build provenance for every file.
