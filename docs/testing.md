# Testing

The rule: **test against the real thing wherever possible**:
- configs go through real `sing-box check`;
- Tor configs go through real `tor --verify-config`;
- tunnels carry real traffic;
- the UI is audited in a real browser.

Where a stand-in is unavoidable, it's small and explicit. Tests that guard
something were checked by **breaking that thing on purpose** and watching the
test fail.

## The layers

| layer | command | what it proves |
|---|---|---|
| unit, 156 tests | `npm test` | the background's behavior, black-box, against an in-memory browser (`test/helpers/webext-mock.mjs`, in Chromium and Firefox flavors), a fake DoH zone, a simulated network, and generated PAC scripts run in a VM the way Chromium runs them; plus the i18n checks |
| Chromium e2e, 12 tests | `npm run test:e2e` | in real Chromium against local fixture servers and a real SOCKS5 proxy: block → diagnose → route → reload → load; split tunnel; remote DNS; PAC failover past a dead hop; probing and discovery; HTTP 451; the UI audit (below) |
| Firefox e2e, 5 tests | `npm run test:e2e` | in real Firefox: routing through `proxy.onRequest`; nothing sent to a resolver without consent; split tunnel; routing still works after the event page is suspended; discovery |
| browser matrix | `npm run test:e2e:matrix` | the e2e suites on Chromium, Edge, Brave and Firefox, whichever are installed (last run: all four pass) |
| companion, 22 Go tests | `npm run test:companion` | real sing-box 1.12.x and latest accept every config shape; real Tor accepts every torrc; host → daemon → sing-box → a real Shadowsocks-2022 server → a site, with a negative control; supervisor give-up; orphan safety; link parsing; certificate pins |
| server, e2e (in the Go suite) | `npm run test:companion` | the script's generated config, served by real sing-box, carries traffic through every link it prints (VLESS-Reality, SS-2022, pinned Hysteria2), parsed and configured by the companion's own code, on sing-box 1.12 and 1.14. The same tunnels refuse a loopback target by address and by name. Deleting the script's `resolve` rule or its private-address rules makes this fail |
| server flows, 12 tests | `npm run test:server` | install, re-install, Hysteria2 on and off, rotate, new ports, doctor, uninstall, the v0.3 upgrade; ufw, firewalld and iptables; port conflicts; cover-site choice; IP changes; the package-repository path; a download that fails its checksum. Run for real against stand-ins (`test/server/fakes/`); sing-box and openssl are real |
| live | `npm run test:live` | every DoH endpoint answers from inside real Chromium; the SagerNet key embedded in the server script verifies today's apt and rpm repository signatures, and a tampered file fails |
| static | `npm run lint`, `lint:sh`, `lint:ci`, `lint:firefox` | eslint; shellcheck at style level on every shell script; actionlint (with shellcheck) on the workflows; Mozilla's add-on linter, 0 errors / 0 warnings / 0 notices |

**The UI audit** (`test/e2e/chromium-ui.test.mjs`) opens the popup and every
dashboard section in a real browser. It checks that:
- nothing logs an error;
- every string is translated;
- every control has an accessible name;
- every piece of visible text meets WCAG AA contrast, measured against its real
  composited background, in light and dark mode;
- nothing overflows horizontally, right-to-left or at phone width.

It then drives the main actions, including routing another tab's site from the
popup through a real proxy and seeing that tab's badge turn to ✓.

## CI

`.github/workflows/ci.yml` runs:
- everything above except the live tests;
- the companion on Linux, Windows and macOS;
- **a real install of the server on a fresh Ubuntu runner with systemd**:
  1. installs the pinned sing-box release, checked against its built-in
     SHA-256;
  2. checks that the service runs sandboxed as its own user;
  3. runs `doctor`;
  4. pushes traffic through every link it printed;
  5. confirms the server's loopback stays closed;
  6. re-runs install (the links must stay identical);
  7. rotates (they must change);
  8. uninstalls (nothing may remain).

`OPENROUTE_REQUIRE_TOOLS=1` turns "tool missing → skip" into a failure, so a
broken download can't pass as green.

## Not covered yet

Saying so plainly:
- **Real censorship.** No test runs inside a censored network. Block types are
  reproduced with host-resolver rules, closed ports and fixture servers.
- **Browsers without automation.** Opera, Vivaldi, Arc, Yandex and the Firefox
  forks aren't automated. Firefox for Android is built and linted, but not run
  on a device. Branded Google Chrome refuses automated extension loading, so
  Chromium stands in for it.
- **Store installs.** Store-signed and AMO-signed installs aren't covered; the
  e2e suites load the extension unpacked or as a temporary add-on.
- **Companion installers.** They register real browsers' native-messaging
  manifests, which the tests don't do to the developer's machine. That's
  deliberate: no registry or home-directory writes.
- **Other Linux distributions.** The server script is exercised for real on
  Ubuntu only in CI. Debian, Fedora and RHEL are covered by the stand-in tests.
