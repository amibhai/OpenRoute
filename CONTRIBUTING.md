# Contributing

Thanks for helping. Issues and pull requests are welcome at
<https://github.com/amibhai/OpenRoute>.

**Most valuable right now:**
- Real-world reports: what blocking you hit, what OpenRoute diagnosed, and
  whether it got you through. Attach *Dashboard → Diagnostics → Download
  report*; it hides site names by default.
- Runs on browsers we don't test end to end yet: Opera, Vivaldi, Arc, Yandex,
  LibreWolf, Floorp, Zen, and Firefox for Android.
- Translations (see below).
- Running the server script on distributions other than Ubuntu.

Security problems go to the private channel in [SECURITY.md](SECURITY.md), not
a public issue.

## Setup

You need Node 22 or newer. That's all: everything else is downloaded into the
project folder.

```sh
npm ci               # dev tools only: eslint, web-ext, Playwright, Selenium
npm run setup-tools  # Go, sing-box 1.12.x + latest, Tor, geckodriver,
                     # shellcheck, actionlint into .tools/, each checked
                     # against its published SHA-256 (nothing system-wide)
npx playwright install chromium   # the browser the e2e tests drive
```

To try your changes, load the repository root as an unpacked extension
(`chrome://extensions` → *Developer mode* → *Load unpacked*). Reload it there
after you edit.

## Commands

| command | what it does |
|---|---|
| `npm run lint` | eslint over the extension, scripts and tests |
| `npm test` | unit tests: the background against an in-memory browser, PAC scripts in a VM, a fake DoH zone, plus the i18n checks |
| `npm run test:e2e` | real Chromium (routing, probing, deep detection, the UI audit) and real Firefox |
| `npm run test:e2e:matrix` | the e2e suites on Chromium, Edge, Brave and Firefox, whichever are installed |
| `npm run test:companion` | `go vet` + `go test` for the companion, against real sing-box and Tor |
| `npm run test:server` | the server script's install, rotate, doctor, uninstall and upgrade flows against stand-ins for systemctl & co. |
| `npm run test:live` | the real internet: every DoH endpoint from inside Chromium, and SagerNet's repository signatures |
| `npm run lint:sh` | shellcheck over every shell script |
| `npm run lint:ci` | actionlint over the GitHub workflows |
| `npm run lint:firefox` | Mozilla's add-on linter on the Firefox build |
| `npm run build` | every package into `dist/`, deterministic, with `SHA256SUMS` |

CI runs all of these except the live tests. It also installs the server for
real on a fresh Ubuntu.

## Ground rules

- **The extension has no runtime dependencies.** It's plain ES modules. Dev
  tooling is fine.
- **Every string users see goes in `_locales/en/messages.json`.**
  - Pages mark text with `data-i18n="key"`, or `data-i18n-attr="placeholder:key"`
    for attributes.
  - Code calls `t("key", { name })`.
  - Placeholders are written `{name}`.
  - `npm test` fails on a missing key, an unused one, text written straight into
    a page, or a placeholder a call doesn't fill.
- **Insert text, never HTML.** Build DOM with `el()` and `textContent`.
- **The background is the only writer.** Pages ask it through validated
  messages (`src/background/messages.js`).
- **Test behavior, against real tools where possible.**
  - Configs are checked by real `sing-box check`, torrc by real
    `tor --verify-config`, and the UI in a real browser.
  - A new test should fail when the thing it guards is broken. Try it by
    breaking it.
- **The companion uses Go's standard library only.** It must stay `gofmt` and
  `go vet` clean.
- **Shell scripts must stay shellcheck-clean,** at style level.

## Adding a language

1. Copy `_locales/en/messages.json` to `_locales/<code>/messages.json`. Use the
   browser's code style, e.g. `fa`, `ru`, `zh_CN`, `pt_BR`.
2. Translate each `"message"`:
   - Keep `{placeholders}` exactly as they are, and leave the keys alone.
   - The `"description"` says what each string is for.
3. Set `localeCode`, a BCP 47 tag such as `zh-CN`, and `localeDir`, either
   `rtl` or `ltr`. Pages take their language and direction from these, so
   right-to-left languages lay out mirrored.
4. Run `npm test`, then load the extension with your browser set to that
   language.

## Pull requests

- Keep each pull request to one logical change, with tests that would fail
  without it.
- `npm run lint`, `npm test` and the suites your change touches must pass. CI
  runs the rest.
- User-facing changes get a line under *Unreleased* in
  [CHANGELOG.md](CHANGELOG.md).
