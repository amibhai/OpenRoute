# Security

## Reporting a vulnerability

Please report it **privately**: on GitHub, open this repository's **Security**
tab and choose **Report a vulnerability**. That reaches the maintainers without
making the problem public. Don't open a public issue for a vulnerability.

A useful report says:
- the version;
- the browser, or for the companion and server, the operating system;
- what an attacker can do;
- how to reproduce it.

*Dashboard → Diagnostics → Download report* produces a redacted report you can
attach.

Supported: the latest release.

## Threat model

**Who OpenRoute is built against:** a network-level censor. That's an ISP or a
national filter that:
- tampers with or poisons DNS;
- filters by the site name in TLS (SNI, DPI);
- blocks addresses;
- injects block pages;
- actively probes servers it suspects of being proxies.

**What OpenRoute aims for:**
- Blocked sites load, through the cheapest rung that works.
- **A routed site never leaks back to the censored direct path.** There's no
  DIRECT fallback in either routing engine.
- Unrouted sites never touch a proxy.
- Your own server is hard to detect and can't be used against you:
  - Reality borrows a real site's TLS handshake, and active probers get that
    site;
  - Shadowsocks-2022 is replay-protected;
  - Hysteria2 is obfuscated, with its certificate pinned;
  - the server refuses clients' requests for its own network, cloud metadata
    services and outbound mail.

**What it doesn't protect against:**
- **Identification.** It isn't anonymity. The server or proxy you use sees
  which sites its traffic goes to, and a server you rent is tied to you. For
  anonymity, use Tor Browser.
- Malware on your device, a compromised browser, or a malicious extension that
  takes over proxy settings. OpenRoute detects that last case and tells you.
- A dishonest proxy or VPS provider. They can see traffic metadata, and
  anything not end-to-end encrypted.
- A global passive adversary, traffic analysis, or a censor who blocks
  everything except an allow-list.
- **Sophisticated DPI against the DPI-bypass rung.** Splitting the TLS
  handshake beats simple name filters only; OpenRoute moves on to a tunnel when
  it fails.

## How it's built to resist abuse

**Extension**
- **No remote code.** The CSP is strict (`script-src 'self'`), and there are no
  runtime dependencies.
- **Pages can't change state directly.** Every request is validated, and only
  the extension's own pages are accepted as senders.
- **No HTML injection.** Pages only ever insert text into the DOM, never HTML.
- **Least privilege.** Broad permissions are optional and asked for when a
  feature needs them.
- **Secrets stay in the background.** Proxy passwords never reach the
  extension's pages, and the diagnostics report never contains addresses or
  credentials.

**Companion**
- **Small attack surface.** It uses Go's standard library only, and the
  transport crypto lives in sing-box and Tor.
- **Only OpenRoute can call it.** The native-messaging host checks the calling
  extension's ID.
- **No network control ports.** It talks to its daemon over a Unix-domain
  socket in a user-private directory:
  - sing-box's API has a random secret;
  - Tor's control port uses cookie authentication.
- **Supervised child processes.**
  - The daemon runs sing-box and Tor as children that die with it.
  - Leftover processes are killed only after their executable is verified, so
    it never kills a process that merely reused a PID.
- **No silent security downgrades.**
  - Links that would turn certificate checks off while relying on a pin it
    can't check are refused.
  - Credentials are removed from logs.

**Server script**
- **Verified sing-box.** It comes from SagerNet's signed repository, trusting
  only the key embedded in the script, or from a release checked against a
  SHA-256 built into the script. There's no `curl | sh`.
- **Sandboxed service.** It runs as its own unprivileged user under a strict
  systemd sandbox, and every start runs `sing-box check` first.
- **Private destinations are refused, including by name.** The server resolves
  names before it checks addresses.
- **Credentials:**
  - every secret comes from `sing-box generate`;
  - state files are readable by root only;
  - `rotate` replaces every credential.

**Supply chain**
- **Checksum-verified dev tools.** Every tool is pinned to a published SHA-256
  and installed into the project folder.
- **Pinned CI actions.** Actions are pinned to commit SHAs and run with
  read-only tokens.
- **Reproducible builds.** Extension zips are deterministic, and Go builds are
  `-trimpath` with an empty build ID.
- **Release provenance.** Every release file carries SLSA build provenance.
  Verify it with `gh attestation verify <file> --repo amibhai/OpenRoute`.

## Known limitations

- Proxy passwords are stored unencrypted in the browser's extension storage
  (see [PRIVACY.md](PRIVACY.md)).
- Wayback and Reader view send the page's URL to those third parties, when you
  click them.
- **No independent security audit.** OpenRoute has never been audited.
