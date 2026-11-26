# Privacy

OpenRoute has **no telemetry, no analytics, no account and no remote
configuration**. Nothing about you or your browsing is sent to the project. This
page lists every network request OpenRoute itself makes: why it's made, what
it contains, and how to turn it off.

## The extension

**Checking a failing site with encrypted DNS.**
- **When:** a page fails to load, or a block page or HTTP 451 is detected.
- **What's sent:** the site's hostname only, never the path or the page. It goes
  to an encrypted-DNS (DNS over HTTPS, RFC 8484) resolver as a padded DNS query.
- **Which resolver:** the one chosen under *DNS*, Cloudflare by default, or your
  own endpoint. If an answer looks wrong (no such domain, or a private address),
  another resolver from the built-in list is asked for a second opinion:
  Cloudflare, Google, Quad9, AdGuard (unfiltered), Mullvad, NextDNS, DNS.SB.
- **If encrypted DNS is blocked where you are:** these queries go through one of
  your own transports for half an hour.
- **Turn it off:** *Dashboard → DNS → Check failing sites with encrypted DNS*.
  In Firefox, this check is off until you give consent; Firefox asks for it in
  its own add-on permissions.

**Health checks of your transports.**
- **When:** when you add a transport, every few minutes for transports that are
  carrying sites, and when you press *Test* or *Find local proxies*.
- **What's sent:** one small plain-HTTP request through the transport to an
  operating system's connectivity-check address:
  `connectivitycheck.gstatic.com/generate_204`, `detectportal.firefox.com/success.txt`
  or `captive.apple.com/hotspot-detect.html`.
- **What it reveals:** these services see a request from your transport's exit
  address. There are no cookies, no referrer and nothing identifying you.
- *Find local proxies* only tries ports on your own computer (`127.0.0.1`).

**Checking whether a routed site works directly again.**
- **When:** a day, then three, then seven days after a site was routed.
- **What's sent:** one request to the site's front page over your normal
  connection, without cookies or referrer. If it loads twice, the site goes back
  to direct.
- In Chromium browsers this check is skipped while you're using the site.

**Wayback and Reader view.** These run only when you click them. The page's URL
goes to `web.archive.org` or `r.jina.ai`.

**Routing itself.** Routed sites go through the transports you set up. Those
transports, and whoever runs them, see that traffic as any proxy would. Sites
you don't route never touch them.

## What's stored, and where

All of it lives in your browser's extension storage, on your device:
- your settings and rules;
- your transports;
- the sites that failed (at most 300) and their routing decisions (at most 500);
- transport health;
- a timeline of the last 300 routing events.

Proxy passwords are stored there too. They're never shown to the extension's
own pages, but browser storage isn't encrypted at rest, so protect your
computer account.

**You can see and remove everything:**
- *Dashboard → Sites* shows the sites, and *Forget all sites* removes them.
- *Settings → Reset everything* returns OpenRoute to a fresh install.
- Uninstalling the extension deletes all of it.

**Backup** (*Settings → Export backup*) writes your settings, rules and own
transports to a file on your computer. Proxy passwords are only included if you
tick the box.

**Bug report** (*Diagnostics → Download report*) writes a file on your computer;
nothing is uploaded.
- Site names are replaced by stand-ins like `site-1`, unless you untick that.
- Proxy addresses, usernames and passwords are never included.

## Permissions, and why

| permission | why |
|---|---|
| `proxy` | to route the blocked sites (and only those) |
| `webNavigation` | to notice when a page fails to load |
| `webRequest`, `webRequestAuthProvider` | deep detection (block pages, HTTP 451, blocked resources), and logging in to HTTP proxies that need it. Nothing is read from or changed in pages. |
| `storage`, `alarms` | your settings; the periodic health check |
| `nativeMessaging` | talking to the optional companion app |
| `activeTab` | the popup reads the address of the tab you opened it on |
| `contextMenus` | the right-click "Route this site" |
| site access to the DNS resolvers and connectivity-check hosts above | to make exactly those requests |
| *optional* access to all sites | Firefox: required to route at all. Chromium browsers: deep detection and proxy logins, asked for only when you turn those on |
| *optional* `privacy` | WebRTC leak protection, asked for when you turn it on |
| Firefox data consent "browsing activity" (*optional*) | the encrypted-DNS check above sends failing sites' domains to a resolver |

OpenRoute never reads or changes page content.

## The companion app (optional)

The companion runs on your computer and starts tunnels the browser can't run
itself. Beyond the tunnels you configure, it makes these requests:
- **Name lookups for routed traffic** go over encrypted DNS to `1.1.1.1`,
  `8.8.8.8` or `9.9.9.9`, whichever is reachable. They bypass your network's
  resolver, which may be tampered with.
- **A latency check every few minutes** through each server in a pool:
  `https://www.gstatic.com/generate_204`. It picks the fastest working server.
- **Tor bridges.** *Refresh bridges* fetches Tor's built-in bridge list from
  `bridges.torproject.org`, optionally through another tunnel, and only when you
  click it.
- **Subscriptions.** A subscription link you paste is fetched from its address,
  through your pool if it's blocked directly.

Its logs stay on your computer, with credentials removed.

## The server script (optional)

[`server/install-server.sh`](server/) runs on your own VPS. As it sets things
up, it contacts:
- `api.ipify.org`, `icanhazip.com` or `ifconfig.me`, to learn the server's
  public address, unless you pass `--host`;
- a handful of big sites, to check they work as a Reality cover site;
- SagerNet's package repository or GitHub, to download sing-box.

The server keeps no access logs: sing-box runs at warning level, so the sites
your clients visit aren't recorded.
