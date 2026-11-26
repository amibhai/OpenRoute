// Site bundles: domains that are blocked (and needed) together. Routing only
// youtube.com while googlevideo.com stays blocked gives a page that "loads"
// but whose videos never play; routing the bundle fixes the whole site.
//
// Entries are registrable domains or specific hosts (a host entry routes that
// host and its subdomains). Curated for widely censored services; extend via
// a pull request with a source for each addition.

import { lookupDomain, normalizeHost } from "../../shared/hosts.js";

export const BUNDLES = Object.freeze({
  youtube: ["youtube.com", "youtu.be", "ytimg.com", "googlevideo.com", "ggpht.com", "youtube-nocookie.com", "youtubei.googleapis.com", "youtube.googleapis.com"],
  x: ["x.com", "twitter.com", "twimg.com", "t.co"],
  meta: ["facebook.com", "fb.com", "fbcdn.net", "facebook.net", "fbsbx.com", "messenger.com", "instagram.com", "cdninstagram.com", "whatsapp.com", "whatsapp.net", "wa.me", "threads.net", "threads.com"],
  telegram: ["telegram.org", "t.me", "telegram.me", "telesco.pe", "cdn-telegram.org"],
  discord: ["discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media"],
  reddit: ["reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"],
  wikipedia: ["wikipedia.org", "wikimedia.org", "wiktionary.org", "wikidata.org", "wikibooks.org", "wikinews.org", "wikiquote.org", "wikisource.org", "wikiversity.org", "wikivoyage.org", "mediawiki.org"],
  soundcloud: ["soundcloud.com", "sndcdn.com"],
  signal: ["signal.org", "signal.me", "signal.group", "signal.art", "whispersystems.org"],
  tiktok: ["tiktok.com", "tiktokcdn.com", "tiktokv.com", "tiktokcdn-us.com", "ttwstatic.com", "byteoversea.com", "ibytedtos.com"],
  linkedin: ["linkedin.com", "licdn.com", "lnkd.in"],
  twitch: ["twitch.tv", "ttvnw.net", "jtvnw.net", "ext-twitch.tv"],
  vimeo: ["vimeo.com", "vimeocdn.com"],
  pinterest: ["pinterest.com", "pinimg.com"],
  proton: ["proton.me", "protonmail.com", "protonvpn.com", "pm.me", "protonmail.ch"],
  bbc: ["bbc.com", "bbc.co.uk", "bbci.co.uk"],
  github: ["github.com", "githubusercontent.com", "githubassets.com"],
  spotify: ["spotify.com", "scdn.co", "spotifycdn.com"],
  medium: ["medium.com"],
  quora: ["quora.com", "quoracdn.net"]
});

const INDEX = (() => {
  const idx = {};
  for (const [name, members] of Object.entries(BUNDLES)) for (const m of members) idx[m] = name;
  return idx;
})();

/** → { name, members } for the bundle containing `domain` (or a parent), else null. */
export function bundleFor(domain) {
  const hit = lookupDomain(normalizeHost(domain), INDEX);
  return hit ? { name: INDEX[hit], members: BUNDLES[INDEX[hit]] } : null;
}
