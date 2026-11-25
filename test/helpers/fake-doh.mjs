// A fake DNS-over-HTTPS service for unit tests. Serves the JSON API
// (application/dns-json, ?name=&type=) on every resolver endpoint OpenRoute
// knows about, from a small zone table:
//
//   installFakeDoH(mock, {
//     "blocked.example": { A: ["93.184.215.14"] },
//     "ech.example":     { A: ["104.16.1.1"], HTTPS: ["1 . alpn=h2 ech=AEX+DQ..."] },
//     "nx.example":      "NXDOMAIN",
//     "poisoned.example":{ A: ["10.10.34.36"] }
//   }, { down: false })          // down: true → every resolver unreachable
//
// `down` may also be a predicate over the request URL to fail selectively.

const TYPE_NUM = { A: 1, NS: 2, CNAME: 5, SOA: 6, TXT: 16, AAAA: 28, SVCB: 64, HTTPS: 65 };
const TYPE_NAME = Object.fromEntries(Object.entries(TYPE_NUM).map(([k, v]) => [v, k]));

export const RESOLVER_HOSTS = [
  "cloudflare-dns.com", "1.1.1.1", "1.0.0.1", "mozilla.cloudflare-dns.com",
  "dns.google", "8.8.8.8", "8.8.4.4",
  "dns.quad9.net", "9.9.9.9", "149.112.112.112",
  "dns.adguard-dns.com", "unfiltered.adguard-dns.com", "94.140.14.140", "94.140.14.141",
  "dns.mullvad.net", "dns.nextdns.io", "doh.opendns.com", "doh.dns.sb", "185.222.222.222"
];

export function isResolverUrl(url) {
  try { return RESOLVER_HOSTS.includes(new URL(url).hostname); } catch { return false; }
}

export function installFakeDoH(mock, zone = {}, opts = {}) {
  const state = { zone, down: opts.down ?? false, queries: [] };
  mock.net.route((req) => isResolverUrl(req.url), (req) => {
    const u = new URL(req.url);
    state.queries.push({ url: req.url, host: u.hostname, at: Date.now() });
    const down = typeof state.down === "function" ? state.down(req) : state.down;
    if (down) throw new TypeError("Failed to fetch (resolver unreachable)");
    const name = (u.searchParams.get("name") || "").replace(/\.$/, "").toLowerCase();
    if (!name) return { status: 400, body: "wire format not supported by this fake" };
    const typeParam = u.searchParams.get("type") || "A";
    const type = /^\d+$/.test(typeParam) ? TYPE_NAME[+typeParam] || typeParam : typeParam.toUpperCase();
    return { status: 200, headers: { "content-type": "application/dns-json" }, json: answer(state.zone, name, type) };
  });
  return state;
}

function answer(zone, name, type) {
  const entry = zone[name];
  const question = [{ name: name + ".", type: TYPE_NUM[type] || 0 }];
  if (entry === "NXDOMAIN" || entry === undefined) {
    return { Status: 3, TC: false, RD: true, RA: true, AD: false, CD: false, Question: question };
  }
  if (entry === "SERVFAIL") return { Status: 2, Question: question };
  const records = entry[type] || [];
  return {
    Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false,
    Question: question,
    Answer: records.map((data) => ({ name: name + ".", type: TYPE_NUM[type], TTL: 300, data }))
  };
}
