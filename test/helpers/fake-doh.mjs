// A fake RFC 8484 DNS-over-HTTPS service for unit tests, serving every
// resolver endpoint OpenRoute knows from a small zone table:
//
//   installFakeDoH(mock, {
//     "blocked.example":  { A: ["93.184.215.14"] },
//     "v6.example":       { AAAA: ["2606:4700::1111"] },
//     "ech.example":      { A: ["104.16.1.1"], HTTPS: [{ ech: true, alpn: ["h2"] }] },
//     "nx.example":       "NXDOMAIN",
//     "poisoned.example": { A: ["10.10.34.36"] }
//   }, { down: false })   // down: true | (req) => bool → resolver unreachable
//
// Deliberately an independent, minimal implementation of the wire format
// (not the extension's codec), so a symmetric codec bug can't hide.

export const RESOLVER_HOSTS = [
  "cloudflare-dns.com", "1.1.1.1", "1.0.0.1", "dns.google", "8.8.8.8", "8.8.4.4",
  "dns.quad9.net", "9.9.9.9", "149.112.112.112", "unfiltered.adguard-dns.com",
  "dns.mullvad.net", "dns.nextdns.io", "doh.dns.sb", "185.222.222.222"
];

const TYPES = { 1: "A", 28: "AAAA", 65: "HTTPS", 64: "SVCB", 5: "CNAME" };

export function isResolverUrl(url) {
  try { return RESOLVER_HOSTS.includes(new URL(url).hostname); } catch { return false; }
}

function parseQuery(b64) {
  const bytes = Buffer.from(b64.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  let p = 12;
  const labels = [];
  while (bytes[p] !== 0) {
    const len = bytes[p];
    labels.push(bytes.subarray(p + 1, p + 1 + len).toString("utf8"));
    p += len + 1;
  }
  p += 1;
  return { id: bytes.readUInt16BE(0), name: labels.join(".").toLowerCase(), qtype: bytes.readUInt16BE(p), question: bytes.subarray(12, p + 4) };
}

function v6bytes(ip) {
  const [head, tail = ""] = ip.split("::");
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  const words = [...h, ...Array(8 - h.length - t.length).fill("0"), ...t].map((w) => parseInt(w || "0", 16));
  const b = Buffer.alloc(16);
  words.forEach((w, i) => b.writeUInt16BE(w, i * 2));
  return b;
}

function svcbBytes(rec) {
  const parts = [Buffer.from([0, rec.priority ?? 1, 0])]; // priority + root target "."
  if (rec.alpn?.length) {
    const ids = Buffer.concat(rec.alpn.map((a) => Buffer.concat([Buffer.from([a.length]), Buffer.from(a)])));
    const hdr = Buffer.alloc(4); hdr.writeUInt16BE(1, 0); hdr.writeUInt16BE(ids.length, 2);
    parts.push(hdr, ids);
  }
  if (rec.ech) {
    const cfg = Buffer.alloc(32, 7);
    const hdr = Buffer.alloc(4); hdr.writeUInt16BE(5, 0); hdr.writeUInt16BE(cfg.length, 2);
    parts.push(hdr, cfg);
  }
  return Buffer.concat(parts);
}

function respond(q, rcode, records) {
  const answers = records.map((rec) => {
    const rdata = q.qtype === 1 ? Buffer.from(rec.split(".").map(Number))
      : q.qtype === 28 ? v6bytes(rec)
        : svcbBytes(rec);
    const rr = Buffer.alloc(12);
    rr.writeUInt16BE(0xc00c, 0); // pointer to the question name
    rr.writeUInt16BE(q.qtype, 2);
    rr.writeUInt16BE(1, 4);
    rr.writeUInt32BE(300, 6);
    rr.writeUInt16BE(rdata.length, 10);
    return Buffer.concat([rr, rdata]);
  });
  const header = Buffer.alloc(12);
  header.writeUInt16BE(q.id, 0);
  header.writeUInt16BE(0x8180 | rcode, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(answers.length, 6);
  return Buffer.concat([header, q.question, ...answers]);
}

export function installFakeDoH(mock, zone = {}, opts = {}) {
  const state = { zone, down: opts.down ?? false, queries: [] };
  mock.net.route((req) => isResolverUrl(req.url), (req) => {
    const u = new URL(req.url);
    const down = typeof state.down === "function" ? state.down(req) : state.down;
    state.queries.push({ url: req.url, host: u.hostname, at: Date.now() });
    if (down) throw new TypeError("Failed to fetch (resolver unreachable)");
    const dns = u.searchParams.get("dns");
    if (!dns) return { status: 400, body: "expected RFC 8484 ?dns=" };
    const q = parseQuery(dns);
    const entry = state.zone[q.name];
    let body;
    if (entry === undefined || entry === "NXDOMAIN") body = respond(q, 3, []);
    else if (entry === "SERVFAIL") body = respond(q, 2, []);
    else body = respond(q, 0, entry[TYPES[q.qtype]] || []);
    return { status: 200, headers: { "content-type": "application/dns-message" }, body };
  });
  return state;
}
