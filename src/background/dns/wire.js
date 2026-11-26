// DNS wire format (RFC 1035) for DNS-over-HTTPS (RFC 8484).
//
// The JSON DoH dialect is non-standard and only some resolvers speak it; the
// wire format works with every DoH server. This codec covers what OpenRoute
// needs: building padded queries (RFC 7830/8467, so the query length doesn't
// leak the domain) and decoding A / AAAA / CNAME / SVCB / HTTPS answers with
// name compression — including SvcParamKey 5 ("ech"), the real signal that a
// site supports Encrypted ClientHello.

export const TYPE = Object.freeze({ A: 1, NS: 2, CNAME: 5, SOA: 6, TXT: 16, AAAA: 28, OPT: 41, SVCB: 64, HTTPS: 65 });
export const RCODE = Object.freeze({ NOERROR: 0, FORMERR: 1, SERVFAIL: 2, NXDOMAIN: 3, NOTIMP: 4, REFUSED: 5 });
const SVC_KEY = Object.freeze({ MANDATORY: 0, ALPN: 1, NO_DEFAULT_ALPN: 2, PORT: 3, IPV4HINT: 4, ECH: 5, IPV6HINT: 6 });

const PAD_BLOCK = 128; // RFC 8467: pad queries to a multiple of 128 octets

function labelsOf(name) {
  const s = String(name).replace(/\.$/, "");
  if (!s) return [];
  const labels = s.split(".");
  for (const l of labels) {
    if (!l.length || l.length > 63) throw new Error(`invalid DNS label in "${name}"`);
  }
  return labels;
}

function encodeName(name) {
  const out = [];
  for (const label of labelsOf(name)) {
    const bytes = new TextEncoder().encode(label);
    if (bytes.length > 63) throw new Error(`label too long in "${name}"`);
    out.push(bytes.length, ...bytes);
  }
  out.push(0);
  if (out.length > 255) throw new Error(`name too long: "${name}"`);
  return out;
}

/**
 * Build a query message. id is 0 for DoH (RFC 8484 §4.1: improves caching).
 * pad: true adds an EDNS(0) OPT record with Padding to a 128-octet boundary.
 */
export function encodeQuery(name, type = TYPE.A, { id = 0, pad = true, recursionDesired = true } = {}) {
  const qtype = typeof type === "string" ? TYPE[type.toUpperCase()] : type;
  if (!qtype) throw new Error(`unknown RR type ${type}`);
  const header = [id >> 8 & 0xff, id & 0xff, recursionDesired ? 0x01 : 0x00, 0x00, 0, 1, 0, 0, 0, 0, 0, pad ? 1 : 0];
  const question = [...encodeName(name), qtype >> 8, qtype & 0xff, 0, 1];
  const msg = [...header, ...question];
  if (pad) {
    // OPT: root name, TYPE 41, CLASS = UDP size 4096, TTL 0, RDLEN, [Padding opt]
    const fixed = 11 + 4; // OPT RR header + padding option header
    const unpadded = msg.length + fixed;
    const padLen = (PAD_BLOCK - (unpadded % PAD_BLOCK)) % PAD_BLOCK;
    const rdlen = 4 + padLen;
    msg.push(0, 0, 41, 0x10, 0x00, 0, 0, 0, 0, rdlen >> 8, rdlen & 0xff, 0, 12, padLen >> 8, padLen & 0xff, ...new Array(padLen).fill(0));
  }
  return new Uint8Array(msg);
}

export function toBase64Url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64Url(s) {
  const b64 = String(s).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

// ---- decoding --------------------------------------------------------------

class Reader {
  constructor(bytes) {
    this.b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    this.p = 0;
  }
  need(n) { if (this.p + n > this.b.length) throw new Error("truncated DNS message"); }
  u8() { this.need(1); return this.b[this.p++]; }
  u16() { this.need(2); const v = (this.b[this.p] << 8) | this.b[this.p + 1]; this.p += 2; return v; }
  u32() { this.need(4); const v = ((this.b[this.p] << 24) >>> 0) + (this.b[this.p + 1] << 16) + (this.b[this.p + 2] << 8) + this.b[this.p + 3]; this.p += 4; return v; }
  bytes(n) { this.need(n); const v = this.b.subarray(this.p, this.p + n); this.p += n; return v; }

  // Domain name with RFC 1035 §4.1.4 compression; bounded so a malicious
  // pointer loop can't hang the worker.
  name() {
    const labels = [];
    let p = this.p;
    let jumped = false;
    let jumps = 0;
    let total = 0;
    for (;;) {
      if (p >= this.b.length) throw new Error("truncated name");
      const len = this.b[p];
      if ((len & 0xc0) === 0xc0) {
        if (p + 1 >= this.b.length) throw new Error("truncated pointer");
        const ptr = ((len & 0x3f) << 8) | this.b[p + 1];
        if (!jumped) this.p = p + 2;
        jumped = true;
        if (++jumps > 32 || ptr >= this.b.length) throw new Error("bad compression pointer");
        p = ptr;
        continue;
      }
      if (len & 0xc0) throw new Error("reserved label type");
      p += 1;
      if (len === 0) break;
      if (p + len > this.b.length) throw new Error("truncated label");
      labels.push(new TextDecoder().decode(this.b.subarray(p, p + len)));
      p += len;
      total += len + 1;
      if (total > 255) throw new Error("name too long");
    }
    if (!jumped) this.p = p;
    return labels.join(".");
  }
}

function ipv4(bytes) { return [...bytes].join("."); }

function ipv6(bytes) {
  const words = [];
  for (let i = 0; i < 16; i += 2) words.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
  // Compress the longest run of zero words (RFC 5952).
  let best = -1, bestLen = 0;
  for (let i = 0; i < 8;) {
    if (words[i] !== "0") { i++; continue; }
    let j = i;
    while (j < 8 && words[j] === "0") j++;
    if (j - i > bestLen && j - i > 1) { best = i; bestLen = j - i; }
    i = j;
  }
  if (best === -1) return words.join(":");
  const head = words.slice(0, best).join(":");
  const tail = words.slice(best + bestLen).join(":");
  return `${head}::${tail}`;
}

function decodeSvcb(r, rdEnd) {
  const priority = r.u16();
  const target = r.name();
  const params = {};
  while (r.p < rdEnd) {
    const key = r.u16();
    const len = r.u16();
    const val = r.bytes(len);
    if (key === SVC_KEY.ALPN) {
      const alpn = [];
      for (let i = 0; i < val.length;) { const l = val[i++]; alpn.push(new TextDecoder().decode(val.subarray(i, i + l))); i += l; }
      params.alpn = alpn;
    } else if (key === SVC_KEY.PORT && val.length === 2) {
      params.port = (val[0] << 8) | val[1];
    } else if (key === SVC_KEY.IPV4HINT) {
      params.ipv4hint = [];
      for (let i = 0; i + 4 <= val.length; i += 4) params.ipv4hint.push(ipv4(val.subarray(i, i + 4)));
    } else if (key === SVC_KEY.IPV6HINT) {
      params.ipv6hint = [];
      for (let i = 0; i + 16 <= val.length; i += 16) params.ipv6hint.push(ipv6(val.subarray(i, i + 16)));
    } else if (key === SVC_KEY.ECH) {
      params.ech = val.length; // the ECHConfigList itself isn't needed, just its presence
    } else if (key === SVC_KEY.NO_DEFAULT_ALPN) {
      params.noDefaultAlpn = true;
    } else {
      params[`key${key}`] = val.length;
    }
  }
  return { priority, target, params };
}

/** Decode a DNS response message. Throws on malformed input. */
export function decodeMessage(bytes) {
  const r = new Reader(bytes);
  const id = r.u16();
  const flags = r.u16();
  const qd = r.u16(), an = r.u16(), ns = r.u16(), ar = r.u16();
  const out = {
    id,
    qr: !!(flags & 0x8000),
    truncated: !!(flags & 0x0200),
    recursionAvailable: !!(flags & 0x0080),
    authenticData: !!(flags & 0x0020),
    rcode: flags & 0x000f,
    questions: [],
    answers: []
  };
  for (let i = 0; i < qd; i++) out.questions.push({ name: r.name(), type: r.u16(), class: r.u16() });
  const records = an + ns + ar;
  for (let i = 0; i < records; i++) {
    const name = r.name();
    const type = r.u16();
    const cls = r.u16();
    const ttl = r.u32();
    const rdlen = r.u16();
    const rdStart = r.p;
    const rdEnd = rdStart + rdlen;
    r.need(rdlen);
    let data = null;
    try {
      if (type === TYPE.A && rdlen === 4) data = ipv4(r.bytes(4));
      else if (type === TYPE.AAAA && rdlen === 16) data = ipv6(r.bytes(16));
      else if (type === TYPE.CNAME || type === TYPE.NS) data = r.name();
      else if (type === TYPE.HTTPS || type === TYPE.SVCB) data = decodeSvcb(r, rdEnd);
    } catch {
      data = null; // a malformed record doesn't poison the whole answer
    }
    r.p = rdEnd;
    if (i < an) out.answers.push({ name, type, class: cls, ttl, data });
  }
  return out;
}
