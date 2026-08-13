// Generates OpenRoute's PNG icons with no external deps (minimal PNG encoder).
// Mark: a white ring (the "O") on a brand-blue rounded square. 4x supersampled
// for crisp edges. Run: node icons/make-icons.mjs
import zlib from "node:zlib";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const OUT = dirname(fileURLToPath(import.meta.url));

// ---- minimal PNG (RGBA, 8-bit) --------------------------------------------
const CRC = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();
function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const t = Buffer.from(type, "ascii");
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length, 0);
  const body = Buffer.concat([t, data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(body), 0);
  return Buffer.concat([len, body, crc]);
}
function encodePNG(w, h, rgba) {
  const stride = w * 4;
  const raw = Buffer.alloc((stride + 1) * h);
  for (let y = 0; y < h; y++) {
    raw[y * (stride + 1)] = 0; // filter: None
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, y * stride + stride);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8; ihdr[9] = 6; // 8-bit, RGBA
  const sig = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  return Buffer.concat([sig, chunk("IHDR", ihdr), chunk("IDAT", zlib.deflateSync(raw)), chunk("IEND", Buffer.alloc(0))]);
}

// ---- drawing ---------------------------------------------------------------
const BLUE = [37, 99, 235];    // #2563eb
const WHITE = [255, 255, 255];
const SS = 4; // supersample factor

function insideRounded(x, y, N, r) {
  const min = r, max = N - 1 - r;
  const dx = x < min ? min - x : x > max ? x - max : 0;
  const dy = y < min ? min - y : y > max ? y - max : 0;
  return Math.hypot(dx, dy) <= r;
}

function sample(x, y, N) {
  // returns [r,g,b,a] at supersampled coords
  const r = N * 0.22;
  if (!insideRounded(x, y, N, r)) return [0, 0, 0, 0];
  const c = (N - 1) / 2;
  const dist = Math.hypot(x - c, y - c);
  const outer = N * 0.34, inner = N * 0.19;
  if (dist <= outer && dist >= inner) return [...WHITE, 255];
  return [...BLUE, 255];
}

function render(N) {
  const buf = Buffer.alloc(N * N * 4);
  for (let y = 0; y < N; y++) {
    for (let x = 0; x < N; x++) {
      let r = 0, g = 0, b = 0, a = 0;
      for (let sy = 0; sy < SS; sy++) {
        for (let sx = 0; sx < SS; sx++) {
          const px = x * SS + sx + 0.5, py = y * SS + sy + 0.5;
          const [rr, gg, bb, aa] = sample(px / SS, py / SS, N);
          // premultiply for correct edge blending
          r += rr * aa; g += gg * aa; b += bb * aa; a += aa;
        }
      }
      const n = SS * SS;
      const o = (y * N + x) * 4;
      if (a === 0) { buf[o] = buf[o + 1] = buf[o + 2] = buf[o + 3] = 0; continue; }
      buf[o] = Math.round(r / a);
      buf[o + 1] = Math.round(g / a);
      buf[o + 2] = Math.round(b / a);
      buf[o + 3] = Math.round(a / n);
    }
  }
  return buf;
}

for (const N of [16, 32, 48, 128]) {
  const png = encodePNG(N, N, render(N));
  writeFileSync(join(OUT, `icon${N}.png`), png);
  console.log(`wrote icon${N}.png (${png.length} bytes)`);
}
