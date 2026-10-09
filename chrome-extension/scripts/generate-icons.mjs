/**
 * Generates the extension's shield icons (16/32/48/128 px PNG) with zero
 * dependencies: hand-rolled PNG encoder (zlib + CRC32) and a small
 * signed-distance shield/checkmark rasterizer with 2x2 supersampling.
 *
 * Run: node scripts/generate-icons.mjs
 */

import { deflateSync } from "node:zlib";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const OUT_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "icons");
const SIZES = [16, 32, 48, 128];

// ---------------------------------------------------------------------------
// PNG encoding
// ---------------------------------------------------------------------------

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, "ascii");
  const crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
  return Buffer.concat([len, typeBuf, data, crcBuf]);
}

function encodePng(width, height, rgba) {
  const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // color type RGBA
  // compression / filter / interlace = 0

  const stride = width * 4;
  const raw = Buffer.alloc((stride + 1) * height);
  for (let y = 0; y < height; y++) {
    raw[y * (stride + 1)] = 0; // filter: none
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }
  const idat = deflateSync(raw, { level: 9 });

  return Buffer.concat([
    sig,
    chunk("IHDR", ihdr),
    chunk("IDAT", idat),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

// ---------------------------------------------------------------------------
// Shield rasterizer
// ---------------------------------------------------------------------------

function inShield(u, v) {
  // u in [-1,1] horizontal, v in [0,1] vertical
  if (v < 0 || v > 1) return false;
  if (v <= 0.55) {
    // Top: half-ellipse with a rounded top edge.
    const du = u;
    const dv = (v - 0.55) / 0.55;
    return du * du + dv * dv <= 1;
  }
  // Bottom: taper to a point at the bottom center.
  const t = (v - 0.55) / 0.45;
  const halfW = Math.pow(1 - t, 1.25);
  return Math.abs(u) <= halfW;
}

function distToSegment(px, py, x1, y1, x2, y2) {
  const dx = x2 - x1;
  const dy = y2 - y1;
  const lenSq = dx * dx + dy * dy;
  let t = lenSq === 0 ? 0 : ((px - x1) * dx + (py - y1) * dy) / lenSq;
  t = Math.max(0, Math.min(1, t));
  const cx = x1 + t * dx;
  const cy = y1 + t * dy;
  return Math.hypot(px - cx, py - cy);
}

function inCheck(px, py) {
  // Checkmark polyline inside the shield (coordinates in 0..1 space).
  const w = 0.11; // half thickness
  const d1 = distToSegment(px, py, 0.3, 0.52, 0.45, 0.67);
  const d2 = distToSegment(px, py, 0.45, 0.67, 0.73, 0.35);
  return Math.min(d1, d2) <= w;
}

function lerp(a, b, t) {
  return a + (b - a) * t;
}

function renderIcon(size) {
  const rgba = Buffer.alloc(size * size * 4);
  const SUB = 2; // 2x2 supersampling
  const pad = 0.04; // margin around the shield

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      let shieldHits = 0;
      let checkHits = 0;
      let total = 0;
      for (let sy = 0; sy < SUB; sy++) {
        for (let sx = 0; sx < SUB; sx++) {
          total++;
          const fx = (x + (sx + 0.5) / SUB) / size;
          const fy = (y + (sy + 0.5) / SUB) / size;
          // Map to shield space with padding.
          const u = (fx - 0.5) / (0.5 - pad) ; // -1..1
          const v = (fy - pad) / (1 - 2 * pad); // 0..1
          if (inShield(u, v)) {
            shieldHits++;
            if (inCheck(fx, fy)) checkHits++;
          }
        }
      }

      const idx = (y * size + x) * 4;
      if (shieldHits === 0) continue; // transparent

      const shieldAlpha = shieldHits / total;
      const checkAlpha = checkHits / total;

      // Gradient: top #38bdf8 -> bottom #1d4ed8
      const t = y / (size - 1 || 1);
      let r = Math.round(lerp(0x38, 0x1d, t));
      let g = Math.round(lerp(0xbd, 0x4e, t));
      let b = Math.round(lerp(0xf8, 0xd8, t));

      // Soft edge darkening for contrast on light backgrounds.
      if (shieldHits < total) {
        r = Math.round(r * 0.75);
        g = Math.round(g * 0.75);
        b = Math.round(b * 0.75);
      }

      // White check on top.
      if (checkAlpha > 0) {
        r = Math.round(lerp(r, 255, checkAlpha));
        g = Math.round(lerp(g, 255, checkAlpha));
        b = Math.round(lerp(b, 255, checkAlpha));
      }

      rgba[idx] = r;
      rgba[idx + 1] = g;
      rgba[idx + 2] = b;
      rgba[idx + 3] = Math.round(shieldAlpha * 255);
    }
  }

  return encodePng(size, size, rgba);
}

mkdirSync(OUT_DIR, { recursive: true });
for (const size of SIZES) {
  const png = renderIcon(size);
  const file = join(OUT_DIR, `icon${size}.png`);
  writeFileSync(file, png);
  console.log(`wrote ${file} (${png.length} bytes)`);
}
