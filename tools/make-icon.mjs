// Writes the 1024x1024 Otpal app icon: dark rounded square, mint timer ring, face.
// Usage: node tools/make-icon.mjs out.png
import { writeFileSync } from 'node:fs';
import { deflateSync } from 'node:zlib';

const N = 1024, S = N / 64, SS = 3;
const MINT = [140, 242, 192], FACE = [236, 239, 244];
const inRound = (x, y) => {
  const r = 230, cx = Math.min(Math.max(x, r), N - 1 - r), cy = Math.min(Math.max(y, r), N - 1 - r);
  return (x - cx) ** 2 + (y - cy) ** 2 <= r * r;
};
// Returns the colour at a point in 64-unit logo space, or null for background.
function logoAt(u, v) {
  const d = Math.hypot(u - 32, v - 32);
  if (d > 22.75 && d < 29.25) {
    // gap is a 12 degree notch starting at -50 degrees + 128/163.4 of the turn
    let a = (Math.atan2(v - 32, u - 32) * 180 / Math.PI + 360 + 50) % 360;
    if (a <= 282.2) return MINT;
    const cap = Math.hypot(d - 26, 0);
    return cap < 0 ? MINT : null;
  }
  for (const ex of [24.5, 39.5]) if (Math.hypot(u - ex, v - 29) < 3.8) return FACE;
  // smile: quadratic curve band
  if (u > 23.5 && u < 40.5) {
    const t = (u - 24) / 16, y = (1 - t) ** 2 * 39.5 + 2 * (1 - t) * t * 46 + t * t * 39.5;
    if (Math.abs(v - y) < 1.5 && t >= 0 && t <= 1) return FACE;
  }
  return null;
}
const px = Buffer.alloc(N * N * 4);
for (let y = 0; y < N; y++) for (let x = 0; x < N; x++) {
  if (!inRound(x, y)) continue;
  const g = 10 + 14 * (1 - y / N);
  let r = 0, gg = 0, b = 0;
  for (let sy = 0; sy < SS; sy++) for (let sx = 0; sx < SS; sx++) {
    const c = logoAt((x + (sx + 0.5) / SS) / S, (y + (sy + 0.5) / SS) / S) ?? [g, g + 1, g + 4];
    r += c[0]; gg += c[1]; b += c[2];
  }
  const i = (y * N + x) * 4, k = SS * SS;
  px[i] = r / k; px[i + 1] = gg / k; px[i + 2] = b / k; px[i + 3] = 255;
}
const crcTable = Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
const crc = (buf) => { let c = 0xffffffff; for (const b of buf) c = crcTable[(c ^ b) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
const chunk = (type, data) => { const len = Buffer.alloc(4); len.writeUInt32BE(data.length); const body = Buffer.concat([Buffer.from(type), data]); const sum = Buffer.alloc(4); sum.writeUInt32BE(crc(body)); return Buffer.concat([len, body, sum]); };
const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(N, 0); ihdr.writeUInt32BE(N, 4); ihdr[8] = 8; ihdr[9] = 6;
const raw = Buffer.alloc((N * 4 + 1) * N);
for (let y = 0; y < N; y++) px.copy(raw, y * (N * 4 + 1) + 1, y * N * 4, (y + 1) * N * 4);
writeFileSync(process.argv[2], Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ihdr), chunk('IDAT', deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]));
