'use strict';
// Generates icon.png (128x128) and images/screenshot.png (1400x900) for JWT, JWKS & X.509 Cert Inspector.
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const crcT = new Int32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c;
});
const crc = (b) => { let c = -1; for (const v of b) c = crcT[(c ^ v) & 255] ^ (c >>> 8); return (c ^ -1) >>> 0; };
const chunk = (t, d) => {
  const l = Buffer.alloc(4); l.writeUInt32BE(d.length);
  const td = Buffer.concat([Buffer.from(t), d]);
  const c = Buffer.alloc(4); c.writeUInt32BE(crc(td));
  return Buffer.concat([l, td, c]);
};
const hex = (h) => [parseInt(h.slice(1, 3), 16), parseInt(h.slice(3, 5), 16), parseInt(h.slice(5, 7), 16)];
const mix = (a, b, t) => a.map((v, i) => Math.round(v + (b[i] - v) * t));

function writePng(filePath, W, H, px) {
  const raw = Buffer.alloc((W * 4 + 1) * H);
  for (let y = 0; y < H; y += 1) {
    raw[y * (W * 4 + 1)] = 0;
    px.copy(raw, y * (W * 4 + 1) + 1, y * W * 4, (y + 1) * W * 4);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(W, 0); ihdr.writeUInt32BE(H, 4); ihdr[8] = 8; ihdr[9] = 6;
  fs.writeFileSync(filePath, Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw)),
    chunk('IEND', Buffer.alloc(0)),
  ]));
}

function makeCanvas(W, H) {
  const px = Buffer.alloc(W * H * 4);
  const set = (x, y, [r, g, b], a = 255) => {
    x = Math.round(x); y = Math.round(y);
    if (x < 0 || y < 0 || x >= W || y >= H) return;
    const i = (y * W + x) * 4;
    const k = a / 255;
    px[i] = Math.round(px[i] * (1 - k) + r * k);
    px[i + 1] = Math.round(px[i + 1] * (1 - k) + g * k);
    px[i + 2] = Math.round(px[i + 2] * (1 - k) + b * k);
    px[i + 3] = Math.max(px[i + 3], a);
  };
  const rect = (x0, y0, w, h, col, r = 3, a = 255) => {
    for (let y = y0; y < y0 + h; y += 1) for (let x = x0; x < x0 + w; x += 1) {
      const dx = Math.max(x0 + r - x, 0, x - (x0 + w - 1 - r));
      const dy = Math.max(y0 + r - y, 0, y - (y0 + h - 1 - r));
      const d = Math.sqrt(dx * dx + dy * dy);
      if (d <= r) set(x, y, col, d > r - 1 ? Math.round(a * (r - d)) : a);
    }
  };
  return { px, set, rect };
}

// 1. Icon (128x128): Amber-slate JWT 3-segment header/payload/sig + X.509 seal
{
  const W = 128, H = 128, R = 22;
  const { px, set, rect } = makeCanvas(W, H);
  for (let y = 0; y < H; y += 1) for (let x = 0; x < W; x += 1) {
    const dx = Math.max(R - x, 0, x - (W - 1 - R)), dy = Math.max(R - y, 0, y - (H - 1 - R));
    const d = Math.sqrt(dx * dx + dy * dy);
    if (d <= R) set(x, y, mix(hex('#18181B'), hex('#451A03'), y / H), d > R - 1 ? Math.round(255 * (R - d)) : 255);
  }
  rect(14, 15, 100, 16, hex('#D97706'), 4);
  rect(20, 20, 44, 6, hex('#FEF3C7'), 2);
  rect(84, 20, 24, 6, hex('#FCD34D'), 2);

  // 3 JWT/Cert rows
  rect(14, 39, 100, 18, hex('#27272A'), 4);
  rect(20, 45, 32, 6, hex('#FB7185'), 2);
  rect(58, 45, 28, 6, hex('#A78BFA'), 2);
  rect(92, 45, 16, 6, hex('#38BDF8'), 2);

  rect(14, 63, 100, 18, hex('#27272A'), 4);
  rect(20, 69, 40, 6, hex('#34D399'), 2);
  rect(66, 69, 20, 6, hex('#94A3B8'), 2);
  rect(92, 69, 16, 6, hex('#34D399'), 2);

  rect(14, 87, 100, 18, hex('#27272A'), 4);
  rect(20, 93, 36, 6, hex('#FBBF24'), 2);
  rect(62, 93, 24, 6, hex('#CBD5E1'), 2);
  rect(92, 93, 16, 6, hex('#F87171'), 2);

  rect(14, 110, 100, 8, hex('#92400E'), 3);
  rect(22, 112, 50, 4, hex('#FDE68A'), 2);
  rect(88, 112, 20, 4, hex('#34D399'), 2);
  writePng(path.join(__dirname, '..', 'icon.png'), W, H, px);
}

// 2. Screenshot preview (1400x900)
{
  const W = 1400, H = 900;
  const { px, rect } = makeCanvas(W, H);
  rect(0, 0, W, H, hex('#1E1E1E'), 0);
  rect(0, 0, W, 44, hex('#252526'), 0);
  rect(16, 12, 290, 20, hex('#D97706'), 4);
  rect(320, 14, 240, 16, hex('#475569'), 3);
  for (let i = 0; i < 4; i += 1) rect(16 + i * 165, 58, 150, 24, i === 2 ? hex('#B91C1C') : hex('#334155'), 10);
  rect(16, 94, 280, 28, hex('#2D2D30'), 3);
  rect(308, 94, 120, 28, hex('#2D2D30'), 3);
  rect(440, 94, 120, 28, hex('#2D2D30'), 3);
  rect(572, 94, 90, 28, hex('#0E639C'), 3);
  rect(680, 94, 175, 28, hex('#B45309'), 3);
  rect(868, 94, 175, 28, hex('#B45309'), 3);
  rect(1056, 94, 175, 28, hex('#B45309'), 3);

  rect(16, 140, 860, 720, hex('#111827'), 4);
  rect(16, 140, 860, 34, hex('#1E293B'), 2);
  for (let r = 0; r < 12; r += 1) {
    const y = 184 + r * 52;
    rect(24, y, 844, 44, r === 0 ? hex('#451A03') : (r % 2 === 0 ? hex('#1A2233') : hex('#111827')), 2);
    rect(34, y + 16, 26, 12, hex('#94A3B8'), 2);
    rect(72, y + 16, 60, 12, hex('#FBBF24'), 2);
    rect(150, y + 16, 195, 12, hex('#E2E8F0'), 2);
    rect(365, y + 16, 85, 12, hex('#38BDF8'), 2);
    rect(470, y + 16, 240, 12, hex('#CBD5E1'), 2);
    rect(755, y + 16, 90, 12, r % 4 === 2 ? hex('#F87171') : hex('#34D399'), 2);
  }

  rect(892, 140, 492, 720, hex('#111827'), 4);
  rect(892, 140, 492, 34, hex('#1E293B'), 2);
  for (let r = 0; r < 8; r += 1) {
    const y = 188 + r * 36;
    rect(908, y, 130, 14, hex('#FBBF24'), 2);
    rect(1050, y, 310, 14, r === 6 ? hex('#F87171') : hex('#E2E8F0'), 2);
  }
  rect(908, 496, 460, 340, hex('#0F172A'), 4);
  for (let r = 0; r < 9; r += 1) {
    const y = 516 + r * 32;
    rect(924, y, 110, 12, hex('#38BDF8'), 2);
    rect(1048, y, 250, 12, r === 2 ? hex('#A78BFA') : hex('#94A3B8'), 2);
  }
  fs.mkdirSync(path.join(__dirname, '..', 'images'), { recursive: true });
  writePng(path.join(__dirname, '..', 'images', 'screenshot.png'), W, H, px);
}
console.log('Generated icon.png and images/screenshot.png');
