// 生成 src-tauri/icons/icon.ico（守护绿盾牌 + 白色对勾）
// 纯 Node 实现：手工绘制 RGBA 像素 → PNG（zlib 内置）→ 打包为 ICO（PNG 载荷，Vista+ 合法）
const zlib = require("zlib");
const fs = require("fs");
const path = require("path");

// ---------- CRC32 ----------
const CRC_TABLE = (() => {
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
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

// ---------- PNG ----------
function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, "ascii");
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
  return Buffer.concat([len, typeBuf, data, crc]);
}

function encodePng(size, rgba) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;
  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0; // filter: none
    rgba.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr),
    chunk("IDAT", zlib.deflateSync(raw, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

// ---------- 盾牌绘制 ----------
// 距离点到线段
function distToSeg(px, py, ax, ay, bx, by) {
  const dx = bx - ax, dy = by - ay;
  const l2 = dx * dx + dy * dy;
  let t = l2 === 0 ? 0 : ((px - ax) * dx + (py - ay) * dy) / l2;
  t = Math.max(0, Math.min(1, t));
  const cx = ax + t * dx, cy = ay + t * dy;
  return Math.hypot(px - cx, py - cy);
}

// inside shield: 顶宽下尖，s 为 0~1 的归一化 y
function shieldHalfWidth(t) {
  // t: 0(顶) → 1(底尖)；抛物线收拢
  const w = 1 - t * t;
  return w < 0 ? 0 : Math.pow(w, 0.62);
}

function drawShield(size) {
  const rgba = Buffer.alloc(size * size * 4);
  const S = size / 256; // 设计稿以 256 为基准
  const topY = 34 * S, botY = 222 * S, cx = size / 2;
  const maxHalf = 78 * S;
  const border = 9 * S;
  // 白色对勾（线宽 15）
  const check = [
    [90 * S, 134 * S, 116 * S, 161 * S],
    [116 * S, 161 * S, 169 * S, 103 * S],
  ];
  const checkW = 7.5 * S;

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const idx = (y * size + x) * 4;
      const t = (y - topY) / (botY - topY);
      let inside = false;
      if (y >= topY && y <= botY) {
        const half = maxHalf * shieldHalfWidth(Math.max(0, Math.min(1, t)));
        inside = Math.abs(x - cx) <= half;
      }
      if (!inside) continue; // 透明背景

      // 内层（去掉边框）判定
      const tIn = (y - topY - border) / (botY - topY - border * 2);
      let insideInner = false;
      if (y >= topY + border && y <= botY - border * 0.4) {
        const halfIn = (maxHalf - border) * shieldHalfWidth(Math.max(0, Math.min(1, tIn)));
        insideInner = Math.abs(x - cx) <= halfIn;
      }

      let r, g, b;
      if (!insideInner) {
        r = 0x0b; g = 0x6b; b = 0x4a; // 深绿边框 #0B6B4A
      } else {
        r = 0x0e; g = 0x8a; b = 0x5f; // 守护绿 #0E8A5F
      }
      // 白色对勾
      for (const [ax, ay, bx, by] of check) {
        if (distToSeg(x + 0.5, y + 0.5, ax, ay, bx, by) <= checkW) {
          r = 0xff; g = 0xff; b = 0xff;
        }
      }
      rgba[idx] = r;
      rgba[idx + 1] = g;
      rgba[idx + 2] = b;
      rgba[idx + 3] = 255;
    }
  }
  return rgba;
}

// ---------- ICO 打包 ----------
function buildIco(sizes) {
  const images = sizes.map((s) => ({ size: s, png: encodePng(s, drawShield(s)) }));
  const count = images.length;
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0); // reserved
  header.writeUInt16LE(1, 2); // type: icon
  header.writeUInt16LE(count, 4);
  const entries = [];
  let offset = 6 + 16 * count;
  for (const img of images) {
    const e = Buffer.alloc(16);
    e[0] = img.size >= 256 ? 0 : img.size; // width (0 = 256)
    e[1] = img.size >= 256 ? 0 : img.size; // height
    e[2] = 0;  // palette
    e[3] = 0;  // reserved
    e.writeUInt16LE(1, 4);  // planes
    e.writeUInt16LE(32, 6); // bpp
    e.writeUInt32LE(img.png.length, 8);
    e.writeUInt32LE(offset, 12);
    offset += img.png.length;
    entries.push(e);
  }
  return Buffer.concat([header, ...entries, ...images.map((i) => i.png)]);
}

const outDir = __dirname;
const ico = buildIco([32, 256]);
fs.writeFileSync(path.join(outDir, "icon.ico"), ico);
console.log("icon.ico written:", ico.length, "bytes");
