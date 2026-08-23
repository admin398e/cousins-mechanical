/*
 * make-favicon.mjs — build public/favicon.ico from the existing PNG icon.
 *
 * Every page already declares <link rel="icon"> pointing at icon-192.png, and
 * browsers request /favicon.ico anyway. That was a 404 on every single page
 * load — the same shape of problem as the {{ token }} image requests, just
 * quieter, and it also means some browsers show a blank tab icon.
 *
 * An .ico may embed a PNG directly (Vista onwards, which is every browser that
 * matters now), so this needs no image library: resize with sips, then write a
 * 22-byte header in front of the PNG bytes.
 *
 *   node tools/make-favicon.mjs
 */
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const source = path.join(root, 'public', 'images', 'icon-192.png');
const out = path.join(root, 'public', 'favicon.ico');

if (!fs.existsSync(source)) {
  console.error('  MISSING  public/images/icon-192.png — cannot build favicon');
  process.exit(1);
}

const tmp = path.join(root, 'public', 'images', '.favicon-32.png');
try {
  execFileSync('sips', ['-z', '32', '32', source, '--out', tmp], { stdio: 'pipe' });
} catch (e) {
  console.error('  sips failed — favicon not rebuilt:', String(e.message).slice(0, 120));
  process.exit(1);
}

const png = fs.readFileSync(tmp);
fs.rmSync(tmp, { force: true });

const header = Buffer.alloc(22);
header.writeUInt16LE(0, 0);            // reserved
header.writeUInt16LE(1, 2);            // 1 = icon
header.writeUInt16LE(1, 4);            // one image
header.writeUInt8(32, 6);              // width
header.writeUInt8(32, 7);              // height
header.writeUInt8(0, 8);               // palette size (0 = no palette)
header.writeUInt8(0, 9);               // reserved
header.writeUInt16LE(1, 10);           // colour planes
header.writeUInt16LE(32, 12);          // bits per pixel
header.writeUInt32LE(png.length, 14);  // size of the image data
header.writeUInt32LE(22, 18);          // offset — straight after this header

fs.writeFileSync(out, Buffer.concat([header, png]));
console.log(`  favicon.ico  ${png.length + 22} bytes (32x32 PNG inside an ICO wrapper)`);
