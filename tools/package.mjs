#!/usr/bin/env node
// Builds store-ready copies of the extension:  node tools/package.mjs [chrome|edge|firefox ...]
// Output: dist/<target>/ (unpacked, loadable for testing) and dist/tripwire-<version>-<target>.zip (for the store).
// No dependencies: the zip is written with a minimal "stored" (uncompressed) zip writer.
import { readFileSync, writeFileSync, mkdirSync, rmSync, readdirSync, statSync, cpSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { deflateRawSync } from 'node:zlib';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const INCLUDE = ['manifest.json', 'background.js', 'src', 'popup', 'offscreen', 'practice', 'vendor', 'icons', 'data', 'LICENSE'];
const targets = process.argv.slice(2).length ? process.argv.slice(2) : ['chrome', 'edge', 'firefox'];
const base = JSON.parse(readFileSync(join(root, 'manifest.json'), 'utf8'));

function manifestFor(target) {
  const m = structuredClone(base);
  if (target === 'firefox') {
    // Firefox runs MV3 background scripts as an event page instead of a service worker, and has no offscreen
    // documents or built-in AI model, so the on-device AI option simply reports "not supported" there.
    m.background = { scripts: ['src/data.js', 'src/analyzer.js', 'src/intel.js', 'vendor/jsQR.js', 'background.js'] };
    m.permissions = m.permissions.filter((p) => p !== 'offscreen');
    m.browser_specific_settings = { gecko: { id: process.env.TRIPWIRE_GECKO_ID || 'tripwire@example.com', strict_min_version: '128.0' } };
    m.content_scripts = m.content_scripts.map((c) => Object.assign({}, c, { matches: c.matches.filter((x) => !x.startsWith('file:')) }));
  }
  return m;
}

const files = (dir) => readdirSync(dir).flatMap((n) => { const p = join(dir, n); return statSync(p).isDirectory() ? files(p) : [p]; });

const CRC = new Uint32Array(256).map((_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
const crc32 = (buf) => { let c = 0xffffffff; for (const b of buf) c = CRC[(c ^ b) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
function zip(entries) { // entries: [{ name, data: Buffer }] -> Buffer (deflate)
  const parts = [], central = [];
  let offset = 0;
  for (const { name, data } of entries) {
    const nameBuf = Buffer.from(name.split(sep).join('/'));
    const packed = deflateRawSync(data, { level: 9 });
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(0, 6); local.writeUInt16LE(8, 8);
    local.writeUInt32LE(0, 10); local.writeUInt32LE(crc, 14); local.writeUInt32LE(packed.length, 18); local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26); local.writeUInt16LE(0, 28);
    parts.push(local, nameBuf, packed);
    const cen = Buffer.alloc(46);
    cen.writeUInt32LE(0x02014b50, 0); cen.writeUInt16LE(20, 4); cen.writeUInt16LE(20, 6); cen.writeUInt16LE(0, 8); cen.writeUInt16LE(8, 10);
    cen.writeUInt32LE(0, 12); cen.writeUInt32LE(crc, 16); cen.writeUInt32LE(packed.length, 20); cen.writeUInt32LE(data.length, 24);
    cen.writeUInt16LE(nameBuf.length, 28); cen.writeUInt32LE(offset, 42);
    central.push(cen, nameBuf);
    offset += 30 + nameBuf.length + packed.length;
  }
  const cenBuf = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cenBuf.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...parts, cenBuf, end]);
}

for (const target of targets) {
  const out = join(root, 'dist', target);
  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  for (const item of INCLUDE) { try { cpSync(join(root, item), join(out, item), { recursive: true }); } catch (e) { if (e.code !== 'ENOENT') throw e; } }
  writeFileSync(join(out, 'manifest.json'), JSON.stringify(manifestFor(target), null, 2) + '\n');
  const entries = files(out).map((p) => ({ name: relative(out, p), data: readFileSync(p) }));
  const zipPath = join(root, 'dist', `tripwire-${base.version}-${target}.zip`);
  writeFileSync(zipPath, zip(entries));
  console.log(`${target}: dist/${target}/ and ${relative(root, zipPath)} (${entries.length} files, ${Math.round(statSync(zipPath).size / 1024)} KB)`);
}
