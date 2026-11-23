#!/usr/bin/env node
// Downloads the public threat-intelligence feeds and compiles them into the compact list bundled with Tripwire:
//   data/threat-intel.bin        sorted 53-bit hashes (see src/intel.js, "compact index")
//   data/threat-intel.meta.json  source names, counts, dates and one sample entry per source (used by tests)
//
// Usage (Node 18+, no dependencies):
//   node tools/build-threat-intel.mjs                    download every feed and rebuild
//   node tools/build-threat-intel.mjs --from-json FILE   rebuild from an old-format threat-intel.json (offline)
//
// Feed parsing and the shared-platform filter come from src/intel.js, the same code the extension's live updater uses.
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, renameSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
for (const f of ['src/data.js', 'src/analyzer.js', 'src/intel.js']) require(join(root, f));
const I = globalThis.PG_Intel, D = globalThis.PG_DATA;

const args = process.argv.slice(2);
const fromJson = args.includes('--from-json') ? args[args.indexOf('--from-json') + 1] : null;
const outDir = args.includes('--out') ? args[args.indexOf('--out') + 1] : join(root, 'data'); // the Tripwire server writes to its state dir

async function download(source) {
  for (const url of source.urls) {
    try {
      const res = await fetch(url, { headers: { 'user-agent': 'Tripwire-threat-intel-builder' }, signal: AbortSignal.timeout(60000) });
      if (!res.ok) { console.warn(`${source.id}: ${url} -> HTTP ${res.status}`); continue; }
      const parsed = I.parseFeed(await res.text(), source.format);
      if (!parsed.hosts.length) { console.warn(`${source.id}: ${url} returned no entries`); continue; }
      return Object.assign(parsed, { fetchedFrom: url, fetched: new Date().toISOString() });
    } catch (e) { console.warn(`${source.id}: ${url} failed (${e.message})`); }
  }
  return null;
}

let parsedById = {}, generated = new Date().toISOString().replace(/\.\d+Z$/, 'Z'); // ISO date; signed lists older than 3 days are refused
if (fromJson) {
  const old = JSON.parse(readFileSync(fromJson, 'utf8'));
  generated = old.generated || generated;
  for (const s of old.sources || []) parsedById[s.id] = s;
} else {
  for (const s of I.SOURCES) {
    const p = await download(s);
    if (p) parsedById[s.id] = p; else console.warn(`${s.id}: all mirrors failed, skipping`);
  }
}

// Never flag well-known brands, free email providers or mail-tracking services as whole domains.
const extra = new Set([...D.BRANDS.flatMap((b) => b.domains), ...D.FREE_MAIL, ...D.TRACKING_DOMAINS]);
const descs = [], descKeys = new Map();
const allEntries = [], sources = [];
for (const s of I.SOURCES) {
  const data = parsedById[s.id];
  if (!data) continue;
  // Description index for (this source, label), stored in one byte. Once all 255 are used, new labels fall back to
  // an existing description of the same source (the entry is kept, only its label is dropped).
  const descFor = (label) => {
    const k = s.id + '|' + (label || '');
    if (descKeys.has(k)) return descKeys.get(k);
    if (descs.length >= 255) { const same = descs.findIndex((d) => d.sourceId === s.id); return same >= 0 ? same : 0; }
    descKeys.set(k, descs.length); descs.push({ cat: s.category, source: s.name, sourceId: s.id, label: label || '' });
    return descKeys.get(k);
  };
  const { entries, count, skipped } = I.sourceEntries(data, descFor, extra);
  for (const e of entries) allEntries.push(e); // not push(...entries): 100k+ arguments overflow the stack
  const sample = entries.find(([k]) => !k.startsWith('url:'));
  sources.push({ id: s.id, name: s.name, category: s.category, license: s.license, homepage: s.homepage,
    fetchedFrom: data.fetchedFrom || '', fetched: data.fetched || generated, count, skipped, sample: sample ? sample[0] : '' });
}
if (!sources.length) { console.error('No sources could be loaded; leaving the existing files alone.'); process.exit(1); }

const idx = I.buildCompact(allEntries);
mkdirSync(outDir, { recursive: true });
// Write to temporary names, then rename, so a reader never sees a half-written file.
const binBytes = I.serializeCompact(idx);
const binSha256 = createHash('sha256').update(binBytes).digest('hex'); // tools/sign-intel.mjs signs meta.json, which pins this
writeFileSync(join(outDir, 'threat-intel.bin.tmp'), binBytes);
writeFileSync(join(outDir, 'threat-intel.meta.json.tmp'), JSON.stringify({ format: 1, generated, total: idx.hi.length, binSha256, descs, sources }, null, 1) + '\n');
renameSync(join(outDir, 'threat-intel.bin.tmp'), join(outDir, 'threat-intel.bin'));
renameSync(join(outDir, 'threat-intel.meta.json.tmp'), join(outDir, 'threat-intel.meta.json'));

console.table(sources.map(({ id, category, count, skipped }) => ({ id, category, count, skipped })));
console.log(`Wrote threat-intel.bin (${Math.round((8 + idx.hi.length * 8) / 1024)} KB, ${idx.hi.length} entries) and threat-intel.meta.json to ${outDir}`);
