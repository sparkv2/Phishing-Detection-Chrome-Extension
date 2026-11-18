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
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
for (const f of ['src/data.js', 'src/analyzer.js', 'src/intel.js']) require(join(root, f));
const I = globalThis.PG_Intel, D = globalThis.PG_DATA;

const args = process.argv.slice(2);
const fromJson = args.includes('--from-json') ? args[args.indexOf('--from-json') + 1] : null;

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

let parsedById = {}, generated = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
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
  const descFor = (label) => {
    const k = s.id + '|' + (label || '');
    if (!descKeys.has(k)) {
      if (descs.length >= 255) return descFor(''); // description byte is full: drop the label, keep the entry
      descKeys.set(k, descs.length); descs.push({ cat: s.category, source: s.name, sourceId: s.id, label: label || '' });
    }
    return descKeys.get(k);
  };
  const { entries, count, skipped } = I.sourceEntries(data, descFor, extra);
  allEntries.push(...entries);
  const sample = entries.find(([k]) => !k.startsWith('url:'));
  sources.push({ id: s.id, name: s.name, category: s.category, license: s.license, homepage: s.homepage,
    fetchedFrom: data.fetchedFrom || '', fetched: data.fetched || generated, count, skipped, sample: sample ? sample[0] : '' });
}
if (!sources.length) { console.error('No sources could be loaded; leaving the existing files alone.'); process.exit(1); }

const idx = I.buildCompact(allEntries);
mkdirSync(join(root, 'data'), { recursive: true });
writeFileSync(join(root, 'data/threat-intel.bin'), I.serializeCompact(idx));
writeFileSync(join(root, 'data/threat-intel.meta.json'), JSON.stringify({ format: 1, generated, total: idx.hi.length, descs, sources }, null, 1) + '\n');

console.table(sources.map(({ id, category, count, skipped }) => ({ id, category, count, skipped })));
console.log(`Wrote data/threat-intel.bin (${Math.round((8 + idx.hi.length * 8) / 1024)} KB, ${idx.hi.length} entries) and data/threat-intel.meta.json`);
