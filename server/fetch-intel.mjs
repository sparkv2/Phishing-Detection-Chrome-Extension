#!/usr/bin/env node
// Downloads the signed threat list that GitHub Actions publishes (release "intel-latest"), verifies it with the
// public key in src/intel.js, and only then replaces the copy this server hands out. The server never holds the
// signing key, so even a compromised server can't produce a list extensions will accept.
import { writeFileSync, renameSync, mkdirSync, readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
for (const f of ['src/data.js', 'src/analyzer.js', 'src/intel.js']) require(join(root, f));
const I = globalThis.PG_Intel;

const SOURCE = process.env.INTEL_SOURCE || 'https://github.com/sparkv2/Phishing-Detection-Chrome-Extension/releases/download/intel-latest';
const OUT = process.env.INTEL_DIR || join(process.env.STATE_DIRECTORY || '/var/lib/tripwire', 'intel');
const FILES = ['threat-intel.meta.json', 'threat-intel.meta.json.sig', 'threat-intel.bin'];

const get = async (name) => {
  const r = await fetch(`${SOURCE}/${name}`, { redirect: 'follow', signal: AbortSignal.timeout(60000), headers: { 'user-agent': 'tripwire-server' } });
  if (!r.ok) throw new Error(`${name}: HTTP ${r.status}`);
  return Buffer.from(await r.arrayBuffer());
};

const [meta, sig, bin] = await Promise.all(FILES.map(get));
let current = null;
try { if (existsSync(join(OUT, FILES[0]))) current = JSON.parse(readFileSync(join(OUT, FILES[0]), 'utf8')).generated; } catch (e) { /* replace a damaged copy */ }
const verified = await I.verifyIntel(meta, sig.toString('utf8'), bin, { notOlderThan: current });
if (current && verified.generated === current) { console.log(`Already serving the list from ${current}.`); process.exit(0); }

mkdirSync(OUT, { recursive: true });
// Write all three, then swap them in: the bin first, so meta.json never points at a list that isn't there yet.
FILES.forEach((n, i) => writeFileSync(join(OUT, n + '.tmp'), [meta, sig, bin][i]));
for (const n of ['threat-intel.bin', 'threat-intel.meta.json.sig', 'threat-intel.meta.json']) renameSync(join(OUT, n + '.tmp'), join(OUT, n));
console.log(`Verified and installed the list from ${verified.generated} (${verified.total} entries).`);
