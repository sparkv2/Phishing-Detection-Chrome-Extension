#!/usr/bin/env node
// Downloads what GitHub Actions publishes in the "intel-latest" release, verifies each file with the public key in
// src/intel.js, and only then replaces the copy this server hands out:
//   - the signed threat list (threat-intel.bin + meta.json + .sig)
//   - the signed webmail layout rules (selectors.json + .sig)
// The server never holds the signing key, so even a compromised server can't produce files extensions will accept.
import { writeFileSync, renameSync, mkdirSync, readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
for (const f of ['src/data.js', 'src/analyzer.js', 'src/intel.js', 'src/selectors.js']) require(join(root, f));
const I = globalThis.PG_Intel, S = globalThis.PG_Selectors;

const SOURCE = process.env.INTEL_SOURCE || 'https://github.com/sparkv2/Phishing-Detection-Chrome-Extension/releases/download/intel-latest';
const OUT = process.env.INTEL_DIR || join(process.env.STATE_DIRECTORY || '/var/lib/tripwire', 'intel');

const get = async (name) => {
  const r = await fetch(`${SOURCE}/${name}`, { redirect: 'follow', signal: AbortSignal.timeout(60000), headers: { 'user-agent': 'tripwire-server' } });
  if (!r.ok) throw new Error(`${name}: HTTP ${r.status}`);
  return Buffer.from(await r.arrayBuffer());
};
const readJson = (name) => { try { return existsSync(join(OUT, name)) ? JSON.parse(readFileSync(join(OUT, name), 'utf8')) : null; } catch (e) { return null; } };
// Write every file under a temporary name, then swap them in (data first, its description last).
function install(files) {
  mkdirSync(OUT, { recursive: true });
  for (const [n, data] of files) writeFileSync(join(OUT, n + '.tmp'), data);
  for (const [n] of files) renameSync(join(OUT, n + '.tmp'), join(OUT, n));
}

let failed = false;

try {
  const [meta, sig, bin] = await Promise.all(['threat-intel.meta.json', 'threat-intel.meta.json.sig', 'threat-intel.bin'].map(get));
  const current = (readJson('threat-intel.meta.json') || {}).generated || null;
  const v = await I.verifyIntel(meta, sig.toString('utf8'), bin, { notOlderThan: current });
  if (current && v.generated === current) console.log(`List: already serving ${current}.`);
  else { install([['threat-intel.bin', bin], ['threat-intel.meta.json.sig', sig], ['threat-intel.meta.json', meta]]); console.log(`List: verified and installed ${v.generated} (${v.total} entries).`); }
} catch (e) { failed = true; console.error('List not updated:', e.message); }

try {
  const [rules, sig] = await Promise.all(['selectors.json', 'selectors.json.sig'].map(get));
  const parsed = await I.verifyRules(rules, sig.toString('utf8'));
  const current = (readJson('selectors.json') || {}).version || 0;
  if (parsed.format !== 1 || !Number.isInteger(parsed.version)) throw new Error('unknown format');
  if (parsed.version < current) throw new Error(`version ${parsed.version} is older than the ${current} already served`);
  if (parsed.version === current) console.log(`Layout rules: already serving version ${current}.`);
  else { install([['selectors.json.sig', sig], ['selectors.json', rules]]); console.log(`Layout rules: verified and installed version ${parsed.version}.`); }
} catch (e) { console.error('Layout rules not updated:', e.message); }

process.exit(failed ? 1 : 0);
