// Signed threat lists: a list is only accepted with a valid signature, a matching checksum and a recent date.
'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { generateKeyPairSync, sign, createHash } = require('node:crypto');
const { join } = require('node:path');

const root = join(__dirname, '..');
for (const f of ['src/data.js', 'src/analyzer.js', 'src/intel.js']) require(join(root, f));
const I = globalThis.PG_Intel;

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const pub = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64');
const bin = Buffer.from(I.serializeCompact(I.buildCompact([['evil.example', 0], ['bad.example', 1]])));
const metaFor = (over) => Buffer.from(JSON.stringify(Object.assign({ format: 1, generated: new Date().toISOString(), total: 2,
  binSha256: createHash('sha256').update(bin).digest('hex'), descs: [], sources: [] }, over)));
const sigOf = (m) => sign(null, m, privateKey).toString('base64');

test('accepts a correctly signed, recent list', async () => {
  const m = metaFor();
  const meta = await I.verifyIntel(m, sigOf(m), bin, { publicKey: pub });
  assert.equal(meta.total, 2);
});

test('rejects a list signed by another key (for example a compromised server)', async () => {
  const other = generateKeyPairSync('ed25519').privateKey;
  const m = metaFor();
  await assert.rejects(I.verifyIntel(m, sign(null, m, other).toString('base64'), bin, { publicKey: pub }), /bad signature/);
});

test('rejects a swapped list file even if meta.json is genuine', async () => {
  const m = metaFor();
  const evilBin = Buffer.from(I.serializeCompact(I.buildCompact([['mail.google.com', 0], ['bad.example', 1]])));
  await assert.rejects(I.verifyIntel(m, sigOf(m), evilBin, { publicKey: pub }), /checksum/);
});

test('rejects an edited meta.json', async () => {
  const m = metaFor();
  const edited = Buffer.from(m.toString().replace('"total":2', '"total":3'));
  await assert.rejects(I.verifyIntel(edited, sigOf(m), bin, { publicKey: pub }), /bad signature/);
});

test('rejects replaying an older signed list, and lists more than 3 days old', async () => {
  const old = metaFor({ generated: new Date(Date.now() - 86400000).toISOString() });
  await assert.rejects(I.verifyIntel(old, sigOf(old), bin, { publicKey: pub, notOlderThan: new Date().toISOString() }), /older than/);
  const stale = metaFor({ generated: new Date(Date.now() - 4 * 86400000).toISOString() });
  await assert.rejects(I.verifyIntel(stale, sigOf(stale), bin, { publicKey: pub }), /3 days/);
});

test('a list that includes protected sites still never flags them', () => {
  const D = globalThis.PG_DATA;
  const never = new Set([...D.BRANDS.flatMap((b) => b.domains), ...D.FREE_MAIL, ...D.TRACKING_DOMAINS]);
  const poisoned = I.buildCompact([['gmail.com', 0], ['google.com', 0], ['github.io', 0], ['paypal.com', 0], ['evil.example', 0], ['bad.vercel.app', 0]]);
  for (const h of ['gmail.com', 'mail.google.com', 'sparkv2.github.io', 'www.paypal.com', 'docs.google.com']) assert.equal(I.lookupHost(poisoned, h, never), null, h);
  assert.equal(I.lookupHost(poisoned, 'login.evil.example', never).matched, 'evil.example');
  assert.equal(I.lookupHost(poisoned, 'bad.vercel.app', never).matched, 'bad.vercel.app');
});

test('the shipped public key is a valid Ed25519 key', async () => {
  const raw = Uint8Array.from(atob(I.SIGNING_PUBLIC_KEY), (c) => c.charCodeAt(0));
  assert.equal(raw.length, 32);
  await crypto.subtle.importKey('raw', raw, { name: 'Ed25519' }, false, ['verify']);
});
