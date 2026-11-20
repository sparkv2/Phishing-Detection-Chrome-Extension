// Webmail layout rules: built-in copy in sync, update acceptance, selector fallback and signatures.
'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { generateKeyPairSync, sign } = require('node:crypto');

const root = join(__dirname, '..');
for (const f of ['src/data.js', 'src/analyzer.js', 'src/intel.js', 'src/selectors.js']) require(join(root, f));
const S = globalThis.PG_Selectors, I = globalThis.PG_Intel;
const manifest = JSON.parse(readFileSync(join(root, 'manifest.json'), 'utf8'));

test('the built-in rules match data/selectors.json', () => {
  const file = JSON.parse(readFileSync(join(root, 'data/selectors.json'), 'utf8'));
  for (const k of ['format', 'version', 'minExtension', 'adapters']) assert.deepEqual(S.BUILTIN[k], file[k], k);
});

test('the rules file never asks for a newer extension than the one it ships in', () => {
  assert.ok(S.cmpVersion(manifest.version, S.BUILTIN.minExtension) >= 0);
});

test('content scripts load the rules before the adapters', () => {
  const js = manifest.content_scripts[0].js;
  assert.ok(js.indexOf('src/selectors.js') >= 0 && js.indexOf('src/selectors.js') < js.indexOf('src/providers.js'), js.join());
});

test('an update is only accepted if newer, well-formed and compatible', () => {
  const rules = (v, min) => ({ format: 1, version: v, minExtension: min || '1.4.0', adapters: {} });
  assert.equal(S.acceptRules(rules(S.BUILTIN.version)).ok, false, 'same version as built-in');
  assert.equal(S.acceptRules(rules(5), { currentVersion: 5 }).ok, false, 'replay of the version in use');
  assert.equal(S.acceptRules(rules(4), { currentVersion: 5 }).ok, false, 'older than the version in use');
  assert.equal(S.acceptRules(rules(6, '9.0.0'), { currentVersion: 5, extensionVersion: '1.4.0' }).ok, false, 'needs a newer extension');
  assert.equal(S.acceptRules({ format: 2, version: 9, adapters: {} }).ok, false, 'unknown format');
  assert.equal(S.acceptRules(rules(6), { currentVersion: 5, extensionVersion: manifest.version }).ok, true);
});

test('updated selectors are tried first, then the built-in ones', () => {
  const valid = (s) => !s.includes('!!');
  const remote = { adapters: { gmail: { row: 'tr.newRow', bogus: 'x', body: '!!broken', sender: 'x'.repeat(700) }, generic: { body: '.new-body' } } };
  assert.deepEqual(S.candidates(remote, 'gmail', 'row', valid), ['tr.newRow', 'tr.zA']);
  assert.deepEqual(S.candidates(remote, 'gmail', 'body', valid), ['div.a3s'], 'invalid selector skipped');
  assert.deepEqual(S.candidates(remote, 'gmail', 'sender', valid), [S.BUILTIN.adapters.gmail.sender], 'over-long selector skipped');
  assert.deepEqual(S.candidates(remote, 'gmail', 'bogus', valid), [], 'unknown keys are ignored');
  assert.deepEqual(S.candidates(remote, 'outlook', 'body', valid), ['.new-body', S.BUILTIN.adapters.generic.body], 'Outlook falls back to generic');
  assert.deepEqual(S.candidates(null, 'yahoo', 'row', valid), [S.BUILTIN.adapters.yahoo.row]);
});

test('rules must carry a valid signature', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pub = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64');
  const bytes = Buffer.from(JSON.stringify({ format: 1, version: 2, minExtension: '1.4.0', adapters: { gmail: { row: 'tr.x' } } }));
  const sig = sign(null, bytes, privateKey).toString('base64');
  assert.equal((await I.verifyRules(bytes, sig, { publicKey: pub })).version, 2);
  const tampered = Buffer.from(bytes.toString().replace('tr.x', 'tr.y'));
  await assert.rejects(I.verifyRules(tampered, sig, { publicKey: pub }), /bad signature/);
  await assert.rejects(I.verifyRules(bytes, sig), /bad signature/, 'must not verify with the project key');
});
