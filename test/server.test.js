// Starts the community server on a free port with a temporary state folder and exercises its API.
'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { mkdtempSync, rmSync, mkdirSync, copyFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { createHash } = require('node:crypto');

const root = join(__dirname, '..');
const PORT = 18000 + Math.floor(Math.random() * 1000);
const base = `http://127.0.0.1:${PORT}`;
let proc, state;
const fp = (d) => createHash('sha256').update('tripwire-report-v1|' + d).digest('hex');
const report = (hashes, ip) => fetch(base + '/v1/reports', { method: 'POST', headers: { 'content-type': 'application/json', 'cf-connecting-ip': ip },
  body: JSON.stringify({ v: 1, hashes }) });

before(async () => {
  state = mkdtempSync(join(tmpdir(), 'tw-server-'));
  mkdirSync(join(state, 'intel'));
  copyFileSync(join(root, 'data/threat-intel.bin'), join(state, 'intel/threat-intel.bin'));
  proc = spawn(process.execPath, [join(root, 'server/tripwire-server.mjs')], { env: Object.assign({}, process.env, {
    PORT: String(PORT), STATE_DIRECTORY: state, NODE_NO_WARNINGS: '1', ELECTRON_RUN_AS_NODE: '1', COMMUNITY_CACHE_MS: '0' }), stdio: 'ignore' });
  for (let i = 0; i < 50; i++) { try { if ((await fetch(base + '/v1/health')).ok) return; } catch (e) { /* starting */ } await new Promise((r) => setTimeout(r, 100)); }
  throw new Error('server did not start');
});
after(() => { proc.kill(); try { rmSync(state, { recursive: true, force: true }); } catch (e) { /* Windows file lock */ } });

test('health', async () => assert.deepEqual(await (await fetch(base + '/v1/health')).json(), { ok: true }));

test('serves the compact threat list', async () => {
  const r = await fetch(base + '/v1/intel/threat-intel.bin');
  assert.equal(r.status, 200);
  assert.ok((await r.arrayBuffer()).byteLength > 1000);
  assert.equal((await fetch(base + '/v1/intel/../reports.db')).status, 404);
});

test('a domain is published only after 3 different networks report it', async () => {
  const h = fp('evil-login.example');
  assert.equal((await report([h], '203.0.113.5')).status, 202);
  assert.equal((await report([h], '203.0.113.99')).status, 202); // same /24: still one reporter
  assert.equal((await report([h], '198.51.100.7')).status, 202);
  let list = await (await fetch(base + '/v1/community.json')).json();
  assert.ok(!list.hashes.includes(h), 'published with only 2 networks');
  assert.equal((await report([h], '192.0.2.44')).status, 202);
  list = await (await fetch(base + '/v1/community.json')).json();
  assert.ok(list.hashes.includes(h), 'not published after 3 networks');
  assert.equal(list.threshold, 3);
});

test('protected domains (brands, free mail, shared platforms) are never accepted', async () => {
  const r = await (await report([fp('paypal.com'), fp('gmail.com'), fp('github.com')], '100.64.1.1')).json();
  assert.equal(r.accepted, 0);
});

test('rejects malformed reports and enforces the daily limit', async () => {
  assert.equal((await fetch(base + '/v1/reports', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{bad' })).status, 400);
  assert.equal((await report(['not-a-hash'], '100.64.2.1')).status, 400);
  const many = Array.from({ length: 20 }, (_, i) => fp(`spam${i}.example`));
  assert.equal((await report(many, '100.64.3.1')).status, 202);
  assert.equal((await report(many, '100.64.3.2')).status, 202);
  assert.equal((await report(many, '100.64.3.3')).status, 429);
});
