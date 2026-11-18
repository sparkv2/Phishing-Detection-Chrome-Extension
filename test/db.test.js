// Community-report rules, tested directly against the storage layer.
'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { mkdtempSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

process.env.STATE_DIRECTORY = mkdtempSync(join(tmpdir(), 'tw-db-'));
delete process.env.REPORT_MIN_AGE_DAYS; // use the real default (1 day)

test('a domain is not published on its first day, even with enough networks', async () => {
  const db = await import('../server/db.mjs');
  const { q, netKey } = db.openDb();
  const h = db.fingerprint('brand-new-scam.example');
  for (const ip of ['203.0.113.1', '198.51.100.1', '192.0.2.1']) { q.insert.run(h, netKey(ip), db.today()); q.firstSeen.run(h, db.today()); }
  assert.ok(!db.publishable(q).includes(h), 'published on day one');
  // Same reports, but first seen two days ago: now it qualifies.
  const { DatabaseSync } = await import('node:sqlite');
  const raw = new DatabaseSync(join(process.env.STATE_DIRECTORY, 'reports.db'));
  raw.prepare('UPDATE first_seen SET day = ? WHERE hash = ?').run(db.today() - 2, h);
  assert.ok(db.publishable(q).includes(h), 'not published once old enough');
});

test('network codes: IPv4 /24 and IPv6 /32 group together, and never contain the address', async () => {
  const db = await import('../server/db.mjs');
  const { netKey, networkOf } = db.openDb();
  assert.equal(netKey('203.0.113.5'), netKey('203.0.113.250'));
  assert.notEqual(netKey('203.0.113.5'), netKey('203.0.114.5'));
  assert.equal(networkOf('2001:db8:1234:5678::1'), '2001:db8::/32');
  assert.ok(!netKey('203.0.113.5').includes('203'));
});
