// =====================================================================================================================
// Community-report storage and rules (server/db.mjs)
//
// Shared by the server (tripwire-server.mjs) and the admin tool (tripwire-admin.mjs). Holds the settings, the SQLite
// database, how reporters are told apart (an HMAC of their network, never their address), and the rule for which
// reported domains get published (publishable()).
// =====================================================================================================================
import { createHmac, randomBytes, createHash } from 'node:crypto';
import { readFileSync, existsSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { DatabaseSync } from 'node:sqlite';

export const STATE = process.env.STATE_DIRECTORY || '/var/lib/tripwire';
export const THRESHOLD = Number(process.env.REPORT_THRESHOLD || 3); // distinct networks before a domain is published
export const MIN_AGE_DAYS = Number(process.env.REPORT_MIN_AGE_DAYS ?? 1); // first report must be this old: no instant flagging
export const RETENTION_DAYS = 90;
export const MAX_REPORTS_PER_NET_PER_DAY = 50;
export const MAX_ROWS = Number(process.env.REPORT_MAX_ROWS || 500000); // hard cap so a flood can't fill the disk
export const HASH_PREFIX = 'tripwire-report-v1|';

// Never accept reports for big brands, free mail, trackers, shorteners or shared platforms.
const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
for (const f of ['src/data.js', 'src/analyzer.js', 'src/intel.js']) require(join(root, f));
const D = globalThis.PG_DATA, I = globalThis.PG_Intel;
// The same fingerprint the extension sends: SHA-256 of "tripwire-report-v1|" + domain.
export const fingerprint = (domain) => createHash('sha256').update(HASH_PREFIX + domain.toLowerCase().trim()).digest('hex');
export const PROTECTED = new Set([...D.BRANDS.flatMap((b) => b.domains), ...D.FREE_MAIL, ...D.TRACKING_DOMAINS, ...D.SHORTENERS,
  ...I.PROTECTED, ...I.SUBDOMAIN_PLATFORMS].map(fingerprint));

export const today = () => Math.floor(Date.now() / 86400000);

// Opens (creating if needed) the SQLite database and the HMAC key. Returns { db, q: prepared queries, netKey, networkOf }.
// Tables:
//   reports     one row per (domain fingerprint, reporting network); `day` = last report from that network
//   first_seen  the day a fingerprint was first reported (for the 1-day delay before publishing)
//   usage       reports per network per day (for the daily limit; pruned after 2 days)
//   suppressed  fingerprints an admin removed (see tripwire-admin.mjs); new reports for them are refused
export function openDb() {
  mkdirSync(STATE, { recursive: true });
  const secretFile = join(STATE, 'hmac.key');
  if (!existsSync(secretFile)) writeFileSync(secretFile, randomBytes(32), { mode: 0o600 });
  const secret = readFileSync(secretFile);
  const db = new DatabaseSync(join(STATE, 'reports.db'));
  db.exec(`PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS reports (hash TEXT NOT NULL, net TEXT NOT NULL, day INTEGER NOT NULL, PRIMARY KEY (hash, net));
    CREATE INDEX IF NOT EXISTS reports_day ON reports(day);
    CREATE TABLE IF NOT EXISTS first_seen (hash TEXT PRIMARY KEY, day INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS usage (net TEXT NOT NULL, day INTEGER NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (net, day));
    CREATE TABLE IF NOT EXISTS suppressed (hash TEXT PRIMARY KEY, day INTEGER NOT NULL, note TEXT NOT NULL DEFAULT '');`);
  const q = {
    insert: db.prepare('INSERT INTO reports (hash, net, day) VALUES (?, ?, ?) ON CONFLICT(hash, net) DO UPDATE SET day = excluded.day'),
    exists: db.prepare('SELECT 1 FROM reports WHERE hash = ? AND net = ?'),
    firstSeen: db.prepare('INSERT INTO first_seen (hash, day) VALUES (?, ?) ON CONFLICT(hash) DO NOTHING'),
    rows: db.prepare('SELECT COUNT(*) AS n FROM reports'),
    usage: db.prepare('SELECT n FROM usage WHERE net = ? AND day = ?'),
    bump: db.prepare('INSERT INTO usage (net, day, n) VALUES (?, ?, ?) ON CONFLICT(net, day) DO UPDATE SET n = n + excluded.n'),
    published: db.prepare(`SELECT r.hash, COUNT(*) AS c FROM reports r JOIN first_seen f ON f.hash = r.hash
      WHERE r.hash NOT IN (SELECT hash FROM suppressed) AND f.day <= ? GROUP BY r.hash HAVING c >= ? ORDER BY r.hash`),
    stats: db.prepare(`SELECT COUNT(*) AS networks, MIN(r.day) AS first, MAX(r.day) AS last, (SELECT day FROM first_seen WHERE hash = ?) AS seen
      FROM reports r WHERE r.hash = ?`),
    isSuppressed: db.prepare('SELECT note, day FROM suppressed WHERE hash = ?'),
    suppress: db.prepare('INSERT INTO suppressed (hash, day, note) VALUES (?, ?, ?) ON CONFLICT(hash) DO UPDATE SET note = excluded.note'),
    unsuppress: db.prepare('DELETE FROM suppressed WHERE hash = ?'),
    dropReports: db.prepare('DELETE FROM reports WHERE hash = ?'),
    prune: db.prepare('DELETE FROM reports WHERE day < ?'),
    pruneFirst: db.prepare('DELETE FROM first_seen WHERE hash NOT IN (SELECT hash FROM reports)'),
    pruneUsage: db.prepare('DELETE FROM usage WHERE day < ?'),
  };
  // Reporters are told apart by network, never by address: /24 for IPv4, /32 for IPv6 (one IPv6 tunnel account
  // easily yields many /48s, so the coarser /32 stops one person posing as several).
  const networkOf = (ip) => {
    ip = (ip || '').replace(/^::ffff:/, '');
    if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return ip.split('.').slice(0, 3).join('.') + '.0/24';
    if (ip.includes(':')) return ip.split(':').slice(0, 2).join(':') + '::/32';
    return 'unknown';
  };
  const netKey = (ip) => createHmac('sha256', secret).update(networkOf(ip)).digest('hex').slice(0, 32);
  return { db, q, netKey, networkOf };
}

// Reports that may be shown to everyone: enough distinct networks, old enough, not suppressed, not protected.
export function publishable(q) {
  q.prune.run(today() - RETENTION_DAYS);
  q.pruneFirst.run();
  q.pruneUsage.run(today() - 2);
  return q.published.all(today() - MIN_AGE_DAYS, THRESHOLD).map((r) => r.hash).filter((h) => !PROTECTED.has(h));
}
