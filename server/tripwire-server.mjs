#!/usr/bin/env node
// Tripwire community server. Node 22+, no dependencies.
//
//   GET  /v1/health                      -> { ok: true }
//   GET  /v1/intel/threat-intel.bin      -> compact threat list (rebuilt from the public feeds by tripwire-intel.timer)
//   GET  /v1/intel/threat-intel.meta.json
//   GET  /v1/community.json              -> fingerprints of domains reported by at least THRESHOLD different networks
//   POST /v1/reports  { v: 1, hashes: ["<64 hex>", ...] }   (opt-in, from extensions)
//
// Privacy: a report is only a SHA-256 fingerprint of a registrable domain ("tripwire-report-v1|" + domain), never an
// email, address or URL. The reporter's IP is not stored: only an HMAC of its /24 (IPv4) or /48 (IPv6) network, used
// to count *different* reporters, and it is deleted with the report after RETENTION_DAYS.
// Runs behind Cloudflare Tunnel on 127.0.0.1 only; the systemd unit forbids any other network access.
import { createServer } from 'node:http';
import { createHmac, randomBytes, createHash } from 'node:crypto';
import { readFileSync, existsSync, writeFileSync, statSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { DatabaseSync } from 'node:sqlite';

const PORT = Number(process.env.PORT || 8787);
const HOST = process.env.HOST || '127.0.0.1';
const STATE = process.env.STATE_DIRECTORY || '/var/lib/tripwire';
const INTEL_DIR = process.env.INTEL_DIR || join(STATE, 'intel');
const THRESHOLD = Number(process.env.REPORT_THRESHOLD || 3); // distinct networks before a domain is published
const RETENTION_DAYS = 90;
const CACHE_MS = Number(process.env.COMMUNITY_CACHE_MS ?? 10 * 60 * 1000);
const MAX_REPORTS_PER_NET_PER_DAY = 50;
const HASH_PREFIX = 'tripwire-report-v1|';
const ALLOWED_ORIGIN = /^chrome-extension:\/\/[a-p]{32}$|^moz-extension:\/\/[0-9a-f-]{36}$|^extension:\/\//;

// ---------- shared data from the extension: never accept reports for big brands, free mail, shared platforms ----------
const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
for (const f of ['src/data.js', 'src/analyzer.js', 'src/intel.js']) require(join(root, f));
const D = globalThis.PG_DATA, I = globalThis.PG_Intel;
const fingerprint = (domain) => createHash('sha256').update(HASH_PREFIX + domain).digest('hex');
const PROTECTED = new Set([...D.BRANDS.flatMap((b) => b.domains), ...D.FREE_MAIL, ...D.TRACKING_DOMAINS, ...D.SHORTENERS,
  ...I.PROTECTED, ...I.SUBDOMAIN_PLATFORMS].map(fingerprint));

// ---------- storage ----------
mkdirSync(STATE, { recursive: true });
const secretFile = join(STATE, 'hmac.key');
if (!existsSync(secretFile)) writeFileSync(secretFile, randomBytes(32), { mode: 0o600 });
const SECRET = readFileSync(secretFile);
const db = new DatabaseSync(join(STATE, 'reports.db'));
db.exec(`PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS reports (hash TEXT NOT NULL, net TEXT NOT NULL, day INTEGER NOT NULL, PRIMARY KEY (hash, net));
  CREATE INDEX IF NOT EXISTS reports_day ON reports(day);
  CREATE TABLE IF NOT EXISTS usage (net TEXT NOT NULL, day INTEGER NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (net, day));`);
const q = {
  insert: db.prepare('INSERT INTO reports (hash, net, day) VALUES (?, ?, ?) ON CONFLICT(hash, net) DO UPDATE SET day = excluded.day'),
  usage: db.prepare('SELECT n FROM usage WHERE net = ? AND day = ?'),
  bump: db.prepare('INSERT INTO usage (net, day, n) VALUES (?, ?, ?) ON CONFLICT(net, day) DO UPDATE SET n = n + excluded.n'),
  published: db.prepare('SELECT hash, COUNT(*) AS c FROM reports GROUP BY hash HAVING c >= ? ORDER BY hash'),
  prune: db.prepare('DELETE FROM reports WHERE day < ?'),
  pruneUsage: db.prepare('DELETE FROM usage WHERE day < ?'),
};
const today = () => Math.floor(Date.now() / 86400000);

function networkOf(ip) {
  ip = (ip || '').replace(/^::ffff:/, '');
  if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return ip.split('.').slice(0, 3).join('.') + '.0/24';
  if (ip.includes(':')) return ip.split(':').slice(0, 3).join(':') + '::/48';
  return 'unknown';
}
const netKey = (ip) => createHmac('sha256', SECRET).update(networkOf(ip)).digest('hex').slice(0, 32);

let communityCache = null;
function community() {
  if (communityCache && Date.now() - communityCache.at < CACHE_MS) return communityCache.body;
  q.prune.run(today() - RETENTION_DAYS);
  q.pruneUsage.run(today() - 2);
  const hashes = q.published.all(THRESHOLD).map((r) => r.hash).filter((h) => !PROTECTED.has(h));
  const body = JSON.stringify({ v: 1, generated: new Date().toISOString(), threshold: THRESHOLD, prefix: HASH_PREFIX, hashes });
  communityCache = { at: Date.now(), body };
  return body;
}

// ---------- http ----------
function send(res, status, body, headers) {
  res.writeHead(status, Object.assign({ 'content-type': 'application/json; charset=utf-8', 'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer', 'cache-control': 'no-store' }, headers || {}));
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}
function cors(req) {
  const o = req.headers.origin || '';
  return ALLOWED_ORIGIN.test(o) ? { 'access-control-allow-origin': o, 'access-control-allow-methods': 'GET, POST',
    'access-control-allow-headers': 'content-type', 'access-control-max-age': '86400', vary: 'origin' } : {};
}
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => { size += c.length; if (size > limit) { reject(new Error('too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

const INTEL_FILES = { 'threat-intel.bin': 'application/octet-stream', 'threat-intel.meta.json': 'application/json; charset=utf-8' };

const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const extra = cors(req);
  try {
    if (req.method === 'OPTIONS') return send(res, 204, '', extra);
    if (req.method === 'GET' && url.pathname === '/v1/health') return send(res, 200, { ok: true }, extra);
    if (req.method === 'GET' && url.pathname.startsWith('/v1/intel/')) {
      const name = url.pathname.slice('/v1/intel/'.length);
      const file = join(INTEL_DIR, name);
      if (!INTEL_FILES[name] || !existsSync(file)) return send(res, 404, { error: 'not found' }, extra);
      const st = statSync(file);
      const etag = `"${st.size}-${st.mtimeMs | 0}"`;
      if (req.headers['if-none-match'] === etag) return send(res, 304, '', Object.assign({ etag }, extra));
      return send(res, 200, readFileSync(file), Object.assign({ 'content-type': INTEL_FILES[name], etag, 'cache-control': 'public, max-age=1800' }, extra));
    }
    if (req.method === 'GET' && url.pathname === '/v1/community.json') {
      return send(res, 200, community(), Object.assign({ 'cache-control': 'public, max-age=600' }, extra));
    }
    if (req.method === 'POST' && url.pathname === '/v1/reports') {
      if (!(req.headers['content-type'] || '').startsWith('application/json')) return send(res, 415, { error: 'json only' }, extra);
      const body = JSON.parse(await readBody(req, 4096));
      const hashes = [...new Set(Array.isArray(body.hashes) ? body.hashes : [])].filter((h) => /^[0-9a-f]{64}$/.test(h)).slice(0, 20);
      if (body.v !== 1 || !hashes.length) return send(res, 400, { error: 'bad request' }, extra);
      // Behind Cloudflare Tunnel every request arrives from localhost; the real client IP is in CF-Connecting-IP.
      const net = netKey(req.headers['cf-connecting-ip'] || req.socket.remoteAddress);
      const used = (q.usage.get(net, today()) || {}).n || 0;
      if (used + hashes.length > MAX_REPORTS_PER_NET_PER_DAY) return send(res, 429, { error: 'too many reports today' }, extra);
      q.bump.run(net, today(), hashes.length);
      let accepted = 0;
      for (const h of hashes) { if (PROTECTED.has(h)) continue; q.insert.run(h, net, today()); accepted++; }
      return send(res, 202, { accepted }, extra);
    }
    return send(res, 404, { error: 'not found' }, extra);
  } catch (e) {
    return send(res, e instanceof SyntaxError ? 400 : 500, { error: e instanceof SyntaxError ? 'bad json' : 'server error' }, extra);
  }
});
server.headersTimeout = 10000;
server.requestTimeout = 15000;
server.listen(PORT, HOST, () => console.log(`tripwire-server listening on ${HOST}:${PORT}, state in ${STATE}`));
