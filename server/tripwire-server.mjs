#!/usr/bin/env node
// Tripwire community server. Node 22+, no dependencies.
//
//   GET  /v1/health                          -> { ok: true }
//   GET  /v1/intel/threat-intel.bin          -> compact threat list, built and signed by GitHub Actions,
//   GET  /v1/intel/threat-intel.meta.json        verified here by tripwire-intel.service before it is served
//   GET  /v1/intel/threat-intel.meta.json.sig
//   GET  /v1/community.json                  -> fingerprints of domains reported by enough different networks
//   POST /v1/reports  { v: 1, hashes: ["<64 hex>", ...] }   (opt-in, from extensions)
//
// Privacy: a report is only a SHA-256 fingerprint of a registrable domain ("tripwire-report-v1|" + domain). The
// reporter's IP is never stored: only an HMAC of its network, used to count *different* reporters. Reports are
// deleted after 90 days. Runs behind Cloudflare Tunnel on 127.0.0.1; the systemd unit forbids other network access.
import { createServer } from 'node:http';
import { readFileSync, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { STATE, THRESHOLD, MAX_REPORTS_PER_NET_PER_DAY, MAX_ROWS, HASH_PREFIX, PROTECTED, today, openDb, publishable } from './db.mjs';

const PORT = Number(process.env.PORT || 8787);
const HOST = process.env.HOST || '127.0.0.1';
const INTEL_DIR = process.env.INTEL_DIR || join(STATE, 'intel');
const CACHE_MS = Number(process.env.COMMUNITY_CACHE_MS ?? 10 * 60 * 1000);
const ALLOWED_ORIGIN = /^chrome-extension:\/\/[a-p]{32}$|^moz-extension:\/\/[0-9a-f-]{36}$|^extension:\/\//;

const { q, netKey } = openDb();

let communityCache = null;
function community() {
  if (communityCache && Date.now() - communityCache.at < CACHE_MS) return communityCache.body;
  const body = JSON.stringify({ v: 1, generated: new Date().toISOString(), threshold: THRESHOLD, prefix: HASH_PREFIX, hashes: publishable(q) });
  communityCache = { at: Date.now(), body };
  return body;
}
let rowCount = { at: 0, n: 0 };
const rows = () => { if (Date.now() - rowCount.at > 60000) rowCount = { at: Date.now(), n: q.rows.get().n }; return rowCount.n; };

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

const INTEL_FILES = { 'threat-intel.bin': 'application/octet-stream', 'threat-intel.meta.json': 'application/json; charset=utf-8',
  'threat-intel.meta.json.sig': 'text/plain; charset=utf-8',
  'selectors.json': 'application/json; charset=utf-8', 'selectors.json.sig': 'text/plain; charset=utf-8' }; // webmail layout rules

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
      // Behind Cloudflare Tunnel every request arrives from localhost; Cloudflare sets the real client IP in CF-Connecting-IP.
      const net = netKey(req.headers['cf-connecting-ip'] || req.socket.remoteAddress);
      const used = (q.usage.get(net, today()) || {}).n || 0;
      if (used + hashes.length > MAX_REPORTS_PER_NET_PER_DAY) return send(res, 429, { error: 'too many reports today' }, extra);
      q.bump.run(net, today(), hashes.length);
      let accepted = 0;
      for (const h of hashes) {
        if (PROTECTED.has(h) || q.isSuppressed.get(h)) continue;
        if (!q.exists.get(h, net) && rows() >= MAX_ROWS) return send(res, 503, { error: 'report store is full', accepted }, extra);
        q.insert.run(h, net, today()); q.firstSeen.run(h, today()); accepted++; rowCount.n++;
      }
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
