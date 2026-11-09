// Background service worker: holds the threat-intelligence index and answers "is this host/URL known-bad?" lookups.
// - Baseline: data/threat-intel.json, bundled with the extension (works offline).
// - Live: the same public feeds re-downloaded every 12 hours (if enabled) and kept in the Cache API.
// Privacy: feeds are only downloaded. Hosts being checked never leave this computer.
importScripts('src/data.js', 'src/analyzer.js', 'src/intel.js');
const I = self.PG_Intel;
const D = self.PG_DATA;
const CACHE = 'tripwire-intel-v1';
const REFRESH_MINUTES = 720;

let indexPromise = null;

async function loadBundled() {
  const res = await fetch(chrome.runtime.getURL('data/threat-intel.json'));
  return res.json();
}
async function loadLive() {
  const out = {};
  try {
    const c = await caches.open(CACHE);
    for (const s of I.SOURCES) {
      const r = await c.match('/live/' + s.id);
      if (r) out[s.id] = await r.json();
    }
  } catch (e) { /* no live data yet */ }
  return out;
}

function buildIndex(bundled, live) {
  // Never flag well-known brands, free email providers or mail-tracking services as whole domains.
  const extra = new Set([...D.BRANDS.flatMap((b) => b.domains), ...D.FREE_MAIL, ...D.TRACKING_DOMAINS]);
  const map = new Map();
  const descs = [];
  const descKeys = new Map();
  const desc = (s, label) => {
    const k = s.id + '|' + (label || '');
    if (!descKeys.has(k)) { descKeys.set(k, descs.length); descs.push({ cat: s.category, source: s.name, sourceId: s.id, label: label || '' }); }
    return descKeys.get(k);
  };
  const stats = [];
  for (const s of I.SOURCES) {
    const isLive = !!live[s.id];
    const data = live[s.id] || (bundled.sources || []).find((x) => x.id === s.id);
    if (!data) { stats.push({ id: s.id, name: s.name, category: s.category, count: 0, skipped: 0, updated: null, origin: 'missing' }); continue; }
    let count = 0, skipped = 0;
    for (const h of data.hosts || []) {
      if (!I.hostIsFlaggable(h, extra)) { skipped++; continue; }
      if (!map.has(h)) { map.set(h, desc(s, data.labels && data.labels[h])); count++; }
    }
    for (const u of data.urls || []) {
      const k = 'url:' + u;
      if (!map.has(k)) { map.set(k, desc(s)); count++; }
    }
    stats.push({ id: s.id, name: s.name, category: s.category, count, skipped, updated: data.fetched || bundled.generated, origin: isLive ? 'live' : 'bundled' });
  }
  return { map, descs, stats, bundledDate: bundled.generated };
}

function getIndex() {
  if (!indexPromise) {
    indexPromise = Promise.all([loadBundled().catch(() => ({ sources: [] })), loadLive()])
      .then(([b, l]) => buildIndex(b, l))
      .catch((e) => { indexPromise = null; throw e; });
  }
  return indexPromise;
}

async function lookup(hosts, urls) {
  const idx = await getIndex();
  const hits = {};
  for (const host of (hosts || []).slice(0, 2000)) {
    for (const h of I.hostAndParents(host)) {
      const d = idx.map.get(h);
      if (d !== undefined) { hits[host] = Object.assign({ matched: h }, idx.descs[d]); break; }
    }
  }
  for (const u of (urls || []).slice(0, 2000)) {
    const d = idx.map.get('url:' + u);
    if (d !== undefined) hits['url:' + u] = Object.assign({ matched: u }, idx.descs[d]);
  }
  return hits;
}

async function updateFeeds() {
  const { useFeed } = await chrome.storage.local.get(['useFeed']);
  if (useFeed === false) return { ok: false, reason: 'disabled' };
  const c = await caches.open(CACHE);
  let okCount = 0;
  for (const s of I.SOURCES) {
    for (const url of s.urls) {
      try {
        const res = await fetch(url, { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' });
        if (!res.ok) continue;
        const parsed = I.parseFeed(await res.text(), s.format);
        if (!parsed.hosts.length) continue;
        parsed.fetched = new Date().toISOString();
        parsed.fetchedFrom = url;
        await c.put('/live/' + s.id, new Response(JSON.stringify(parsed), { headers: { 'content-type': 'application/json' } }));
        okCount++;
        break;
      } catch (e) { /* try next mirror */ }
    }
  }
  indexPromise = null;
  await chrome.storage.local.set({ intelUpdated: Date.now() }); // tells open tabs to re-check
  return { ok: okCount > 0, updated: okCount, total: I.SOURCES.length };
}

chrome.runtime.onInstalled.addListener(async (details) => {
  const s = await chrome.storage.local.get(['enabled', 'useFeed']);
  const defaults = {};
  if (s.enabled === undefined) defaults.enabled = true;
  if (s.useFeed === undefined) defaults.useFeed = true;
  await chrome.storage.local.set(defaults);
  await chrome.storage.local.remove(['feedHosts', 'feedSource', 'feedUpdated']); // old single-feed storage
  chrome.alarms.create('pg-feed', { periodInMinutes: REFRESH_MINUTES });
  updateFeeds();
  if (details.reason === 'install') chrome.tabs.create({ url: chrome.runtime.getURL('popup/welcome.html') });
});
chrome.runtime.onStartup.addListener(() => updateFeeds());
chrome.alarms.onAlarm.addListener((a) => { if (a.name === 'pg-feed') updateFeeds(); });

chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  if (!msg) return;
  if (msg.type === 'pg-lookup') { lookup(msg.hosts, msg.urls).then((hits) => reply({ hits })).catch(() => reply({ hits: {} })); return true; }
  if (msg.type === 'pg-update-feed') { updateFeeds().then(reply); return true; }
  if (msg.type === 'pg-intel-status') {
    getIndex().then((idx) => reply({ total: idx.map.size, stats: idx.stats, bundledDate: idx.bundledDate })).catch(() => reply(null));
    return true;
  }
});
