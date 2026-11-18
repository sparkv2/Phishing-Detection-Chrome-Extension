// Background service worker.
// - Threat-intelligence index: data/threat-intel.bin (bundled, works offline) merged with the same public feeds
//   re-downloaded every 12 hours (if enabled) and kept in the Cache API. Answers "is this host/URL known-bad?".
// - Follows shortened links (bit.ly…) one redirect at a time without opening the destination.
// - Decodes QR codes in email images (jsQR, on this device).
// - Optional on-device AI check through Chrome's built-in model (Prompt API).
// - Registers Tripwire on extra webmail sites the user enables, and the optional page guard.
// Privacy: nothing about the user's email is sent anywhere. Network use: feed downloads, shortener lookups
// (only for links the user is about to open), and re-fetching images already shown in the email (for QR codes).
if (typeof importScripts === 'function') importScripts('src/data.js', 'src/analyzer.js', 'src/intel.js', 'vendor/jsQR.js');
const I = self.PG_Intel;
const D = self.PG_DATA;
const A = self.PG_Analyzer;
const CACHE = 'tripwire-intel-v2';
const REFRESH_MINUTES = 720;
const CONTENT_JS = ['src/data.js', 'src/analyzer.js', 'src/intel.js', 'src/providers.js', 'src/ui.js', 'src/content.js'];
const CONTENT_CSS = ['src/content.css'];
const GUARD_JS = ['src/data.js', 'src/analyzer.js', 'src/intel.js', 'src/guard.js'];
const MANIFEST_HOSTS = (chrome.runtime.getManifest().content_scripts || []).flatMap((c) => c.matches);

// ---------------- threat index ----------------
let indexPromise = null;

async function loadBundled() {
  const [meta, bin] = await Promise.all([
    fetch(chrome.runtime.getURL('data/threat-intel.meta.json')).then((r) => r.json()),
    fetch(chrome.runtime.getURL('data/threat-intel.bin')).then((r) => r.arrayBuffer()),
  ]);
  return { meta, idx: I.parseCompact(bin) };
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
  const meta = bundled.meta || { descs: [], sources: [] };
  const descs = meta.descs.slice();
  const descKeys = new Map(descs.map((d, i) => [d.sourceId + '|' + (d.label || ''), i]));
  const liveIds = new Set(Object.keys(live));
  // Never flag well-known brands, free email providers or mail-tracking services as whole domains.
  const extra = new Set([...D.BRANDS.flatMap((b) => b.domains), ...D.FREE_MAIL, ...D.TRACKING_DOMAINS]);
  const fresh = [], stats = [];
  for (const s of I.SOURCES) {
    const descFor = (label) => {
      const k = s.id + '|' + (label || '');
      if (!descKeys.has(k)) {
        if (descs.length >= 255) return descFor('');
        descKeys.set(k, descs.length); descs.push({ cat: s.category, source: s.name, sourceId: s.id, label: label || '' });
      }
      return descKeys.get(k);
    };
    if (live[s.id]) {
      const r = I.sourceEntries(live[s.id], descFor, extra);
      fresh.push(...r.entries);
      stats.push({ id: s.id, name: s.name, category: s.category, count: r.count, skipped: r.skipped, updated: live[s.id].fetched, origin: 'live' });
    } else {
      const m = meta.sources.find((x) => x.id === s.id);
      stats.push(m ? { id: s.id, name: s.name, category: s.category, count: m.count, skipped: m.skipped, updated: m.fetched || meta.generated, origin: 'bundled' }
        : { id: s.id, name: s.name, category: s.category, count: 0, skipped: 0, updated: null, origin: 'missing' });
    }
  }
  let idx = bundled.idx || { hi: new Uint32Array(0), lo: new Uint32Array(0) };
  if (fresh.length) {
    // Keep bundled records only for sources that have no live copy, then add the live ones.
    const replaced = new Set(descs.map((d, i) => (liveIds.has(d.sourceId) ? i : -1)).filter((i) => i >= 0));
    idx = I.mergeCompact([I.compactRecords(idx, (d) => !replaced.has(d))], fresh);
  }
  return { idx, descs, stats, bundledDate: meta.generated };
}

function getIndex() {
  if (!indexPromise) {
    indexPromise = Promise.all([loadBundled().catch(() => ({})), loadLive()])
      .then(([b, l]) => buildIndex(b, l))
      .catch((e) => { indexPromise = null; throw e; });
  }
  return indexPromise;
}

async function lookup(hosts, urls) {
  const { idx, descs } = await getIndex();
  const hits = {};
  for (const host of (hosts || []).slice(0, 2000)) {
    for (const h of I.hostAndParents(host)) {
      const d = I.lookupCompact(idx, h);
      if (d >= 0) { hits[host] = Object.assign({ matched: h }, descs[d]); break; }
    }
  }
  for (const u of (urls || []).slice(0, 2000)) {
    const d = I.lookupCompact(idx, 'url:' + u);
    if (d >= 0) hits['url:' + u] = Object.assign({ matched: u }, descs[d]);
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

// ---------------- shortened links ----------------
// Asks the shortener where a link goes by reading its redirect header. The destination itself is never opened.
const pendingRedirects = new Map(); // request URL -> resolve(location)
if (chrome.webRequest) {
  chrome.webRequest.onHeadersReceived.addListener((d) => {
    const done = pendingRedirects.get(d.url);
    if (!done || d.statusCode < 300 || d.statusCode >= 400) return;
    const loc = (d.responseHeaders || []).find((h) => h.name.toLowerCase() === 'location');
    if (loc && loc.value) done(new URL(loc.value, d.url).href);
  }, { urls: D.SHORTENERS.map((s) => `*://${s}/*`).concat(D.SHORTENERS.map((s) => `*://*.${s}/*`)) }, ['responseHeaders']);
}
const isShortener = (host) => { const h = (host || '').replace(/^www\./, ''); return D.SHORTENERS.includes(h) || D.SHORTENERS.includes(A.registrableDomain(h)); };

async function oneHop(url) {
  return new Promise((resolve) => {
    const finish = (v) => { pendingRedirects.delete(url); clearTimeout(timer); resolve(v); };
    const timer = setTimeout(() => finish(null), 6000);
    pendingRedirects.set(url, finish);
    fetch(url, { method: 'GET', redirect: 'manual', credentials: 'omit', referrerPolicy: 'no-referrer', cache: 'no-store' })
      .then(() => setTimeout(() => finish(null), 300)) // no redirect header seen
      .catch(() => finish(null));
  });
}
const expandCache = new Map();
async function expandShortLink(href) {
  if (expandCache.has(href)) return expandCache.get(href);
  const { expandLinks } = await chrome.storage.local.get(['expandLinks']);
  if (expandLinks === false) return { final: null, hops: [], reason: 'disabled' };
  let cur = href; const hops = [];
  for (let i = 0; i < 5; i++) {
    let u; try { u = new URL(cur); } catch (e) { break; }
    if (!/^https?:$/.test(u.protocol) || !isShortener(u.hostname)) break;
    const next = await oneHop(u.href);
    if (!next || next === cur) break;
    hops.push(next); cur = next;
  }
  const out = { final: hops.length ? cur : null, hops };
  expandCache.set(href, out);
  if (expandCache.size > 500) expandCache.delete(expandCache.keys().next().value);
  return out;
}

// ---------------- QR codes ----------------
async function decodeQr(src) {
  if (!self.jsQR || typeof OffscreenCanvas === 'undefined') return null;
  const res = await fetch(src, { credentials: 'include', referrerPolicy: 'no-referrer' });
  if (!res.ok) return null;
  const blob = await res.blob();
  if (blob.size > 6e6 || !/^image\//.test(blob.type || 'image/')) return null;
  const bmp = await createImageBitmap(blob);
  try {
    for (const max of [1000, 500]) {
      const scale = Math.min(1, max / Math.max(bmp.width, bmp.height));
      const w = Math.max(1, Math.round(bmp.width * scale)), h = Math.max(1, Math.round(bmp.height * scale));
      if (w < 40 || h < 40) break;
      const canvas = new OffscreenCanvas(w, h);
      const ctx = canvas.getContext('2d', { willReadFrequently: true });
      ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, w, h); // transparent PNGs: QR codes are drawn on white
      ctx.drawImage(bmp, 0, 0, w, h);
      const found = self.jsQR(ctx.getImageData(0, 0, w, h).data, w, h, { inversionAttempts: 'attemptBoth' });
      if (found && found.data) return found.data.slice(0, 2000);
      if (scale === 1) break;
    }
  } finally { bmp.close && bmp.close(); }
  return null;
}
async function decodeQrList(srcs) {
  const out = [];
  for (const src of (srcs || []).slice(0, 8)) {
    try { const data = await decodeQr(src); if (data) out.push({ data }); } catch (e) { /* not an image we can read */ }
  }
  return out;
}

// ---------------- on-device AI (optional) ----------------
// Chrome's Prompt API is not available in service workers, so it runs in an offscreen extension page.
async function ensureOffscreen() {
  if (!chrome.offscreen) return false;
  if (chrome.runtime.getContexts) {
    const have = await chrome.runtime.getContexts({ contextTypes: ['OFFSCREEN_DOCUMENT'] });
    if (have.length) return true;
  }
  try {
    await chrome.offscreen.createDocument({ url: 'offscreen/offscreen.html', reasons: ['DOM_PARSER'],
      justification: 'Runs Chrome\'s built-in on-device language model on the text of an opened email. Nothing leaves the device.' });
  } catch (e) { if (!/single offscreen/i.test(e.message)) return false; }
  return true;
}
async function aiCheck(payload) {
  const { aiEnabled } = await chrome.storage.local.get(['aiEnabled']);
  if (!aiEnabled) return null;
  if (!(await ensureOffscreen())) return null;
  try { return await chrome.runtime.sendMessage({ target: 'offscreen', type: 'pg-ai-run', payload }); } catch (e) { return null; }
}

// ---------------- extra webmail sites & page guard ----------------
const siteId = (origin) => 'pg-site-' + origin.replace(/[^a-z0-9]/gi, '_');
async function registerSite(origin) {
  const id = siteId(origin);
  const existing = await chrome.scripting.getRegisteredContentScripts({ ids: [id] });
  if (existing.length) return;
  await chrome.scripting.registerContentScripts([{ id, matches: [origin + '/*'], js: CONTENT_JS, css: CONTENT_CSS, runAt: 'document_idle', persistAcrossSessions: true }]);
}
async function enableSite(origin, tabId) {
  await registerSite(origin);
  const host = new URL(origin).host;
  const s = await chrome.storage.local.get(['enabledHosts', 'disabledHosts']);
  await chrome.storage.local.set({ enabledHosts: [...new Set([...(s.enabledHosts || []), host])], disabledHosts: (s.disabledHosts || []).filter((h) => h !== host) });
  if (tabId) {
    try {
      await chrome.scripting.insertCSS({ target: { tabId }, files: CONTENT_CSS });
      await chrome.scripting.executeScript({ target: { tabId }, files: CONTENT_JS });
    } catch (e) { /* page will pick it up on reload */ }
  }
}
async function disableSite(origin) {
  try { await chrome.scripting.unregisterContentScripts({ ids: [siteId(origin)] }); } catch (e) { /* wasn't registered */ }
  const host = new URL(origin).host;
  const s = await chrome.storage.local.get(['enabledHosts']);
  await chrome.storage.local.set({ enabledHosts: (s.enabledHosts || []).filter((h) => h !== host) });
  try { await chrome.permissions.remove({ origins: [origin + '/*'] }); } catch (e) { /* still needed by the guard, or already gone */ }
}
const ALL_SITES = ['https://*/*', 'http://*/*'];
async function syncGuard() {
  const { guardEnabled } = await chrome.storage.local.get(['guardEnabled']);
  const granted = await chrome.permissions.contains({ origins: ALL_SITES });
  const existing = await chrome.scripting.getRegisteredContentScripts({ ids: ['pg-guard'] });
  if (guardEnabled && granted && !existing.length) {
    await chrome.scripting.registerContentScripts([{ id: 'pg-guard', matches: ALL_SITES, excludeMatches: MANIFEST_HOSTS.filter((m) => !m.startsWith('file:')),
      js: GUARD_JS, runAt: 'document_idle', persistAcrossSessions: true }]);
  } else if ((!guardEnabled || !granted) && existing.length) {
    await chrome.scripting.unregisterContentScripts({ ids: ['pg-guard'] });
  }
}
async function syncSites() {
  // Re-register per-site scripts for every webmail origin the user granted (permissions survive; registrations might not).
  // A site permission is only ever requested by "Check emails on this site", so a granted origin means "enabled",
  // even if the popup closed while Chrome's permission prompt was showing.
  const { origins = [] } = await chrome.permissions.getAll();
  const declared = new Set([...MANIFEST_HOSTS, ...(chrome.runtime.getManifest().host_permissions || [])]);
  const s = await chrome.storage.local.get(['enabledHosts']);
  const enabled = new Set(s.enabledHosts || []);
  for (const o of origins) {
    if (ALL_SITES.includes(o) || declared.has(o) || o.includes('*.')) continue;
    const origin = o.replace(/\/\*$/, '');
    try {
      await registerSite(origin);
      enabled.add(new URL(origin).host);
    } catch (e) { /* pattern, not an origin */ }
  }
  await chrome.storage.local.set({ enabledHosts: [...enabled] });
  await syncGuard();
}
chrome.permissions.onRemoved.addListener(() => syncSites());
chrome.permissions.onAdded.addListener(() => syncSites());

// Pages opened from a risky email, so the page guard can warn harder there. Kept in session storage (memory only).
async function rememberRiskyOpen(tabId, url, level) {
  const key = 'risky:' + tabId;
  await chrome.storage.session.set({ [key]: { host: new URL(url).hostname, at: Date.now(), level } });
}
chrome.tabs.onRemoved.addListener((tabId) => chrome.storage.session.remove('risky:' + tabId));

// ---------------- health (webmail layout changes) ----------------
async function setHealth(tabId, report) {
  const s = await chrome.storage.local.get(['health']);
  const health = s.health || {};
  const prev = health[report.adapter] || {};
  health[report.adapter] = report.ok ? { ok: true, lastOk: Date.now(), lastFail: prev.lastFail || null, detail: '' }
    : { ok: false, lastOk: prev.lastOk || null, lastFail: Date.now(), detail: report.detail };
  await chrome.storage.local.set({ health });
  if (tabId != null) {
    chrome.action.setBadgeText({ tabId, text: report.ok ? '' : '!' });
    if (!report.ok) chrome.action.setBadgeBackgroundColor({ tabId, color: '#b45309' });
    chrome.action.setTitle({ tabId, title: report.ok ? 'Tripwire' : `Tripwire: can't read ${report.label || 'this mail site'} right now. Detection may be off.` });
  }
}

// ---------------- lifecycle & messages ----------------
chrome.runtime.onInstalled.addListener(async (details) => {
  const s = await chrome.storage.local.get(['enabled', 'useFeed', 'expandLinks']);
  const defaults = {};
  if (s.enabled === undefined) defaults.enabled = true;
  if (s.useFeed === undefined) defaults.useFeed = true;
  if (s.expandLinks === undefined) defaults.expandLinks = true;
  await chrome.storage.local.set(defaults);
  await chrome.storage.local.remove(['feedHosts', 'feedSource', 'feedUpdated']); // old single-feed storage
  try { await caches.delete('tripwire-intel-v1'); } catch (e) { /* none */ }
  chrome.alarms.create('pg-feed', { periodInMinutes: REFRESH_MINUTES });
  updateFeeds();
  syncSites();
  if (details.reason === 'install') chrome.tabs.create({ url: chrome.runtime.getURL('popup/welcome.html') });
});
chrome.runtime.onStartup.addListener(() => { updateFeeds(); syncSites(); });
chrome.alarms.onAlarm.addListener((a) => { if (a.name === 'pg-feed') updateFeeds(); });

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (!msg || msg.target === 'offscreen') return;
  const tabId = sender.tab ? sender.tab.id : null;
  const run = (p) => { p.then(reply, () => reply(null)); return true; };
  switch (msg.type) {
    case 'pg-lookup': return run(lookup(msg.hosts, msg.urls).then((hits) => ({ hits })));
    case 'pg-update-feed': return run(updateFeeds());
    case 'pg-intel-status': return run(getIndex().then((idx) => ({ total: idx.idx.hi.length, stats: idx.stats, bundledDate: idx.bundledDate })));
    case 'pg-expand': return run(expandShortLink(msg.href));
    case 'pg-qr': return run(decodeQrList(msg.srcs));
    case 'pg-ai': return run(aiCheck(msg.payload));
    case 'pg-health': return run(setHealth(tabId, msg.report));
    case 'pg-enable-site': return run(enableSite(msg.origin, msg.tabId).then(() => ({ ok: true })));
    case 'pg-disable-site': return run(disableSite(msg.origin).then(() => ({ ok: true })));
    case 'pg-sync-guard': return run(syncGuard().then(() => ({ ok: true })));
    case 'pg-open-risky':
      return run(chrome.tabs.create({ url: msg.url, index: sender.tab ? sender.tab.index + 1 : undefined })
        .then((tab) => rememberRiskyOpen(tab.id, msg.url, msg.level)).then(() => ({ ok: true })));
    case 'pg-guard-context':
      return run((async () => {
        const host = msg.host;
        const [hits, sess] = await Promise.all([lookup([host], msg.urlKeys || []), chrome.storage.session.get(['risky:' + tabId])]);
        const risky = sess['risky:' + tabId];
        const fromEmail = risky && risky.host === host && Date.now() - risky.at < 30 * 60 * 1000 ? risky : null;
        const threat = hits[host] || (msg.urlKeys || []).map((k) => hits['url:' + k]).find(Boolean) || null;
        return { threat, fromEmail };
      })());
  }
});
