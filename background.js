// =====================================================================================================================
// Background service worker (background.js)
//
// The extension's long-lived side. Content scripts and the popup ask it for things by message (see the switch at the
// bottom for the full list). Sections:
//   1. threat index       the ~190k-entry list: bundled copy, signed server copy, or live public feeds; lookups
//   2. community reports  the opt-in shared list (download, lookups, sending a report fingerprint)
//   3. updates            every 12 hours: community list, layout rules, then the threat list (server first, feeds if not)
//   4. short links        asks bit.ly & co. where a link goes, without opening the destination
//   5. QR codes           decodes QR codes in email images with jsQR, on this device
//   6. on-device AI       Chrome's built-in model, run in an offscreen page
//   7. sites & guard      registering Tripwire on extra webmail sites, and the optional page guard
//   8. health             toolbar badge when a webmail layout change breaks detection
//   9. lifecycle          install / startup / alarm handlers and the message switch
//
// Privacy: nothing about the user's email is sent anywhere. Network use: list downloads, shortener lookups (only for
// links the user is about to open), re-fetching images already shown in the email (QR codes), and opt-in reports.
// =====================================================================================================================
if (typeof importScripts === 'function') importScripts('src/data.js', 'src/analyzer.js', 'src/intel.js', 'src/selectors.js', 'vendor/jsQR.js');
const I = self.PG_Intel;
const D = self.PG_DATA;
const A = self.PG_Analyzer;
const CACHE = 'tripwire-intel-v2'; // Cache API bucket holding downloaded lists
const REFRESH_MINUTES = 720;       // update every 12 hours
// The scripts injected on extra webmail sites (same as the manifest's) and on all sites for the page guard.
const CONTENT_JS = ['src/data.js', 'src/analyzer.js', 'src/intel.js', 'src/selectors.js', 'src/providers.js', 'src/ui.js', 'src/content.js'];
const CONTENT_CSS = ['src/content.css'];
const GUARD_JS = ['src/data.js', 'src/analyzer.js', 'src/intel.js', 'src/guard.js'];
const MANIFEST_HOSTS = (chrome.runtime.getManifest().content_scripts || []).flatMap((c) => c.matches);

// The Tripwire server: a mirror of the threat list (rebuilt every 6 hours) and the opt-in community reports.
const SERVER = 'https://tripwire.sparkv2.com';
const REPORT_PREFIX = 'tripwire-report-v1|';

// ---------------- 1. threat index ----------------
// Built once on first use (getIndex) and rebuilt after every update (indexPromise = null).
let indexPromise = null;

// The base list: the signed copy last downloaded from the server if there is one, otherwise the copy shipped with
// the extension (always available, even offline).
async function loadBundled() {
  try {
    const c = await caches.open(CACHE);
    const [m, b] = await Promise.all([c.match('/server/meta'), c.match('/server/bin')]);
    if (m && b) return { meta: await m.json(), idx: I.parseCompact(await b.arrayBuffer()), origin: 'server' };
  } catch (e) { /* fall back to the bundled copy */ }
  const [meta, bin] = await Promise.all([
    fetch(chrome.runtime.getURL('data/threat-intel.meta.json')).then((r) => r.json()),
    fetch(chrome.runtime.getURL('data/threat-intel.bin')).then((r) => r.arrayBuffer()),
  ]);
  return { meta, idx: I.parseCompact(bin), origin: 'bundled' };
}

// ---------------- 2. community reports ----------------
// A domain's report fingerprint: SHA-256 of "tripwire-report-v1|domain" (the server only ever sees these).
async function fingerprint(domain) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(REPORT_PREFIX + domain));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
// The downloaded community list as a Set of fingerprints (null if switched off or never downloaded).
let communityPromise = null;
function getCommunity() {
  if (!communityPromise) {
    communityPromise = (async () => {
      const { communityEnabled } = await chrome.storage.local.get(['communityEnabled']);
      if (communityEnabled === false) return null;
      const r = await (await caches.open(CACHE)).match('/server/community');
      if (!r) return null;
      const j = await r.json();
      return { hashes: new Set(j.hashes || []), threshold: j.threshold || 3, generated: j.generated };
    })().catch(() => null);
  }
  return communityPromise;
}
// Only with the user's opt-in: send fingerprints (never the domain itself) of domains they reported.
async function shareReport(domain) {
  const { shareReports } = await chrome.storage.local.get(['shareReports']);
  if (!shareReports || !domain) return { ok: false, reason: 'off' };
  const res = await fetch(SERVER + '/v1/reports', { method: 'POST', credentials: 'omit', referrerPolicy: 'no-referrer',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify({ v: 1, hashes: [await fingerprint(domain)] }) });
  return { ok: res.ok, status: res.status };
}
// Feeds downloaded directly (only used when the server was unreachable): { sourceId: parsed feed }.
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

// Combines the base list with any live feeds into one index. A live feed replaces that source's entries from the
// base list. Also produces the per-source statistics the popup shows. Returns { idx, descs, stats, bundledDate };
// `descs[i]` describes what an entry with description index i means ({ cat, source, label }).
function buildIndex(bundled, live) {
  const meta = bundled.meta || { descs: [], sources: [] };
  const descs = meta.descs.slice();
  const descKeys = new Map(descs.map((d, i) => [d.sourceId + '|' + (d.label || ''), i]));
  const liveIds = new Set(Object.keys(live));
  // Never flag well-known brands, free email providers or mail-tracking services as whole domains.
  const extra = new Set([...D.BRANDS.flatMap((b) => b.domains), ...D.FREE_MAIL, ...D.TRACKING_DOMAINS]);
  const fresh = [], stats = [];
  for (const s of I.SOURCES) {
    // Description index for (this source, label). The index is stored in one byte, so there are at most 256; once
    // full, new labels fall back to an existing description of the same source (without its label).
    const descFor = (label) => {
      const k = s.id + '|' + (label || '');
      if (descKeys.has(k)) return descKeys.get(k);
      if (descs.length >= 255) { const same = descs.findIndex((d) => d.sourceId === s.id); return same >= 0 ? same : 0; }
      descKeys.set(k, descs.length); descs.push({ cat: s.category, source: s.name, sourceId: s.id, label: label || '' });
      return descKeys.get(k);
    };
    if (live[s.id]) {
      const r = I.sourceEntries(live[s.id], descFor, extra);
      for (const e of r.entries) fresh.push(e); // not push(...entries): 100k+ arguments overflow the stack
      stats.push({ id: s.id, name: s.name, category: s.category, count: r.count, skipped: r.skipped, updated: live[s.id].fetched, origin: 'live' });
    } else {
      const m = meta.sources.find((x) => x.id === s.id);
      stats.push(m ? { id: s.id, name: s.name, category: s.category, count: m.count, skipped: m.skipped, updated: m.fetched || meta.generated, origin: bundled.origin || 'bundled' }
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

// Brands, free mail, trackers and shared platforms are never flagged as a whole, whatever a downloaded list says.
// The lists are filtered when they are built, but checking again here means a bad list can't mark gmail.com as a scam.
const NEVER_FLAG = new Set([...D.BRANDS.flatMap((b) => b.domains), ...D.FREE_MAIL, ...D.TRACKING_DOMAINS]);

// Answers a content script's question: which of these hosts / exact URLs are listed?
// Returns { host: hit, 'url:'+key: hit } for the listed ones only. A host is checked against the threat index
// (including its parent domains), then against the community list.
async function lookup(hosts, urls) {
  const [{ idx, descs }, community] = await Promise.all([getIndex(), getCommunity()]);
  const hits = {};
  for (const host of (hosts || []).slice(0, 2000)) {
    if (!I.hostIsFlaggable(host, NEVER_FLAG)) continue; // protected hosts skip the community check too
    const m = I.lookupHost(idx, host, NEVER_FLAG);
    if (m) hits[host] = Object.assign({ matched: m.matched }, descs[m.desc]);
    if (!hits[host] && community && community.hashes.size) {
      const reg = A.registrableDomain(host);
      if (community.hashes.has(await fingerprint(reg))) {
        hits[host] = { cat: 'community', source: 'Tripwire community reports', threshold: community.threshold, matched: reg };
      }
    }
  }
  for (const u of (urls || []).slice(0, 2000)) {
    const d = I.lookupCompact(idx, 'url:' + u);
    if (d >= 0) hits['url:' + u] = Object.assign({ matched: u }, descs[d]);
  }
  return hits;
}

// ---------------- 3. updates ----------------
// Download the threat list from the Tripwire server (one ~1.5 MB file). It is only used if it carries a valid
// signature from the project's signing key (see src/intel.js): the server can't forge one. Returns true on success.
async function updateFromServer(c) {
  const opts = { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' };
  try {
    const [m, s, b] = await Promise.all(['threat-intel.meta.json', 'threat-intel.meta.json.sig', 'threat-intel.bin']
      .map((n) => fetch(SERVER + '/v1/intel/' + n, opts)));
    if (!m.ok || !s.ok || !b.ok) return false;
    const metaBytes = await m.arrayBuffer(), sig = await s.text(), bin = await b.arrayBuffer();
    // The newest list date ever accepted is kept separately, so an attacker can't replay an older signed list,
    // even after Tripwire has fallen back to the public feeds and dropped its server copy.
    const { intelNewest } = await chrome.storage.local.get(['intelNewest']);
    const meta = await I.verifyIntel(metaBytes, sig, bin, { notOlderThan: intelNewest || null }); // throws on any problem
    if (meta.total < 1000) return false;
    await chrome.storage.local.set({ intelNewest: meta.generated });
    await c.put('/server/meta', new Response(JSON.stringify(meta), { headers: { 'content-type': 'application/json' } }));
    await c.put('/server/bin', new Response(bin));
    for (const s of I.SOURCES) await c.delete('/live/' + s.id); // the server copy is newer than any per-feed copy
    return true;
  } catch (e) { console.warn('[Tripwire] server list not used:', e.message); return false; }
}
// Refresh (or, if switched off, delete) the downloaded community list.
async function updateCommunity(c) {
  const { communityEnabled } = await chrome.storage.local.get(['communityEnabled']);
  communityPromise = null;
  if (communityEnabled === false) { await c.delete('/server/community'); return; }
  try {
    const r = await fetch(SERVER + '/v1/community.json', { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' });
    if (r.ok) await c.put('/server/community', new Response(await r.text(), { headers: { 'content-type': 'application/json' } }));
  } catch (e) { /* keep the previous copy */ }
}

// Webmail layout rules ------------------------------------------------------------------------------------------------
// When Gmail, Outlook or Yahoo change their page layout, a fixed data/selectors.json is signed by GitHub Actions and
// mirrored by the Tripwire server. It is only used with a valid signature, a higher version than the rules in use,
// and if this extension version is new enough for it. Open tabs pick it up through storage.onChanged.
async function updateRules(reason) {
  const { layoutRules } = await chrome.storage.local.get(['layoutRules']);
  await chrome.storage.local.set({ layoutRulesChecked: Date.now() });
  try {
    const opts = { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' };
    const [r, s] = await Promise.all(['selectors.json', 'selectors.json.sig'].map((n) => fetch(SERVER + '/v1/intel/' + n, opts)));
    if (!r.ok || !s.ok) return { ok: false, reason: 'unavailable' };
    const rules = await I.verifyRules(await r.arrayBuffer(), await s.text()); // throws on a bad signature
    const verdict = self.PG_Selectors.acceptRules(rules, { currentVersion: layoutRules ? layoutRules.version : 0,
      extensionVersion: chrome.runtime.getManifest().version });
    if (!verdict.ok) return { ok: false, reason: verdict.reason };
    await chrome.storage.local.set({ layoutRules: { version: rules.version, adapters: rules.adapters, installed: Date.now(), reason: reason || 'update' } });
    return { ok: true, version: rules.version };
  } catch (e) { console.warn('[Tripwire] layout rules not used:', e.message); return { ok: false, reason: e.message }; }
}

// The whole update. Startup, the 12-hour alarm and the popup's "Update lists now" can all ask for one at the same
// time; they share a single run instead of downloading everything twice.
let updating = null;
function updateFeeds() {
  if (!updating) updating = runUpdate().finally(() => { updating = null; });
  return updating;
}
async function runUpdate() {
  const { useFeed } = await chrome.storage.local.get(['useFeed']);
  if (useFeed === false) return { ok: false, reason: 'disabled' };
  const c = await caches.open(CACHE);
  await updateCommunity(c);
  await updateRules('scheduled');
  if (await updateFromServer(c)) {
    indexPromise = null;
    await chrome.storage.local.set({ intelUpdated: Date.now() }); // tells open tabs to re-check
    return { ok: true, updated: I.SOURCES.length, total: I.SOURCES.length, via: 'server' };
  }
  // Server unreachable (or its list failed verification): download the public feeds directly, trying each mirror.
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
  // Fresh feeds are newer than the last server copy, so stop using that copy as the base list.
  if (okCount) { try { await c.delete('/server/meta'); await c.delete('/server/bin'); } catch (e) { /* none */ } }
  indexPromise = null;
  await chrome.storage.local.set({ intelUpdated: Date.now() }); // tells open tabs to re-check
  return { ok: okCount > 0, updated: okCount, total: I.SOURCES.length, via: 'feeds' };
}

// ---------------- 4. shortened links ----------------
// Asks the shortener where a link goes by reading its redirect header. The destination itself is never opened.
// How: fetch() with redirect:'manual' hides the Location header from scripts, so a webRequest listener (allowed
// for the shortener hosts in the manifest) reads the header as the response arrives and hands it to oneHop().
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

// One redirect step: resolves to the next URL, or null if there was no redirect (or after 6 seconds).
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
// Follows up to 5 hops while each step is still a shortener. Returns { final, hops }. Remembers the last 500 links.
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

// ---------------- 5. QR codes ----------------
// Fetches an image the email already showed, draws it on an off-screen canvas and asks jsQR for a QR code. Tries
// the image at up to 1000 px, then at 500 px (small codes in big images decode better when scaled down).
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
    try { const data = await decodeQr(src); if (data) out.push({ data, src }); } catch (e) { /* not an image we can read */ }
  }
  return out;
}

// ---------------- 6. on-device AI (optional) ----------------
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

// ---------------- 7. extra webmail sites & page guard ----------------
// The manifest only covers well-known webmail. "Check emails on this site" (popup) asks Chrome for permission on one
// more site; these functions then register the content scripts there so they load on every visit.
const siteId = (origin) => 'pg-site-' + origin.replace(/[^a-z0-9]/gi, '_');
async function registerSite(origin) {
  const id = siteId(origin);
  const existing = await chrome.scripting.getRegisteredContentScripts({ ids: [id] });
  if (existing.length) return;
  await chrome.scripting.registerContentScripts([{ id, matches: [origin + '/*'], js: CONTENT_JS, css: CONTENT_CSS, runAt: 'document_idle', persistAcrossSessions: true }]);
}
// Register for future visits, mark the site enabled, and inject into the open tab right away.
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
// The page guard runs only while it is switched on AND Chrome's all-sites permission is granted.
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

// ---------------- 8. health (webmail layout changes) ----------------
// A content script reports whether it can read its webmail page. Stored per adapter for the popup, and shown as a
// "!" badge on that tab's toolbar icon.
async function setHealth(tabId, report) {
  // A site stopped matching the rules: look for a published fix now instead of at the next update (at most every 30 min).
  if (!report.ok) {
    const { layoutRulesChecked } = await chrome.storage.local.get(['layoutRulesChecked']);
    if (!layoutRulesChecked || Date.now() - layoutRulesChecked > 30 * 60 * 1000) updateRules('health-check');
  }
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

// ---------------- 9. lifecycle & messages ----------------
// On install or update: default settings, clean up storage from old versions, schedule updates, and run one now.
chrome.runtime.onInstalled.addListener(async (details) => {
  const s = await chrome.storage.local.get(['enabled', 'useFeed', 'expandLinks']);
  const defaults = {};
  if (s.enabled === undefined) defaults.enabled = true;
  if (s.useFeed === undefined) defaults.useFeed = true;
  if (s.expandLinks === undefined) defaults.expandLinks = true;
  await chrome.storage.local.set(defaults);
  await chrome.storage.local.remove(['feedHosts', 'feedSource', 'feedUpdated']); // left over from version 1.0
  try { await caches.delete('tripwire-intel-v1'); } catch (e) { /* none */ }      // list cache format before 1.2
  chrome.alarms.create('pg-feed', { periodInMinutes: REFRESH_MINUTES });
  updateFeeds();
  syncSites();
  if (details.reason === 'install') chrome.tabs.create({ url: chrome.runtime.getURL('popup/welcome.html') });
});
chrome.runtime.onStartup.addListener(() => { updateFeeds(); syncSites(); });
chrome.alarms.onAlarm.addListener((a) => { if (a.name === 'pg-feed') updateFeeds(); });

// Messages that change settings or start work on the user's behalf. Only the extension's own pages (the popup)
// may send these, never a script running inside a website's tab.
const POPUP_ONLY = new Set(['pg-update-feed', 'pg-enable-site', 'pg-disable-site', 'pg-sync-guard', 'pg-community-changed']);

// Every request from content scripts, the page guard and the popup arrives here. Each case returns `run(promise)`,
// which keeps the channel open (return true) and replies with the promise's result, or null if it failed.
chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (!msg || msg.target === 'offscreen') return; // meant for the offscreen AI page
  if (sender.id !== chrome.runtime.id) return;
  if (POPUP_ONLY.has(msg.type) && sender.tab) return;
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
    case 'pg-share-report': return run(shareReport(msg.domain).catch(() => ({ ok: false })));
    case 'pg-community-changed': return run((async () => { await updateCommunity(await caches.open(CACHE)); return { ok: true }; })());
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
