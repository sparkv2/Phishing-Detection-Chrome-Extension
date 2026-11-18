// Main content script: scans inbox rows and opened emails, highlights, shows banner, guards link clicks.
// Privacy: email text is analysed in memory only. Stored on the device: counts, the user's own trust/report lists,
// salted hashes of past senders (for "first email from this sender"), and which kinds of warning signs were seen.
(function () {
  'use strict';
  if (window.__tripwireLoaded) return; // injected twice (manifest + "Check emails on this site")
  window.__tripwireLoaded = true;
  if (window.top !== window && !/mail\.google\.com|outlook\./.test(location.hostname)) return; // skip ads/iframes
  const A = window.PG_Analyzer, P = window.PG_Providers, UI = window.PG_UI, D = window.PG_DATA;
  const HOST = location.host || 'local-file';

  const state = { enabled: true, aiEnabled: false, trusted: new Set(), blocked: new Set(), enabledHosts: [], disabledHosts: [], active: false };
  // Threat-list answers from the background worker: host or 'url:'+key -> hit object, or null if clean. Memory only.
  const threats = new Map();
  const expanded = new Map(); // shortened link -> where it really goes (memory only)
  const verdicts = new Map(); // in-memory only: rowKey -> {level, score, known}
  const extras = new Map(); // in-memory only: message key -> { auth, attHtml, qr, ai, started:Set }
  const seenKeys = new Set();
  const pendingStats = { scanned: 0, suspicious: 0, phishing: 0, warnings: 0 };
  let adapter = null, observer = null, scanTimer = null;

  const lc = (s) => (s || '').toString().toLowerCase().trim();
  const keyOf = (email, name, subject) => (lc(email) || lc(name)) + '|' + lc(subject).replace(/\s+/g, ' ').slice(0, 200);
  const lists = () => ({ trusted: state.trusted, blocked: state.blocked, threats, expanded });
  const send = async (msg) => { try { return await chrome.runtime.sendMessage(msg); } catch (e) { return null; } }; // null while the extension reloads

  // Ask the background worker which hosts / URLs are on the threat lists (answers are cached for this page).
  async function lookupThreats(hosts, urlKeys) {
    const needHosts = [...new Set(hosts.filter((h) => h && !threats.has(h)))];
    const needUrls = [...new Set(urlKeys.filter((u) => u && !threats.has('url:' + u)))];
    if (!needHosts.length && !needUrls.length) return;
    const r = await send({ type: 'pg-lookup', hosts: needHosts, urls: needUrls });
    if (!r) return; // try again next scan
    const hits = r.hits || {};
    for (const h of needHosts) threats.set(h, hits[h] || null);
    for (const u of needUrls) threats.set('url:' + u, hits['url:' + u] || null);
  }
  const senderDomain = (email) => (lc(email).split('@')[1] || '');
  function linkTargets(links) {
    const hosts = [], urls = [];
    for (const l of links) {
      const u = A.unwrapUrl(expanded.get((l.href || '').trim()) || l.href);
      if (!u || !/^https?:$/.test(u.protocol) || u.hostname === 'invalid.local') continue;
      hosts.push(lc(u.hostname));
      urls.push(...window.PG_Intel.urlKeys(u));
    }
    return { hosts, urls };
  }

  async function loadState() {
    const s = await chrome.storage.local.get(['enabled', 'aiEnabled', 'trusted', 'blocked', 'enabledHosts', 'disabledHosts']);
    state.enabled = s.enabled !== false;
    state.aiEnabled = !!s.aiEnabled;
    state.trusted = new Set(s.trusted || []);
    state.blocked = new Set(s.blocked || []);
    state.enabledHosts = s.enabledHosts || [];
    state.disabledHosts = s.disabledHosts || [];
  }

  function shouldRun() {
    if (!state.enabled || state.disabledHosts.includes(HOST)) return false;
    adapter = P.pickAdapter();
    return adapter.id !== 'generic' || state.enabledHosts.includes(HOST) || P.looksLikeWebmail() || location.protocol === 'file:';
  }

  // ---------- sender history (hashed, on this device) ----------
  // Remembers which senders have emailed before, and which addresses a display name normally uses, as salted
  // SHA-256 hashes. Nothing readable is stored: the list can't be turned back into names or addresses.
  const history = { data: null, dirty: false, timer: null, cache: new Map() };
  const DAY = 86400000;
  async function loadHistory() {
    if (history.data) return history.data;
    const s = await chrome.storage.local.get(['senderHistory']);
    let h = s.senderHistory;
    if (!h || !h.salt) {
      const salt = [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, '0')).join('');
      h = { v: 1, salt, since: Date.now(), senders: {}, names: {} };
      history.dirty = true;
    }
    history.data = h;
    return h;
  }
  async function hash(value) {
    if (history.cache.has(value)) return history.cache.get(value);
    const h = await loadHistory();
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(h.salt + '|' + value));
    const hex = [...new Uint8Array(buf).slice(0, 8)].map((b) => b.toString(16).padStart(2, '0')).join('');
    history.cache.set(value, hex);
    return hex;
  }
  function personName(name) { // "Mark Davis (CEO)" -> "mark davis"; null for names that aren't a person's
    const n = lc(name).replace(/\(.*?\)|\[.*?\]|\bvia\b.*$/g, ' ').replace(/[^a-zÀ-ɏ\s'-]/g, ' ').replace(/\s+/g, ' ').trim();
    const tokens = n.split(' ').filter((t) => t.length >= 2);
    if (tokens.length < 2 || tokens.length > 4 || name.includes('@')) return null;
    if (tokens.every((t) => D.SERVICE_WORDS.includes(t))) return null;
    return tokens.join(' ');
  }
  async function historyFor(senderName, senderEmail, msgKey) {
    const email = lc(senderEmail);
    if (!email.includes('@')) return null;
    const h = await loadHistory();
    const sh = await hash('s:' + email), mk = (await hash('m:' + msgKey)).slice(0, 8);
    const dh = await hash('d:' + A.registrableDomain(email.split('@').pop()));
    const pn = personName(senderName);
    const nh = pn ? await hash('n:' + pn) : null;
    const rec = h.senders[sh];
    const seenBefore = !!(rec && rec.m.some((k) => k !== mk));
    let nameKnownElsewhere = false;
    if (nh && !seenBefore && h.names[nh]) {
      nameKnownElsewhere = h.names[nh].s.some((o) => o.s !== sh && o.d !== dh && h.senders[o.s] && h.senders[o.s].m.length >= 2);
    }
    const mature = Date.now() - h.since > 14 * DAY || Object.keys(h.senders).length >= 150;
    // Record this message after judging it, so it doesn't vouch for itself.
    const today = Math.floor(Date.now() / DAY);
    const r = h.senders[sh] || (h.senders[sh] = { d: today, m: [] });
    r.d = today;
    if (!r.m.includes(mk)) { r.m.push(mk); if (r.m.length > 12) r.m.shift(); history.dirty = true; }
    if (nh) {
      const n = h.names[nh] || (h.names[nh] = { d: today, s: [] });
      n.d = today;
      if (!n.s.some((o) => o.s === sh)) { n.s.push({ s: sh, d: dh }); if (n.s.length > 6) n.s.shift(); history.dirty = true; }
    }
    saveHistorySoon();
    return { seenBefore, mature, nameKnownElsewhere };
  }
  function saveHistorySoon() {
    if (!history.dirty) return;
    clearTimeout(history.timer);
    history.timer = setTimeout(async () => {
      const h = history.data;
      const keys = Object.keys(h.senders);
      if (keys.length > 6000) keys.sort((a, b) => h.senders[a].d - h.senders[b].d).slice(0, keys.length - 6000).forEach((k) => delete h.senders[k]);
      const names = Object.keys(h.names);
      if (names.length > 6000) names.sort((a, b) => h.names[a].d - h.names[b].d).slice(0, names.length - 6000).forEach((k) => delete h.names[k]);
      history.dirty = false;
      try { await chrome.storage.local.set({ senderHistory: h }); } catch (e) { /* extension reloaded */ }
    }, 3000);
  }

  // ---------- inbox list ----------
  function classify(row, level) {
    row.classList.remove('pg-row-suspicious', 'pg-row-phishing');
    if (level === 'suspicious') row.classList.add('pg-row-suspicious');
    if (level === 'phishing') row.classList.add('pg-row-phishing');
  }

  async function scanRows() {
    const rows = adapter.rows();
    await lookupThreats(rows.map((r) => senderDomain(r.senderEmail)), []);
    for (const r of rows) {
      const key = keyOf(r.senderEmail, r.senderName, r.subject || r.snippet.slice(0, 80));
      const cached = verdicts.get(key);
      if (r.row.dataset.pgKey === key && (r.row.dataset.pgLevel === (cached ? cached.level : r.row.dataset.pgLevel))) {
        // Same row, same verdict; just make sure the site didn't strip our class
        if (r.row.dataset.pgLevel !== 'safe' && !r.row.classList.contains('pg-row-' + r.row.dataset.pgLevel)) classify(r.row, r.row.dataset.pgLevel);
        continue;
      }
      let res = cached;
      if (!res) {
        const hist = await historyFor(r.senderName, r.senderEmail, key);
        const a = A.analyzeEmail({ senderName: r.senderName, senderEmail: r.senderEmail, subject: r.subject, body: r.snippet, links: [], context: 'list', history: hist }, lists());
        res = { level: a.level, score: a.score, known: a.known, high: a.high, top: a.signals.slice(0, 2).map((x) => x.title), partial: true, hist };
        verdicts.set(key, res);
        count(key, res.level);
      }
      r.row.dataset.pgKey = key;
      r.row.dataset.pgLevel = res.level;
      classify(r.row, res.level);
      if (res.level !== 'safe') {
        r.row.setAttribute('title', `Tripwire: ${res.level === 'phishing' ? 'KNOWN PHISHING (confirmed scam)' : res.high ? 'Very suspicious' : 'Suspicious'} — safety ${res.score}/100` +
          (res.top && res.top.length ? `\n• ${res.top.join('\n• ')}` : '') + '\nOpen the email to see the full explanation.');
      } else if ((r.row.getAttribute('title') || '').startsWith('Tripwire')) r.row.removeAttribute('title');
    }
    return rows.length;
  }

  // ---------- opened email ----------
  // Slow checks (headers, attachments, QR codes, AI) run in the background; the banner is redrawn as each one finishes.
  function enrich(key, m, bodyText) {
    const ex = extras.get(key) || { started: new Set() };
    extras.set(key, ex);
    const redraw = () => { if (m.body.isConnected) { delete m.body.dataset.pgSig; scheduleScan(); } };
    const once = (name, fn) => {
      if (ex.started.has(name)) return;
      ex.started.add(name);
      Promise.resolve().then(fn).then((changed) => { if (changed) redraw(); }).catch((e) => console.debug('[Tripwire]', name, e));
    };
    if (adapter.fetchHeaders && m.messageId) {
      once('auth', async () => {
        const raw = await adapter.fetchHeaders(m);
        ex.auth = raw ? A.parseAuthResults(raw) : null;
        return !!ex.auth;
      });
    }
    const htmlAtts = (m.attachments || []).filter((a) => a.url && /\.(html?|shtml|xhtml|svg)$/i.test(a.name));
    if (adapter.fetchAttachment && htmlAtts.length) {
      once('attachments', async () => {
        ex.attHtml = {};
        for (const a of htmlAtts.slice(0, 3)) {
          const t = await adapter.fetchAttachment(a);
          if (!t) continue;
          ex.attHtml[a.name] = {
            password: /<input[^>]+type\s*=\s*["']?password/i.test(t),
            form: /<form\b/i.test(t) && /<input\b/i.test(t),
            redirect: /(window|document|top)\.location(\.href)?\s*=|location\.(replace|assign)\s*\(|http-equiv\s*=\s*["']?refresh/i.test(t),
            obfuscated: /\batob\s*\(|unescape\s*\(|eval\s*\(|String\.fromCharCode\s*\(/i.test(t),
          };
        }
        return Object.keys(ex.attHtml).length > 0;
      });
    }
    if (m.images && m.images.length) {
      once('qr', async () => {
        const srcs = [];
        for (const src of m.images) {
          if (!src.startsWith('blob:')) { srcs.push(src); continue; }
          try { // blob: URLs only work in this page, so hand the background a data: copy
            const b = await (await fetch(src)).blob();
            if (b.size > 3e6) continue;
            srcs.push(await new Promise((res) => { const fr = new FileReader(); fr.onload = () => res(fr.result); fr.readAsDataURL(b); }));
          } catch (e) { /* revoked */ }
        }
        const r = await send({ type: 'pg-qr', srcs });
        ex.qr = r || [];
        if (!ex.qr.length) return false;
        const t = linkTargets(ex.qr.map((q) => ({ href: /^https?:/i.test(q.data) ? q.data : 'https://' + q.data })));
        await lookupThreats(t.hosts, t.urls);
        return true;
      });
    }
    if (state.aiEnabled && bodyText.length > 40) {
      once('ai', async () => {
        ex.ai = await send({ type: 'pg-ai', payload: { subject: m.subject, sender: `${m.senderName || ''} <${m.senderEmail || ''}>`, body: bodyText } });
        return !!ex.ai;
      });
    }
    return ex;
  }

  async function scanOpened() {
    const opened = adapter.opened();
    for (const m of opened) {
      const body = m.body;
      const bodyText = P.text(body);
      const key = keyOf(m.senderEmail, m.senderName, m.subject);
      const ex = extras.get(key) || {};
      const sig = bodyText.length + '|' + (m.senderEmail || '') + '|' + m.subject + '|' + ['auth', 'attHtml', 'qr', 'ai'].map((k) => (ex[k] ? 1 : 0)).join('');
      const hasBanner = () => body.previousElementSibling && body.previousElementSibling.classList && body.previousElementSibling.classList.contains('pg-banner-host');
      if (body.dataset.pgSig === sig && hasBanner()) continue;

      const links = P.linksIn(body);
      const targets = linkTargets(links);
      await lookupThreats([senderDomain(m.senderEmail), ...targets.hosts], targets.urls);
      if (!body.isConnected) continue; // the email was closed while we were checking
      const listVerdict = verdicts.get(key);
      const hist = listVerdict && listVerdict.hist ? listVerdict.hist : await historyFor(m.senderName, m.senderEmail, key);
      const e = enrich(key, m, bodyText);
      const attachments = (m.attachments || []).map((a) => Object.assign({}, a, { html: e.attHtml && e.attHtml[a.name] }));
      const result = A.analyzeEmail({ senderName: m.senderName, senderEmail: m.senderEmail, subject: m.subject, body: bodyText,
        links, hasForm: P.hasForm(body), context: 'open', auth: e.auth, attachments, qrCodes: e.qr, history: hist, ai: e.ai }, lists());
      if (hasBanner()) body.previousElementSibling.remove();
      body.dataset.pgSig = sig;

      verdicts.set(key, { level: result.level, score: result.score, known: result.known, high: result.high, top: result.signals.slice(0, 2).map((x) => x.title), hist });
      count(key, result.level);
      countSignals(key, result.signals);

      const pending = [...(e.started || [])].filter((n) => ({ auth: !('auth' in e), attachments: !e.attHtml, qr: !e.qr, ai: !('ai' in e) })[n]);
      const banner = UI.renderBanner(result, {
        reportHelp: adapter.reportHelp,
        pending,
        onReport: () => report(result.sender, result.verifiedBrand),
        onTrust: () => updateList('trusted', result.sender.email, true),
        onUntrust: () => updateList('trusted', result.sender.email, false),
      });
      body.parentNode.insertBefore(banner, body);
      guardLinks(body, links, result);
    }
    return opened.length;
  }

  function linkInfoFor(anchor, links, result) {
    const href = anchor.getAttribute('href') || '';
    const r = result.links.find((x) => x.href === href.trim() && x.text === (P.text(anchor) || anchor.getAttribute('title') || '').trim())
      || result.links.find((x) => x.href === href.trim());
    return Object.assign({ href, text: P.text(anchor), host: '', weight: 0, signals: [] }, r || {}, { emailLevel: result.level });
  }
  const isShortLink = (info) => !info.expandedFrom && (info.signals || []).some((s) => s.id === 'short-link');

  // Follow a shortened link (in the background, without opening it) and judge where it really goes.
  async function expandAndJudge(info) {
    const r = await send({ type: 'pg-expand', href: info.href.trim() });
    if (!r || !r.final) return null;
    expanded.set(info.href.trim(), r.final);
    const t = linkTargets([{ href: r.final }]);
    await lookupThreats(t.hosts, t.urls);
    const judged = A.analyzeLink({ href: info.href, text: info.text }, lists(), null);
    return Object.assign({}, info, judged, { emailLevel: info.emailLevel, hops: r.hops });
  }

  function openLink(url, risky, level) {
    if (risky) send({ type: 'pg-open-risky', url, level }).then((r) => { if (!r) window.open(url, '_blank', 'noopener,noreferrer'); });
    else window.open(url, '_blank', 'noopener,noreferrer');
  }

  function guardLinks(body, links, result) {
    // Mark risky links visibly
    for (const l of links) {
      const info = linkInfoFor(l.el, links, result);
      l.el.classList.toggle('pg-risky-link', info.weight >= 20 || (result.level === 'phishing' && !!info.host));
    }
    if (body._pgGuard) { body._pgGuard.result = result; body._pgGuard.links = links; return; }
    const g = body._pgGuard = { result, links };
    body.addEventListener('mouseover', (e) => {
      const a = e.target.closest && e.target.closest('a[href]');
      if (!a || !body.contains(a) || /^(mailto:|tel:|#)/i.test(a.getAttribute('href'))) return;
      UI.showTooltip(a, linkInfoFor(a, g.links, g.result));
    });
    body.addEventListener('mouseout', (e) => { if (e.target.closest && e.target.closest('a[href]')) UI.hideTooltip(); });
    body.addEventListener('click', async (e) => {
      const a = e.target.closest && e.target.closest('a[href]');
      if (!a || !body.contains(a)) return;
      const info = linkInfoFor(a, g.links, g.result);
      if (/^(mailto:|tel:|#)/i.test(info.href)) return;
      const riskyNow = (x) => x.known || x.weight >= 20 || g.result.level === 'phishing' || (g.result.level === 'suspicious' && x.weight > 0) || /^(javascript|data):/i.test(x.href);
      const short = isShortLink(info);
      if (!riskyNow(info) && !short) return;
      e.preventDefault(); e.stopPropagation(); e.stopImmediatePropagation();
      UI.hideTooltip();
      if (short && !riskyNow(info)) {
        // Harmless-looking email: check the short link quickly, and only interrupt if it leads somewhere risky.
        const judged = await expandAndJudge(info);
        if (!judged || !riskyNow(judged)) return openLink((judged && judged.finalHref) || info.href, false);
        pendingStats.warnings++; flushStatsSoon();
        if (await UI.confirmLink(judged)) openLink(judged.finalHref || info.href, true, g.result.level);
        return;
      }
      pendingStats.warnings++; flushStatsSoon();
      const expand = short ? expandAndJudge(info) : null;
      let chosen = info;
      if (expand) expand.then((j) => { if (j) chosen = j; });
      if (await UI.confirmLink(info, { expand })) openLink(chosen.finalHref || info.finalHref || info.href, true, g.result.level);
    }, true);
  }

  // ---------- user actions ----------
  async function updateList(name, value, add) {
    if (!value) return;
    const s = await chrome.storage.local.get([name]);
    const set = new Set(s[name] || []);
    add ? set.add(lc(value)) : set.delete(lc(value));
    await chrome.storage.local.set({ [name]: [...set] }); // storage.onChanged triggers a rescan
  }
  async function report(sender, verifiedBrand) {
    if (!sender.email) return;
    const dom = sender.domain;
    const freeOrBrand = verifiedBrand || D.FREE_MAIL.includes(A.registrableDomain(dom));
    // Block the whole fake domain, but only the single address if it's a shared provider like gmail.com
    await updateList('blocked', freeOrBrand ? sender.email : A.registrableDomain(dom), true);
    await updateList('trusted', sender.email, false);
    const s = await chrome.storage.local.get(['stats']);
    const st = s.stats || {}; st.reported = (st.reported || 0) + 1;
    await chrome.storage.local.set({ stats: st });
  }

  // ---------- stats (counts only) ----------
  function count(key, level) {
    if (seenKeys.has(key)) return;
    seenKeys.add(key);
    pendingStats.scanned++;
    if (level === 'suspicious') pendingStats.suspicious++;
    if (level === 'phishing') pendingStats.phishing++;
    flushStatsSoon();
  }
  // Which kinds of warning sign you've actually received (ids only, e.g. "lookalike-sender"). Practice mode uses it
  // to pick lessons about tricks aimed at you.
  const signalSeen = new Set(), pendingSignals = {};
  function countSignals(key, signals) {
    if (signalSeen.has(key)) return;
    signalSeen.add(key);
    for (const s of signals) if (s.weight >= 10) pendingSignals[s.id] = (pendingSignals[s.id] || 0) + 1;
    flushStatsSoon();
  }
  let statsTimer = null;
  function flushStatsSoon() {
    clearTimeout(statsTimer);
    statsTimer = setTimeout(async () => {
      try {
        const s = await chrome.storage.local.get(['stats', 'signalCounts']);
        const st = s.stats || {}, sc = s.signalCounts || {};
        for (const k of Object.keys(pendingStats)) { st[k] = (st[k] || 0) + pendingStats[k]; pendingStats[k] = 0; }
        for (const k of Object.keys(pendingSignals)) { sc[k] = (sc[k] || 0) + pendingSignals[k]; delete pendingSignals[k]; }
        await chrome.storage.local.set({ stats: st, signalCounts: sc });
      } catch (e) { /* extension reloaded */ }
    }, 2000);
  }

  // ---------- health check ----------
  // If a known webmail page clearly shows an inbox (or an open email) but the adapter finds nothing for a while,
  // the site's layout probably changed. Tell the user (toolbar badge + popup) instead of failing silently.
  const health = { strikes: 0, firstStrike: 0, reported: null };
  function checkHealth(rowCount, openCount) {
    if (!adapter.health) return;
    const h = adapter.health();
    const broken = (h.listShown && rowCount === 0) ? 'inbox list' : (h.messageShown && openCount === 0) ? 'open email' : null;
    if (!broken) {
      health.strikes = 0;
      if ((rowCount || openCount) && health.reported !== 'ok') { health.reported = 'ok'; send({ type: 'pg-health', report: { adapter: adapter.id, label: adapter.label, ok: true } }); }
      return;
    }
    if (!health.strikes++) health.firstStrike = Date.now();
    if (health.strikes >= 3 && Date.now() - health.firstStrike > 8000 && health.reported !== broken) {
      health.reported = broken;
      send({ type: 'pg-health', report: { adapter: adapter.id, label: adapter.label, ok: false, detail: `found no ${broken} on ${location.host}` } });
    }
  }

  // ---------- lifecycle ----------
  // One scan at a time; if the page changes mid-scan, run once more afterwards.
  let scanning = false, rescan = false;
  async function scan() {
    if (!state.active) return;
    if (scanning) { rescan = true; return; }
    scanning = true;
    try { const rows = await scanRows(); const open = await scanOpened(); checkHealth(rows, open); } catch (e) { console.debug('[Tripwire]', e); }
    scanning = false;
    if (rescan) { rescan = false; scheduleScan(); }
  }
  function scheduleScan() { clearTimeout(scanTimer); scanTimer = setTimeout(scan, 350); }

  function resetAll() {
    verdicts.clear();
    document.querySelectorAll('.pg-banner-host').forEach((b) => b.remove());
    document.querySelectorAll('[data-pg-key]').forEach((r) => { classify(r, 'safe'); delete r.dataset.pgKey; delete r.dataset.pgLevel;
      if ((r.getAttribute('title') || '').startsWith('Tripwire')) r.removeAttribute('title'); });
    document.querySelectorAll('[data-pg-sig]').forEach((b) => delete b.dataset.pgSig);
    document.querySelectorAll('.pg-risky-link').forEach((a) => a.classList.remove('pg-risky-link'));
  }

  function start() {
    if (state.active) return;
    state.active = true;
    observer = new MutationObserver((muts) => {
      if (muts.every((m) => m.target.closest && m.target.closest('[data-pg-ui]'))) return;
      scheduleScan();
    });
    observer.observe(document.body, { childList: true, subtree: true, characterData: true });
    scan();
  }
  function stop() {
    state.active = false;
    if (observer) observer.disconnect();
    resetAll();
  }

  chrome.storage.onChanged.addListener(async (changes, area) => {
    if (area !== 'local') return;
    const keys = Object.keys(changes);
    if (keys.every((k) => ['stats', 'signalCounts', 'senderHistory', 'health'].includes(k))) return;
    if (keys.includes('intelUpdated')) threats.clear(); // threat lists were refreshed: re-check everything
    await loadState();
    resetAll();
    if (shouldRun()) { start(); scan(); } else stop();
  });

  chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
    if (msg && msg.type === 'pg-status') {
      reply({ active: state.active, provider: adapter ? adapter.label : '', known: adapter ? adapter.id !== 'generic' : false, host: HOST });
    }
  });

  (async function init() {
    await loadState();
    if (shouldRun()) { start(); return; }
    // Single-page webmail apps load late; check a few more times.
    let tries = 0;
    const iv = setInterval(() => {
      if (state.active || ++tries > 6) return clearInterval(iv);
      if (shouldRun()) { clearInterval(iv); start(); }
    }, 2500);
  })();
})();
