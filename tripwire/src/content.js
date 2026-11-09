// Main content script: scans inbox rows and opened emails, highlights, shows banner, guards link clicks.
// Privacy: email text is analysed in memory only. Nothing is stored except counts and the user's own trust/report lists.
(function () {
  'use strict';
  if (window.top !== window && !/mail\.google\.com|outlook\./.test(location.hostname)) return; // skip ads/iframes
  const A = window.PG_Analyzer, P = window.PG_Providers, UI = window.PG_UI;
  const HOST = location.host || 'local-file';

  const state = { enabled: true, trusted: new Set(), blocked: new Set(), enabledHosts: [], disabledHosts: [], active: false };
  // Threat-list answers from the background worker: host or 'url:'+key -> hit object, or null if clean. Memory only.
  const threats = new Map();
  const verdicts = new Map(); // in-memory only: rowKey -> {level, score, known}
  const seenKeys = new Set();
  const pendingStats = { scanned: 0, suspicious: 0, phishing: 0, warnings: 0 };
  let adapter = null, observer = null, scanTimer = null;

  const lc = (s) => (s || '').toString().toLowerCase().trim();
  const keyOf = (email, name, subject) => (lc(email) || lc(name)) + '|' + lc(subject).replace(/\s+/g, ' ').slice(0, 200);
  const lists = () => ({ trusted: state.trusted, blocked: state.blocked, threats });

  // Ask the background worker which hosts / URLs are on the threat lists (answers are cached for this page).
  async function lookupThreats(hosts, urlKeys) {
    const needHosts = [...new Set(hosts.filter((h) => h && !threats.has(h)))];
    const needUrls = [...new Set(urlKeys.filter((u) => u && !threats.has('url:' + u)))];
    if (!needHosts.length && !needUrls.length) return;
    let hits = {};
    try { hits = ((await chrome.runtime.sendMessage({ type: 'pg-lookup', hosts: needHosts, urls: needUrls })) || {}).hits || {}; }
    catch (e) { return; } // extension reloading; try again next scan
    for (const h of needHosts) threats.set(h, hits[h] || null);
    for (const u of needUrls) threats.set('url:' + u, hits['url:' + u] || null);
  }
  const senderDomain = (email) => (lc(email).split('@')[1] || '');
  function linkTargets(links) {
    const hosts = [], urls = [];
    for (const l of links) {
      const u = A.unwrapUrl(l.href);
      if (!u || !/^https?:$/.test(u.protocol) || u.hostname === 'invalid.local') continue;
      hosts.push(lc(u.hostname));
      urls.push(...window.PG_Intel.urlKeys(u));
    }
    return { hosts, urls };
  }

  async function loadState() {
    const s = await chrome.storage.local.get(['enabled', 'trusted', 'blocked', 'enabledHosts', 'disabledHosts']);
    state.enabled = s.enabled !== false;
    state.trusted = new Set(s.trusted || []);
    state.blocked = new Set(s.blocked || []);
    state.enabledHosts = s.enabledHosts || [];
    state.disabledHosts = s.disabledHosts || [];
  }

  function shouldRun() {
    if (!state.enabled || state.disabledHosts.includes(HOST)) return false;
    adapter = P.pickAdapter();
    return adapter.id !== 'generic' || state.enabledHosts.includes(HOST) || P.looksLikeWebmail();
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
        const a = A.analyzeEmail({ senderName: r.senderName, senderEmail: r.senderEmail, subject: r.subject, body: r.snippet, links: [], context: 'list' }, lists());
        res = { level: a.level, score: a.score, known: a.known, high: a.high, top: a.signals.slice(0, 2).map((x) => x.title), partial: true };
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
  }

  // ---------- opened email ----------
  async function scanOpened() {
    for (const m of adapter.opened()) {
      const body = m.body;
      const bodyText = P.text(body);
      const sig = bodyText.length + '|' + (m.senderEmail || '') + '|' + m.subject;
      const hasBanner = () => body.previousElementSibling && body.previousElementSibling.classList && body.previousElementSibling.classList.contains('pg-banner-host');
      if (body.dataset.pgSig === sig && hasBanner()) continue;

      const links = P.linksIn(body);
      const targets = linkTargets(links);
      await lookupThreats([senderDomain(m.senderEmail), ...targets.hosts], targets.urls);
      if (!body.isConnected) continue; // the email was closed while we were checking
      if (hasBanner()) body.previousElementSibling.remove();
      const result = A.analyzeEmail({ senderName: m.senderName, senderEmail: m.senderEmail, subject: m.subject, body: bodyText,
        links, hasForm: P.hasForm(body), context: 'open' }, lists());
      body.dataset.pgSig = sig;

      const key = keyOf(m.senderEmail, m.senderName, m.subject);
      verdicts.set(key, { level: result.level, score: result.score, known: result.known, high: result.high, top: result.signals.slice(0, 2).map((x) => x.title) });
      count(key, result.level);

      const banner = UI.renderBanner(result, {
        reportHelp: adapter.reportHelp,
        onReport: () => report(result.sender, result.verifiedBrand),
        onTrust: () => updateList('trusted', result.sender.email, true),
        onUntrust: () => updateList('trusted', result.sender.email, false),
      });
      body.parentNode.insertBefore(banner, body);
      guardLinks(body, links, result);
    }
  }

  function linkInfoFor(anchor, links, result) {
    const href = anchor.getAttribute('href') || '';
    const r = result.links.find((x) => x.href === href.trim() && x.text === (P.text(anchor) || anchor.getAttribute('title') || '').trim())
      || result.links.find((x) => x.href === href.trim());
    return Object.assign({ href, text: P.text(anchor), host: '', weight: 0, signals: [] }, r || {}, { emailLevel: result.level });
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
      const risky = info.weight >= 20 || g.result.level === 'phishing' || (g.result.level === 'suspicious' && info.weight > 0) || /^(javascript|data):/i.test(info.href);
      if (!risky) return;
      e.preventDefault(); e.stopPropagation(); e.stopImmediatePropagation();
      UI.hideTooltip();
      pendingStats.warnings++; flushStatsSoon();
      if (await UI.confirmLink(info)) window.open(info.finalHref || info.href, '_blank', 'noopener,noreferrer');
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
    const freeOrBrand = verifiedBrand || window.PG_DATA.FREE_MAIL.includes(A.registrableDomain(dom));
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
  let statsTimer = null;
  function flushStatsSoon() {
    clearTimeout(statsTimer);
    statsTimer = setTimeout(async () => {
      try {
        const s = await chrome.storage.local.get(['stats']);
        const st = s.stats || {};
        for (const k of Object.keys(pendingStats)) { st[k] = (st[k] || 0) + pendingStats[k]; pendingStats[k] = 0; }
        await chrome.storage.local.set({ stats: st });
      } catch (e) { /* extension reloaded */ }
    }, 2000);
  }

  // ---------- lifecycle ----------
  // One scan at a time; if the page changes mid-scan, run once more afterwards.
  let scanning = false, rescan = false;
  async function scan() {
    if (!state.active) return;
    if (scanning) { rescan = true; return; }
    scanning = true;
    try { await scanRows(); await scanOpened(); } catch (e) { console.debug('[Tripwire]', e); }
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
    if (keys.every((k) => k === 'stats')) return;
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
