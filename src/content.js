// =====================================================================================================================
// Content script (content.js): runs inside the webmail page
//
// Ties everything together on the page:
//   - colours inbox rows (scanRows) and draws the banner above each opened email (scanOpened)
//   - asks the background worker for threat-list lookups, QR decoding, short-link expansion and the AI check
//   - remembers past senders as salted hashes (sender history) for first-time / look-alike / bank-change checks
//   - intercepts clicks on risky links and shows the warning dialog (guardLinks)
//   - "Show me" highlighting, the user's report / trust buttons, counters and the layout health check
// A MutationObserver re-scans whenever the page changes, since webmail apps redraw constantly.
//
// Privacy: email text is analysed in memory only. Stored on the device: counts, the user's own trust/report lists,
// salted hashes of past senders, and which kinds of warning signs were seen (ids only).
// =====================================================================================================================
(function () {
  'use strict';
  if (window.__tripwireLoaded) return; // injected twice (manifest + "Check emails on this site")
  window.__tripwireLoaded = true;
  if (window.top !== window && !/mail\.google\.com|outlook\./.test(location.hostname)) return; // skip ads/iframes
  const A = window.PG_Analyzer, P = window.PG_Providers, UI = window.PG_UI, D = window.PG_DATA;
  const HOST = location.host || 'local-file';

  // ---------- state (all in memory, for this page only) ----------
  const state = { enabled: true, aiEnabled: false, trusted: new Set(), blocked: new Set(), enabledHosts: [], disabledHosts: [], active: false };
  const threats = new Map();  // threat-list answers: host or 'url:'+key -> hit, or null if clean
  const expanded = new Map(); // shortened link -> where it really goes
  const verdicts = new Map(); // email key -> { level, score, known, high, top } (so rows and banners agree)
  const extras = new Map();   // email key -> results of the slow checks: { auth, attHtml, qr, ai, hist, started }
  const seenKeys = new Set(); // emails already counted in the stats
  const pendingStats = { scanned: 0, suspicious: 0, phishing: 0, warnings: 0 };
  let adapter = null, observer = null, scanTimer = null;

  const lc = (s) => (s || '').toString().toLowerCase().trim();
  // Identifies one email across inbox row and opened view: sender + subject.
  const keyOf = (email, name, subject) => (lc(email) || lc(name)) + '|' + lc(subject).replace(/\s+/g, ' ').slice(0, 200);
  const lists = () => ({ trusted: state.trusted, blocked: state.blocked, threats, expanded });
  // Message the background worker. Returns null instead of throwing while the extension is being reloaded.
  const send = async (msg) => { try { return await chrome.runtime.sendMessage(msg); } catch (e) { return null; } };

  // ---------- threat lookups ----------
  // Ask the background worker which hosts / URLs are on the threat lists. Only new ones are asked about; answers
  // (including "clean") are cached in `threats` for as long as the page is open.
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
  // The hosts and exact-URL keys to look up for a set of links (after unwrapping redirects and expanded short links).
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

  // ---------- settings ----------
  async function loadState() {
    const s = await chrome.storage.local.get(['enabled', 'aiEnabled', 'trusted', 'blocked', 'enabledHosts', 'disabledHosts', 'layoutRules']);
    state.enabled = s.enabled !== false;
    state.aiEnabled = !!s.aiEnabled;
    state.trusted = new Set(s.trusted || []);
    state.blocked = new Set(s.blocked || []);
    state.enabledHosts = s.enabledHosts || [];
    state.disabledHosts = s.disabledHosts || [];
    P.configure(s.layoutRules || null); // updated webmail layout rules (signature-checked by the background worker), or built-in
  }

  // Run here? Not if switched off; yes on known webmail, sites the user enabled, and the local demo inbox.
  function shouldRun() {
    if (!state.enabled || state.disabledHosts.includes(HOST)) return false;
    adapter = P.pickAdapter();
    return adapter.id !== 'generic' || state.enabledHosts.includes(HOST) || P.looksLikeWebmail() || location.protocol === 'file:';
  }

  // ---------- sender history (hashed, on this device) ----------
  // Remembers which senders, company domains and display names have emailed before, and the bank details known
  // senders used, as salted SHA-256 hashes. Nothing readable is stored: it can't be turned back into names or
  // addresses. Stored shape (chrome.storage.local "senderHistory"):
  //   { salt, since, senders: { hash: { d: lastDay, m: [message hashes], b: [bank hashes] } },
  //     domains: { hash: { d, m, b } }, names: { hash: { d, s: [{ s: sender hash, d: domain hash }] } } }
  const history = { data: null, loading: null, dirty: false, timer: null, cache: new Map(),
    tabId: Math.random().toString(36).slice(2) }; // marks our own saves, to tell them apart from other tabs'
  const DAY = 86400000;
  const HASH_CACHE_MAX = 5000;
  // Loaded once; concurrent callers share the same promise, so a fresh install creates exactly one salt.
  function loadHistory() {
    if (history.data) return Promise.resolve(history.data);
    if (!history.loading) {
      history.loading = chrome.storage.local.get(['senderHistory']).then((s) => {
        let h = s.senderHistory;
        if (!h || !h.salt) {
          const salt = [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, '0')).join('');
          h = { v: 1, salt, since: Date.now(), senders: {}, names: {} };
          history.dirty = true;
        }
        history.data = h;
        return h;
      });
    }
    return history.loading;
  }
  // Salted SHA-256 of a value, first 16 hex characters. Cached, since the same senders come up again and again.
  async function hash(value) {
    if (history.cache.has(value)) return history.cache.get(value);
    const h = await loadHistory();
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(h.salt + '|' + value));
    const hex = [...new Uint8Array(buf).slice(0, 8)].map((b) => b.toString(16).padStart(2, '0')).join('');
    if (history.cache.size >= HASH_CACHE_MAX) history.cache.clear(); // keep memory bounded on long-open tabs
    history.cache.set(value, hex);
    return hex;
  }
  // "Mark Davis (CEO)" -> "mark davis"; null for names that aren't a person's ("Support Team", one-word names).
  function personName(name) {
    const n = lc(name).replace(/\(.*?\)|\[.*?\]|\bvia\b.*$/g, ' ').replace(/[^a-zÀ-ɏ\s'-]/g, ' ').replace(/\s+/g, ' ').trim();
    const tokens = n.split(' ').filter((t) => t.length >= 2);
    if (tokens.length < 2 || tokens.length > 4 || name.includes('@')) return null;
    if (tokens.every((t) => D.SERVICE_WORDS.includes(t))) return null;
    return tokens.join(' ');
  }
  // Uncached salted hash, for the hundreds of look-alike candidates checked per new sender.
  async function hashOnce(value) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(history.data.salt + '|' + value));
    return [...new Uint8Array(buf).slice(0, 8)].map((b) => b.toString(16).padStart(2, '0')).join('');
  }
  // How many *other* emails (not this one) a history record has seen.
  const otherMessages = (rec, mk) => (rec ? rec.m.filter((k) => k !== mk).length : 0);

  // Looks this sender up in the history, then records this email. Returns what the analyzer's historySignals needs:
  //   { seenBefore, mature, nameKnownElsewhere, knownDomain, lookalikeOf, lookalikeAddress, bankChanged, ... }
  // opts.deep: also look for look-alikes of people you correspond with (opened emails only, it hashes ~1,000 candidates).
  // opts.banks: bank identifiers found in this email ([{type, id}]), compared with the ones this sender used before.
  async function historyFor(senderName, senderEmail, msgKey, opts) {
    opts = opts || {};
    const email = lc(senderEmail);
    if (!email.includes('@')) return null;
    const h = await loadHistory();
    h.domains = h.domains || {};
    const reg = A.registrableDomain(email.split('@').pop());
    const free = D.FREE_MAIL.includes(reg);
    const sh = await hash('s:' + email), mk = (await hash('m:' + msgKey)).slice(0, 8);
    const dh = await hash('d:' + reg);
    const pn = personName(senderName);
    const nh = pn ? await hash('n:' + pn) : null;
    const rec = h.senders[sh];
    const seenBefore = otherMessages(rec, mk) > 0;
    const knownDomain = !free && otherMessages(h.domains[dh], mk) > 0;
    let nameKnownElsewhere = false;
    if (nh && !seenBefore && h.names[nh]) {
      nameKnownElsewhere = h.names[nh].s.some((o) => o.s !== sh && o.d !== dh && h.senders[o.s] && h.senders[o.s].m.length >= 2);
    }
    // "First email from this sender" is meaningless until the history has had time to learn who you correspond with.
    const mature = Date.now() - h.since > 14 * DAY || Object.keys(h.senders).length >= 150;

    // Look-alike of a domain (or, for free mail, an address) you've had at least 2 emails from.
    let lookalikeOf = null, lookalikeAddress = null;
    if (opts.deep && !seenBefore && !knownDomain) {
      const cand = A.lookalikeCandidates(email);
      for (const d of cand.domains) {
        const x = h.domains[await hashOnce('d:' + d)];
        if (x && x.m.length >= 2) { lookalikeOf = d; break; }
      }
      if (!lookalikeOf) for (const a of cand.addresses) {
        const x = h.senders[await hashOnce('s:' + a)];
        if (x && x.m.length >= 2) { lookalikeAddress = a; break; }
      }
    }

    // Bank details: fingerprints per company domain (per address for free mail), compared with earlier emails.
    const holder = free ? (h.senders[sh] || null) : (h.domains[dh] || null);
    const bankHashes = [];
    for (const b of opts.banks || []) bankHashes.push((await hash('b:' + b.type + ':' + b.id)).slice(0, 12));
    const bankChanged = !!(bankHashes.length && holder && (holder.b || []).length && (free ? seenBefore : knownDomain)
      && !bankHashes.some((x) => holder.b.includes(x)));

    // Record this message after judging it, so it doesn't vouch for itself.
    const today = Math.floor(Date.now() / DAY);
    const r = h.senders[sh] || (h.senders[sh] = { d: today, m: [] });
    r.d = today;
    if (!r.m.includes(mk)) { r.m.push(mk); if (r.m.length > 12) r.m.shift(); history.dirty = true; }
    if (!free) {
      const dr = h.domains[dh] || (h.domains[dh] = { d: today, m: [] });
      dr.d = today;
      if (!dr.m.includes(mk)) { dr.m.push(mk); if (dr.m.length > 12) dr.m.shift(); history.dirty = true; }
    }
    if (nh) {
      const n = h.names[nh] || (h.names[nh] = { d: today, s: [] });
      n.d = today;
      if (!n.s.some((o) => o.s === sh)) { n.s.push({ s: sh, d: dh }); if (n.s.length > 6) n.s.shift(); history.dirty = true; }
    }
    // Remember bank details only from senders you already know, so a scammer's first email can't set the "usual" account.
    if (bankHashes.length && !bankChanged && (free ? seenBefore : knownDomain)) {
      const target = free ? r : h.domains[dh];
      target.b = target.b || [];
      for (const x of bankHashes) if (!target.b.includes(x)) { target.b.push(x); if (target.b.length > 6) target.b.shift(); history.dirty = true; }
    }
    saveHistorySoon();
    return { seenBefore, mature, nameKnownElsewhere, knownDomain, lookalikeOf, lookalikeAddress, bankChanged, bankChangedDomain: bankChanged ? reg : null };
  }
  // Saves the history a few seconds after the last change (many rows change at once), pruning the oldest entries
  // so storage stays bounded.
  function saveHistorySoon() {
    if (!history.dirty) return;
    clearTimeout(history.timer);
    history.timer = setTimeout(async () => {
      const h = history.data;
      const keys = Object.keys(h.senders);
      if (keys.length > 6000) keys.sort((a, b) => h.senders[a].d - h.senders[b].d).slice(0, keys.length - 6000).forEach((k) => delete h.senders[k]);
      const names = Object.keys(h.names);
      if (names.length > 6000) names.sort((a, b) => h.names[a].d - h.names[b].d).slice(0, names.length - 6000).forEach((k) => delete h.names[k]);
      const doms = Object.keys(h.domains || {});
      if (doms.length > 3000) doms.sort((a, b) => h.domains[a].d - h.domains[b].d).slice(0, doms.length - 3000).forEach((k) => delete h.domains[k]);
      history.dirty = false;
      h.savedBy = history.tabId;
      try { await chrome.storage.local.set({ senderHistory: h }); } catch (e) { /* extension reloaded */ }
    }, 3000);
  }

  // ---------- inbox list ----------
  // Rows only show sender, subject and a snippet, so their verdict is a quick first pass; opening the email runs the
  // full analysis and updates the row's colour through `verdicts`.
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
        res = { level: a.level, score: a.score, known: a.known, high: a.high, top: a.signals.slice(0, 2).map((x) => x.title) };
        verdicts.set(key, res);
        count(key, res.level);
      }
      // Remember what we drew, so an unchanged row is skipped next scan. The hover title summarises the warning.
      r.row.dataset.pgKey = key;
      r.row.dataset.pgLevel = res.level;
      classify(r.row, res.level);
      if (res.level !== 'safe') {
        r.row.setAttribute('title', `Tripwire: ${res.known ? 'KNOWN PHISHING (confirmed scam)' : res.level === 'phishing' ? 'Dangerous: likely a phishing scam' : res.high ? 'Very suspicious' : 'Suspicious'} — safety ${res.score}/100` +
          (res.top && res.top.length ? `\n• ${res.top.join('\n• ')}` : '') + '\nOpen the email to see the full explanation.');
      } else if ((r.row.getAttribute('title') || '').startsWith('Tripwire')) r.row.removeAttribute('title');
    }
    return rows.length;
  }

  // ---------- opened email ----------
  // Slow checks (headers, attachments, QR codes, AI) run in the background; the banner is drawn straight away and
  // redrawn as each one finishes. Each check runs at most once per email (`started`), and its result goes in `extras`.
  function enrich(key, m, bodyText) {
    const ex = extras.get(key) || { started: new Set() };
    extras.set(key, ex);
    const redraw = () => { if (m.body.isConnected) { delete m.body.dataset.pgSig; scheduleScan(); } };
    const once = (name, fn) => {
      if (ex.started.has(name)) return;
      ex.started.add(name);
      Promise.resolve().then(fn).then((changed) => { if (changed) redraw(); }).catch((e) => console.debug('[Tripwire]', name, e));
    };
    // Sender authentication (SPF/DKIM/DMARC) from the message's raw headers (Gmail only).
    if (adapter.fetchHeaders && m.messageId) {
      once('auth', async () => {
        // "Show original" returns the whole raw message: headers for the authentication check, and the full structure
        // for the header / signature / script tricks the page itself never shows (see inspectRawMessage).
        const raw = await adapter.fetchHeaders(m);
        ex.auth = raw ? A.parseAuthResults(raw) : null;
        ex.raw = raw ? raw.slice(0, 2000000) : null;
        return !!(ex.auth || ex.raw);
      });
    }
    // HTML attachments: read them as text (never render them) and look for login forms and hidden redirects.
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
    // QR codes in images: the background worker decodes them; any web address found is then looked up like a link.
    if (m.images && m.images.length) {
      once('qr', async () => {
        const srcs = [], original = new Map(); // what the background fetches -> the image's real src on the page
        for (const src of m.images) {
          if (!src.startsWith('blob:')) { srcs.push(src); original.set(src, src); continue; }
          try { // blob: URLs only work in this page, so hand the background a data: copy
            const b = await (await fetch(src)).blob();
            if (b.size > 3e6) continue;
            const dataUrl = await new Promise((res) => { const fr = new FileReader(); fr.onload = () => res(fr.result); fr.readAsDataURL(b); });
            srcs.push(dataUrl); original.set(dataUrl, src);
          } catch (e) { /* revoked */ }
        }
        const r = await send({ type: 'pg-qr', srcs });
        ex.qr = (r || []).map((q) => ({ data: q.data, src: original.get(q.src) || q.src })); // src lets "Show me" find the image
        if (!ex.qr.length) return false;
        const t = linkTargets(ex.qr.map((q) => ({ href: /^https?:/i.test(q.data) ? q.data : 'https://' + q.data })));
        await lookupThreats(t.hosts, t.urls);
        return true;
      });
    }
    // Optional on-device AI check (only if the user turned it on).
    if (state.aiEnabled && bodyText.length > 40) {
      once('ai', async () => {
        ex.ai = await send({ type: 'pg-ai', payload: { subject: m.subject, sender: `${m.senderName || ''} <${m.senderEmail || ''}>`, body: bodyText } });
        return !!ex.ai;
      });
    }
    return ex;
  }

  // For every opened email: look up its links, run the full analysis, draw the banner above it, guard its links.
  async function scanOpened() {
    const opened = adapter.opened();
    for (const m of opened) {
      const body = m.body;
      const bodyText = P.text(body);
      const key = keyOf(m.senderEmail, m.senderName, m.subject);
      const ex = extras.get(key) || {};
      // A fingerprint of what the banner was drawn from. Unchanged email + same finished checks = nothing to redraw.
      const sig = bodyText.length + '|' + (m.senderEmail || '') + '|' + m.subject + '|' + ['auth', 'raw', 'attHtml', 'qr', 'ai'].map((k) => (ex[k] ? 1 : 0)).join('');
      const hasBanner = () => body.previousElementSibling && body.previousElementSibling.classList && body.previousElementSibling.classList.contains('pg-banner-host');
      if (body.dataset.pgSig === sig && hasBanner()) continue;

      const links = P.linksIn(body);
      const targets = linkTargets(links);
      await lookupThreats([senderDomain(m.senderEmail), ...targets.hosts], targets.urls);
      if (!body.isConnected) continue; // the email was closed while we were checking
      const e = enrich(key, m, bodyText);
      // Full history check once per opened email: look-alikes of people you correspond with, and changed bank details.
      if (!e.hist) e.hist = await historyFor(m.senderName, m.senderEmail, key, { deep: true, banks: A.findBankDetails(m.subject + '\n' + bodyText) });
      if (!body.isConnected) continue;
      const hist = e.hist;
      const attachments = (m.attachments || []).map((a) => Object.assign({}, a, { html: e.attHtml && e.attHtml[a.name] }));
      const result = A.analyzeEmail({ senderName: m.senderName, senderEmail: m.senderEmail, subject: m.subject, body: bodyText,
        links, hasForm: P.hasForm(body), context: 'open', auth: e.auth, rawMessage: e.raw || undefined, attachments, qrCodes: e.qr,
        history: hist, ai: e.ai, thread: m.thread }, lists());
      if (hasBanner()) body.previousElementSibling.remove();
      body.dataset.pgSig = sig;

      verdicts.set(key, { level: result.level, score: result.score, known: result.known, high: result.high, top: result.signals.slice(0, 2).map((x) => x.title) });
      count(key, result.level);
      countSignals(key, result.signals);

      // Checks still running are listed in the banner ("Still checking: ...").
      const pending = [...(e.started || [])].filter((n) => ({ auth: !('auth' in e), attachments: !e.attHtml, qr: !e.qr, ai: !('ai' in e) })[n]);
      const banner = UI.renderBanner(result, {
        reportHelp: adapter.reportHelp,
        pending,
        onReport: () => report(result.sender, result.verifiedBrand),
        onShow: (s) => showMe(m, links, result, s),
        onTrust: () => updateList('trusted', result.sender.email, true),
        onUntrust: () => updateList('trusted', result.sender.email, false),
      });
      body.parentNode.insertBefore(banner, body);
      guardLinks(body, links, result);
    }
    return opened.length;
  }

  // ---------- "Show me": point at the exact part of the email a reason is about ----------
  // Elements get a pulsing outline; words get the browser's built-in text highlight (CSS Custom Highlight API),
  // which marks text without changing the email's page structure. Both clear after a few seconds.
  let showTimer = null;
  function clearShow() {
    document.querySelectorAll('.pg-show').forEach((el) => el.classList.remove('pg-show'));
    try { if (window.CSS && CSS.highlights) CSS.highlights.delete('tripwire-show'); } catch (e) { /* unsupported */ }
  }
  // Text ranges where any of `phrases` appears (case-insensitive, any whitespace), skipping Tripwire's own UI.
  // A phrase split across two page elements isn't found; that's rare for the short phrases used here.
  function textRanges(roots, phrases) {
    const res = [...new Set((phrases || []).filter((p) => p && p.trim().length >= 2))]
      .map((p) => new RegExp(p.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s+'), 'gi'));
    const ranges = [];
    for (const root of roots.filter(Boolean)) {
      const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
        acceptNode: (n) => (n.parentElement && n.parentElement.closest('[data-pg-ui], script, style') ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT) });
      for (let n = walker.nextNode(); n && ranges.length < 50; n = walker.nextNode()) {
        for (const re of res) {
          re.lastIndex = 0;
          for (let mt = re.exec(n.data); mt && ranges.length < 50; mt = re.exec(n.data)) {
            if (!mt[0]) { re.lastIndex++; continue; }
            const r = document.createRange(); r.setStart(n, mt.index); r.setEnd(n, mt.index + mt[0].length); ranges.push(r);
          }
        }
      }
    }
    return ranges;
  }
  function hostOf(href) { const u = A.unwrapUrl(expanded.get((href || '').trim()) || href); return u && u.hostname !== 'invalid.local' ? lc(u.hostname) : ''; }
  // Finds what signal `s` is about (see its `target`), outlines or highlights it and scrolls to it.
  // Returns how many things were marked (0 = nothing visible, so the button says so).
  function showMe(m, links, result, s) {
    const t = s.target || {};
    clearShow(); clearTimeout(showTimer);
    let els = [], ranges = [];
    if (t.type === 'sender') els = [m.senderEl];
    else if (t.type === 'subject') els = [m.subjectEl];
    else if (t.type === 'form') els = [...m.body.querySelectorAll('form, input, textarea, select')];
    else if (t.type === 'link') els = links.filter((l) => (t.href && l.href.trim() === t.href) || (t.host && hostOf(l.href) === t.host)).map((l) => l.el);
    else if (t.type === 'image') els = [...(m.scope || m.body).querySelectorAll('img')].filter((i) => t.src && (i.currentSrc === t.src || i.src === t.src));
    else if (t.type === 'attachment') {
      const name = lc(t.name);
      els = [...(m.scope || document).querySelectorAll('[title], [aria-label], span, div, a')]
        .filter((e) => !m.body.contains(e) && !e.closest('[data-pg-ui]') && lc((e.getAttribute('title') || '') + ' ' + (e.getAttribute('aria-label') || '') + ' ' + (e.children.length ? '' : e.textContent)).includes(name))
        .slice(0, 1);
    } else if (t.type === 'text') ranges = textRanges([m.subjectEl, m.body], t.phrases);
    els = els.filter((e) => e && e.isConnected);
    if (!els.length && !ranges.length) return 0;
    els.forEach((e) => e.classList.add('pg-show'));
    if (ranges.length && window.CSS && CSS.highlights && window.Highlight) CSS.highlights.set('tripwire-show', new Highlight(...ranges));
    const first = els[0] || (ranges[0] && ranges[0].startContainer.parentElement);
    if (first) first.scrollIntoView({ behavior: 'smooth', block: 'center' });
    showTimer = setTimeout(clearShow, 6000);
    return els.length + ranges.length;
  }

  // ---------- link protection ----------
  // The analysis of one link element (matched by href and text), plus the email's overall level.
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

  // Opens a link in a new tab. Risky ones are opened by the background worker, which remembers the tab so the
  // optional page guard can warn harder if that page asks for a password.
  function openLink(url, risky, level) {
    if (risky) send({ type: 'pg-open-risky', url, level }).then((r) => { if (!r) window.open(url, '_blank', 'noopener,noreferrer'); });
    else window.open(url, '_blank', 'noopener,noreferrer');
  }

  // Marks risky links, shows where a link really goes on hover, and intercepts clicks:
  //   risky link                       -> warning dialog first (short links are expanded inside the dialog)
  //   short link in a harmless email   -> expanded silently; opens normally unless it leads somewhere risky
  //   anything else                    -> left alone
  // Listeners are attached once per email body; later scans only refresh the data they read (body._pgGuard).
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

  // ---------- user actions (banner buttons) ----------
  // Adds or removes a value in a stored list ('trusted' or 'blocked').
  async function updateList(name, value, add) {
    if (!value) return;
    const s = await chrome.storage.local.get([name]);
    const set = new Set(s[name] || []);
    add ? set.add(lc(value)) : set.delete(lc(value));
    await chrome.storage.local.set({ [name]: [...set] }); // storage.onChanged triggers a rescan
  }
  // "Report phishing": block the sender on this device, untrust them, and (if opted in) share a fingerprint.
  async function report(sender, verifiedBrand) {
    if (!sender.email) return;
    const dom = sender.domain;
    const freeOrBrand = verifiedBrand || D.FREE_MAIL.includes(A.registrableDomain(dom));
    // Block the whole fake domain, but only the single address if it's a shared provider like gmail.com
    await updateList('blocked', freeOrBrand ? sender.email : A.registrableDomain(dom), true);
    // If the user opted in, share a fingerprint of the fake domain (never for shared providers like gmail.com).
    if (!freeOrBrand) send({ type: 'pg-share-report', domain: A.registrableDomain(dom) });
    await updateList('trusted', sender.email, false);
    const s = await chrome.storage.local.get(['stats']);
    const st = s.stats || {}; st.reported = (st.reported || 0) + 1;
    await chrome.storage.local.set({ stats: st });
  }

  // ---------- stats (counts only) ----------
  // Counts each email once per page, and saves in batches (flushStatsSoon) rather than on every scan.
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
  // A problem must persist for 3 scans over at least 8 seconds before it is reported, so a page still loading
  // doesn't raise a false alarm. Each state change (broken / ok) is reported once.
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
  // Page changes come in bursts; wait for a short quiet moment before scanning.
  function scheduleScan() { clearTimeout(scanTimer); scanTimer = setTimeout(scan, 350); }

  // Removes everything Tripwire drew (used when settings change, and when protection is switched off).
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
    // Re-scan whenever the page changes, except for changes inside Tripwire's own banner and dialogs.
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

  // Storage keys whose changes don't affect what this page shows (counters, background bookkeeping, and settings
  // that only the popup or background worker use).
  const IGNORED_KEYS = ['stats', 'signalCounts', 'senderHistory', 'health', 'intelNewest', 'layoutRulesChecked',
    'useFeed', 'expandLinks', 'shareReports', 'communityEnabled', 'guardEnabled', 'pwAlert'];

  // React to changes from the popup, other tabs and the background worker.
  chrome.storage.onChanged.addListener(async (changes, area) => {
    if (area !== 'local') return;
    const keys = Object.keys(changes);
    // Another tab saved the sender history: take its copy (unless we have unsaved changes of our own), so two open
    // mail tabs don't keep overwriting each other's newly recorded senders.
    const other = changes.senderHistory && changes.senderHistory.newValue;
    if (other && other.savedBy !== history.tabId && !history.dirty) {
      if (!history.data || history.data.salt !== other.salt) history.cache.clear(); // cached hashes depend on the salt
      history.data = other;
    }
    if (keys.every((k) => IGNORED_KEYS.includes(k))) return;
    if (keys.includes('intelUpdated')) threats.clear(); // threat lists were refreshed: re-check everything
    await loadState();
    resetAll();
    if (shouldRun()) { start(); scan(); } else stop();
  });

  // The popup asks each tab whether Tripwire is active there.
  chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
    if (msg && msg.type === 'pg-status') {
      reply({ active: state.active, provider: adapter ? adapter.label : '', known: adapter ? adapter.id !== 'generic' : false, host: HOST, rules: P.rulesVersion() });
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
