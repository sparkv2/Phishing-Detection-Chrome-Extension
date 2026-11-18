// Adapters that know how to find inbox rows and opened emails on different webmail sites.
// Each adapter returns plain data; the analyzer never touches the page.
(function (root) {
  'use strict';
  const EMAIL_RE = /[a-z0-9._%+\-]+@[a-z0-9.\-\u00a1-\uffff]+\.[a-z\u00a1-\uffff]{2,}/i;
  const text = (el) => (el ? (el.innerText || el.textContent || '').trim() : '');
  const $ = (sel, ctx) => { try { return (ctx || document).querySelector(sel); } catch (e) { return null; } };
  const $$ = (sel, ctx) => { try { return [...(ctx || document).querySelectorAll(sel)]; } catch (e) { return []; } };

  function linksIn(el) {
    return $$('a[href]', el).map((a) => ({ href: a.getAttribute('href') || '', text: text(a) || a.getAttribute('title') || '', el: a }))
      .filter((l) => l.href && !/^(mailto:|tel:|#)/i.test(l.href));
  }
  function hasForm(el) { return !!$('form input, input[type="password"]', el); }

  // Is this element part of an email the user is writing (new message, reply, forward)?
  // Outlook's compose editor is also labelled "Message body", and Gmail's reply box can sit inside a thread,
  // so every adapter skips editable areas: the banner is only for emails being read.
  const COMPOSE_SEL = '[contenteditable=""], [contenteditable="true"], [contenteditable="plaintext-only"], [g_editable], textarea, ' +
    '.M9, .AD, [aria-label*="compose" i], [aria-label*="new message" i], [data-test-id*="compose" i]';
  function isCompose(el) {
    if (!el) return false;
    if (el.isContentEditable || el.closest(COMPOSE_SEL)) return true;
    return !!$('[contenteditable=""], [contenteditable="true"], [contenteditable="plaintext-only"], [g_editable], textarea', el);
  }

  // Images large enough to hold a QR code (tracking pixels and icons are skipped).
  function imagesIn(...scopes) {
    const srcs = [];
    for (const scope of scopes.filter(Boolean)) {
      for (const img of $$('img', scope)) {
        const w = img.naturalWidth || img.width, h = img.naturalHeight || img.height;
        if (w < 60 || h < 60 || Math.max(w, h) / Math.min(w, h) > 4 || img.closest('[data-pg-ui]')) continue;
        const src = img.currentSrc || img.src;
        if (src && /^(https?:|data:image\/|blob:)/i.test(src) && !srcs.includes(src)) srcs.push(src);
      }
    }
    return srcs.slice(0, 8);
  }

  // File names shown in a message's attachment area, outside the message body.
  const FILE_RE = /([^\\/:*?"<>|\n\r]{1,120}\.[a-z0-9]{2,5})\b/i;
  function genericAttachments(scope, body) {
    if (!scope) return [];
    const names = new Set();
    for (const e of $$('[aria-label*="attachment" i], [class*="attachment" i], [data-test-id*="attachment" i], [title*="."]', scope)) {
      if (body && body.contains(e)) continue;
      const t = (e.getAttribute('title') || '') + '\n' + (e.getAttribute('aria-label') || '') + '\n' + (text(e).length < 160 ? text(e) : '');
      for (const part of t.split('\n')) {
        const m = part.replace(/^(download|open|preview|attachment:?)\s+/i, '').match(FILE_RE);
        if (m && !/^https?:|www\./i.test(m[1]) && !EMAIL_RE.test(m[1])) names.add(m[1].trim());
      }
    }
    return [...names].slice(0, 20).map((name) => ({ name }));
  }

  // Signs that the page is showing an inbox list / an open email, independent of the adapter's own selectors.
  // Used to notice when a site redesign has silently broken detection.
  function pageShowsList() { return $$('[role="main"] [role="row"], [role="main"] [role="option"], [role="main"] tr').length >= 3; }

  // Find a sender email near an element by checking common attributes, then visible text.
  function findSender(scope, excludeEl) {
    if (!scope) return { name: '', email: '' };
    const attrEl = $$('[email], [data-email], [data-hovercard-id*="@"], [title*="@"], [aria-label*="@"]', scope)
      .find((e) => !excludeEl || !excludeEl.contains(e));
    if (attrEl) {
      const email = attrEl.getAttribute('email') || attrEl.getAttribute('data-email') || attrEl.getAttribute('data-hovercard-id')
        || ((attrEl.getAttribute('title') || attrEl.getAttribute('aria-label') || '').match(EMAIL_RE) || [''])[0];
      const name = attrEl.getAttribute('name') || text(attrEl).replace(EMAIL_RE, '').replace(/[<>]/g, '').trim();
      if (email) return { name, email };
    }
    // Text like "Jane Doe <jane@example.com>" in a header area
    // Pick the smallest element containing an address, then take the name from it or its parent.
    let best = null, bestLen = Infinity;
    for (const e of $$('span, div, a, td, b, strong', scope)) {
      if (excludeEl && (excludeEl.contains(e) || e.contains(excludeEl))) continue;
      const t = text(e);
      if (t.length > 160 || t.length >= bestLen || !EMAIL_RE.test(t)) continue;
      best = e; bestLen = t.length;
    }
    if (best) {
      const email = text(best).match(EMAIL_RE)[0];
      const clean = (s) => s.replace(email, '').replace(/[<>"]/g, '').replace(/^\s*from:?\s*/i, '').trim();
      let name = clean(text(best));
      if (!name && best.parentElement && text(best.parentElement).length < 120) name = clean(text(best.parentElement));
      return { name, email };
    }
    return { name: '', email: '' };
  }

  // ---------------- Gmail ----------------
  const gmail = {
    id: 'gmail', label: 'Gmail',
    match: () => location.hostname === 'mail.google.com',
    rows: () => $$('tr.zA').map((row) => {
      const s = $('span[email]', row);
      return { row, senderName: s ? (s.getAttribute('name') || text(s)) : '', senderEmail: s ? s.getAttribute('email') : '',
        subject: text($('.bog', row)), snippet: text($('.y2', row)) };
    }),
    opened: () => $$('div.a3s').filter((b) => b.offsetParent !== null && text(b).length > 0 && !isCompose(b)).map((body) => {
      const msg = body.closest('.adn, .gs') || body.parentElement;
      const s = msg ? $('span.gD[email], span[email].gD, h3 span[email]', msg) : null;
      return { body, anchor: body, scope: msg, senderName: s ? (s.getAttribute('name') || text(s)) : '', senderEmail: s ? s.getAttribute('email') : '',
        subject: text($('h2.hP')), messageId: gmailMessageId(msg), attachments: gmailAttachments(msg, body), images: imagesIn(body, $('.aQH', msg)) };
    }),
    // Raw headers via Gmail's own "Show original" page (same site, the user's own session). Never leaves the device.
    fetchHeaders: async (m) => {
      if (!m.messageId) return null;
      const base = (location.pathname.match(/^\/mail\/u\/\d+\//) || ['/mail/u/0/'])[0];
      const ik = gmailIk();
      const url = `${location.origin}${base}?${ik ? 'ik=' + ik + '&' : ''}view=om&permmsgid=${encodeURIComponent(m.messageId)}`;
      const res = await fetch(url, { credentials: 'include' });
      if (!res.ok) return null;
      const html = await res.text();
      const doc = new DOMParser().parseFromString(html, 'text/html');
      const pre = doc.querySelector('#raw_message_text, pre');
      return pre ? pre.textContent : null;
    },
    // HTML attachments can be read (same site) to see whether they hide a login form or a redirect.
    fetchAttachment: async (a) => {
      if (!a.url || !/^https:\/\/mail\.google\.com\//.test(a.url)) return null;
      const res = await fetch(a.url, { credentials: 'include' });
      if (!res.ok) return null;
      const buf = await res.arrayBuffer();
      return new TextDecoder().decode(buf.slice(0, 300000));
    },
    health: () => ({ listShown: /#(inbox|all|spam|search|label|category)/.test(location.hash) && pageShowsList(),
      messageShown: /\/[A-Za-z0-9]{16,}$/.test(location.hash) }),
    reportHelp: 'In Gmail, click the three dots (⋮) at the top-right of the email and choose "Report phishing".',
  };
  function gmailMessageId(msg) {
    if (!msg) return '';
    const el = msg.matches('[data-message-id], [data-legacy-message-id]') ? msg : $('[data-message-id], [data-legacy-message-id]', msg);
    if (!el) return '';
    const id = el.getAttribute('data-message-id') || '';
    if (/msg-f:\d+/.test(id)) return id.match(/msg-f:\d+/)[0];
    const legacy = el.getAttribute('data-legacy-message-id');
    if (legacy && /^[0-9a-f]+$/i.test(legacy)) { try { return 'msg-f:' + BigInt('0x' + legacy).toString(); } catch (e) { /* ignore */ } }
    return '';
  }
  let ikCache = null;
  function gmailIk() { // Gmail's per-account key, found in its startup script (GLOBALS[9])
    if (ikCache) return ikCache;
    for (const s of document.scripts) {
      const m = (s.textContent || '').match(/GLOBALS\s*=\s*\[(?:[^,\]]*,){9}\s*"([0-9a-f]{6,16})"/);
      if (m) return (ikCache = m[1]);
    }
    return '';
  }
  function gmailAttachments(msg, body) {
    if (!msg) return [];
    const out = new Map();
    for (const e of $$('[download_url]', msg)) { // "mime/type:file name.ext:https://mail.google.com/..."
      const m = (e.getAttribute('download_url') || '').match(/^([^:]*):(.+?):(https:\/\/.+)$/);
      if (m) out.set(m[2], { name: m[2], mime: m[1], url: m[3] });
    }
    for (const e of $$('.aV3, .aQA span[title]', msg)) {
      const name = (e.getAttribute('title') || text(e)).trim();
      if (name && !out.has(name)) out.set(name, { name });
    }
    if (!out.size) for (const a of genericAttachments(msg, body)) out.set(a.name, a);
    return [...out.values()].slice(0, 20);
  }

  // ---------------- Yahoo ----------------
  const yahoo = {
    id: 'yahoo', label: 'Yahoo Mail',
    match: () => /(^|\.)mail\.yahoo\.com$/.test(location.hostname),
    rows: () => $$('[data-test-id="message-list-item"]').map((row) => {
      const s = $('[data-test-id="senders"] [title], [data-test-id="senders"]', row);
      const title = s ? (s.getAttribute('title') || '') : '';
      return { row, senderName: text(s), senderEmail: (title.match(EMAIL_RE) || [''])[0],
        subject: text($('[data-test-id="message-subject"]', row)), snippet: text($('[data-test-id="snippet"]', row)) };
    }),
    opened: () => $$('[data-test-id="message-view-body-content"]').filter((b) => !isCompose(b)).map((body) => {
      const msg = body.closest('[data-test-id="message-view"]') || body.closest('article') || body.parentElement.parentElement;
      const from = $('[data-test-id="message-from"]', msg) || $('[data-test-id="email-pill"]', msg);
      let sender = { name: '', email: '' };
      if (from) {
        const t = (from.getAttribute('title') || '') + ' ' + text(from);
        sender = { name: text($('[data-test-id="email-pill-name"]', from)) || text(from).replace(EMAIL_RE, '').trim(), email: (t.match(EMAIL_RE) || [''])[0] };
      }
      if (!sender.email) sender = findSender(msg, body);
      return { body, anchor: body, scope: msg, senderName: sender.name, senderEmail: sender.email,
        subject: text($('[data-test-id="message-group-subject-text"]')),
        attachments: genericAttachments(msg, body), images: imagesIn(body, $('[data-test-id*="attachment" i]', msg)) };
    }),
    health: () => ({ listShown: /\/folders\//.test(location.pathname) && !/\/messages\//.test(location.pathname) && pageShowsList(),
      messageShown: /\/messages\/[^/]+/.test(location.pathname) }),
    reportHelp: 'In Yahoo Mail, click the "Spam" button, or the three dots (…) → "Report phishing".',
  };

  // ---------------- Outlook + any other webmail (generic, ARIA-based) ----------------
  const ROW_SEL = '[role="listbox"] [role="option"], [role="grid"] [role="row"], [role="table"] [role="row"], [data-pg-row], .email-row, .message-list-item';
  const BODY_SEL = '[aria-label="Message body"], [aria-label*="message body" i], [role="document"], [data-pg-body], [class*="message-body" i], [class*="email-body" i], [class*="mail-body" i], [class*="messagebody" i]';

  const generic = {
    id: 'generic', label: 'Web mail',
    match: () => true,
    rows: () => {
      const rows = $$(ROW_SEL).filter((r) => !r.closest('[data-pg-ui]'));
      return rows.map((row) => {
        const t = text(row);
        if (t.length < 5 || t.length > 1200) return null;
        const s = findSender(row);
        const subjEl = $('[class*="subject" i], [data-subject]', row);
        return { row, senderName: s.name || (t.split('\n')[0] || '').slice(0, 80), senderEmail: s.email,
          subject: text(subjEl), snippet: subjEl ? t.replace(text(subjEl), '') : t };
      }).filter(Boolean);
    },
    opened: () => {
      // Compose editors are dropped first, so a wrapper around one never becomes the "innermost" body.
      const bodies = $$(BODY_SEL).filter((b) => !b.closest('[data-pg-ui]') && b.offsetParent !== null && text(b).length > 20 && !isCompose(b));
      // Keep innermost bodies only (avoid analysing a wrapper and its child twice)
      const inner = bodies.filter((b) => !bodies.some((o) => o !== b && b.contains(o)));
      return inner.map((body) => {
        let scope = body.parentElement, sender = { name: '', email: '' };
        for (let i = 0; i < 6 && scope && !sender.email; i++, scope = scope.parentElement) sender = findSender(scope, body);
        const heading = $('[role="main"] [role="heading"], [class*="subject" i], h1, h2', body.closest('[role="main"]') || document);
        let msg = body;
        for (let i = 0; i < 4 && msg.parentElement && !msg.parentElement.matches('[role="main"], body'); i++) msg = msg.parentElement;
        return { body, anchor: body, scope: msg, senderName: sender.name, senderEmail: sender.email, subject: text(heading),
          attachments: genericAttachments(msg, body), images: imagesIn(body) };
      });
    },
    reportHelp: 'Use your email provider\'s "Report phishing" or "Report junk" option (often under the three dots ⋯ menu). In Outlook: Report → Report phishing.',
  };
  const outlook = Object.assign({}, generic, {
    id: 'outlook', label: 'Outlook',
    match: () => /(^|\.)outlook\.(live|office|office365)\.com$/.test(location.hostname) || location.hostname === 'outlook.cloud.microsoft',
    health: () => ({ listShown: /\/mail\//.test(location.pathname) && pageShowsList(), messageShown: /\/id\/[^/]+/.test(location.pathname) }),
    reportHelp: 'In Outlook, select the email, then click "Report" in the toolbar and choose "Report phishing".',
  });

  const ADAPTERS = [gmail, yahoo, outlook];
  const KNOWN_HOSTS = /^(mail\.google\.com|mail\.yahoo\.com|.*\.mail\.yahoo\.com|outlook\.(live|office|office365)\.com|outlook\.cloud\.microsoft|mail\.aol\.com|mail\.proton\.me|mail\.zoho\.com|.*\.fastmail\.com|app\.fastmail\.com|mail\.yandex\.\w+|mail\.gmx\.\w+|navigator-\w+\.gmx\.\w+|www\.icloud\.com)$/;

  function pickAdapter() { return ADAPTERS.find((a) => a.match()) || generic; }

  // Heuristic for sites we don't know: does this page look like a webmail inbox?
  function looksLikeWebmail() {
    if (KNOWN_HOSTS.test(location.hostname)) return true;
    const t = (document.title + ' ' + text($('nav, [role="navigation"], aside'))).toLowerCase();
    return /\binbox\b/.test(t) && !!$('[role="listbox"] [role="option"], [role="grid"] [role="row"], .email-row, [data-pg-row]');
  }

  // Hosts the extension is installed for by default (manifest content_scripts). Other sites are opt-in per site.
  root.PG_Providers = { pickAdapter, looksLikeWebmail, linksIn, hasForm, text, isCompose, KNOWN_HOSTS };
})(typeof globalThis !== 'undefined' ? globalThis : this);
