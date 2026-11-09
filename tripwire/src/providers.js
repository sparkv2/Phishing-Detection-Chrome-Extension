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
    opened: () => $$('div.a3s').filter((b) => b.offsetParent !== null && text(b).length > 0).map((body) => {
      const msg = body.closest('.adn, .gs') || body.parentElement;
      const s = msg ? $('span.gD[email], span[email].gD, h3 span[email]', msg) : null;
      return { body, anchor: body, senderName: s ? (s.getAttribute('name') || text(s)) : '', senderEmail: s ? s.getAttribute('email') : '',
        subject: text($('h2.hP')) };
    }),
    reportHelp: 'In Gmail, click the three dots (⋮) at the top-right of the email and choose "Report phishing".',
  };

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
    opened: () => $$('[data-test-id="message-view-body-content"]').map((body) => {
      const msg = body.closest('[data-test-id="message-view"]') || body.closest('article') || body.parentElement.parentElement;
      const from = $('[data-test-id="message-from"]', msg) || $('[data-test-id="email-pill"]', msg);
      let sender = { name: '', email: '' };
      if (from) {
        const t = (from.getAttribute('title') || '') + ' ' + text(from);
        sender = { name: text($('[data-test-id="email-pill-name"]', from)) || text(from).replace(EMAIL_RE, '').trim(), email: (t.match(EMAIL_RE) || [''])[0] };
      }
      if (!sender.email) sender = findSender(msg, body);
      return { body, anchor: body, senderName: sender.name, senderEmail: sender.email,
        subject: text($('[data-test-id="message-group-subject-text"]')) };
    }),
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
      const bodies = $$(BODY_SEL).filter((b) => !b.closest('[data-pg-ui]') && b.offsetParent !== null && text(b).length > 20);
      // Keep innermost bodies only (avoid analysing a wrapper and its child twice)
      const inner = bodies.filter((b) => !bodies.some((o) => o !== b && b.contains(o)));
      return inner.map((body) => {
        let scope = body.parentElement, sender = { name: '', email: '' };
        for (let i = 0; i < 6 && scope && !sender.email; i++, scope = scope.parentElement) sender = findSender(scope, body);
        const heading = $('[role="main"] [role="heading"], [class*="subject" i], h1, h2', body.closest('[role="main"]') || document);
        return { body, anchor: body, senderName: sender.name, senderEmail: sender.email, subject: text(heading) };
      });
    },
    reportHelp: 'Use your email provider\'s "Report phishing" or "Report junk" option (often under the three dots ⋯ menu). In Outlook: Report → Report phishing.',
  };
  const outlook = Object.assign({}, generic, {
    id: 'outlook', label: 'Outlook',
    match: () => /(^|\.)outlook\.(live|office|office365)\.com$/.test(location.hostname) || location.hostname === 'outlook.cloud.microsoft',
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

  root.PG_Providers = { pickAdapter, looksLikeWebmail, linksIn, hasForm, text };
})(typeof globalThis !== 'undefined' ? globalThis : this);
