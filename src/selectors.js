// Webmail layout rules: the CSS selectors each adapter uses to find inbox rows, opened emails, senders and so on.
// The built-in copy below ships with the extension (it must match data/selectors.json; the tests check). When a
// webmail site changes its layout, a fixed data/selectors.json is signed by GitHub Actions and delivered through the
// Tripwire server; the extension verifies the signature and uses the new rules without needing a new version.
// The rules are data only: CSS selectors, each validated before use, never code.
(function (root) {
  'use strict';

  const BUILTIN = {
    format: 1,
    version: 1,
    minExtension: '1.4.0',
    adapters: {
      gmail: {
        row: 'tr.zA',
        rowSender: 'span[email]',
        rowSubject: '.bog',
        rowSnippet: '.y2',
        body: 'div.a3s',
        message: '.adn, .gs',
        sender: 'span.gD[email], span[email].gD, h3 span[email]',
        subject: 'h2.hP',
        attachmentArea: '.aQH',
        attachmentDownload: '[download_url]',
        attachmentName: '.aV3, .aQA span[title]',
        threadRoot: '[role="list"], .nH.if',
        threadSender: 'span.gD[email], span.zF[email], span.yP[email], h3 span[email]',
        messageId: '[data-message-id], [data-legacy-message-id]',
      },
      yahoo: {
        row: '[data-test-id="message-list-item"]',
        rowSender: '[data-test-id="senders"] [title], [data-test-id="senders"]',
        rowSubject: '[data-test-id="message-subject"]',
        rowSnippet: '[data-test-id="snippet"]',
        body: '[data-test-id="message-view-body-content"]',
        message: '[data-test-id="message-view"], article',
        sender: '[data-test-id="message-from"], [data-test-id="email-pill"]',
        senderName: '[data-test-id="email-pill-name"]',
        subject: '[data-test-id="message-group-subject-text"]',
        attachmentArea: '[data-test-id*="attachment" i]',
      },
      generic: {
        row: '[role="listbox"] [role="option"], [role="grid"] [role="row"], [role="table"] [role="row"], [data-pg-row], .email-row, .message-list-item',
        rowSubject: '[class*="subject" i], [data-subject]',
        body: '[aria-label="Message body"], [aria-label*="message body" i], [role="document"], [data-pg-body], [class*="message-body" i], [class*="email-body" i], [class*="mail-body" i], [class*="messagebody" i]',
        subject: '[role="main"] [role="heading"], [class*="subject" i], h1, h2',
      },
      outlook: {},
    },
  };

  const MAX_LEN = 600; // a real selector is far shorter; anything longer is refused

  // Compares "1.4.0"-style versions: negative if a < b, 0 if equal, positive if a > b.
  const cmpVersion = (a, b) => {
    const pa = String(a || '0').split('.').map(Number), pb = String(b || '0').split('.').map(Number);
    for (let i = 0; i < 3; i++) { if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0); }
    return 0;
  };

  // Should an update (already signature-checked) replace the rules in use?
  // Returns { ok: true } or { ok: false, reason }.
  function acceptRules(rules, ctx) {
    ctx = ctx || {};
    if (!rules || rules.format !== 1 || typeof rules.adapters !== 'object' || !Number.isInteger(rules.version)) return { ok: false, reason: 'unknown format' };
    if (rules.version <= Math.max(BUILTIN.version, ctx.currentVersion || 0)) return { ok: false, reason: 'not newer than the rules in use' };
    if (ctx.extensionVersion && cmpVersion(ctx.extensionVersion, rules.minExtension) < 0) return { ok: false, reason: 'needs a newer extension' };
    return { ok: true };
  }

  // The selectors to try for adapter `id`, key `key`: the updated rule first (if any and valid), then the built-in.
  // `isValid(selector)` checks that a selector parses; unknown adapters/keys and non-strings are ignored.
  // Order of preference for Outlook (which has few rules of its own): updated Outlook rule, updated generic rule,
  // built-in Outlook rule, built-in generic rule. For every other adapter: updated rule, then built-in rule.
  function candidates(remote, id, key, isValid) {
    const out = [];
    const ra = (remote && remote.adapters) || {};
    // Accept a selector only if it is a non-empty, reasonably short string that parses, and isn't a duplicate.
    const add = (s) => { if (typeof s === 'string' && s.length <= MAX_LEN && s.trim() && (!isValid || isValid(s)) && !out.includes(s)) out.push(s); };
    const knownKey = (adapter) => !!BUILTIN.adapters[adapter] && key in BUILTIN.adapters[adapter]; // ignore keys we don't use
    if (ra[id] && (knownKey(id) || (id === 'outlook' && knownKey('generic')))) add(ra[id][key]);
    if (id === 'outlook' && ra.generic && knownKey('generic')) add(ra.generic[key]);
    add((BUILTIN.adapters[id] || {})[key]);
    if (id === 'outlook') add(BUILTIN.adapters.generic[key]);
    return out;
  }

  root.PG_Selectors = { BUILTIN, acceptRules, candidates, cmpVersion };
  if (typeof module === 'object' && module.exports) module.exports = root.PG_Selectors;
})(typeof globalThis !== 'undefined' ? globalThis : this);
