// =====================================================================================================================
// Tripwire detection engine (analyzer.js)
//
// Turns one email into a verdict: a 0-100 safety score, a level (safe / suspicious / phishing) and a list of
// plain-language reasons ("signals"). It is made of pure functions: no network, no storage, no page access. Everything
// it needs (the email's text, links, headers, history...) is passed in by the content script, which is what makes it
// easy to test in Node (see test/).
//
// How an email flows through it (see analyzeEmail at the bottom):
//   1. Sender      analyzeSender      who claims to be sending it, and does the address back that up?
//   2. Wording     analyzeContent     pressure, threats, requests for passwords or money...
//   3. Payments    paymentChange...   "our bank details changed" and account numbers
//   4. History     historySignals     first-time sender, look-alike of someone you know, changed bank details
//   5. Thread      threadSignals      a reply from a different / look-alike company mid-conversation
//   6. Links       analyzeLink        where each link and QR code really goes
//   7. Attachments analyzeAttachments disguised programs, web-page attachments, login forms
//   +  Raw message inspectRawMessage  header / signature / script tricks only visible in the raw email (Gmail)
//   8. Scoring     each group adds a capped penalty; red is for confirmed threats and for direct requests for
//                  passwords, personal details, or money from an unverified sender (findDirectRequests)
//
// Accuracy is measured with tools/eval-dataset.mjs against a folder of real emails (e.g. the EPVME dataset).
//
// Every signal looks like: { id, category, weight, title, explain, evidence, target }
//   weight  how much it lowers the score;  target  where the banner's "Show me" button points on the page.
// =====================================================================================================================
(function (root) {
  'use strict';
  const D = root.PG_DATA; // reference lists from src/data.js (brands, phrases, free-mail providers...)

  // ---------- small helpers ----------
  const lc = (s) => (s || '').toString().toLowerCase();
  const uniq = (arr) => [...new Set(arr)];
  const EMAIL_RE = /[a-z0-9._%+\-]+@[a-z0-9.\-\u00a1-\uffff]+\.[a-z\u00a1-\uffff]{2,}/i;

  // Characters from other alphabets that look identical to Latin letters (Cyrillic "\u0430" vs Latin "a"...).
  const CONFUSABLES = { 'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y', 'і': 'i', 'ӏ': 'l',
    'ԁ': 'd', 'ɡ': 'g', 'ո': 'n', 'ս': 'u', 'ѕ': 's', 'ј': 'j', 'һ': 'h', 'ԛ': 'q', 'ԝ': 'w', 'ı': 'i', 'ɩ': 'l' };

  // Undo common disguises so "paypa1", "rnicrosoft" and a Cyrillic-"а" "аpple" all compare equal to the real name.
  function mapConfusables(s) {
    let out = '';
    for (const ch of lc(s)) out += CONFUSABLES[ch] || ch;
    return out;
  }
  function normalizeHomoglyphs(s) {
    return mapConfusables(s).replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e').replace(/5/g, 's').replace(/\$/g, 's')
      .replace(/rn/g, 'm').replace(/vv/g, 'w');
  }

  // Scammers hide trigger words from filters with invisible characters ("pass​word"), and phones and mail apps
  // turn ' into ’. Both used to stop phrases like "I'm in a meeting" or "verify your account" from matching.
  const INVISIBLE_RE = /[­͏؜ᅟᅠ឴឵᠎​-‏‪-‮⁠-⁤⁦-⁯ㅤ﻿ﾠ]/g;
  function cleanText(s) {
    return (s || '').toString().replace(INVISIBLE_RE, '').replace(/[‘’‚‛′ʼ`´]/g, '\'')
      .replace(/[“”„‟″]/g, '"');
  }

  // Punycode (RFC 3492) so "xn--pple-43d.com" can be read as "аpple.com" and recognised as an Apple look-alike.
  function punyDecode(input) {
    const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
    const out = [];
    let i = 0, n = 128, bias = 72;
    const d = input.lastIndexOf('-');
    for (let j = 0; j < Math.max(d, 0); j++) out.push(input.charCodeAt(j));
    for (let idx = d > 0 ? d + 1 : 0; idx < input.length;) {
      const oldi = i;
      for (let w = 1, k = base; ; k += base) {
        if (idx >= input.length) return null;
        const c = input.charCodeAt(idx++);
        const digit = c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base;
        if (digit >= base) return null;
        i += digit * w;
        const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
        if (digit < t) break;
        w *= base - t;
      }
      const len = out.length + 1;
      let delta = oldi === 0 ? Math.floor((i - oldi) / damp) : (i - oldi) >> 1;
      delta += Math.floor(delta / len);
      let k = 0;
      for (; delta > ((base - tMin) * tMax) >> 1; k += base) delta = Math.floor(delta / (base - tMin));
      bias = Math.floor(k + ((base - tMin + 1) * delta) / (delta + skew));
      n += Math.floor(i / len);
      i %= len;
      out.splice(i++, 0, n);
    }
    return String.fromCodePoint(...out);
  }
  function toUnicodeHost(host) {
    if (!host || !host.includes('xn--')) return host;
    return host.split('.').map((p) => (p.startsWith('xn--') ? punyDecode(p.slice(4)) || p : p)).join('.');
  }

  // ---------- domain helpers ----------
  // The "registrable domain" is the part someone actually buys: mail.paypal.com -> paypal.com, x.evil.co.uk -> evil.co.uk.
  // Comparing these (not full hosts) is what tells "a PayPal server" apart from "a server that mentions PayPal".
  function registrableDomain(host) {
    host = lc(host).replace(/\.$/, '');
    if (!host || isIP(host)) return host;
    const parts = host.split('.');
    if (parts.length <= 2) return host;
    const last2 = parts.slice(-2).join('.');
    if (D.MULTI_SUFFIXES.includes(last2)) return parts.slice(-3).join('.');
    return last2;
  }
  function domainLabel(regDomain) { // "paypal.co.uk" -> "paypal"
    const parts = regDomain.split('.');
    const last2 = parts.slice(-2).join('.');
    return D.MULTI_SUFFIXES.includes(last2) ? parts.slice(0, -2).join('.') : parts.slice(0, -1).join('.');
  }
  function tld(host) { const p = lc(host).split('.'); return p[p.length - 1]; }
  // A shared mailbox service (gmail.com, icloud.com, Apple's privaterelay.appleid.com relay...): each address
  // belongs to a different person, so the domain says nothing about who sent the email.
  function isSharedMail(host) { host = lc(host); return D.FREE_MAIL.includes(host) || D.FREE_MAIL.includes(registrableDomain(host)); }
  // IPv4 (1.2.3.4) or IPv6 ([2001:db8::1]) literal instead of a name.
  function isIP(host) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || (/^\[?[0-9a-f:]+\]?$/i.test(host) && host.includes(':')); }
  // Is `host` one of `domains`, or a subdomain of one? (mail.paypal.com matches paypal.com; paypal.com.evil.ru doesn't.)
  function domainMatches(host, domains) {
    host = lc(host);
    return domains.some((d) => host === d || host.endsWith('.' + d));
  }
  // Edit distance (with swaps counted as one edit). Returns 99 early when lengths differ too much to be a typo.
  function levenshtein(a, b) {
    if (Math.abs(a.length - b.length) > 2) return 99;
    const dp = Array.from({ length: a.length + 1 }, (_, i) => [i]);
    for (let j = 1; j <= b.length; j++) dp[0][j] = j;
    for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++) {
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) dp[i][j] = Math.min(dp[i][j], dp[i - 2][j - 2] + 1);
    }
    return dp[a.length][b.length];
  }
  // Regex for a whole word (so "ups" doesn't match inside "groups").
  function wordRe(word) { return new RegExp('(^|[^a-z0-9])' + word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '($|[^a-z0-9])', 'i'); }

  // Does free text name this brand? 3-letter names (UPS, IRS, DHL, AWS) used to be skipped entirely to avoid
  // matching ordinary words, which hid parcel-fee and tax-refund scams. They now count when written in capitals.
  function mentionsBrand(b, rawText) {
    return b.keywords.some((k) => (k.length >= 4 ? wordRe(k).test(rawText)
      : new RegExp('(^|[^A-Za-z0-9])' + k.toUpperCase() + '($|[^A-Za-z0-9])').test(rawText)));
  }

  // ---------- brand look-alikes ----------
  function brandLabels(brand) { return uniq(brand.domains.map((d) => domainLabel(d)).filter((l) => l.length >= 3)); }
  function brandOfDomain(host) { return D.BRANDS.find((b) => domainMatches(host, b.domains)) || null; }

  // Brand names that are also everyday words ("apple", "chase", "office"): these only count as a fake brand domain
  // when combined with phishing words, so apple-pie-recipes.com isn't flagged as fake Apple.
  const GENERIC_LABELS = new Set(['office', 'outlook', 'live', 'square', 'squareup', 'cash', 'steam', 'zoom', 'chase',
    'citi', 'meta', 'apple', 'prime', 'drive', 'wells', 'capital']);

  // Does `host` look like an imitation of a known brand? Returns { brand, kind } or null. The checks run from most
  // to least certain; `kind` picks the explanation shown to the user (LOOKALIKE_TEXT) and the weight.
  function lookalikeBrand(host) {
    host = lc(toUnicodeHost(lc(host))); // links arrive as punycode; judge the characters the reader actually sees
    if (!host || isIP(host) || brandOfDomain(host)) return null;
    const reg = registrableDomain(host);
    const label = domainLabel(reg);
    const normLabel = normalizeHomoglyphs(label);
    const hostTokens = host.split(/[.\-_]+/);
    for (const brand of D.BRANDS) {
      for (const bl of brandLabels(brand)) {
        // Brand names that are also ordinary words only count when combined with phishing words.
        const generic = GENERIC_LABELS.has(bl);
        if (normLabel === bl && label !== bl) return { brand, kind: 'homoglyph' }; // paypa1, rnicrosoft, аpple (Cyrillic)
        if (label === bl && !generic) return { brand, kind: 'wrong-tld' }; // paypal.support
        const tokens = normLabel.split(/[-_]+/);
        if (tokens.length > 1 && tokens.includes(bl) && tokens.some((t) => t !== bl && D.PHISH_DOMAIN_WORDS.includes(t))) return { brand, kind: 'combo' };
        if (bl.length >= 5) {
          for (const w of D.PHISH_DOMAIN_WORDS) {
            if (normLabel === bl + w || normLabel === w + bl) return { brand, kind: 'combo' };
          }
        }
        if (!generic && ((bl.length >= 6 && levenshtein(normLabel, bl) === 1) || (bl.length >= 9 && levenshtein(normLabel, bl) === 2))) {
          return { brand, kind: 'typo' };
        }
        // Brand's real domain used as a subdomain of something else: paypal.com.account-check.ru
        if (brand.domains.some((d) => host.startsWith(d + '.') || host.includes('.' + d + '.'))) return { brand, kind: 'subdomain' };
        if (!generic && hostTokens.length > 2 && hostTokens.slice(0, -2).map(normalizeHomoglyphs).includes(bl)) return { brand, kind: 'subdomain' };
      }
    }
    return null;
  }
  const LOOKALIKE_WEIGHT = { homoglyph: 45, combo: 40, typo: 40, subdomain: 40, 'wrong-tld': 35 };
  function lookalikeWeight(look, host) {
    if (look.kind === 'wrong-tld' && tld(host).length === 2) return 20; // e.g. amazon.es may be a real regional site
    return LOOKALIKE_WEIGHT[look.kind];
  }

  const LOOKALIKE_TEXT = {
    'wrong-tld': (b, h) => `"${h}" uses ${b.name}'s name but is not one of ${b.name}'s real web addresses.`,
    homoglyph: (b, h) => `"${h}" is made to look like ${b.name}, using look-alike characters (for example "1" instead of "l", or "0" instead of "o").`,
    combo: (b, h) => `"${h}" glues ${b.name}'s name to other words. ${b.name} does not use this address; scammers create these to look official.`,
    typo: (b, h) => `"${h}" is a misspelling of ${b.name}. Scammers register near-identical names hoping you won't notice.`,
    subdomain: (b, h) => `"${h}" puts "${b.name}" at the start of the address, but the part that really matters (the end) belongs to someone else.`,
  };

  // ---------- look-alikes of the company the email names ----------
  // The brand list can't hold every company. So also compare the sender's domain with the company the email itself
  // claims to be: its display name ("Menards", "The Home Depot") and capitalised names in the subject and text.
  // A domain that is a near-miss spelling of that name (menrds.com, homedep0t.com) is an impersonation.
  // Only near-misses count; a domain that contains the full name (menards-email.com) is not flagged here.
  const NAME_FILLER = new Set(['the', 'inc', 'llc', 'ltd', 'co', 'corp', 'company', 'store', 'stores', 'shop', 'official',
    'do', 'not', 'from', 'your', 'via', 'and', 'of']);
  function nameClaims(name, email) {
    const words = (name || '').replace(/[^\p{L}\p{N}\s'&.-]/gu, ' ').split(/[\s.&'-]+/).filter(Boolean);
    const kept = words.filter((w) => !NAME_FILLER.has(lc(w)) && !D.SERVICE_WORDS.includes(lc(w)));
    if (!kept.length) return [];
    // A person's name ("Jon Smith" <jon@johnsmith.com>): their own domain may be spelled any way they like.
    const local = lc((email || '').split('@')[0]);
    const personLike = kept.length >= 2 && kept.length <= 3 && kept.every((w) => /^\p{Lu}\p{Ll}+$/u.test(w));
    if (personLike && kept.some((w) => w.length >= 3 && local.includes(lc(w)))) return [];
    const joined = lc(kept.join(''));
    return joined.length >= 5 ? [joined] : [];
  }
  // Capitalised words and word pairs in the text, as { claim: 'homedepot', display: 'Home Depot' }.
  function textClaims(text) {
    const out = new Map();
    const words = (text || '').slice(0, 3000).match(/\b\p{Lu}[\p{L}'’]+\b/gu) || [];
    const key = (w) => lc(w).replace(/['’]/g, '');
    for (let i = 0; i < words.length; i++) {
      const w = key(words[i]);
      if (w.length >= 6 && !out.has(w)) out.set(w, words[i]);
      if (i + 1 < words.length) { const pair = w + key(words[i + 1]); if (pair.length >= 7 && !out.has(pair)) out.set(pair, words[i] + ' ' + words[i + 1]); }
    }
    return [...out].map(([claim, display]) => ({ claim, display }));
  }
  // Returns { claim, kind: 'homoglyph'|'typo', from: 'name'|'text' } when the sender's domain imitates a name the
  // email uses, otherwise null.
  function nameLookalike(sender, subject, body) {
    const domain = lc(sender.domain);
    if (!domain || isIP(domain) || brandOfDomain(domain)) return null;
    const reg = registrableDomain(domain);
    if (isSharedMail(domain)) return null;
    const label = domainLabel(reg).replace(/[-_]/g, '');
    const norm = normalizeHomoglyphs(label);
    if (label.length < 4) return null;
    const text = (subject || '') + '\n' + (body || '');
    // If the email also spells the domain's own name correctly, the domain is probably just this company's name.
    if (wordRe(label).test(text)) return null;
    const near = (claim, minLen) => {
      if (claim.length < minLen || claim === label) return null;
      if (norm === claim) return 'homoglyph';
      const d = levenshtein(norm, claim);
      if (d === 1 || (d === 2 && claim.length >= 9)) return 'typo';
      return null;
    };
    for (const claim of nameClaims(sender.name, sender.email)) { const k = near(claim, 5); if (k) return { claim, kind: k, from: 'name' }; }
    for (const { claim, display } of textClaims(text)) { const k = near(claim, 6); if (k) return { claim: display, kind: k, from: 'text' }; }
    return null;
  }

  // The softer case: the domain *contains* the company's full name plus something else (menards-deals.com,
  // menardsmail.com). Real companies sometimes send from domains like this, and so do scammers, so Tripwire can't
  // tell. Returns { claim, display } for a yellow "not sure this is the official address", otherwise null.
  const GENERIC_SENDER_WORDS = new Set(['refunds', 'orders', 'order', 'news', 'deals', 'rewards', 'shipping', 'payroll',
    'invoice', 'invoices', 'receipts', 'receipt', 'updates', 'newsletter', 'marketing', 'sales', 'events', 'store',
    'shop', 'offers', 'members', 'membership', 'tickets', 'travel', 'jobs', 'careers', 'hello', 'contact']);
  function unsureCompanyDomain(sender, subject, body) {
    const domain = lc(sender.domain);
    if (!domain || isIP(domain) || brandOfDomain(domain)) return null;
    const reg = registrableDomain(domain);
    if (isSharedMail(domain)) return null;
    const label = normalizeHomoglyphs(domainLabel(reg).replace(/[-_]/g, ''));
    const fromName = nameClaims(sender.name, sender.email);
    const fromText = textClaims((subject || '') + '\n' + (body || ''));
    // The domain is exactly a name the email uses (tractorsupply.com and "Tractor Supply"): it's that company's own.
    if (fromName.includes(label) || fromText.some((t) => t.claim === label)) return null;
    // Ordinary words ("Refunds" <refunds@gov-refunds.example>, "Orders") are not company names.
    const ordinary = (claim) => D.PHISH_DOMAIN_WORDS.includes(claim) || D.PHISH_DOMAIN_WORDS.includes(claim.replace(/s$/, '')) || GENERIC_SENDER_WORDS.has(claim);
    const contains = (claim) => claim.length >= 5 && label.includes(claim) && !ordinary(claim);
    for (const claim of fromName) if (contains(claim)) return { claim, display: sender.name.trim() };
    for (const t of fromText) if (t.claim.length >= 6 && contains(t.claim)) return t;
    return null;
  }

  // ---------- URLs ----------
  // Relative links resolve against a dummy base; a result on "invalid.local" therefore means "not a real web link".
  function parseUrl(href) {
    try { return new URL(href, 'https://invalid.local/'); } catch (e) { return null; }
  }

  // Proofpoint URL Defense (used by many workplaces) rewrites every link. Without decoding it, every link in a
  // protected mailbox looked like a harmless urldefense.com link and was never checked.
  function proofpointInner(u) {
    try {
      if (/^\/v1\//.test(u.pathname)) return u.searchParams.get('u');
      if (/^\/v2\//.test(u.pathname)) {
        const enc = u.searchParams.get('u');
        return enc ? decodeURIComponent(enc.replace(/-/g, '%').replace(/_/g, '/')) : null;
      }
      const m = u.href.match(/\/v3\/__(.+?)__;([^!]*)/);
      if (!m) return null;
      // v3 replaces some characters with "*" and keeps them, base64url-encoded, after "__;".
      let fill = '';
      try { fill = atob(m[2].replace(/-/g, '+').replace(/_/g, '/')); } catch (e) { /* none */ }
      let k = 0;
      return m[1].replace(/\*/g, () => fill[k++] || '');
    } catch (e) { return null; }
  }

  // Unwrap well-known redirect wrappers (Google, Outlook Safe Links, Facebook, Reddit) so we judge the real
  // destination, not the wrapper. Up to 3 layers, since wrappers can be nested.
  function unwrapUrl(href) {
    let u = parseUrl(href);
    for (let i = 0; u && i < 3; i++) {
      const h = lc(u.hostname);
      let inner = null;
      if ((h === 'www.google.com' || h === 'google.com') && u.pathname === '/url') inner = u.searchParams.get('q') || u.searchParams.get('url');
      else if (h.endsWith('safelinks.protection.outlook.com')) inner = u.searchParams.get('url');
      else if (h === 'l.facebook.com' || h === 'lm.facebook.com') inner = u.searchParams.get('u');
      else if (h === 'out.reddit.com') inner = u.searchParams.get('url');
      else if (h === 'l.instagram.com') inner = u.searchParams.get('u');
      else if ((h === 'www.youtube.com' || h === 'youtube.com') && u.pathname === '/redirect') inner = u.searchParams.get('q');
      else if (/(^|\.)linkedin\.com$/.test(h) && /^\/redir\/redirect/.test(u.pathname)) inner = u.searchParams.get('url');
      else if (h === 'urldefense.com' || h === 'urldefense.proofpoint.com') inner = proofpointInner(u);
      if (!inner) break;
      const next = parseUrl(inner);
      if (!next || next.hostname === 'invalid.local') break;
      u = next;
    }
    return u;
  }

  // Builds one signal (a reason shown in the banner). See the file header for the fields.
  // target: where "Show me" points ({ type: 'sender'|'link'|'text'|'attachment'|'image'|'form'|'subject', ... }).
  function sig(id, category, weight, title, explain, evidence, target) {
    const s = { id, category, weight, title, explain, evidence: evidence || '' };
    if (target) s.target = target;
    return s;
  }

  // ---------- one URL ----------
  // Judges a single URL on its own (no link text). Returns { href, host, regDomain, finalHref, weight, signals, known }.
  // `known` means it is on a threat list, which makes the whole email red.
  function analyzeUrl(href, lists) {
    lists = lists || {};
    const raw = (href || '').trim();
    const out = { href: raw, host: '', regDomain: '', weight: 0, signals: [], known: false };
    // Links that aren't web pages at all: running code, or a whole page packed into the link.
    if (/^\s*javascript:/i.test(raw)) {
      out.signals.push(sig('js-link', 'link', 40, 'Link runs hidden code', 'This link doesn\'t open a web page — it runs code. Real emails never need this.', raw.slice(0, 60)));
    } else if (/^\s*data:/i.test(raw)) {
      out.signals.push(sig('data-link', 'link', 40, 'Link hides a whole page inside itself', 'This link contains an entire web page packed into the link, a trick used to show fake login forms.', 'data: link'));
    }
    if (out.signals.length) { out.weight = 40; return out; }

    const u = unwrapUrl(raw);
    if (!u || !/^https?:$/.test(u.protocol) || u.hostname === 'invalid.local') return out; // mailto:, #anchor, etc.
    const host = lc(u.hostname);
    const reg = registrableDomain(host);
    out.host = host; out.regDomain = reg; out.finalHref = u.href;

    // 1) Is it on a list? Community reports only warn (yellow); curated threat lists confirm (red).
    const threat = knownThreat(host, lists, u);
    if (threat && threat.cat === 'community') {
      // Reported by several Tripwire users, but not confirmed by a curated list: a strong warning, never "red".
      out.signals.push(sig('community-link', 'link', 35, 'Link goes to a site other Tripwire users reported',
        `"${host}" was reported as phishing by at least ${threat.threshold || 3} different Tripwire users. It isn't on a confirmed list yet, so treat it as dangerous but unconfirmed.`, host));
    } else if (threat) {
      out.known = true;
      out.threat = threat;
      out.signals.push(threatSignal('known-bad-link', 'link', threat, threat.byUrl ? (threat.matched || host) : host));
    }
    // 2) Tricks visible in the address itself, each with its own weight.
    if (isIP(host)) out.signals.push(sig('ip-link', 'link', 30, 'Link uses a number instead of a name',
      'The link goes to a raw number address (like 192.168.1.1) instead of a company website name. Legitimate companies almost never do this.', host));
    if (host.includes('xn--')) out.signals.push(sig('punycode-link', 'link', 25, 'Link uses disguised characters',
      'This web address contains special foreign characters that can make a fake site look like a real one.', host));
    const look = lookalikeBrand(host);
    if (look) out.signals.push(sig('lookalike-link', 'link', lookalikeWeight(look, host), `Fake ${look.brand.name} website`, LOOKALIKE_TEXT[look.kind](look.brand, host), host));
    if (u.username || u.password || /^https?:\/\/[^/]*@/i.test(raw)) out.signals.push(sig('at-link', 'link', 30, 'Link hides its real destination',
      'This link contains an "@" sign. Everything before the "@" is ignored by your browser, so the real destination is hidden at the end.', host));
    if (D.SUSPICIOUS_TLDS.includes(tld(host))) out.signals.push(sig('tld-link', 'link', 10, 'Unusual web address ending',
      `Addresses ending in ".${tld(host)}" are cheap to register and are often used for scams.`, host));
    if (D.SHORTENERS.includes(host) || D.SHORTENERS.includes(reg)) out.signals.push(sig('short-link', 'link', 10, 'Shortened link hides the destination',
      'This is a shortened link, so you can\'t see where it really goes until you click.', host));
    if (u.protocol === 'http:') out.signals.push(sig('http-link', 'link', 5, 'Link is not secure (no https)',
      'The link doesn\'t use a secure connection. Never type passwords or card numbers on such pages.', host));
    if (u.port && !['80', '443'].includes(u.port)) out.signals.push(sig('port-link', 'link', 10, 'Link uses an unusual port',
      'The link points to an unusual "door" on the server, which is uncommon for normal websites.', host + ':' + u.port));
    if (host.split('.').length > 5) out.signals.push(sig('deep-link', 'link', 8, 'Very long, layered web address',
      'This address has many parts stacked together, which is often done to bury the real site name.', host));

    out.weight = out.signals.reduce((s, x) => s + x.weight, 0);
    return out;
  }

  // Is this host (or exact URL) on a threat list? Returns { cat, source, label, matched } or null.
  // Checked in order: the user's own reports, the small built-in list, then the answers the content script got from
  // the background worker's big index (lists.threats: host or 'url:'+key -> hit, or null when it is clean).
  function knownThreat(host, lists, u) {
    host = lc(host);
    const reg = registrableDomain(host);
    if (lists.blocked && (lists.blocked.has(host) || lists.blocked.has(reg))) return { cat: 'reported', source: 'your reports' };
    if (D.BUILTIN_BLOCKLIST.includes(host) || D.BUILTIN_BLOCKLIST.includes(reg)) return { cat: 'phishing', source: 'Tripwire built-in list' };
    const t = lists.threats;
    if (t) {
      // Exact-URL matches first: on shared hosts (Google Sites, GitHub...) only the listed page is bad, not the host.
      if (u && root.PG_Intel) for (const k of root.PG_Intel.urlKeys(u)) { const hit = t.get('url:' + k); if (hit) return Object.assign({ byUrl: true }, hit); }
      const hit = t.get(host);
      if (hit) return hit;
    }
    return null;
  }

  // Wording for list matches, per threat category and per "where it was found" (a link or the sender).
  const THREAT_TEXT = {
    phishing: { link: 'Link goes to a known phishing site', sender: 'Sender is on a phishing blocklist',
      explain: (x, src) => `"${x}" is on a list of confirmed phishing websites${src}. These pages are built to steal passwords and card details. Do not open it.` },
    malware: { link: 'Link goes to a known malware site', sender: 'Sender\'s domain is known for spreading malware',
      explain: (x, src) => `"${x}" is known for spreading harmful software such as viruses or ransomware${src}. Opening it could infect your computer.` },
    c2: { link: 'Link goes to a hacker-controlled server', sender: 'Sender\'s domain is a known hacker-controlled server',
      explain: (x, src, label) => `"${x}" is a known command-and-control server${label}: a computer criminals use to remotely control hacked machines${src}. There is no safe reason to visit it.` },
    reported: { link: 'Link goes to a site you reported', sender: 'You reported this sender',
      explain: (x) => `You previously reported "${x}" as phishing on this computer.` },
  };
  function threatSignal(id, kind, hit, subject) {
    const t = THREAT_TEXT[hit.cat] || THREAT_TEXT.phishing;
    const src = hit.source && hit.cat !== 'reported' ? ` (source: ${hit.source})` : '';
    const label = hit.label ? ` (${hit.label})` : '';
    const s = sig(id, 'known', 100, t[kind], t.explain(subject, src, label), hit.matched && hit.matched !== subject ? `${subject} — listed as ${hit.matched}` : subject);
    s.threatCategory = hit.cat;
    return s;
  }

  // Extract a domain-looking string from visible link text ("www.paypal.com", "https://paypal.com/login").
  function domainInText(text) {
    const t = lc(text).trim();
    const m = t.match(/(?:https?:\/\/)?((?:[a-z0-9\-]+\.)+[a-z]{2,})(?:[\/:?#]\S*)?/i);
    if (!m) return null;
    if (t.length > m[0].length + 40) return null; // a sentence that merely contains a domain
    const host = m[1].replace(/^www\./, '');
    if (!/\.[a-z]{2,}$/.test(host) || /\.(png|jpg|gif|pdf|docx?)$/.test(host)) return null;
    return host;
  }

  // ---------- one link (URL + the text shown for it) ----------
  // Adds the checks that need the visible text: "the link says chase.com but goes to evil.example", or a button
  // saying "Log in to PayPal" that doesn't go to PayPal. ctx.senderBrand avoids flagging a brand's own links.
  function analyzeLink(link, lists, ctx) {
    // A shortened link the background worker already followed is judged by where it really ends up.
    const expandedTo = lists && lists.expanded && lists.expanded.get((link.href || '').trim());
    const res = analyzeUrl(expandedTo || link.href, lists);
    if (expandedTo) {
      res.href = (link.href || '').trim();
      res.expandedFrom = res.href;
      res.signals.push(sig('short-link-expanded', 'link', 5, 'Shortened link (checked)',
        `This shortened link was followed for you: it really goes to "${res.host || expandedTo}".`, res.host || expandedTo));
      res.weight += 5;
    }
    const text = cleanText(link.text).trim();
    if (!res.host) return res;
    const shown = domainInText(text);
    // Newsletters route links through click-tracking services; that alone isn't a lie about the destination.
    const tracking = domainMatches(res.host, D.TRACKING_DOMAINS);
    if (shown && registrableDomain(shown) !== res.regDomain && !tracking) {
      const sameBrand = brandOfDomain(shown) && brandOfDomain(shown) === brandOfDomain(res.host);
      if (!sameBrand) {
        res.signals.push(sig('mismatch-link', 'link', 35, 'Link text lies about where it goes',
          `The link says "${shown}" but actually takes you to "${res.host}". This is one of the most common phishing tricks.`, `${shown} → ${res.host}`));
        res.weight += 35;
      }
    } else if (!shown && text) {
      // Text names a brand ("Log in to PayPal") but the link goes elsewhere.
      for (const b of D.BRANDS) {
        if (mentionsBrand(b, text) && !domainMatches(res.host, b.domains) && !tracking
          && !(ctx && ctx.senderBrand === b)) {
          if (/(log ?in|sign ?in|verify|confirm|account|update|secure|password|pay)/i.test(text)) {
            res.signals.push(sig('brand-text-link', 'link', 20, `Link mentions ${b.name} but goes elsewhere`,
              `The button says "${text.slice(0, 50)}", but it leads to "${res.host}", which is not a ${b.name} website.`, `${text.slice(0, 40)} → ${res.host}`));
            res.weight += 20;
          }
          break;
        }
      }
    }
    return res;
  }

  // ---------- email authentication (SPF / DKIM / DMARC) ----------
  // Parses raw message headers (or just Authentication-Results lines) into { spf, dkim, dmarc, dkimDomains, fromDomain }.
  // Only the first (top-most) Authentication-Results header counts: it was added by the user's own mail provider.
  // Lower headers could have been written by the sender and are ignored.
  function parseAuthResults(headers) {
    const text = (headers || '').toString();
    const head = text.split(/\r?\n\r?\n/)[0].replace(/\r?\n[ \t]+/g, ' '); // header block only, unfolded
    const line = head.split(/\r?\n/).find((l) => /^authentication-results:/i.test(l));
    if (!line) return null;
    let v = line.replace(/^authentication-results:\s*/i, '');
    // Text in (parentheses) is a comment, and parts of it come from the sender: Gmail copies an upstream ARC seal's
    // claims in as "arc=pass (... dmarc=pass ...)", and anyone can run an ARC sealer. Reading those made a forged
    // PayPal email with dmarc=fail count as proven. Drop comments (they can nest) before reading any result.
    for (let prev = ''; prev !== v;) { prev = v; v = v.replace(/\([^()]*\)/g, ' '); }
    const res = (method) => { const m = v.match(new RegExp('\\b' + method + '\\s*=\\s*([a-z]+)', 'i')); return m ? lc(m[1]) : ''; };
    const dkimDomains = [];
    for (const m of v.matchAll(/\bdkim\s*=\s*pass\b[^;]*?header\.(?:i|d)\s*=\s*@?([a-z0-9.\-]+)/gi)) dkimDomains.push(lc(m[1]));
    const from = v.match(/header\.from\s*=\s*([a-z0-9.\-]+)/i);
    const spfFrom = v.match(/smtp\.mailfrom\s*=\s*(?:[^@;\s]*@)?([a-z0-9.\-]+)/i);
    return { spf: res('spf'), dkim: res('dkim'), dmarc: res('dmarc'), dkimDomains: uniq(dkimDomains),
      fromDomain: from ? lc(from[1]) : '', spfDomain: spfFrom ? lc(spfFrom[1]) : '', source: 'headers' };
  }

  // 'pass' (the From address is proven), 'fail' (it is probably forged) or 'unknown'.
  function authVerdict(auth, senderDomain) {
    if (!auth) return 'unknown';
    const reg = registrableDomain(senderDomain || '');
    if (auth.dmarc === 'pass') return 'pass';
    if (auth.dmarc === 'fail') return 'fail';
    const aligned = (auth.dkimDomains || []).some((d) => registrableDomain(d) === reg);
    if (auth.dkim === 'pass' && aligned) return 'pass';
    if (['fail', 'softfail'].includes(auth.spf) && auth.dkim !== 'pass') return 'fail';
    if (auth.dkim === 'fail' && auth.spf !== 'pass') return 'fail';
    return 'unknown';
  }

  // ---------- the raw message (Gmail's "Show original") ----------
  // Some attacks only show in the raw email, not in what the mail page displays. Measured on the EPVME dataset of
  // ~49k malicious emails (see tools/eval-dataset.mjs), these structural tricks are common there and essentially
  // absent from ordinary mail, so each is a strong sign on its own.

  // base64 / quoted-printable -> text, working the same in browsers and Node.
  function decodeTransfer(raw, encoding, charset) {
    let bytes;
    try {
      if (/base64/i.test(encoding)) {
        // Mail apps tolerate bad padding ("...YQ==="), and attackers use it; atob doesn't, so re-pad first.
        const b = raw.replace(/[^A-Za-z0-9+/]/g, '');
        bytes = Uint8Array.from(atob(b + '='.repeat((4 - (b.length % 4)) % 4)), (c) => c.charCodeAt(0));
      }
      else if (/quoted-printable/i.test(encoding)) {
        const s = raw.replace(/=\r?\n/g, '').replace(/=([0-9a-f]{2})/gi, (m, h) => String.fromCharCode(parseInt(h, 16)));
        bytes = Uint8Array.from(s, (c) => c.charCodeAt(0) & 0xff);
      } else return raw;
      return new TextDecoder(/utf-?8/i.test(charset || '') ? 'utf-8' : 'latin1').decode(bytes);
    } catch (e) { return raw; }
  }
  // RFC 2047 encoded words in headers: =?utf-8?B?...?= / =?iso-8859-1?Q?...?=
  function decodeWords(s) {
    return (s || '').replace(/=\?([^?]+)\?([bq])\?([^?]*)\?=/gi, (_, cs, enc, txt) =>
      decodeTransfer(enc.toLowerCase() === 'b' ? txt : txt.replace(/_/g, ' '), enc.toLowerCase() === 'b' ? 'base64' : 'quoted-printable', cs));
  }
  function headerLines(block) { // [{ name, value, indented }], folded lines joined
    const out = [];
    for (const line of block.split(/\r?\n/)) {
      if (/^[ \t]/.test(line) && out.length && !/^\s+[\w-]+:/.test(line)) { out[out.length - 1].value += ' ' + line.trim(); continue; }
      const m = line.trim().match(/^([\w-]+):\s?(.*)$/);
      if (m) out.push({ name: m[1].toLowerCase(), value: m[2], indented: /^[ \t]/.test(line) });
    }
    return out;
  }
  const mparam = (v, name) => { const m = (v || '').match(new RegExp(name + '\\s*=\\s*"?([^";]+)"?', 'i')); return m ? m[1].trim() : ''; };

  // Splits a MIME message into its parts. Returns:
  //   { headers, type, parts: [{ type, headers, body (decoded), rawBody, parentType }], containers, preamble }
  // `containers` lists every nested multipart ({ type, disposition, depth }); `preamble` is any text before the first
  // part of the top-level multipart (normally just a stock sentence).
  function parseMime(raw, depth, containers) {
    depth = depth || 0;
    containers = containers || [];
    const sep = raw.search(/\r?\n\r?\n/);
    const headers = headerLines(sep < 0 ? raw : raw.slice(0, sep));
    const body = sep < 0 ? '' : raw.slice(sep).replace(/^\r?\n\r?\n/, '');
    const get = (n) => (headers.find((h) => h.name === n) || {}).value || '';
    const type = get('content-type') || 'text/plain';
    const boundary = /^\s*multipart\//i.test(type) && mparam(type, 'boundary');
    if (!boundary || depth > 6) {
      return { headers, type, containers, parts: [{ type, headers, body: decodeTransfer(body, get('content-transfer-encoding'), mparam(type, 'charset')), rawBody: body }], preamble: '' };
    }
    if (depth > 0) containers.push({ type, disposition: get('content-disposition'), depth });
    const chunks = body.split('--' + boundary);
    const parts = [];
    for (const c of chunks.slice(1)) {
      if (c.startsWith('--')) break; // closing boundary
      const sub = parseMime(c.replace(/^\r?\n/, ''), depth + 1, containers);
      parts.push(...sub.parts.map((p) => Object.assign(p, { parentType: p.parentType || type })));
    }
    return { headers, type, containers, parts, preamble: chunks[0] };
  }

  const ADDRESS_MARKUP = /<\s*(script|img|svg|iframe|body|style|a\s|div|object|embed|link|meta|input|form)\b|\bon[a-z]+\s*=|javascript:/i;
  const SUBJECT_MARKUP = /<\s*(script|iframe|object|embed|svg)\b|<[^>]*\bon[a-z]+\s*=|javascript:/i;

  // Finds the structural tricks in a raw message. Returns flags for rawMessageSignals().
  function inspectRawMessage(raw) {
    if (!raw) return null;
    const mime = parseMime(String(raw).slice(0, 2000000));
    const hs = mime.headers;
    const froms = hs.filter((h) => h.name === 'from');
    const out = {};
    // Two or more From lines (counting an indented one injected above the real header).
    out.multipleFrom = froms.length > 1;
    // A whole address hidden inside an encoded word (names are encoded normally; addresses never need to be).
    for (const f of froms) for (const m of f.value.matchAll(/=\?[^?]+\?[bq]\?[^?]*\?=/gi)) if (/@/.test(decodeWords(m[0]))) out.encodedAddress = decodeWords(m[0]).trim().slice(0, 80);
    // HTML tags, event handlers or javascript: inside address headers (never legitimate there), or clearly malicious
    // markup in the Subject (a plain tag name can appear when people discuss HTML: "Re: <div> tags in Gmail").
    out.headerMarkup = hs.some((h) => (['from', 'to', 'cc', 'reply-to', 'sender'].includes(h.name) && ADDRESS_MARKUP.test(decodeWords(h.value)))
      || (h.name === 'subject' && SUBJECT_MARKUP.test(decodeWords(h.value))));
    // Scripts in the email's HTML (mail clients strip them, but they are never there by accident).
    out.script = mime.parts.some((p) => /html/i.test(p.type) && /<script\b|\bon(error|load|click|mouseover|mouseenter|focus)\s*=|href\s*=\s*["']?\s*javascript:/i.test(p.body));
    // Signed email with a tampered signature: missing, or far too short to hold a real certificate and signature
    // (genuine S/MIME signatures are thousands of characters), or with unsigned text placed before the signed part.
    if (/^\s*multipart\/signed/i.test(mime.type)) {
      const sigPart = mime.parts.find((p) => /pkcs7-signature/i.test(p.type));
      const pgp = /pgp-signature/i.test(mime.type);
      const sigLen = sigPart ? (sigPart.rawBody || '').replace(/\s+/g, '').length : 0;
      out.brokenSignature = !pgp && sigLen < 400;
      // Mail programs write stock notes here ("This is a multi-part message...", "It has been signed conforming to
      // RFC2015. You'll need PGP or GPG to check the signature."), so those sentences don't count.
      const pre = (mime.preamble || '')
        .replace(/this is (an s\/mime signed|a multi-?part|an openpgp\/mime signed) message[^\n]*/gi, '')
        .replace(/[^\n.]*(signed conforming to rfc|(pgp|gpg) or (pgp|gpg)|check the signature|signature (below|attached))[^\n]*/gi, '')
        .trim();
      out.unsignedPreamble = pre.length > 40;
    }
    // A signed message tucked inside the email and deliberately hidden: forged text is shown on top while the mail
    // app still shows a "signed" badge. Hidden with CSS / the obsolete <plaintext> tag, or labelled as an attachment.
    // (A signed message nested inside on its own is normal: mailing lists wrap signed posts to add a footer.)
    const nestedSigned = mime.containers.filter((c) => /multipart\/signed/i.test(c.type));
    if (nestedSigned.length) {
      const asAttachment = nestedSigned.some((c) => /attachment/i.test(c.disposition));
      const hidingCss = mime.parts.some((p) => /html/i.test(p.type) && /<plaintext\b|\{[^}]*display\s*:\s*none|style\s*=\s*["'][^"']*display\s*:\s*none/i.test(p.body))
        || /<plaintext\b/i.test(mime.preamble || '') || mime.parts.some((p) => /<plaintext\b/i.test(p.body));
      out.hiddenSignedPart = asAttachment || hidingCss;
    }
    return out;
  }

  function rawMessageSignals(raw) {
    const out = [];
    if (!raw) return out;
    if (raw.multipleFrom) out.push(sig('multiple-from', 'sender', 45, 'The email has two different senders',
      'This email carries more than one "From" line. Different mail apps show different ones, so you may see a trusted name while the email really comes from someone else. Real emails have exactly one.', 'two From headers', { type: 'sender' }));
    if (raw.encodedAddress) out.push(sig('encoded-sender', 'sender', 35, 'The sender\'s address is hidden in encoded text',
      `The From line hides an address inside encoded text ("${raw.encodedAddress}"). Encoding is used for names in other alphabets, never needed for an address: it is a trick to slip past checks.`, raw.encodedAddress, { type: 'sender' }));
    if (raw.headerMarkup) out.push(sig('header-markup', 'sender', 45, 'Hidden code in the email\'s sender or subject',
      'The sender, recipient or subject line contains web-page code. That is an attack on mail apps and never appears in a real email.', 'code in headers', { type: 'sender' }));
    if (raw.script) out.push(sig('script-in-email', 'structure', 35, 'The email contains hidden scripts',
      'The email\'s code includes scripts or "run on load" instructions. Mail apps block them, but their presence shows the email was built to attack, not to inform.', 'script in email'));
    if (raw.brokenSignature) out.push(sig('broken-signature', 'structure', 40, 'Fake or damaged digital signature',
      'This email claims to be digitally signed, but the signature is missing or far too short to be real. Attackers tamper with signatures so a mail app shows a "signed" badge on a forged email.', 'invalid S/MIME signature'));
    if (raw.hiddenSignedPart) out.push(sig('hidden-signed-part', 'structure', 40, 'A signed message is hidden behind other text',
      'This email contains a genuinely signed message, but hides it and shows you different text on top. Your mail app may still display a "signed" badge for the text you see, which the signature does not cover.', 'hidden signed part'));
    if (raw.unsignedPreamble) out.push(sig('unsigned-content', 'structure', 35, 'Text added outside the signed part',
      'Part of what you see sits outside the signed section of this email, so the signature does not vouch for it. This is how attackers add their own text to a genuinely signed email.', 'unsigned text before signed part'));
    return out;
  }

  // Visible-header versions of two of the checks above, for every provider (no raw message needed).
  const BIDI = /[‪-‮⁦-⁩‎‏]/;
  function visibleHeaderSignals(sender, subject) {
    const out = [];
    if (ADDRESS_MARKUP.test(sender.name || '') || ADDRESS_MARKUP.test(sender.email || '') || SUBJECT_MARKUP.test(subject || '')) out.push(sig('header-markup', 'sender', 45,
      'Hidden code in the email\'s sender or subject', 'The sender or subject line contains web-page code. That is an attack on mail apps and never appears in a real email.', 'code in headers', { type: 'sender' }));
    if (BIDI.test(sender.name || '') || BIDI.test(sender.email || '')) out.push(sig('bidi-sender', 'sender', 45, 'The sender\'s name is reversed to disguise it',
      'The sender contains an invisible character that flips the direction of the text, so the address you see is not the address that sent it.', 'text-direction trick', { type: 'sender' }));
    return out;
  }

  // ---------- sender ----------
  // Normalizes the From line into { name, email, domain }. Some pages only show "Name <address>" as text.
  function parseSender(name, email) {
    name = (name || '').trim();
    email = lc(email || '').trim();
    if (!email) { const m = name.match(EMAIL_RE); if (m) email = lc(m[0]); }
    const domain = email.includes('@') ? email.split('@').pop() : '';
    return { name, email, domain };
  }

  // Which brand, if any, does the display name claim to be? ("PayPal Security" -> PayPal; "Chase Miller" -> none.)
  function claimedBrand(displayName) {
    // Look-alike letters are mapped first, so "P\u0430yPal" (Cyrillic \u0430) still claims to be PayPal.
    const n = mapConfusables(cleanText(displayName)).replace(/[^a-z0-9\u00a1-\uffff\s.\-]/g, ' ');
    const esc = (k) => k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    for (const b of D.BRANDS) {
      if (!b.keywords.some((k) => wordRe(k).test(n))) continue;
      // Only count it as a brand claim if the rest of the name is generic ("Apple Support"),
      // so real people named "Chase Smith" are not flagged. All of the brand's own names are removed, longest
      // first, so "Microsoft Outlook" and "Apple iCloud" count as claims too (they used to slip through).
      let rest = n;
      for (const k of [...b.keywords].sort((x, y) => y.length - x.length)) {
        rest = rest.replace(new RegExp('(^|[^a-z0-9])' + esc(k) + '(?=$|[^a-z0-9])', 'gi'), '$1 ');
      }
      const tokens = rest.split(/[\s.\-]+/).filter(Boolean).filter((t) => !D.SERVICE_WORDS.includes(t));
      if (tokens.length === 0) return b;
    }
    return null;
  }

  // Checks the sender. Returns { signals, ctx } where ctx tells the rest of the analysis who the sender really is:
  //   senderBrand    the brand whose real domain sent it (or null)
  //   verifiedBrand  the address belongs to that brand (not yet proof: From lines can be forged)
  //   authVerified   ...and the provider's DMARC/DKIM check proves it
  //   free           sent from a personal free-mail account (gmail.com, outlook.com...)
  //   auth           'pass' | 'fail' | 'unknown' anti-forgery verdict
  function analyzeSender(sender, lists, auth) {
    const signals = [];
    const { name, email, domain } = sender;
    const ctx = { senderBrand: null, verifiedBrand: false, free: false, auth: 'unknown' };
    if (!domain) return { signals, ctx }; // the page didn't show an address: nothing to check
    const reg = registrableDomain(domain);
    ctx.free = isSharedMail(domain);

    // On a list? (A reported single address, e.g. a gmail.com scammer, is checked by full address.)
    const senderThreat = (lists.blocked && lists.blocked.has(email)) ? { cat: 'reported', source: 'your reports' } : knownThreat(domain, lists);
    if (senderThreat && senderThreat.cat === 'community') {
      signals.push(sig('community-sender', 'sender', 35, 'Other Tripwire users reported this sender\'s domain',
        `${domain} was reported as phishing by at least ${senderThreat.threshold || 3} different Tripwire users. It isn't on a confirmed list yet.`, email));
    } else if (senderThreat) signals.push(threatSignal('known-bad-sender', 'sender', senderThreat, senderThreat.cat === 'reported' ? email : domain));
    if (/[^\x00-\x7f]/.test(domain) || domain.includes('xn--')) {
      signals.push(sig('unicode-sender', 'sender', 30, 'Sender address uses disguised characters',
        'The sender\'s address contains foreign look-alike letters, a trick to impersonate a real company.', email));
    }
    const look = lookalikeBrand(domain);
    if (look) signals.push(sig('lookalike-sender', 'sender', lookalikeWeight(look, domain) + 5, `Fake ${look.brand.name} address`, LOOKALIKE_TEXT[look.kind](look.brand, domain), email));

    // Does the display name claim a brand, and does the address belong to it?
    const claimed = claimedBrand(name);
    if (claimed) {
      if (domainMatches(domain, claimed.domains) && !ctx.free) { ctx.senderBrand = claimed; ctx.verifiedBrand = true; }
      else if (ctx.free) signals.push(sig('brand-freemail', 'sender', 40, `Claims to be ${claimed.name}, but uses a free email account`,
        `The sender calls themselves "${name}", but the email comes from a personal ${reg} account. ${claimed.name} would never email you from ${reg}.`, `${name} <${email}>`));
      else if (!look) signals.push(sig('brand-mismatch', 'sender', 30, `Sender name says ${claimed.name}, address doesn't`,
        `The name shown is "${name}", but the real address is ${email}, which does not belong to ${claimed.name}.`, `${name} <${email}>`));
    } else {
      const own = brandOfDomain(domain);
      if (own && !ctx.free) { ctx.senderBrand = own; ctx.verifiedBrand = true; }
    }
    // A From address is easy to fake. Brand trust only stands if the provider's authentication check agrees.
    ctx.auth = authVerdict(auth, domain);
    if (ctx.auth === 'fail') {
      const what = auth.dmarc === 'fail' ? 'DMARC' : auth.dkim === 'fail' ? 'DKIM' : 'SPF';
      if (ctx.verifiedBrand) {
        signals.push(sig('auth-fail-brand', 'sender', 50, `Forged ${ctx.senderBrand.name} address`,
          `The email claims to come from ${email}, a real ${ctx.senderBrand.name} address, but it failed the anti-forgery check (${what}) that real ${ctx.senderBrand.name} mail passes. Someone else sent it and faked the From address.`,
          `${what}=fail for ${domain}`));
        ctx.verifiedBrand = false; ctx.forgedBrand = ctx.senderBrand.name;
      } else {
        signals.push(sig('auth-fail', 'sender', 25, 'Sender address may be forged',
          `This email failed the anti-forgery check (${what}) for ${domain}, so it may not really come from ${email}.`, `${what}=fail for ${domain}`));
      }
    }
    ctx.authVerified = ctx.verifiedBrand && ctx.auth === 'pass';
    // Smaller tricks: an address written in the display name, departments on personal accounts, cheap endings.
    const nameEmail = name.match(EMAIL_RE);
    if (nameEmail && lc(nameEmail[0]) !== email) {
      signals.push(sig('name-email-mismatch', 'sender', 35, 'Sender name shows a different address',
        `The sender's name is written as "${nameEmail[0]}", but the email really came from ${email}. This is done to trick you.`, `${name} <${email}>`));
    }
    if (ctx.free && /(security|it department|it support|help ?desk|support team|billing|administrator|admin team|account team|payroll|hr department|human resources|tech support)/i.test(name)) {
      signals.push(sig('org-freemail', 'sender', 20, 'Official-sounding name from a personal account',
        `"${name}" sounds like an organisation's department, but the message comes from a personal ${reg} address.`, `${name} <${email}>`));
    }
    if (D.SUSPICIOUS_TLDS.includes(tld(domain))) signals.push(sig('tld-sender', 'sender', 10, 'Unusual sender address ending',
      `Addresses ending in ".${tld(domain)}" are cheap and often used for scams.`, email));
    return { signals, ctx };
  }

  // ---------- wording ----------
  // Each phrase category (phrases live in data.js) scores `w` for the first match, `step` more per extra distinct
  // match, up to `cap`. So one "urgent" costs a little; a wall of threats costs more, but never unboundedly.
  const CATEGORY_INFO = {
    urgency: { w: 8, step: 3, cap: 14, title: 'Pressures you to act fast',
      explain: 'Scammers rush you so you don\'t stop to think or check. Real companies rarely demand action within hours.' },
    fear: { w: 10, step: 3, cap: 16, title: 'Uses threats or scary warnings',
      explain: 'Messages that threaten account closure, legal trouble, or "suspicious activity" are designed to frighten you into clicking.' },
    credentials: { w: 16, step: 4, cap: 24, title: 'Asks for passwords, codes or personal details',
      explain: 'Legitimate companies never ask you to confirm your password, security codes, or ID numbers by email.' },
    financial: { w: 12, step: 4, cap: 20, title: 'Asks for money or payment details',
      explain: 'Requests for payments, gift cards, wire transfers or card details by email are a top sign of fraud.' },
    prize: { w: 12, step: 3, cap: 18, title: 'Promises a prize or money',
      explain: 'Unexpected winnings, refunds or inheritances are bait. If it sounds too good to be true, it is.' },
    greeting: { w: 5, step: 0, cap: 5, title: 'Generic greeting',
      explain: 'Using "Dear Customer" instead of your name suggests a mass message sent to many people.' },
    secrecy: { w: 10, step: 3, cap: 14, title: 'Asks for secrecy or a quick favour',
      explain: 'Requests to keep something quiet, or "quick favours" from a boss or friend, are common in gift-card and wire-fraud scams.' },
  };
  // Phrases compiled once at load time, not per email.
  const COMPILED = {};
  for (const cat of Object.keys(D.PHRASES)) COMPILED[cat] = D.PHRASES[cat].map((p) => new RegExp('\\b' + p, 'i'));

  // Returns { category: [matched phrases, lowercased] } for every category that matched.
  function findPhrases(text) {
    const found = {};
    for (const cat of Object.keys(COMPILED)) {
      const hits = [];
      for (const re of COMPILED[cat]) { const m = text.match(re); if (m) hits.push(m[0].trim()); }
      if (hits.length) found[cat] = uniq(hits.map(lc));
    }
    return found;
  }

  function analyzeContent(subject, body) {
    const text = cleanText((subject || '') + '\n' + (body || '')).replace(/\s+/g, ' ');
    const found = findPhrases(text);
    const signals = [];
    for (const cat of Object.keys(found)) {
      const info = CATEGORY_INFO[cat];
      const n = found[cat].length;
      const weight = Math.min(info.cap, info.w + info.step * (n - 1));
      signals.push(sig('content-' + cat, cat, weight, info.title, info.explain, found[cat].slice(0, 4).map((x) => `"${x}"`).join(', ')));
    }
    return { signals, found };
  }

  // ---------- direct requests ----------
  // Some requests are dangerous whatever else the email looks like: "reply with your password", "send us your SSN",
  // "buy gift cards and send me the codes", "wire $2,000 to this account". No real company asks for the first kind
  // by email, and a stranger demanding money is a scam. These make the email red even when no list confirms it.
  // Checked one sentence at a time, so "never share your password" (a negation) doesn't count.
  const SENSITIVE = '(?:e-?mail(?: address)? and password|user ?name and password|password|passcode|pin(?: number| code)?|' +
    'log ?in(?: details| credentials| information| info)?|credentials|social security(?: number)?|ssn|security (?:code|questions?)|' +
    'verification code|one[- ]time (?:code|password|passcode)|2fa code|(?:credit |debit |bank )?card (?:number|details|info(?:rmation)?)|' +
    'cvv|cvc|bank (?:account(?: number| details)?|login|details|information)|account number|routing number|date of birth|' +
    'driver\'?s licen[cs]e(?: number)?|passport(?: number| details)?|tax id|national id(?: number)?|mother\'?s maiden name)';
  const ASK_VERB = '(?:reply|respond|send|e-?mail|text|give|provide|share|submit|enter|type|confirm|verify|tell|forward|include|update)';
  const CRED_RES = [
    new RegExp(`\\b${ASK_VERB}(?:s|ing|ed)?\\b[^.!?\\n]{0,40}?\\byour\\s+(?:(?:full|current|old|account|online|banking|email)\\s+){0,2}${SENSITIVE}\\b`, 'i'),
    new RegExp(`\\bwhat(?:'s| is) your\\s+(?:(?:current|account|online|banking|email)\\s+)?${SENSITIVE}\\b`, 'i'),
    new RegExp(`\\b(?:need|require|want)\\s+(?:your|the)\\s+${SENSITIVE}\\b`, 'i'),
  ];
  const AMOUNT = '(?:[$£€]\\s?\\d[\\d,.]*(?:\\s?k)?|\\d[\\d,.]*\\s?(?:dollars|usd|eur|euros|gbp|pounds))';
  const MONEY_RES = [
    new RegExp(`\\b(?:send|give|transfer|wire)\\s+(?:me|us)\\s+(?:the\\s+|some\\s+)?(?:money|funds|cash|${AMOUNT})`, 'i'),
    new RegExp(`\\b(?:pay|lend|loan|venmo|zelle|cash ?app|paypal)\\s+(?:me|us)\\b`, 'i'),
    new RegExp(`\\b(?:send|transfer|wire)\\s+(?:the\\s+|a\\s+)?(?:money|funds|cash|payment|${AMOUNT})\\b`, 'i'),
    new RegExp(`\\bpay\\s+(?:the\\s+)?${AMOUNT}\\s+(?:to|into)\\b`, 'i'),
    /\b(?:buy|purchase|get|pick up)\s+(?:\w+\s+){0,4}?gift ?cards?\b/i,
    /\b(?:send|reply with|text|email)\s+(?:me|us)?\s*(?:the\s+)?(?:gift ?card\s+)?(?:codes?|card numbers?)\s+(?:on|from|off)\b|\bscratch (?:off )?the (?:back|codes?)\b/i,
    /\bsend\b[^!?\n]{0,30}?\b(?:bitcoin|btc|crypto(?:currency)?|usdt|tether|ethereum|eth)\b/i, // "." allowed: "0.05 BTC"
  ];
  const NEGATED = /\b(?:never|do not|don't|dont|will not|won't|should not|shouldn't|must not|nobody|no one|not ask|not request)\b/i;

  // Returns { credentials: [phrases], money: [phrases] } for direct requests found in the text.
  function findDirectRequests(text) {
    const out = { credentials: [], money: [] };
    const sentences = (text || '').replace(/\s+/g, ' ').split(/(?<=[.!?])\s+|\n/);
    for (const s of sentences) {
      if (NEGATED.test(s)) continue;
      for (const re of CRED_RES) { const m = s.match(re); if (m && !/\bnew (?:password|pin|passcode)\b/i.test(m[0])) out.credentials.push(m[0].trim()); }
      for (const re of MONEY_RES) { const m = s.match(re); if (m) out.money.push(m[0].trim()); }
    }
    out.credentials = uniq(out.credentials.map(lc));
    out.money = uniq(out.money.map(lc));
    return out;
  }

  // ---------- attachments ----------
  // attachments: [{ name, mime, html: { password, form, redirect, obfuscated } }] read from the webmail page.
  // `html` is only present for HTML attachments whose contents the content script could read (Gmail).
  // .one (OneNote), .xll (Excel add-in), .iqy/.slk (Excel web query / symbolic link) and .appref-ms / .library-ms /
  // .search-ms are delivery formats used in real campaigns since macros were blocked by default.
  const EXEC_EXT = /\.(exe|scr|js|jse|vbs|vbe|bat|cmd|com|pif|msi|msix|appx|appxbundle|msixbundle|hta|wsf|wsh|wsc|sct|lnk|jar|ps1|psm1|cpl|reg|dll|chm|application|url|one|onepkg|xll|iqy|slk|appref-ms|library-ms|search-ms|settingcontent-ms|msc|inf|gadget)$/i;
  const HTML_EXT = /\.(html?|shtml|xhtml|svg|mht|mhtml)$/i;
  const DISK_EXT = /\.(iso|img|vhdx?)$/i;
  const MACRO_EXT = /\.(docm|dotm|xlsm|xltm|xlam|pptm|potm|ppam|sldm)$/i;
  const ARCHIVE_EXT = /\.(zip|rar|7z|gz|tgz|cab|ace|arj)$/i;
  const DOC_EXT = /\.(pdf|docx?|xlsx?|pptx?|txt|rtf|csv|odt|jpe?g|png|gif|mp3|mp4|wav)$/i;
  // Invisible text-direction characters. U+202E ("right-to-left override") flips the rest of a file name on screen,
  // so "invoice‮fdp.exe" displays as "invoiceexe.pdf". It is replaced with a visible «RTL» marker; the others
  // (LRM, RLM, LRE..PDF, LRI..PDI) are simply removed before checking the extension.
  const BIDI_CHARS = /[‎‏‪-‮⁦-⁩]/g;

  // One signal per suspicious file; the strongest reason for each file wins (if / else-if chain).
  function analyzeAttachments(attachments, body) {
    const signals = [];
    const seen = new Set();
    for (const a of attachments || []) {
      const name = (a.name || '').trim().replace(BIDI_CHARS, (c) => (c === '‮' ? '«RTL»' : ''));
      if (!name || seen.has(lc(name))) continue;
      seen.add(lc(name));
      const add = (id, weight, title, explain) => signals.push(sig(id, 'attachment', weight, title, explain, name));
      const base = name.replace(/\.(?:[a-z0-9]{1,5}|[a-z]+-ms|application)$/i, '');
      if (name.includes('«RTL»')) add('attachment-rtlo', 45, 'Attachment name is reversed to hide its type',
        'The file name contains a hidden character that flips the text, so a program can pretend to be a document.');
      if ((EXEC_EXT.test(name) || HTML_EXT.test(name) || DISK_EXT.test(name)) && (DOC_EXT.test(base) || /\.(pdf|docx?|xlsx?)\s+$/i.test(base))) {
        add('attachment-double-ext', 40, 'Attachment pretends to be a document',
          `"${name}" looks like a ${base.split('.').pop().toUpperCase()} file, but the real type is the last part (.${name.split('.').pop()}). This trick is used to sneak in fake login pages and harmful programs.`);
      } else if (EXEC_EXT.test(name)) {
        add('attachment-executable', 35, 'Attachment is a program', `"${name}" is a program or script. Opening it could install harmful software. Real invoices and documents are never programs.`);
      } else if (DISK_EXT.test(name)) {
        add('attachment-disk-image', 30, 'Attachment is a disk image', `"${name}" is a disk image. These are used to slip harmful programs past security checks.`);
      } else if (HTML_EXT.test(name)) {
        add('attachment-html', 25, 'Attachment is a web page', `"${name}" opens in your browser like a website. Scammers send these to show a fake login page that isn't on any blocklist.`);
      } else if (MACRO_EXT.test(name)) {
        add('attachment-macro', 20, 'Attachment can run macros', `"${name}" is an Office file that can run built-in programs (macros). Don't click "Enable content".`);
      } else if (ARCHIVE_EXT.test(name) && /pass(word|code)|\bpwd\b|kennwort|contraseña|mot de passe/i.test(body || '')) {
        add('attachment-locked-archive', 15, 'Password-protected archive', `"${name}" is a compressed file and the email gives you a password for it. Locking a file this way stops security scanners from looking inside.`);
      }
      // What the content script found inside an HTML attachment (independent of the name checks above).
      const h = a.html;
      if (h && (h.password || h.form)) {
        add('attachment-login-form', 45, 'Attachment contains a login form', `"${name}" has boxes for a password or other details. Typing into a file you got by email sends your details to whoever made it.`);
      } else if (h && (h.redirect || h.obfuscated)) {
        add('attachment-redirect', 30, 'Attachment secretly opens a website', `"${name}" contains hidden code that sends you to another website as soon as it opens.`);
      }
    }
    return signals;
  }

  // Text-only fallback when the page doesn't show an attachment list.
  // A name that is really part of a web or email address ("example.com", "site.org/index.html", "bob@x.com") is
  // not a file, so only names that stand on their own count. ".com" is skipped entirely: it's every other domain.
  function mentionedAttachment(body) {
    const text = body || '';
    const re = new RegExp(D.RISKY_ATTACHMENT.source, 'gi');
    let att = null;
    for (let m; (m = re.exec(text)) && !att;) {
      if (/\.com$/i.test(m[0])) continue;
      const end = m.index + m[0].length;
      const word = (text.slice(0, end).match(/\S*$/)[0] + (text.slice(end).match(/^\S*/)[0]));
      const continuesAsDomain = text[end] === '.' && /\w/.test(text[end + 1] || ''); // "something.js.org"
      if (/[/@\\]|^(www\.|https?:)/i.test(word) || continuesAsDomain) continue;
      att = m;
    }
    if (att && /(attach|download|open|file|document|invoice)/i.test(text)) {
      return sig('risky-attachment', 'attachment', 15, 'Mentions a risky file type',
        `The email refers to "${att[0].trim()}". Files like this can install harmful software when opened.`, att[0].trim());
    }
    return null;
  }

  // ---------- bank details & payment changes ----------
  // Account numbers in the text, validated by their checksums so ordinary numbers aren't mistaken for them.
  // IBAN: move the first 4 characters to the end, turn letters into numbers (A=10...Z=35), and the whole number
  // mod 97 must be 1. Done digit by digit so it never needs big-number arithmetic.
  function ibanValid(iban) {
    const s = iban.slice(4) + iban.slice(0, 4);
    let rem = 0;
    for (const ch of s) {
      const v = /[0-9]/.test(ch) ? ch : String(ch.charCodeAt(0) - 55);
      for (const d of v) rem = (rem * 10 + Number(d)) % 97;
    }
    return rem === 1;
  }
  // US routing (ABA) number: weighted digit sum (3, 7, 1 repeating) must be a multiple of 10.
  function abaValid(n) {
    const d = n.split('').map(Number);
    return (3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8])) % 10 === 0 && !/^0{9}$/.test(n);
  }
  // Returns [{ type: 'iban'|'routing'|'sortcode'|'account', id: normalized, raw: text as written }]
  function findBankDetails(text) {
    const t = text || '';
    const out = [], seen = new Set();
    const add = (type, id, raw) => { if (!seen.has(type + id)) { seen.add(type + id); out.push({ type, id, raw: raw.trim() }); } };
    for (const m of t.matchAll(/\b([A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?)\b/g)) {
      const id = m[1].replace(/\s+/g, '');
      if (id.length >= 15 && id.length <= 34 && ibanValid(id)) add('iban', id, m[1]);
    }
    for (const m of t.matchAll(/(?:routing|aba|ach|transit)[^0-9\n]{0,25}(\d{9})\b/gi)) if (abaValid(m[1])) add('routing', m[1], m[1]);
    for (const m of t.matchAll(/sort[\s-]*code[^0-9\n]{0,15}(\d{2})[\s-]?(\d{2})[\s-]?(\d{2})\b/gi)) add('sortcode', m[1] + m[2] + m[3], m[0].slice(m[0].search(/\d/)));
    for (const m of t.matchAll(/(?:account|acct|a\/c)\s*(?:number|no\.?|num|#)?\s*[:#]?\s*(\d[\d -]{5,20}\d)\b/gi)) {
      const id = m[1].replace(/[\s-]/g, '');
      if (id.length >= 6 && id.length <= 17 && !seen.has('routing' + id)) add('account', id, m[1]);
    }
    return out.slice(0, 10);
  }
  const PAYCHANGE_RE = D.PAYMENT_CHANGE.map((p) => new RegExp('\\b' + p, 'i'));
  // Returns { signals, phrases, banks }. Three cases, strongest first:
  //   1. a known sender's bank details changed (from history)  2. "payment details changed" wording
  //   3. bank details from a first-time sender (only once history has had time to learn who you know)
  function paymentChangeSignals(text, banks, history) {
    const t = (text || '').replace(/\s+/g, ' ');
    const phrases = uniq(PAYCHANGE_RE.map((re) => (t.match(re) || [])[0]).filter(Boolean).map((x) => x.trim()));
    const out = [];
    const bankTarget = { type: 'text', phrases: banks.map((b) => b.raw) };
    if (history && history.bankChanged) {
      out.push(sig('bank-details-changed', 'payment', 40, 'Bank details differ from this sender\'s usual ones',
        `Earlier emails from ${history.bankChangedDomain || 'this sender'} gave different bank details. Criminals who break into, or imitate, a supplier's email send "new" account numbers so the next payment goes to them.`,
        banks.map((b) => b.raw).join(', '), bankTarget));
    }
    if (phrases.length) {
      out.push(sig('payment-change', 'payment', banks.length ? 35 : 28, 'Asks you to send money to a new account',
        'The email says payment details have changed. This is the most expensive email scam: the email often looks completely normal, sometimes even comes from the real company\'s hacked mailbox, and the money is gone once sent.',
        phrases.slice(0, 2).map((x) => `"${x}"`).join(', '), { type: 'text', phrases: [...phrases, ...banks.map((b) => b.raw)] }));
    } else if (banks.length && history && history.mature && !history.seenBefore) {
      out.push(sig('bank-details-new-sender', 'payment', 15, 'First email from this sender, and it includes bank details',
        'Before paying an account number from someone who has never emailed you, confirm it with them by phone using a number you find yourself.',
        banks.map((b) => b.raw).join(', '), bankTarget));
    }
    return { signals: out, phrases, banks };
  }

  // ---------- reply-chain hijack & lookalike correspondents ----------
  // Candidate originals for a lookalike: one character removed, swapped, changed or added, look-alike letters
  // undone, or the same name under a different ending (.com/.co/...). The content script hashes these and checks
  // them against the hashed history of who you correspond with, so no address book is ever stored in plain text.
  const VARIANT_CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789-';
  const COMMON_TLDS = ['com', 'net', 'org', 'co', 'io', 'us', 'biz', 'info', 'co.uk', 'com.au', 'ca', 'de', 'fr', 'nl', 'eu'];
  // Every string one edit away from `label` (delete, swap neighbours, replace, insert), plus undone look-alikes.
  // About 75 x length candidates: a few hundred to ~1,500 for typical names.
  function editVariants(label) {
    const out = new Set();
    for (let i = 0; i < label.length; i++) out.add(label.slice(0, i) + label.slice(i + 1));
    for (let i = 0; i < label.length - 1; i++) out.add(label.slice(0, i) + label[i + 1] + label[i] + label.slice(i + 2));
    for (let i = 0; i <= label.length; i++) for (const c of VARIANT_CHARS) {
      out.add(label.slice(0, i) + c + label.slice(i));
      if (i < label.length) out.add(label.slice(0, i) + c + label.slice(i + 1));
    }
    out.add(normalizeHomoglyphs(label));
    out.add(label.replace(/m/g, 'rn')); out.add(label.replace(/w/g, 'vv'));
    out.delete(label); out.delete('');
    return out;
  }
  // Possible "originals" this sender could be imitating: { domains: [...], addresses: [...] }.
  function lookalikeCandidates(email) {
    email = lc(email);
    const [local, domain] = email.split('@');
    if (!domain) return { domains: [], addresses: [] };
    const reg = registrableDomain(domain);
    const label = domainLabel(reg), suffix = reg.slice(label.length + 1);
    const domains = new Set();
    if (!isSharedMail(domain) && label.length >= 3 && label.length <= 40) {
      for (const v of editVariants(label)) if (/^[a-z0-9]/.test(v) && v.length >= 2) domains.add(v + '.' + suffix);
      for (const t of COMMON_TLDS) domains.add(label + '.' + t);
      domains.delete(reg);
    }
    // Free-mail lookalikes copy the person instead: john.smith@gmail.com -> johnsmith@ or john.smlth@gmail.com
    const addresses = new Set();
    if (isSharedMail(domain) && local && local.length <= 40) {
      for (const v of editVariants(local)) if (v) addresses.add(v + '@' + domain);
      addresses.add(local.replace(/\./g, '') + '@' + domain);
      addresses.delete(email);
    }
    return { domains: [...domains], addresses: [...addresses] };
  }
  // Is domain `a` a near-copy of domain `b`? (Used for thread participants, whose domains are on the page.)
  function looksLike(a, b) {
    if (!a || !b || a === b) return false;
    const la = domainLabel(a), lb = domainLabel(b);
    if (la === lb) return true; // same name, different ending: acme.com vs acme.co
    if (normalizeHomoglyphs(la) === normalizeHomoglyphs(lb)) return true;
    return lb.length >= 4 && levenshtein(la, lb) === 1;
  }
  // "Re:" in several languages (German AW, Nordic SV, Dutch Antw, Italian R/RIF, Turkish YNT, Polish ODP, Finnish VS).
  const REPLY_RE = /^\s*(re|aw|sv|antw|r|rif|ynt|odp|vs)\s*(\[\d+\])?\s*:/i;

  // thread: { senders: [emails of the other messages in this conversation] }, from the webmail page (Gmail only).
  // `risky`: the email asks for money or details, which turns "a new company joined" from a note into a warning.
  function threadSignals(thread, sender, risky) {
    const out = [];
    if (!thread || !sender.email || !(thread.senders || []).length) return out;
    const others = uniq(thread.senders.map(lc).filter((e) => e && e !== sender.email));
    const otherRegs = uniq(others.map((e) => registrableDomain(e.split('@').pop())));
    const reg = registrableDomain(sender.domain);
    if (!others.length || otherRegs.includes(reg) || others.includes(sender.email)) return out;
    const copied = otherRegs.find((d) => looksLike(reg, d));
    const target = { type: 'sender' };
    if (copied) {
      out.push(sig('thread-lookalike', 'sender', 45, 'Reply comes from a copy of the other side\'s address',
        `Earlier messages in this conversation came from ${copied}. This reply comes from ${reg}, which is made to look the same. Criminals who have been reading a conversation slip in a reply from a look-alike address, usually to change where a payment goes.`,
        `${copied} → ${reg}`, target));
    } else {
      out.push(sig('thread-new-sender', 'sender', risky ? 30 : 10, 'A new company joined this conversation',
        `Earlier messages here came from ${otherRegs.slice(0, 2).join(', ')}, but this one comes from ${reg}.` +
        (risky ? ' It also asks for money or details: check with the people you were talking to, using contact details you already have.' : ' That can be normal, but check before acting on any request.'),
        `${otherRegs[0]} → ${reg}`, target));
    }
    return out;
  }

  // ---------- sender history ----------
  // history (computed on the device from salted hashes of past senders):
  //   seenBefore, mature, nameKnownElsewhere,
  //   lookalikeOf: 'acme.com'            a domain you correspond with, that this sender's domain imitates
  //   lookalikeAddress: 'j.smith@gmail.com'  an address you correspond with, that this sender imitates
  //   bankChanged, bankChangedDomain     bank details differ from the ones this domain sent before
  function historySignals(history, sender, found, trusted, subject, risky) {
    const out = [];
    if (!history || trusted || !sender.email) return out;
    const target = { type: 'sender' };
    if (history.lookalikeOf || history.lookalikeAddress) {
      const real = history.lookalikeOf || history.lookalikeAddress;
      out.push(sig('lookalike-correspondent', 'sender', risky ? 45 : 38, 'Imitates someone you email with',
        `You normally get emails from ${real}. This one comes from ${history.lookalikeOf ? sender.domain : sender.email}, a near-copy. Scammers register look-alike addresses of real suppliers and colleagues, then send invoices or payment changes.`,
        `${real} → ${history.lookalikeOf ? sender.domain : sender.email}`, target));
    }
    if (history.nameKnownElsewhere) {
      out.push(sig('new-address-for-name', 'sender', 30, 'Familiar name, new address',
        `You've had emails from "${sender.name}" before, but always from a different address. This one comes from ${sender.email}. Scammers copy the names of bosses, colleagues and suppliers to ask for money or details.`,
        `${sender.name} <${sender.email}>`, target));
    }
    if (history.mature && !history.seenBefore && !history.knownDomain && REPLY_RE.test(subject || '')) {
      out.push(sig('fake-reply', 'sender', risky ? 20 : 12, 'Pretends to be a reply',
        `The subject starts with "${(subject.match(REPLY_RE) || [''])[0].trim()}" as if you'd been talking, but you've never had an email from ${sender.email}. Faking a conversation makes a scam feel familiar.`,
        subject.slice(0, 60), { type: 'subject' }));
    } else if (history.mature && !history.seenBefore) {
      const sensitive = !!(found.credentials || found.financial || found.secrecy || risky);
      out.push(sig('first-time-sender', 'sender', sensitive ? 15 : 4, 'First email from this sender',
        sensitive ? `This is the first email you've had from ${sender.email}, and it already asks for money, details or secrecy. Check who they are another way before replying.`
          : `This is the first email you've had from ${sender.email}.`, sender.email, target));
    }
    return out;
  }

  // ---------- on-device AI hints ----------
  // ai: { risk: 'low'|'medium'|'high', asks: [...], reasons: [...], summary } from Chrome's built-in model (optional).
  // The AI counts for more when the keyword checks found nothing (e.g. a scam in another language).
  const AI_ASK_TEXT = { credentials: 'Give personal information, a password or a code', payment: 'Make a payment or share payment details',
    gift_cards: 'Buy gift cards', click_link: 'Click a link or button', open_attachment: 'Open an attachment', call_phone: 'Call a phone number',
    reply: 'Reply to the email', personal_info: 'Give personal information, a password or a code' };
  function aiSignals(ai, found) {
    if (!ai || !ai.risk || ai.risk === 'low') return [];
    const keywordsMissed = !(found.credentials || found.financial || found.secrecy || found.prize);
    // Alone, a "high" verdict is just enough for yellow (score 68), never for red or "very suspicious".
    const weight = ai.risk === 'high' ? (keywordsMissed ? 32 : 15) : (keywordsMissed ? 12 : 6);
    const why = (ai.reasons || []).filter(Boolean).slice(0, 2).join(' ');
    return [sig('ai-intent', 'ai', weight, ai.risk === 'high' ? 'Reads like a scam (on-device AI)' : 'Wording looks manipulative (on-device AI)',
      (why ? why + ' ' : '') + 'This judgement comes from Chrome\'s built-in AI model, running on your computer. It can be wrong, so it only nudges the score.',
      (ai.asks || []).filter((a) => a !== 'none').join(', '))];
  }

  // What does the email want the reader to do? Plain-language list for the summary.
  function detectAsks(text, links, found) {
    const asks = [];
    const t = lc(text);
    if (found.credentials) asks.push('Give personal information, a password or a code');
    if (found.financial || /\b(pay|payment|invoice|transfer)\b/.test(t)) asks.push('Make a payment or share payment details');
    if (/(click|tap|press|follow) (the |this |on |below|here|link|button)/.test(t) || (links && links.length && /(log ?in|sign ?in|verify|confirm|update)/.test(t))) asks.push('Click a link or button');
    if (/(open|download|view|see) (the )?(attached|attachment|file|document)/.test(t)) asks.push('Open an attachment');
    if (/(call|phone|contact) (us|our|this number|the number|\+?\d)/.test(t)) asks.push('Call a phone number');
    if (/\b(reply|respond)\b/.test(t)) asks.push('Reply to the email');
    if (found.prize) asks.push('Claim a prize or reward');
    return uniq(asks);
  }

  // Simple on-device summary: drop greetings, sign-offs and footer boilerplate, score the remaining sentences
  // (action words and position near the top score higher), and keep the best two in their original order.
  function summarize(subject, body) {
    const clean = (body || '').replace(/\s+/g, ' ').trim();
    if (!clean) return subject ? `This email is about: "${subject}".` : 'This email has no readable text.';
    const sentences = clean.split(/(?<=[.!?])\s+(?=[A-Z0-9"'(])/)
      .map((s) => s.trim().replace(/^(hi|hello|dear|hey|good (morning|afternoon|evening))\b[^,.!:]{0,40}[,!:]\s*/i, ''))
      .filter((s) => s.length > 25 && s.length < 400)
      .filter((s) => !/^(hi|hello|dear|hey|thanks|thank you|regards|best|sincerely|cheers)\b/i.test(s))
      .filter((s) => !/(unsubscribe|privacy policy|all rights reserved|view (this|it) in (your )?browser|copyright|©)/i.test(s));
    if (!sentences.length) return clean.slice(0, 220) + (clean.length > 220 ? '…' : '');
    const keyRe = /(account|payment|order|password|verify|confirm|invoice|delivery|meeting|please|need|request|click|update|deadline|due|refund|win|won|transfer|review|sign)/i;
    const scored = sentences.slice(0, 15).map((s, i) => ({ s, i, score: (keyRe.test(s) ? 2 : 0) + (i < 3 ? 1.5 - i * 0.4 : 0) }));
    const picked = scored.sort((a, b) => b.score - a.score).slice(0, 2).sort((a, b) => a.i - b.i).map((x) => x.s);
    let out = picked.join(' ');
    if (out.length > 320) out = out.slice(0, 317) + '…';
    return out;
  }

  // =================================================================================================================
  // analyzeEmail: the main entry point. Runs every check above and combines them into one verdict.
  //
  // input: { senderName, senderEmail, subject, body, links: [{href, text}], hasForm, context: 'list'|'open',
  //          auth, attachments, qrCodes: [{data, src}], history, thread, ai }   (all but the first few are optional)
  //          context 'list' = an inbox row (only the snippet is known), 'open' = a fully opened email.
  // lists:   { blocked: Set, trusted: Set, threats: Map, expanded: Map(shortHref -> finalHref) }
  // returns: { score, level, high, known, signals, sender, verifiedBrand, auth, links, asks, tips, summary, ... }
  // =================================================================================================================
  function analyzeEmail(input, lists) {
    lists = lists || {};
    const sender = parseSender(input.senderName, input.senderEmail);
    const trusted = !!(lists.trusted && sender.email && (lists.trusted.has(sender.email) || lists.trusted.has(sender.domain)));
    // A sender domain the user said they know ("I know this sender" on the "not sure this is the official address"
    // warning). It vouches for who sent the email, but unlike `trusted` the email's contents are still fully checked.
    const knownDomain = !trusted && !!(lists.knownDomains && sender.domain && lists.knownDomains.has(registrableDomain(sender.domain)));

    // ----- 1. sender -----
    const s = analyzeSender(sender, lists, input.auth);
    // Header and structure tricks: from the raw message when we have it (Gmail), otherwise from what the page shows.
    const raw = input.rawMessage ? inspectRawMessage(input.rawMessage) : null;
    const forgery = [...rawMessageSignals(raw), ...visibleHeaderSignals(sender, input.subject)];
    const seenForgery = new Set();
    const headerTricks = forgery.filter((x) => x.category === 'sender' && !seenForgery.has(x.id) && seenForgery.add(x.id));
    const structureSignals = forgery.filter((x) => x.category === 'structure');
    // Trusting a sender silences warnings about them, except known threats and signs of forgery: a forged
    // sender can copy anyone, including people you trust.
    const FORGERY = /^(auth-fail|multiple-from|encoded-sender|header-markup|bidi-sender)/;
    const senderSignals = (trusted || knownDomain ? s.signals.filter((x) => x.category === 'known' || FORGERY.test(x.id)) : s.signals).concat(headerTricks);

    // ----- 2. wording -----
    const content = analyzeContent(input.subject, input.body);
    const contentSignals = content.signals;
    // ----- 3. payments -----
    // Payment changes: wording, bank numbers, and whether this sender's bank details changed since last time.
    const banks = findBankDetails((input.subject || '') + '\n' + (input.body || ''));
    const pay = paymentChangeSignals((input.subject || '') + ' ' + (input.body || ''), banks, input.history);
    // A changed account from a trusted sender still counts: their mailbox may have been broken into.
    const paySignals = trusted ? pay.signals.filter((x) => x.id === 'bank-details-changed') : pay.signals;
    const moneyAsk = !!(pay.phrases.length || content.found.financial || content.found.credentials || banks.length);
    // ----- 4. history and 5. thread (both count as sender signals) -----
    senderSignals.push(...historySignals(input.history, sender, content.found, trusted || knownDomain, input.subject, moneyAsk));
    if (!trusted && !knownDomain) senderSignals.push(...threadSignals(input.thread, sender, moneyAsk));
    // A misspelling of the company the email itself names (menrds.com from "Menards"). Skipped for senders you trust,
    // know, or already correspond with, and when the brand list already caught it.
    let unsureSender = null;
    if (!trusted && !knownDomain && !(input.history && input.history.seenBefore) && !senderSignals.some((x) => x.id === 'lookalike-sender')) {
      const nl = nameLookalike(sender, input.subject, input.body);
      if (nl) senderSignals.push(sig('lookalike-name', 'sender', 45, 'Fake company address',
        `This email says it's from "${nl.claim}", but it was sent from ${sender.domain}, a ${nl.kind === 'homoglyph' ? 'look-alike using swapped characters (for example "0" for "o")' : 'misspelling'} of that name. Scammers register near-identical addresses to impersonate real companies.`,
        sender.email, { type: 'sender' }));
      // The domain contains the company's full name plus something else: can't tell, so yellow and ask the user.
      const un = nl ? null : unsureCompanyDomain(sender, input.subject, input.body);
      if (un) {
        unsureSender = { company: un.display, domain: registrableDomain(sender.domain) };
        senderSignals.push(sig('unsure-company-domain', 'sender', 31, `Not sure this is ${un.display}'s official address`,
          `This email says it's from "${un.display}" and comes from ${unsureSender.domain}, which contains that name. Tripwire can't confirm it is the company's official email address: real companies sometimes use addresses like this, and so do scammers. If you know this sender, click "I know this sender".`,
          sender.email, { type: 'sender' }));
      }
    }
    // ----- 7. attachments (the real list if the page shows one, otherwise file names mentioned in the text) -----
    const attachmentSignals = input.attachments && input.attachments.length ? analyzeAttachments(input.attachments, input.body)
      : [mentionedAttachment(input.body)].filter(Boolean);
    const aiSigs = trusted ? [] : aiSignals(input.ai, content.found);

    // ----- 6. links -----
    // QR codes found in images are treated like links: scammers use them to get past link scanners.
    const qrLinks = [];
    for (const q of (input.qrCodes || [])) {
      const data = (q.data || '').trim();
      // A bare "evil.example" (no https://, no path) is a web address too; phone cameras open it.
      if (!/^https?:\/\//i.test(data) && !/^(?:[a-z0-9\-]+\.)+[a-z]{2,}(?:[/?#:]\S*)?$/i.test(data)) continue;
      qrLinks.push({ href: /^https?:/i.test(data) ? data : 'https://' + data, text: '', qr: true, src: q.src });
    }

    // Links: judge each unique destination, keep the most serious ones.
    const linkResults = [];
    const seen = new Set();
    for (const r of qrLinks) {
      const res = analyzeLink(r, lists, s.ctx);
      if (!res.host) continue;
      res.qr = true;
      res.signals.unshift(sig('qr-code', 'link', 15, 'QR code hides a link',
        `An image in this email is a QR code that opens "${res.host}". Scanning it with your phone skips the link checks your computer does, which is why scammers use them.`, res.host));
      res.weight += 15;
      for (const x of res.signals) x.target = { type: 'image', src: r.src || '' }; // "Show me" points at the QR image
      linkResults.push(Object.assign(res, { text: 'QR code' }));
    }
    for (const l of (input.links || [])) {
      const key = (l.href || '') + '|' + (l.text || '').trim().slice(0, 60);
      if (seen.has(key)) continue; seen.add(key);
      const r = analyzeLink(l, lists, s.ctx);
      if (r.host || r.signals.length) linkResults.push(Object.assign(r, { text: (l.text || '').trim() }));
      if (linkResults.length > 200) break;
    }
    // Keep one copy of each kind of warning per destination domain, most serious links first, so ten links to the
    // same bad site produce one reason, not ten.
    const riskyLinks = linkResults.filter((r) => r.weight > 0).sort((a, b) => b.weight - a.weight);
    const linkSignals = [];
    const seenLinkSig = new Set();
    for (const r of riskyLinks) for (const x of r.signals) {
      const k = x.id + '|' + r.regDomain;
      if (seenLinkSig.has(k)) continue; seenLinkSig.add(k);
      if (!x.target) x.target = { type: 'link', host: r.host, href: r.href };
      linkSignals.push(x);
    }

    if (input.hasForm) linkSignals.push(sig('form', 'link', 30, 'Email contains a sign-in form',
      'This email has boxes for you to type information directly into it. Real companies never ask you to log in inside an email.', 'form in email', { type: 'form' }));

    // Brand mentioned in text while asking for credentials/payment, but neither sender nor links belong to that brand.
    if ((content.found.credentials || content.found.financial) && !s.ctx.verifiedBrand && !trusted) {
      const txt = cleanText((input.subject || '') + ' ' + (input.body || '').slice(0, 1500));
      for (const b of D.BRANDS) {
        if (!mentionsBrand(b, txt)) continue;
        const linksToBrand = linkResults.some((r) => domainMatches(r.host, b.domains));
        if (!linksToBrand && !(sender.domain && domainMatches(sender.domain, b.domains)) && !senderSignals.some((x) => x.title.includes(b.name))) {
          contentSignals.push(sig('brand-impersonation', 'sender', 20, `Pretends to be from ${b.name}`,
            `The message talks about your ${b.name} account and asks for information, but it was not sent by ${b.name} and its links don't go to ${b.name}.`, b.name,
            { type: 'text', phrases: b.keywords.filter((k) => k.length >= 4) }));
        }
        break;
      }
    }

    // Direct requests for passwords or personal details, and money demands from a sender we can't vouch for.
    // A sender is vouched for if you trust them, they are a brand address that passed authentication, or you've
    // corresponded with them before (and they aren't a look-alike or a new address for a familiar name).
    const direct = findDirectRequests((input.subject || '') + '\n' + (input.body || ''));
    const hist = input.history || {};
    const knownCorrespondent = !!(hist.seenBefore && !hist.lookalikeOf && !hist.lookalikeAddress && !hist.nameKnownElsewhere);
    const vouched = trusted || knownDomain || s.ctx.authVerified || knownCorrespondent;
    const directSignals = [];
    if (direct.credentials.length && !trusted) directSignals.push(sig('asks-credentials', 'request', 50, 'Asks you to send a password or personal details',
      'This email asks you to send a password, security code, or personal number such as an SSN by email. Real companies and services never do this. Don\'t reply with any of it.',
      direct.credentials.slice(0, 3).map((x) => `"${x}"`).join(', '), { type: 'text', phrases: direct.credentials }));
    if (direct.money.length && !vouched) directSignals.push(sig('asks-money', 'request', 45, 'Tells you to send money',
      `This email tells you to send money, gift cards or cryptocurrency, and it comes from ${sender.email || 'a sender'} that Tripwire can't verify. Contact the person or company another way before paying anything.`,
      direct.money.slice(0, 3).map((x) => `"${x}"`).join(', '), { type: 'text', phrases: direct.money }));
    const redRequest = directSignals.length > 0;
    // Impersonation: a look-alike of a known brand, of the company the email names, or of someone you email with.
    const impersonation = senderSignals.some((x) => x.id === 'lookalike-name' || x.id === 'lookalike-correspondent' ||
      (x.id === 'lookalike-sender' && x.weight >= 40));

    // Combination bonus: pressure + a sensitive request is the classic phishing recipe.
    const coercion = !!(content.found.urgency || content.found.fear || content.found.secrecy);
    const ask = !!(content.found.credentials || content.found.financial || pay.phrases.length);
    if (coercion && ask) contentSignals.push(sig('combo-pressure-ask', 'combo', 12, 'Pressure combined with a request for information',
      'This email both rushes or scares you AND asks for sensitive information or money — the classic phishing formula.', '',
      { type: 'text', phrases: [...(content.found.urgency || []), ...(content.found.fear || []), ...(content.found.secrecy || []),
        ...(content.found.credentials || []), ...(content.found.financial || []), ...pay.phrases] }));

    // ----- 8. scoring -----
    // Each group's weights become one capped penalty, subtracted from 100. Caps keep any single kind of evidence
    // (especially wording, which marketing email also uses) from dominating. Within links and attachments the worst
    // item counts fully and the rest at a quarter.
    let contentPenalty = contentSignals.reduce((a, x) => a + x.weight, 0);
    contentPenalty = Math.min(contentPenalty, 45); // general wording alone never makes an email "red" (direct requests can)
    const cleanLinks = !riskyLinks.some((r) => r.weight >= 20);
    if (trusted) contentPenalty *= 0.3;
    else if (s.ctx.authVerified && cleanLinks) contentPenalty *= 0.4; // proven brand address, clean links
    else if (s.ctx.verifiedBrand && cleanLinks) contentPenalty *= 0.6; // brand address, but authentication couldn't be checked

    const senderPenalty = senderSignals.filter((x) => x.category !== 'known').reduce((a, x) => a + x.weight, 0);
    const linkWeights = riskyLinks.filter((r) => !r.known).map((r) => r.weight);
    let linkPenalty = 0;
    if (linkWeights.length) linkPenalty = linkWeights[0] + linkWeights.slice(1).reduce((a, w) => a + w * 0.25, 0);
    linkPenalty += linkSignals.filter((x) => x.id === 'form').reduce((a, x) => a + x.weight, 0);
    linkPenalty = Math.min(linkPenalty, 70);
    const worstPlusQuarter = (list) => { const w = list.map((x) => x.weight).sort((a, b) => b - a); return (w[0] || 0) + w.slice(1).reduce((a, x) => a + x * 0.25, 0); };
    const attachmentPenalty = Math.min(60, worstPlusQuarter(attachmentSignals));
    const structurePenalty = Math.min(50, worstPlusQuarter(structureSignals)); // scripts, tampered signatures
    const aiPenalty = Math.min(32, aiSigs.reduce((a, x) => a + x.weight, 0));
    // Payment changes have their own bucket: they are the costliest scam, and their wording is often perfectly calm.
    const paymentPenalty = Math.min(55, paySignals.reduce((a, x) => a + x.weight, 0));

    // Technical red flags combined with a coercive request strengthen each other.
    let comboTech = 0;
    if ((senderPenalty >= 30 || linkPenalty >= 30 || attachmentPenalty >= 30) && (ask || coercion)) comboTech = 15;
    // A look-alike or hijacked sender asking to change where money goes is the textbook invoice-fraud pattern.
    if (paymentPenalty && senderSignals.some((x) => /lookalike|thread-|new-address-for-name|auth-fail/.test(x.id))) comboTech = Math.max(comboTech, 20);

    const known = senderSignals.some((x) => x.category === 'known') || linkResults.some((r) => r.known);
    const requestPenalty = directSignals.reduce((a, x) => a + x.weight, 0);
    let score = Math.round(100 - contentPenalty - senderPenalty - linkPenalty - attachmentPenalty - structurePenalty - aiPenalty - paymentPenalty - comboTech - requestPenalty);
    // 0 is reserved for confirmed phishing; unconfirmed emails bottom out at 10 however many warning signs they have.
    score = known ? 0 : Math.max(10, Math.min(redRequest || impersonation ? 20 : 100, score));

    // Red ("phishing") for:
    //   - confirmed phishing: a sender/link on a threat list, or one the user reported;
    //   - direct requests: a password or personal details, or money from a sender we can't vouch for;
    //   - impersonation: a sender address that imitates a brand, the company the email names, or a correspondent;
    //   - strong signs of a scam: enough warning signs together to push the score below 35.
    // Milder warning signs are yellow ("suspicious"). `high` is kept for older callers and is now always false,
    // because strongly suspicious emails are red.
    let level = 'safe';
    if (known || redRequest || impersonation || score < 35) level = 'phishing';
    else if (score < 70) level = 'suspicious';
    const high = false;

    // ----- the result -----
    // All reasons, most serious first (that is the order the banner shows them in).
    const signals = [...directSignals, ...senderSignals, ...linkSignals, ...attachmentSignals, ...structureSignals, ...paySignals, ...contentSignals, ...aiSigs].sort((a, b) => b.weight - a.weight);
    // Every reason gets a "Show me" target unless it already has one.
    for (const x of signals) {
      if (x.target) continue;
      if (x.category === 'attachment') x.target = { type: 'attachment', name: x.evidence };
      else if (CATEGORY_INFO[x.category]) x.target = { type: 'text', phrases: content.found[x.category] || [] };
      else if (x.category === 'sender' || /sender/.test(x.id)) x.target = { type: 'sender' };
    }
    const bodyText = cleanText(input.body);
    let asks = input.context === 'open' ? detectAsks(bodyText, input.links, content.found) : [];
    if (input.context === 'open') {
      if (direct.credentials.length) asks.unshift('Give personal information, a password or a code');
      if (direct.money.length) asks.unshift('Send money, gift cards or cryptocurrency');
      asks = uniq(asks);
    }
    if (pay.phrases.length && input.context === 'open') asks.unshift('Send money to a new or different bank account');
    if (input.ai && input.context === 'open') asks = uniq([...asks, ...(input.ai.asks || []).map((a) => AI_ASK_TEXT[a]).filter(Boolean)]);
    // Advice specific to what was found, shown first under "What you should do".
    const tips = [];
    if (paySignals.length) tips.push('Before paying, call the company on a phone number you already have (an old invoice, their website). Never use a number or reply address from this email.');
    if (signals.some((x) => /^thread-|lookalike-correspondent/.test(x.id))) tips.push('Compare the sender\'s address letter by letter with earlier emails in your inbox.');
    return {
      score, level, high, known, trusted, knownDomain, unsureSender, signals,
      threatCategory: known ? ((signals.find((x) => x.category === 'known') || {}).threatCategory || 'phishing') : null,
      sender,
      verifiedBrand: s.ctx.verifiedBrand ? s.ctx.senderBrand.name : null,
      auth: s.ctx.auth, // 'pass' | 'fail' | 'unknown'
      forgedBrand: s.ctx.forgedBrand || null,
      links: linkResults,
      riskyLinks,
      attachments: (input.attachments || []).map((a) => a.name),
      banks: banks.map((b) => ({ type: b.type, id: b.id })), // the content script fingerprints these per sender (on device)
      tips,
      asks,
      summary: input.context === 'open' ? ((input.ai && input.ai.summary) || summarize(input.subject, bodyText)) : '',
      aiSummary: !!(input.ai && input.ai.summary && input.context === 'open'),
    };
  }

  // Exported for the content script, background worker, page guard, server and tests.
  root.PG_Analyzer = { analyzeEmail, analyzeUrl, analyzeLink, analyzeAttachments, registrableDomain, lookalikeBrand, unwrapUrl, summarize,
    parseSender, parseAuthResults, authVerdict, findBankDetails, findDirectRequests, isSharedMail, lookalikeCandidates, looksLike, parseMime, inspectRawMessage, decodeWords };
})(typeof globalThis !== 'undefined' ? globalThis : this);
