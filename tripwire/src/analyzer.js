// Phishing analysis engine. Pure functions, no network, no storage. Runs entirely on the user's device.
(function (root) {
  'use strict';
  const D = root.PG_DATA;

  // ---------- helpers ----------
  const lc = (s) => (s || '').toString().toLowerCase();
  const uniq = (arr) => [...new Set(arr)];
  const EMAIL_RE = /[a-z0-9._%+\-]+@[a-z0-9.\-\u00a1-\uffff]+\.[a-z\u00a1-\uffff]{2,}/i;

  const CONFUSABLES = { 'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y', 'і': 'i', 'ӏ': 'l',
    'ԁ': 'd', 'ɡ': 'g', 'ո': 'n', 'ս': 'u', 'ѕ': 's', 'ј': 'j', 'һ': 'h', 'ԛ': 'q', 'ԝ': 'w', 'ı': 'i', 'ɩ': 'l' };

  function normalizeHomoglyphs(s) {
    let out = '';
    for (const ch of lc(s)) out += CONFUSABLES[ch] || ch;
    return out.replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e').replace(/5/g, 's').replace(/\$/g, 's')
      .replace(/rn/g, 'm').replace(/vv/g, 'w');
  }

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
  function isIP(host) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || /^\[?[0-9a-f:]+\]?$/i.test(host) && host.includes(':'); }
  function domainMatches(host, domains) {
    host = lc(host);
    return domains.some((d) => host === d || host.endsWith('.' + d));
  }
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
  function wordRe(word) { return new RegExp('(^|[^a-z0-9])' + word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '($|[^a-z0-9])', 'i'); }

  function brandLabels(brand) { return uniq(brand.domains.map((d) => domainLabel(d)).filter((l) => l.length >= 3)); }
  function brandOfDomain(host) { return D.BRANDS.find((b) => domainMatches(host, b.domains)) || null; }

  // Does `host` look like an imitation of a known brand? Returns { brand, kind } or null.
  function lookalikeBrand(host) {
    host = lc(host);
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
  const GENERIC_LABELS = new Set(['office', 'outlook', 'live', 'square', 'squareup', 'cash', 'steam', 'zoom', 'chase',
    'citi', 'meta', 'apple', 'prime', 'drive', 'wells', 'capital']);
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

  function parseUrl(href) {
    try { return new URL(href, 'https://invalid.local/'); } catch (e) { return null; }
  }

  // Unwrap well-known redirect wrappers so we judge the real destination.
  function unwrapUrl(href) {
    let u = parseUrl(href);
    for (let i = 0; u && i < 3; i++) {
      const h = lc(u.hostname);
      let inner = null;
      if ((h === 'www.google.com' || h === 'google.com') && u.pathname === '/url') inner = u.searchParams.get('q') || u.searchParams.get('url');
      else if (h.endsWith('safelinks.protection.outlook.com')) inner = u.searchParams.get('url');
      else if (h === 'l.facebook.com' || h === 'lm.facebook.com') inner = u.searchParams.get('u');
      else if (h === 'out.reddit.com') inner = u.searchParams.get('url');
      if (!inner) break;
      const next = parseUrl(inner);
      if (!next || next.hostname === 'invalid.local') break;
      u = next;
    }
    return u;
  }

  function sig(id, category, weight, title, explain, evidence) {
    return { id, category, weight, title, explain, evidence: evidence || '' };
  }

  // ---------- URL analysis ----------
  // Returns { host, regDomain, weight, signals, known }
  function analyzeUrl(href, lists) {
    lists = lists || {};
    const raw = (href || '').trim();
    const out = { href: raw, host: '', regDomain: '', weight: 0, signals: [], known: false };
    if (/^\s*javascript:/i.test(raw)) {
      out.signals.push(sig('js-link', 'link', 40, 'Link runs hidden code', 'This link doesn\'t open a web page — it runs code. Real emails never need this.', raw.slice(0, 60)));
    } else if (/^\s*data:/i.test(raw)) {
      out.signals.push(sig('data-link', 'link', 40, 'Link hides a whole page inside itself', 'This link contains an entire web page packed into the link, a trick used to show fake login forms.', 'data: link'));
    }
    if (out.signals.length) { out.weight = 40; return out; }

    const u = unwrapUrl(raw);
    if (!u || !/^https?:$/.test(u.protocol) || u.hostname === 'invalid.local') return out;
    const host = lc(u.hostname);
    const reg = registrableDomain(host);
    out.host = host; out.regDomain = reg; out.finalHref = u.href;

    const threat = knownThreat(host, lists, u);
    if (threat) {
      out.known = true;
      out.threat = threat;
      out.signals.push(threatSignal('known-bad-link', 'link', threat, threat.byUrl ? (threat.matched || host) : host));
    }
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

  // Is this host (or exact URL) on a threat list? Returns { cat, source, label } or null.
  // lists.threats: Map filled by the content script from the background index (host / 'url:'+key -> hit or null).
  function knownThreat(host, lists, u) {
    host = lc(host);
    const reg = registrableDomain(host);
    if (lists.blocked && (lists.blocked.has(host) || lists.blocked.has(reg))) return { cat: 'reported', source: 'your reports' };
    if (D.BUILTIN_BLOCKLIST.includes(host) || D.BUILTIN_BLOCKLIST.includes(reg)) return { cat: 'phishing', source: 'Tripwire built-in list' };
    const t = lists.threats;
    if (t) {
      if (u && root.PG_Intel) for (const k of root.PG_Intel.urlKeys(u)) { const hit = t.get('url:' + k); if (hit) return Object.assign({ byUrl: true }, hit); }
      const hit = t.get(host);
      if (hit) return hit;
    }
    if (lists.feed && (lists.feed.has(host) || lists.feed.has(reg))) return { cat: 'phishing', source: 'phishing list' };
    return null;
  }

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

  // ---------- link-text mismatch ----------
  function analyzeLink(link, lists, ctx) {
    const res = analyzeUrl(link.href, lists);
    const text = (link.text || '').trim();
    if (!res.host) return res;
    const shown = domainInText(text);
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
        if (b.keywords.some((k) => k.length >= 4 && wordRe(k).test(text)) && !domainMatches(res.host, b.domains) && !tracking
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

  // ---------- sender analysis ----------
  function parseSender(name, email) {
    name = (name || '').trim();
    email = lc(email || '').trim();
    if (!email) { const m = name.match(EMAIL_RE); if (m) email = lc(m[0]); }
    const domain = email.includes('@') ? email.split('@').pop() : '';
    return { name, email, domain };
  }

  function claimedBrand(displayName) {
    const n = lc(displayName).replace(/[^a-z0-9\u00a1-\uffff\s.\-]/g, ' ');
    for (const b of D.BRANDS) {
      for (const k of b.keywords) {
        if (!wordRe(k).test(n)) continue;
        // Only count it as a brand claim if the rest of the name is generic ("Apple Support"),
        // so real people named "Chase Smith" are not flagged.
        let rest = n.replace(new RegExp(k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'), ' ');
        const tokens = rest.split(/[\s.\-]+/).filter(Boolean).filter((t) => !D.SERVICE_WORDS.includes(t));
        if (tokens.length === 0) return b;
      }
    }
    return null;
  }

  function analyzeSender(sender, lists) {
    const signals = [];
    const { name, email, domain } = sender;
    const ctx = { senderBrand: null, verifiedBrand: false, free: false };
    if (!domain) {
      const b = claimedBrand(name);
      ctx.claimed = b;
      return { signals, ctx };
    }
    const reg = registrableDomain(domain);
    ctx.free = D.FREE_MAIL.includes(reg) || D.FREE_MAIL.includes(domain);

    const senderThreat = (lists.blocked && lists.blocked.has(email)) ? { cat: 'reported', source: 'your reports' } : knownThreat(domain, lists);
    if (senderThreat) signals.push(threatSignal('known-bad-sender', 'sender', senderThreat, senderThreat.cat === 'reported' ? email : domain));
    if (/[^\x00-\x7f]/.test(domain) || domain.includes('xn--')) {
      signals.push(sig('unicode-sender', 'sender', 30, 'Sender address uses disguised characters',
        'The sender\'s address contains foreign look-alike letters, a trick to impersonate a real company.', email));
    }
    const look = lookalikeBrand(domain);
    if (look) signals.push(sig('lookalike-sender', 'sender', lookalikeWeight(look, domain) + 5, `Fake ${look.brand.name} address`, LOOKALIKE_TEXT[look.kind](look.brand, domain), email));

    const claimed = claimedBrand(name);
    ctx.claimed = claimed;
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

  // ---------- content analysis ----------
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
  const COMPILED = {};
  for (const cat of Object.keys(D.PHRASES)) COMPILED[cat] = D.PHRASES[cat].map((p) => new RegExp('\\b' + p, 'i'));

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
    const text = ((subject || '') + '\n' + (body || '')).replace(/\s+/g, ' ');
    const found = findPhrases(text);
    const signals = [];
    for (const cat of Object.keys(found)) {
      const info = CATEGORY_INFO[cat];
      const n = found[cat].length;
      const weight = Math.min(info.cap, info.w + info.step * (n - 1));
      signals.push(sig('content-' + cat, cat, weight, info.title, info.explain, found[cat].slice(0, 4).map((x) => `"${x}"`).join(', ')));
    }
    const att = (body || '').match(D.RISKY_ATTACHMENT);
    if (att && /(attach|download|open|file|document|invoice)/i.test(body)) {
      signals.push(sig('risky-attachment', 'attachment', 15, 'Mentions a risky file type',
        `The email refers to "${att[0].trim()}". Files like this can install harmful software when opened.`, att[0].trim()));
    }
    return { signals, found };
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

  // Simple on-device summary: pick the most informative sentences.
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

  // ---------- main ----------
  // input: { senderName, senderEmail, subject, body, links: [{href,text}], hasForm, context: 'list'|'open' }
  // lists: { feed:Set, blocked:Set, trusted:Set }
  function analyzeEmail(input, lists) {
    lists = lists || {};
    const sender = parseSender(input.senderName, input.senderEmail);
    const trusted = !!(lists.trusted && sender.email && (lists.trusted.has(sender.email) || lists.trusted.has(sender.domain)));

    const s = analyzeSender(sender, lists);
    let senderSignals = trusted ? s.signals.filter((x) => x.category === 'known') : s.signals;

    const content = analyzeContent(input.subject, input.body);
    let contentSignals = content.signals;

    // Links: judge each unique destination, keep the most serious ones.
    const linkResults = [];
    const seen = new Set();
    for (const l of (input.links || [])) {
      const key = (l.href || '') + '|' + (l.text || '').trim().slice(0, 60);
      if (seen.has(key)) continue; seen.add(key);
      const r = analyzeLink(l, lists, s.ctx);
      if (r.host || r.signals.length) linkResults.push(Object.assign(r, { text: (l.text || '').trim() }));
      if (linkResults.length > 200) break;
    }
    const riskyLinks = linkResults.filter((r) => r.weight > 0).sort((a, b) => b.weight - a.weight);
    const linkSignals = [];
    const seenLinkSig = new Set();
    for (const r of riskyLinks) for (const x of r.signals) {
      const k = x.id + '|' + r.regDomain;
      if (seenLinkSig.has(k)) continue; seenLinkSig.add(k); linkSignals.push(x);
    }

    if (input.hasForm) linkSignals.push(sig('form', 'link', 30, 'Email contains a sign-in form',
      'This email has boxes for you to type information directly into it. Real companies never ask you to log in inside an email.', 'form in email'));

    // Brand mentioned in text while asking for credentials/payment, but neither sender nor links belong to that brand.
    if ((content.found.credentials || content.found.financial) && !s.ctx.verifiedBrand && !trusted) {
      const txt = lc((input.subject || '') + ' ' + (input.body || '').slice(0, 1500));
      for (const b of D.BRANDS) {
        if (!b.keywords.some((k) => k.length >= 4 && wordRe(k).test(txt))) continue;
        const linksToBrand = linkResults.some((r) => domainMatches(r.host, b.domains));
        if (!linksToBrand && !(sender.domain && domainMatches(sender.domain, b.domains)) && !senderSignals.some((x) => x.title.includes(b.name))) {
          contentSignals.push(sig('brand-impersonation', 'sender', 20, `Pretends to be from ${b.name}`,
            `The message talks about your ${b.name} account and asks for information, but it was not sent by ${b.name} and its links don't go to ${b.name}.`, b.name));
        }
        break;
      }
    }

    // Combination bonus: pressure + a sensitive request is the classic phishing recipe.
    const coercion = !!(content.found.urgency || content.found.fear || content.found.secrecy);
    const ask = !!(content.found.credentials || content.found.financial);
    if (coercion && ask) contentSignals.push(sig('combo-pressure-ask', 'combo', 12, 'Pressure combined with a request for information',
      'This email both rushes or scares you AND asks for sensitive information or money — the classic phishing formula.', ''));

    // ----- scoring -----
    let contentPenalty = contentSignals.reduce((a, x) => a + x.weight, 0);
    contentPenalty = Math.min(contentPenalty, 45); // wording alone can never make an email "red"
    if (trusted) contentPenalty *= 0.3;
    else if (s.ctx.verifiedBrand && !riskyLinks.some((r) => r.weight >= 20)) contentPenalty *= 0.4; // real brand, clean links

    const senderPenalty = senderSignals.filter((x) => x.category !== 'known').reduce((a, x) => a + x.weight, 0);
    const linkWeights = riskyLinks.filter((r) => !r.known).map((r) => r.weight);
    let linkPenalty = 0;
    if (linkWeights.length) linkPenalty = linkWeights[0] + linkWeights.slice(1).reduce((a, w) => a + w * 0.25, 0);
    linkPenalty += linkSignals.filter((x) => x.id === 'form').reduce((a, x) => a + x.weight, 0);
    linkPenalty = Math.min(linkPenalty, 70);

    // Technical red flags combined with a coercive request strengthen each other.
    let comboTech = 0;
    if ((senderPenalty >= 30 || linkPenalty >= 30) && (ask || coercion)) comboTech = 15;

    const known = senderSignals.some((x) => x.category === 'known') || linkResults.some((r) => r.known);
    let score = Math.round(100 - contentPenalty - senderPenalty - linkPenalty - comboTech);
    // 0 is reserved for confirmed phishing; unconfirmed emails bottom out at 10 however many warning signs they have.
    score = known ? 0 : Math.max(10, Math.min(100, score));

    // Red ("phishing") ONLY for confirmed phishing: a sender/link on the known-scam list or reported by the user.
    // Everything else with warning signs is yellow ("suspicious"); `high` marks the strongly suspicious ones.
    let level = 'safe';
    if (known) level = 'phishing';
    else if (score < 70) level = 'suspicious';
    const high = !known && score < 35;

    const signals = [...senderSignals, ...linkSignals, ...contentSignals].sort((a, b) => b.weight - a.weight);
    const bodyText = input.body || '';
    return {
      score, level, high, known, trusted, signals,
      threatCategory: known ? ((signals.find((x) => x.category === 'known') || {}).threatCategory || 'phishing') : null,
      sender,
      verifiedBrand: s.ctx.verifiedBrand ? s.ctx.senderBrand.name : null,
      links: linkResults,
      riskyLinks,
      asks: input.context === 'open' ? detectAsks(bodyText, input.links, content.found) : [],
      summary: input.context === 'open' ? summarize(input.subject, bodyText) : '',
    };
  }

  root.PG_Analyzer = { analyzeEmail, analyzeUrl, analyzeLink, registrableDomain, lookalikeBrand, unwrapUrl, summarize, parseSender };
})(typeof globalThis !== 'undefined' ? globalThis : this);
