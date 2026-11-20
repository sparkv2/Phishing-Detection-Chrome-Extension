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

  // target: where the banner's "Show me" button points in the email ({ type: 'sender'|'link'|'text'|'attachment'|'image'|'form'|'subject', ... })
  function sig(id, category, weight, title, explain, evidence, target) {
    const s = { id, category, weight, title, explain, evidence: evidence || '' };
    if (target) s.target = target;
    return s;
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
    if (threat && threat.cat === 'community') {
      // Reported by several Tripwire users, but not confirmed by a curated list: a strong warning, never "red".
      out.signals.push(sig('community-link', 'link', 35, 'Link goes to a site other Tripwire users reported',
        `"${host}" was reported as phishing by at least ${threat.threshold || 3} different Tripwire users. It isn't on a confirmed list yet, so treat it as dangerous but unconfirmed.`, host));
    } else if (threat) {
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

  // ---------- email authentication (SPF / DKIM / DMARC) ----------
  // Parses raw message headers (or just Authentication-Results lines) into { spf, dkim, dmarc, dkimDomains, fromDomain }.
  // Only the first (top-most) Authentication-Results header counts: it was added by the user's own mail provider.
  // Lower headers could have been written by the sender and are ignored.
  function parseAuthResults(headers) {
    const text = (headers || '').toString();
    const head = text.split(/\r?\n\r?\n/)[0].replace(/\r?\n[ \t]+/g, ' '); // header block only, unfolded
    const line = head.split(/\r?\n/).find((l) => /^authentication-results:/i.test(l));
    if (!line) return null;
    const v = line.replace(/^authentication-results:\s*/i, '');
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

  function analyzeSender(sender, lists, auth) {
    const signals = [];
    const { name, email, domain } = sender;
    const ctx = { senderBrand: null, verifiedBrand: false, free: false, auth: 'unknown' };
    if (!domain) {
      const b = claimedBrand(name);
      ctx.claimed = b;
      return { signals, ctx };
    }
    const reg = registrableDomain(domain);
    ctx.free = D.FREE_MAIL.includes(reg) || D.FREE_MAIL.includes(domain);

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
    return { signals, found };
  }

  // ---------- attachments ----------
  // attachments: [{ name, mime, html: { password, form, redirect, obfuscated } }] read from the webmail page.
  const EXEC_EXT = /\.(exe|scr|js|jse|vbs|vbe|bat|cmd|com|pif|msi|msix|appx|hta|wsf|wsh|lnk|jar|ps1|psm1|cpl|reg|dll|chm|application|url)$/i;
  const HTML_EXT = /\.(html?|shtml|xhtml|svg|mht|mhtml)$/i;
  const DISK_EXT = /\.(iso|img|vhdx?)$/i;
  const MACRO_EXT = /\.(docm|dotm|xlsm|xltm|xlam|pptm|potm|ppam|sldm)$/i;
  const ARCHIVE_EXT = /\.(zip|rar|7z|gz|tgz|cab|ace|arj)$/i;
  const DOC_EXT = /\.(pdf|docx?|xlsx?|pptx?|txt|rtf|csv|odt|jpe?g|png|gif|mp3|mp4|wav)$/i;

  function analyzeAttachments(attachments, body) {
    const signals = [];
    const seen = new Set();
    for (const a of attachments || []) {
      const name = (a.name || '').trim().replace(/[‎‏‪-‮⁦-⁩]/g, (c) => (c === '‮' ? '«RTL»' : ''));
      if (!name || seen.has(lc(name))) continue;
      seen.add(lc(name));
      const add = (id, weight, title, explain) => signals.push(sig(id, 'attachment', weight, title, explain, name));
      const base = name.replace(/\.[a-z0-9]{1,5}$/i, '');
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
  function mentionedAttachment(body) {
    const att = (body || '').match(D.RISKY_ATTACHMENT);
    if (att && /(attach|download|open|file|document|invoice)/i.test(body)) {
      return sig('risky-attachment', 'attachment', 15, 'Mentions a risky file type',
        `The email refers to "${att[0].trim()}". Files like this can install harmful software when opened.`, att[0].trim());
    }
    return null;
  }

  // ---------- bank details & payment changes ----------
  // Account numbers in the text, validated by their checksums so ordinary numbers aren't mistaken for them.
  function ibanValid(iban) {
    const s = iban.slice(4) + iban.slice(0, 4);
    let rem = 0;
    for (const ch of s) {
      const v = /[0-9]/.test(ch) ? ch : String(ch.charCodeAt(0) - 55);
      for (const d of v) rem = (rem * 10 + Number(d)) % 97;
    }
    return rem === 1;
  }
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
  function lookalikeCandidates(email) {
    email = lc(email);
    const [local, domain] = email.split('@');
    if (!domain) return { domains: [], addresses: [] };
    const reg = registrableDomain(domain);
    const label = domainLabel(reg), suffix = reg.slice(label.length + 1);
    const domains = new Set();
    if (!D.FREE_MAIL.includes(reg) && label.length >= 3 && label.length <= 40) {
      for (const v of editVariants(label)) if (/^[a-z0-9]/.test(v) && v.length >= 2) domains.add(v + '.' + suffix);
      for (const t of COMMON_TLDS) domains.add(label + '.' + t);
      domains.delete(reg);
    }
    // Free-mail lookalikes copy the person instead: john.smith@gmail.com -> johnsmith@ or john.smlth@gmail.com
    const addresses = new Set();
    if (D.FREE_MAIL.includes(reg) && local && local.length <= 40) {
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
  const REPLY_RE = /^\s*(re|aw|sv|antw|r|rif|ynt|odp|vs)\s*(\[\d+\])?\s*:/i;

  // thread: { senders: [emails of the other messages in this conversation] }, from the webmail page.
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
  // input: { senderName, senderEmail, subject, body, links: [{href,text}], hasForm, context: 'list'|'open',
  //          auth: parsed Authentication-Results, attachments: [{name, html}], qrCodes: [{data}], history: {...}, ai: {...} }
  // lists: { blocked:Set, trusted:Set, threats:Map, expanded:Map(shortHref -> finalHref), feed:Set }
  function analyzeEmail(input, lists) {
    lists = lists || {};
    const sender = parseSender(input.senderName, input.senderEmail);
    const trusted = !!(lists.trusted && sender.email && (lists.trusted.has(sender.email) || lists.trusted.has(sender.domain)));

    const s = analyzeSender(sender, lists, input.auth);
    // Trusting a sender silences warnings about them, except known threats and failed anti-forgery checks:
    // a forged From address can copy anyone, including people you trust.
    let senderSignals = trusted ? s.signals.filter((x) => x.category === 'known' || x.id.startsWith('auth-fail')) : s.signals;

    const content = analyzeContent(input.subject, input.body);
    let contentSignals = content.signals;
    // Payment changes: wording, bank numbers, and whether this sender's bank details changed since last time.
    const banks = findBankDetails((input.subject || '') + '\n' + (input.body || ''));
    const pay = paymentChangeSignals((input.subject || '') + ' ' + (input.body || ''), banks, input.history);
    // A changed account from a trusted sender still counts: their mailbox may have been broken into.
    const paySignals = trusted ? pay.signals.filter((x) => x.id === 'bank-details-changed') : pay.signals;
    const moneyAsk = !!(pay.phrases.length || content.found.financial || content.found.credentials || banks.length);
    senderSignals.push(...historySignals(input.history, sender, content.found, trusted, input.subject, moneyAsk));
    if (!trusted) senderSignals.push(...threadSignals(input.thread, sender, moneyAsk));
    const attachmentSignals = input.attachments && input.attachments.length ? analyzeAttachments(input.attachments, input.body)
      : [mentionedAttachment(input.body)].filter(Boolean);
    const aiSigs = trusted ? [] : aiSignals(input.ai, content.found);

    // QR codes found in images are treated like links: scammers use them to get past link scanners.
    const qrLinks = [];
    for (const q of (input.qrCodes || [])) {
      const data = (q.data || '').trim();
      if (!/^https?:\/\//i.test(data) && !/^[a-z0-9.\-]+\.[a-z]{2,}\//i.test(data)) continue;
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
      const txt = lc((input.subject || '') + ' ' + (input.body || '').slice(0, 1500));
      for (const b of D.BRANDS) {
        if (!b.keywords.some((k) => k.length >= 4 && wordRe(k).test(txt))) continue;
        const linksToBrand = linkResults.some((r) => domainMatches(r.host, b.domains));
        if (!linksToBrand && !(sender.domain && domainMatches(sender.domain, b.domains)) && !senderSignals.some((x) => x.title.includes(b.name))) {
          contentSignals.push(sig('brand-impersonation', 'sender', 20, `Pretends to be from ${b.name}`,
            `The message talks about your ${b.name} account and asks for information, but it was not sent by ${b.name} and its links don't go to ${b.name}.`, b.name,
            { type: 'text', phrases: b.keywords.filter((k) => k.length >= 4) }));
        }
        break;
      }
    }

    // Combination bonus: pressure + a sensitive request is the classic phishing recipe.
    const coercion = !!(content.found.urgency || content.found.fear || content.found.secrecy);
    const ask = !!(content.found.credentials || content.found.financial || pay.phrases.length);
    if (coercion && ask) contentSignals.push(sig('combo-pressure-ask', 'combo', 12, 'Pressure combined with a request for information',
      'This email both rushes or scares you AND asks for sensitive information or money — the classic phishing formula.', '',
      { type: 'text', phrases: [...(content.found.urgency || []), ...(content.found.fear || []), ...(content.found.secrecy || []),
        ...(content.found.credentials || []), ...(content.found.financial || []), ...pay.phrases] }));

    // ----- scoring -----
    let contentPenalty = contentSignals.reduce((a, x) => a + x.weight, 0);
    contentPenalty = Math.min(contentPenalty, 45); // wording alone can never make an email "red"
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
    const attWeights = attachmentSignals.map((x) => x.weight).sort((a, b) => b - a);
    const attachmentPenalty = Math.min(60, (attWeights[0] || 0) + attWeights.slice(1).reduce((a, w) => a + w * 0.25, 0));
    const aiPenalty = Math.min(32, aiSigs.reduce((a, x) => a + x.weight, 0));
    // Payment changes have their own bucket: they are the costliest scam, and their wording is often perfectly calm.
    const paymentPenalty = Math.min(55, paySignals.reduce((a, x) => a + x.weight, 0));

    // Technical red flags combined with a coercive request strengthen each other.
    let comboTech = 0;
    if ((senderPenalty >= 30 || linkPenalty >= 30 || attachmentPenalty >= 30) && (ask || coercion)) comboTech = 15;
    // A look-alike or hijacked sender asking to change where money goes is the textbook invoice-fraud pattern.
    if (paymentPenalty && senderSignals.some((x) => /lookalike|thread-|new-address-for-name|auth-fail/.test(x.id))) comboTech = Math.max(comboTech, 20);

    const known = senderSignals.some((x) => x.category === 'known') || linkResults.some((r) => r.known);
    let score = Math.round(100 - contentPenalty - senderPenalty - linkPenalty - attachmentPenalty - aiPenalty - paymentPenalty - comboTech);
    // 0 is reserved for confirmed phishing; unconfirmed emails bottom out at 10 however many warning signs they have.
    score = known ? 0 : Math.max(10, Math.min(100, score));

    // Red ("phishing") ONLY for confirmed phishing: a sender/link on the known-scam list or reported by the user.
    // Everything else with warning signs is yellow ("suspicious"); `high` marks the strongly suspicious ones.
    let level = 'safe';
    if (known) level = 'phishing';
    else if (score < 70) level = 'suspicious';
    const high = !known && score < 35;

    const signals = [...senderSignals, ...linkSignals, ...attachmentSignals, ...paySignals, ...contentSignals, ...aiSigs].sort((a, b) => b.weight - a.weight);
    // Every reason gets a "Show me" target unless it already has one.
    for (const x of signals) {
      if (x.target) continue;
      if (x.category === 'attachment') x.target = { type: 'attachment', name: x.evidence };
      else if (CATEGORY_INFO[x.category]) x.target = { type: 'text', phrases: content.found[x.category] || [] };
      else if (x.category === 'sender' || /sender/.test(x.id)) x.target = { type: 'sender' };
    }
    const bodyText = input.body || '';
    let asks = input.context === 'open' ? detectAsks(bodyText, input.links, content.found) : [];
    if (pay.phrases.length && input.context === 'open') asks.unshift('Send money to a new or different bank account');
    if (input.ai && input.context === 'open') asks = uniq([...asks, ...(input.ai.asks || []).map((a) => AI_ASK_TEXT[a]).filter(Boolean)]);
    // Advice specific to what was found, shown first under "What you should do".
    const tips = [];
    if (paySignals.length) tips.push('Before paying, call the company on a phone number you already have (an old invoice, their website). Never use a number or reply address from this email.');
    if (signals.some((x) => /^thread-|lookalike-correspondent/.test(x.id))) tips.push('Compare the sender\'s address letter by letter with earlier emails in your inbox.');
    return {
      score, level, high, known, trusted, signals,
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

  root.PG_Analyzer = { analyzeEmail, analyzeUrl, analyzeLink, analyzeAttachments, registrableDomain, lookalikeBrand, unwrapUrl, summarize,
    parseSender, parseAuthResults, authVerdict, isIP, brandOfDomain, findBankDetails, lookalikeCandidates, looksLike };
})(typeof globalThis !== 'undefined' ? globalThis : this);
