// =====================================================================================================================
// Threat intelligence (intel.js)
//
// Everything about the list of known-bad sites, shared by the extension's background worker, the content scripts,
// the Tripwire server and the build tools:
//   1. SOURCES                the public feeds the list is built from
//   2. parseFeed / urlKeys    turning a downloaded feed into hosts and exact-URL keys
//   3. hostIsFlaggable        the safety filter: shared platforms and big services are never flagged as a whole
//   4. compact index          ~190k entries stored as sorted 53-bit hashes (8 bytes each) with binary-search lookup
//   5. signatures             checking that a downloaded list or rules file really comes from the project
// =====================================================================================================================
(function (root) {
  'use strict';

  // ---------- 1. sources ----------
  // Each source: where to download it (mirrors in order), what it means, and how to parse it.
  // format: 'url-lines' = one URL per line, 'host-lines' = one domain/IP per line, 'csv-label' = "host,label" per line.
  const SOURCES = [
    { id: 'openphish', name: 'OpenPhish', category: 'phishing', format: 'url-lines', license: 'OpenPhish Community Feed (free)',
      homepage: 'https://openphish.com/',
      urls: ['https://openphish.com/feed.txt', 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt'] },
    { id: 'phishing-filter', name: 'Phishing Filter (PhishTank, OpenPhish, PhishStats)', category: 'phishing', format: 'host-lines', license: 'CC0 / source terms',
      homepage: 'https://gitlab.com/malware-filter/phishing-filter',
      urls: ['https://malware-filter.gitlab.io/phishing-filter/phishing-filter-domains.txt', 'https://curbengh.github.io/phishing-filter/phishing-filter-domains.txt'] },
    { id: 'cert-pl', name: 'CERT Polska warning list', category: 'phishing', format: 'host-lines', license: 'CERT Polska open data',
      homepage: 'https://cert.pl/en/warning-list/',
      urls: ['https://hole.cert.pl/domains/v2/domains.txt'] },
    { id: 'urlhaus', name: 'URLhaus (abuse.ch) online malware sites', category: 'malware', format: 'host-lines', license: 'CC0',
      homepage: 'https://urlhaus.abuse.ch/',
      urls: ['https://malware-filter.gitlab.io/urlhaus-filter/urlhaus-filter-domains-online.txt', 'https://curbengh.github.io/urlhaus-filter/urlhaus-filter-domains-online.txt'] },
    { id: 'feodo', name: 'Feodo Tracker (abuse.ch) botnet C2 servers', category: 'c2', format: 'host-lines', license: 'CC0',
      homepage: 'https://feodotracker.abuse.ch/',
      urls: ['https://feodotracker.abuse.ch/downloads/ipblocklist.txt'] },
    { id: 'botnet-filter', name: 'Botnet Filter (abuse.ch based) malicious server IPs', category: 'c2', format: 'host-lines', license: 'CC0',
      homepage: 'https://gitlab.com/malware-filter/botnet-filter',
      urls: ['https://malware-filter.gitlab.io/botnet-filter/botnet-filter-dnscrypt-blocked-ips.txt', 'https://curbengh.github.io/botnet-filter/botnet-filter-dnscrypt-blocked-ips.txt'] },
    { id: 'c2intel-ip', name: 'C2IntelFeeds (C2 server IPs, last 30 days)', category: 'c2', format: 'csv-label', license: 'C2IntelFeeds (GitHub, drb-ra)',
      homepage: 'https://github.com/drb-ra/C2IntelFeeds',
      urls: ['https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv'] },
    { id: 'c2intel-domain', name: 'C2IntelFeeds (C2 server domains, last 30 days)', category: 'c2', format: 'csv-label', license: 'C2IntelFeeds (GitHub, drb-ra)',
      homepage: 'https://github.com/drb-ra/C2IntelFeeds',
      urls: ['https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2s-30day-filter-abused.csv'] },
  ];

  // ---------- 3. the safety filter's lists ----------
  // Feeds sometimes list a whole shared service because one customer's page on it was bad. These lists stop that
  // from ever flagging the whole service (only the exact bad URL, or the customer's own subdomain).

  // Platforms where each subdomain belongs to a different customer (evil.vercel.app ≠ vercel.app).
  // A listed subdomain is flagged; the platform itself never is.
  const SUBDOMAIN_PLATFORMS = ['github.io', 'gitlab.io', 'vercel.app', 'netlify.app', 'pages.dev', 'workers.dev', 'web.app',
    'firebaseapp.com', 'glitch.me', 'blogspot.com', 'wixsite.com', 'weebly.com', 'webflow.io', 'godaddysites.com', 'square.site',
    '000webhostapp.com', 'duckdns.org', 'ngrok.io', 'ngrok-free.app', 'ngrok.app', 'r2.dev', 'sslip.io', 'nip.io', 'repl.co', 'replit.dev',
    'myshopify.com', 'wordpress.com', 'notion.site', 'gitbook.io', 'surge.sh', 'onrender.com', 'fly.dev', 'herokuapp.com',
    'azurewebsites.net', 'windows.net', 'cloudfront.net', 'amazonaws.com', 'sharepoint.com', 'translate.goog', 'appspot.com',
    'framer.app', 'framer.website', 'carrd.co', 'mystrikingly.com', 'jimdosite.com', 'yolasite.com', 'site123.me', 'webcindario.com',
    'firebasestorage.app', 'web.core.windows.net', 'trycloudflare.com', 'loca.lt', 'serveo.net', 'ddns.net', 'no-ip.org', 'hopto.org'];

  // Big shared services: never flag the whole domain (a single bad file on GitHub must not flag all of GitHub).
  const PROTECTED = ['google.com', 'googleapis.com', 'googleusercontent.com', 'gstatic.com', 'goo.gl', 'forms.gle', 'g.co', 'github.com',
    'githubusercontent.com', 'gitlab.com', 'bitbucket.org', 'dropbox.com', 'dropboxusercontent.com', 'discord.com', 'discord.gg',
    'discordapp.com', 'discordapp.net', 'microsoft.com', 'live.com', 'office.com', 'outlook.com', 'onedrive.com', '1drv.ms',
    'microsoftonline.com', 'mediafire.com', 'mega.nz', 'pastebin.com', 't.me', 'telegram.org', 'telegra.ph', 'archive.org', 'bit.ly',
    'tinyurl.com', 'cutt.ly', 'is.gd', 'rb.gy', 'linkedin.com', 'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
    'youtube.com', 'apple.com', 'icloud.com', 'adobe.com', 'canva.com', 'box.com', 'wetransfer.com', 'we.tl', 'docusign.net',
    'docusign.com', 'jotform.com', 'typeform.com', 'yahoo.com', 'cloudflare.com', 'akamaihd.net', 'fastly.net', 'ipfs.io',
    'dweb.link', 'cloudflare-ipfs.com', 'amazon.com', 'paypal.com', 'whatsapp.com', 'wa.me', 'zoom.us', 'slack.com', 'notion.so',
    'figma.com', 'airtable.com', 'hubspot.com', 'mailchimp.com', 'sendgrid.net', 'salesforce.com', 'force.com', 'zendesk.com',
    'baidu.com', 'baidubce.com', 'qq.com', 'yandex.ru', 'yandex.com', 'vk.com', 'reddit.com', 'medium.com', 'substack.com',
    'gmail.com', 'hotmail.com', 'aol.com', 'proton.me', 'protonmail.com', 'wikipedia.org', 'mozilla.org', 'npmjs.com', 'pypi.org',
    'sourceforge.net', 'filemail.com', 'sendspace.com', 'anonfiles.com', 'transfer.sh', 'catbox.moe', 'imgur.com', 'ibb.co'];

  // Exact hosts that serve many unrelated customers' files under one name.
  const SHARED_HOSTS = ['s3.amazonaws.com', 'raw.githubusercontent.com', 'objects.githubusercontent.com', 'gist.githubusercontent.com',
    'storage.googleapis.com', 'firebasestorage.googleapis.com', 'blob.core.windows.net', 'web.core.windows.net', 'dl.dropboxusercontent.com',
    'cdn.discordapp.com', 'media.discordapp.net', 'drive.google.com', 'docs.google.com', 'sites.google.com', 'pub-r2.dev'];

  const lc = (s) => (s || '').toString().toLowerCase().trim();

  // ---------- 2. parsing feeds ----------
  // One line of a feed -> a lowercase host ('' for comments, blanks and sinkhole addresses). Accepts plain domains,
  // full URLs, "host,label" CSV rows and adblock-style "||host^" lines.
  function hostFromLine(line) {
    let l = line.trim();
    if (!l || l[0] === '#' || l[0] === '!' || l[0] === ';') return '';
    l = l.split(/[\s,]/)[0];
    if (l.startsWith('||')) l = l.slice(2).replace(/\^.*$/, ''); // adblock syntax
    if (/^0\.0\.0\.0$|^127\.0\.0\.1$/.test(l)) return '';
    try {
      const h = new URL(l.includes('://') ? l : 'http://' + l).hostname.toLowerCase().replace(/^\[|\]$/g, '');
      return h.includes('.') || h.includes(':') ? h.replace(/\.$/, '') : '';
    } catch (e) { return ''; }
  }

  // Normalised keys for exact-URL matches: "host/path?query" and "host/path" (www. and trailing slashes dropped),
  // so the same page written slightly differently still matches.
  function urlKeys(u) {
    if (typeof u === 'string') { try { u = new URL(u); } catch (e) { return []; } }
    if (!u || !/^https?:$/.test(u.protocol)) return [];
    const host = lc(u.hostname).replace(/^www\./, '');
    const path = u.pathname.replace(/\/+$/, '');
    const keys = [host + path + (u.search || '')];
    if (u.search) keys.push(host + path);
    return keys;
  }

  // A whole feed -> { hosts: [...], urls: [url keys, only for URL feeds], labels: { host: label, for CSV feeds } }.
  function parseFeed(text, format) {
    const hosts = new Set(), urls = new Set(), labels = {};
    for (const raw of (text || '').split(/\r?\n/)) {
      const line = raw.trim();
      if (!line || line[0] === '#' || line[0] === '!') continue;
      if (format === 'csv-label') {
        const [h, ...rest] = line.split(',');
        const host = hostFromLine(h);
        if (!host || /^(domain|ip|host)$/i.test(h)) continue;
        hosts.add(host);
        const label = rest.join(',').trim();
        if (label) labels[host] = label.slice(0, 80);
      } else {
        const host = hostFromLine(line);
        if (!host) continue;
        hosts.add(host);
        if (format === 'url-lines') urlKeys(line.trim()).forEach((k) => urls.add(k));
      }
    }
    return { hosts: [...hosts], urls: [...urls], labels };
  }

  // ---------- 3. the safety filter ----------
  // May this host be flagged as a whole? False for shared hosts, hosting platforms themselves (but true for their
  // customers' subdomains), big services, and anything in `extraProtected` (brands, free mail, trackers).
  function hostIsFlaggable(host, extraProtected) {
    host = lc(host).replace(/^www\./, '');
    if (SHARED_HOSTS.includes(host)) return false;
    const reg = root.PG_Analyzer.registrableDomain(host);
    const inList = (list, d) => list.some((p) => d === p || d.endsWith('.' + p));
    if (inList(SUBDOMAIN_PLATFORMS, host)) return !SUBDOMAIN_PLATFORMS.includes(host); // evil.vercel.app yes, vercel.app no
    if (inList(PROTECTED, reg) || inList(PROTECTED, host)) return false;
    if (extraProtected && (extraProtected.has(reg) || extraProtected.has(host))) return false;
    return true;
  }

  // Host and its parent domains, most specific first (a.b.evil.com -> a.b.evil.com, b.evil.com, evil.com), so a
  // listed evil.com also catches its subdomains. IP addresses have no parents.
  function hostAndParents(host) {
    host = lc(host);
    if (/^[\d.]+$/.test(host) || host.includes(':')) return [host];
    const parts = host.split('.');
    const out = [];
    for (let i = 0; i < parts.length - 1; i++) out.push(parts.slice(i).join('.'));
    return out;
  }

  // ---------- 4. compact index ----------
  // The threat list is stored as a sorted array of 53-bit hashes instead of ~193k strings.
  // Each record is two Uint32 values: hi = 32 hash bits, lo = 21 more hash bits << 8 | description index.
  // With 53 bits, the chance that a clean host collides with a listed one is about 1 in 40 billion per lookup.
  // File layout (little-endian): "TWI1" magic, Uint32 count, then `count` hi values, then `count` lo values.
  const MAGIC = 0x31495754; // "TWI1"

  // cyrb53 (public domain): a fast, well-distributed 53-bit string hash that gives identical results in browsers and
  // Node (Math.imul keeps the arithmetic in 32-bit integers). Returns [32 high bits, 21 low bits].
  function hash53(str) {
    let h1 = 0xdeadbeef, h2 = 0x41c6ce57;
    for (let i = 0; i < str.length; i++) {
      const ch = str.charCodeAt(i);
      h1 = Math.imul(h1 ^ ch, 2654435761);
      h2 = Math.imul(h2 ^ ch, 1597334677);
    }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507); h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507); h2 ^= Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    return [h1 >>> 0, h2 & 0x1fffff];
  }

  // entries: iterable of [key, descIndex]. Keys are hosts, or 'url:' + urlKey. Lower descIndex wins on duplicates.
  function buildCompact(entries) { return mergeCompact([], entries); }

  // Index -> bytes for data/threat-intel.bin (layout described above).
  function serializeCompact(idx) {
    const n = idx.hi.length;
    const buf = new ArrayBuffer(8 + n * 8);
    const head = new DataView(buf);
    head.setUint32(0, MAGIC, true); head.setUint32(4, n, true);
    new Uint32Array(buf, 8, n).set(idx.hi);
    new Uint32Array(buf, 8 + n * 4, n).set(idx.lo);
    return new Uint8Array(buf);
  }

  // Bytes -> index ({ hi: Uint32Array, lo: Uint32Array }). Throws on anything that isn't a Tripwire list.
  function parseCompact(arrayBuffer) {
    const head = new DataView(arrayBuffer);
    if (head.byteLength < 8 || head.getUint32(0, true) !== MAGIC) throw new Error('not a Tripwire threat index');
    const n = head.getUint32(4, true);
    // Copy into fresh arrays so the views are aligned regardless of the source buffer's offset.
    return { hi: new Uint32Array(arrayBuffer.slice(8, 8 + n * 4)), lo: new Uint32Array(arrayBuffer.slice(8 + n * 4, 8 + n * 8)) };
  }

  // Binary search for `key`. Returns its description index (which source listed it), or -1 if it isn't listed.
  // Records are sorted by (hi, lo without the description byte), the same order mergeCompact produces.
  function lookupCompact(idx, key) {
    const [hi, lo] = hash53(key);
    let a = 0, b = idx.hi.length - 1;
    while (a <= b) {
      const m = (a + b) >>> 1;
      const mh = idx.hi[m];
      if (mh < hi) a = m + 1;
      else if (mh > hi) b = m - 1;
      else {
        const ml = idx.lo[m] >>> 8;
        if (ml < lo) a = m + 1;
        else if (ml > lo) b = m - 1;
        else return idx.lo[m] & 0xff;
      }
    }
    return -1;
  }

  // All records as [hi, lo] pairs whose description index passes `keep` (used to merge bundled + live lists).
  function* compactRecords(idx, keep) {
    for (let i = 0; i < idx.hi.length; i++) if (!keep || keep(idx.lo[i] & 0xff)) yield [idx.hi[i], idx.lo[i]];
  }
  // Builds a sorted, de-duplicated index from existing records (recordIters) plus new [key, descIndex] entries.
  // Each record is packed into one 64-bit BigInt (hi << 32 | lo) so a single native sort orders everything.
  function mergeCompact(recordIters, freshEntries) {
    const packed = [];
    for (const it of recordIters) for (const [hi, lo] of it) packed.push((BigInt(hi) << 32n) | BigInt(lo >>> 0));
    for (const [key, d] of freshEntries) {
      const [hi, lo] = hash53(key);
      packed.push((BigInt(hi) << 32n) | BigInt(((lo << 8) | d) >>> 0));
    }
    const all = BigUint64Array.from(packed).sort();
    const his = [], los = [];
    let prev = -1n;
    for (const v of all) {
      const k = v >> 8n; // hash without the description byte
      if (k === prev) continue; // same key listed twice: keep the first (lowest description index)
      prev = k;
      his.push(Number(v >> 32n)); los.push(Number(v & 0xffffffffn));
    }
    return { hi: Uint32Array.from(his), lo: Uint32Array.from(los) };
  }

  // Entries for one parsed source, already filtered so shared platforms are never flagged as a whole.
  // Returns { entries: [[key, descIndex]], count, skipped }. `descFor(label)` maps a label to a description index.
  function sourceEntries(data, descFor, extraProtected) {
    const entries = [];
    let skipped = 0;
    for (const h of data.hosts || []) {
      if (!hostIsFlaggable(h, extraProtected)) { skipped++; continue; }
      entries.push([h, descFor(data.labels && data.labels[h])]);
    }
    for (const u of data.urls || []) entries.push(['url:' + u, descFor('')]);
    return { entries, count: entries.length, skipped };
  }

  // Host (or one of its parent domains) on the list? Protected hosts and parents are never matched as a whole,
  // even if a list includes them. Returns { matched, desc } or null.
  function lookupHost(idx, host, neverFlag) {
    if (!hostIsFlaggable(host, neverFlag)) return null;
    for (const h of hostAndParents(host)) {
      if (!hostIsFlaggable(h, neverFlag)) return null; // e.g. vercel.app or a brand's domain above a subdomain
      const d = lookupCompact(idx, h);
      if (d >= 0) return { matched: h, desc: d };
    }
    return null;
  }

  // ---------- 5. signed lists ----------
  // The list the Tripwire server hands out is built and signed by the project's GitHub Actions (tools/sign-intel.mjs).
  // Only this public key is shipped. The private key never touches the server, so taking over the server or the
  // Cloudflare account can't forge a list: at worst it can withhold one, and then Tripwire falls back to the public feeds.
  const SIGNING_PUBLIC_KEY = 'X/NMGsz5BIfnmzB6I2LZFCgCb9mxLVXj9yiv7EucimQ=';
  const MAX_LIST_AGE_MS = 3 * 86400000; // an older "fresh" list is treated as withheld updates

  const b64 = (s) => Uint8Array.from(atob(s.trim()), (c) => c.charCodeAt(0));
  const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

  // Throws unless `sig` (base64) is the project's Ed25519 signature over exactly `bytes`.
  // opts.publicKey overrides the shipped key (tests only); opts.crypto supplies WebCrypto where there is no global.
  async function verifySigned(bytes, sig, opts) {
    opts = opts || {};
    const subtle = (opts.crypto || root.crypto).subtle;
    const key = await subtle.importKey('raw', b64(opts.publicKey || SIGNING_PUBLIC_KEY), { name: 'Ed25519' }, false, ['verify']);
    if (!(await subtle.verify({ name: 'Ed25519' }, key, b64(sig), bytes))) throw new Error('bad signature');
  }

  // Webmail layout rules (data/selectors.json): signed like the list; returns the parsed rules.
  async function verifyRules(bytes, sig, opts) {
    await verifySigned(bytes, sig, opts);
    return JSON.parse(new TextDecoder().decode(bytes));
  }

  // Checks a downloaded threat list. metaBytes: meta.json exactly as downloaded; sig: base64 signature of it;
  // bin: the list file. The signature covers meta.json, which pins the list's SHA-256, so both are covered.
  // opts.notOlderThan: date of the list already in use (stops an attacker replaying an old, validly signed list).
  // Returns the parsed meta on success; throws with a reason otherwise.
  async function verifyIntel(metaBytes, sig, bin, opts) {
    opts = opts || {};
    const subtle = (opts.crypto || root.crypto).subtle;
    await verifySigned(metaBytes, sig, opts);
    const meta = JSON.parse(new TextDecoder().decode(metaBytes));
    if (!meta.binSha256 || hex(await subtle.digest('SHA-256', bin)) !== meta.binSha256) throw new Error('list does not match its signed checksum');
    const generated = Date.parse(meta.generated);
    if (!(generated > 0)) throw new Error('no build date');
    if (opts.notOlderThan && generated < Date.parse(opts.notOlderThan)) throw new Error('older than the list already in use');
    if ((opts.now || Date.now()) - generated > MAX_LIST_AGE_MS) throw new Error('list is more than 3 days old');
    const ab = bin instanceof ArrayBuffer ? bin : bin.buffer.slice(bin.byteOffset, bin.byteOffset + bin.byteLength);
    if (parseCompact(ab).hi.length !== meta.total) throw new Error('entry count mismatch');
    return meta;
  }

  root.PG_Intel = {
    SOURCES, SUBDOMAIN_PLATFORMS, PROTECTED, SIGNING_PUBLIC_KEY,                                 // data
    parseFeed, urlKeys, hostIsFlaggable, hostAndParents, sourceEntries,                          // parsing & filtering
    buildCompact, serializeCompact, parseCompact, lookupCompact, lookupHost, compactRecords, mergeCompact, // index
    verifySigned, verifyIntel, verifyRules,                                                      // signatures
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
