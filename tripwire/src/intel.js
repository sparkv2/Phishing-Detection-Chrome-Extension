// Threat-intelligence sources, feed parsing and the safety filter that keeps shared platforms from being flagged wholesale.
// Used by the background worker (to build its lookup index) and by content scripts (for URL keys).
(function (root) {
  'use strict';

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

  // Normalised keys for URL-level matches: host+path+query and host+path.
  function urlKeys(u) {
    if (typeof u === 'string') { try { u = new URL(u); } catch (e) { return []; } }
    if (!u || !/^https?:$/.test(u.protocol)) return [];
    const host = lc(u.hostname).replace(/^www\./, '');
    const path = u.pathname.replace(/\/+$/, '');
    const keys = [host + path + (u.search || '')];
    if (u.search) keys.push(host + path);
    return keys;
  }

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

  // Should this host be flagged as a whole? (false for shared platforms and well-known services)
  function hostIsFlaggable(host, extraProtected) {
    host = lc(host).replace(/^www\./, '');
    if (SHARED_HOSTS.includes(host)) return false;
    const reg = root.PG_Analyzer.registrableDomain(host);
    const inList = (list, d) => list.some((p) => d === p || d.endsWith('.' + p));
    if (inList(SUBDOMAIN_PLATFORMS, host)) {
      // flag customer subdomains, never the platform itself
      return !SUBDOMAIN_PLATFORMS.includes(host) && !SUBDOMAIN_PLATFORMS.includes(host.replace(/^www\./, ''));
    }
    if (inList(PROTECTED, reg) || inList(PROTECTED, host)) return false;
    if (extraProtected && (extraProtected.has(reg) || extraProtected.has(host))) return false;
    return true;
  }

  // Host and its parent domains, most specific first (a.b.evil.com -> a.b.evil.com, b.evil.com, evil.com)
  function hostAndParents(host) {
    host = lc(host);
    if (/^[\d.]+$/.test(host) || host.includes(':')) return [host];
    const parts = host.split('.');
    const out = [];
    for (let i = 0; i < parts.length - 1; i++) out.push(parts.slice(i).join('.'));
    return out;
  }

  const CATEGORY_TEXT = {
    phishing: 'phishing (fake login / payment pages)',
    malware: 'malware (sites that spread viruses or ransomware)',
    c2: 'command-and-control (servers criminals use to control hacked computers)',
  };

  root.PG_Intel = { SOURCES, SUBDOMAIN_PLATFORMS, PROTECTED, parseFeed, urlKeys, hostIsFlaggable, hostAndParents, hostFromLine, CATEGORY_TEXT };
})(typeof globalThis !== 'undefined' ? globalThis : this);
