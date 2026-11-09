// Reference data used by the analyzer. Everything here is local — nothing is fetched at scan time.
(function (root) {
  'use strict';

  // Brands commonly impersonated in phishing. `keywords` are what appears in display names / text,
  // `domains` are the registrable domains the brand really sends mail and hosts links from.
  const BRANDS = [
    { name: 'PayPal', keywords: ['paypal'], domains: ['paypal.com', 'paypal.me', 'paypal-communication.com', 'paypalobjects.com'] },
    { name: 'Apple', keywords: ['apple', 'icloud', 'itunes', 'apple id'], domains: ['apple.com', 'icloud.com', 'me.com', 'itunes.com', 'apple.news'] },
    { name: 'Microsoft', keywords: ['microsoft', 'office 365', 'office365', 'outlook', 'onedrive', 'microsoft 365', 'xbox'], domains: ['microsoft.com', 'office.com', 'office365.com', 'microsoftonline.com', 'live.com', 'outlook.com', 'onedrive.com', 'sharepoint.com', 'xbox.com', 'microsoft365.com', 'msn.com', 'azure.com'] },
    { name: 'Google', keywords: ['google', 'gmail', 'google drive', 'youtube'], domains: ['google.com', 'youtube.com', 'googlemail.com', 'gmail.com', 'goo.gl', 'googleusercontent.com', 'withgoogle.com', 'google.co.uk'] },
    { name: 'Amazon', keywords: ['amazon', 'amazon prime', 'prime video', 'aws'], domains: ['amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.de', 'amazon.in', 'amazon.com.au', 'amazon.fr', 'amazon.co.jp', 'amazonaws.com', 'aws.com', 'amzn.to', 'primevideo.com', 'a.co'] },
    { name: 'Netflix', keywords: ['netflix'], domains: ['netflix.com', 'nflxext.com'] },
    { name: 'Facebook', keywords: ['facebook', 'meta', 'instagram', 'whatsapp'], domains: ['facebook.com', 'facebookmail.com', 'meta.com', 'instagram.com', 'whatsapp.com', 'fb.com', 'fb.me'] },
    { name: 'Bank of America', keywords: ['bank of america', 'bankofamerica'], domains: ['bankofamerica.com', 'bofa.com', 'ml.com'] },
    { name: 'Chase', keywords: ['chase', 'jpmorgan chase', 'chase bank'], domains: ['chase.com', 'jpmorgan.com', 'jpmorganchase.com'] },
    { name: 'Wells Fargo', keywords: ['wells fargo', 'wellsfargo'], domains: ['wellsfargo.com', 'wf.com'] },
    { name: 'Citibank', keywords: ['citibank', 'citi'], domains: ['citi.com', 'citibank.com'] },
    { name: 'Capital One', keywords: ['capital one', 'capitalone'], domains: ['capitalone.com'] },
    { name: 'American Express', keywords: ['american express', 'amex'], domains: ['americanexpress.com', 'aexp.com'] },
    { name: 'DHL', keywords: ['dhl'], domains: ['dhl.com', 'dhl.de'] },
    { name: 'FedEx', keywords: ['fedex'], domains: ['fedex.com'] },
    { name: 'UPS', keywords: ['ups'], domains: ['ups.com'] },
    { name: 'USPS', keywords: ['usps', 'postal service'], domains: ['usps.com', 'usps.gov'] },
    { name: 'IRS', keywords: ['irs', 'internal revenue service'], domains: ['irs.gov'] },
    { name: 'Coinbase', keywords: ['coinbase'], domains: ['coinbase.com'] },
    { name: 'DocuSign', keywords: ['docusign'], domains: ['docusign.com', 'docusign.net'] },
    { name: 'Dropbox', keywords: ['dropbox'], domains: ['dropbox.com', 'dropboxmail.com'] },
    { name: 'LinkedIn', keywords: ['linkedin'], domains: ['linkedin.com', 'lnkd.in'] },
    { name: 'Adobe', keywords: ['adobe'], domains: ['adobe.com', 'adobesign.com'] },
    { name: 'Zoom', keywords: ['zoom'], domains: ['zoom.us', 'zoom.com'] },
    { name: 'Venmo', keywords: ['venmo'], domains: ['venmo.com'] },
    { name: 'Cash App', keywords: ['cash app', 'cashapp'], domains: ['cash.app', 'square.com', 'squareup.com'] },
    { name: 'Walmart', keywords: ['walmart'], domains: ['walmart.com'] },
    { name: 'Steam', keywords: ['steam'], domains: ['steampowered.com', 'steamcommunity.com'] },
    { name: 'Spotify', keywords: ['spotify'], domains: ['spotify.com'] },
    { name: 'eBay', keywords: ['ebay'], domains: ['ebay.com', 'ebay.co.uk'] },
    { name: 'Yahoo', keywords: ['yahoo'], domains: ['yahoo.com', 'yahoo-inc.com', 'yahoomail.com'] },
    { name: 'Roblox', keywords: ['roblox'], domains: ['roblox.com'] },
    { name: 'Discord', keywords: ['discord'], domains: ['discord.com', 'discord.gg', 'discordapp.com'] },
  ];

  // Words that can surround a brand name in a display name without changing who it claims to be.
  const SERVICE_WORDS = ['support', 'security', 'team', 'service', 'services', 'account', 'accounts', 'billing',
    'alert', 'alerts', 'notification', 'notifications', 'customer', 'care', 'help', 'helpdesk', 'desk', 'no', 'reply',
    'noreply', 'no-reply', 'info', 'center', 'centre', 'online', 'official', 'admin', 'administrator', 'verification',
    'department', 'dept', 'payments', 'payment', 'mail', 'com', 'inc', 'the', 'via', 'id', 'store', 'shipping',
    'delivery', 'express', 'bank', 'banking', 'card', 'cards', 'services', 'update', 'updates', 'secure', 'safety',
    'protection', 'fraud', 'prevention', 'membership', 'premium', 'prime', 'cloud', 'drive', 'pay', 'wallet', 'us', 'usa'];

  // Words often glued to a brand name in fake domains, e.g. paypal-secure-login.com
  const PHISH_DOMAIN_WORDS = ['secure', 'security', 'login', 'signin', 'verify', 'verification', 'account', 'accounts',
    'support', 'help', 'service', 'services', 'update', 'billing', 'alert', 'confirm', 'auth', 'online', 'customer',
    'recovery', 'unlock', 'wallet', 'pay', 'payment', 'id', 'web', 'app', 'center', 'team', 'access', 'portal', 'official',
    'alerts', 'notice', 'check', 'mail', 'info', 'refund', 'reset', 'password', 'locked', 'safe', 'auth', 'sso', 'bill',
    'delivery', 'redelivery', 'tracking', 'track', 'parcel', 'shipping', 'package', 'fee', 'tax', 'gov', 'bank'];

  const FREE_MAIL = ['gmail.com', 'googlemail.com', 'yahoo.com', 'ymail.com', 'outlook.com', 'hotmail.com', 'live.com',
    'msn.com', 'aol.com', 'icloud.com', 'me.com', 'mac.com', 'proton.me', 'protonmail.com', 'gmx.com', 'gmx.net',
    'mail.com', 'yandex.com', 'yandex.ru', 'zoho.com', 'tutanota.com', 'mail.ru', 'qq.com', '163.com', 'inbox.com'];

  // TLDs that are cheap/free and disproportionately used for phishing. Mild signal only.
  const SUSPICIOUS_TLDS = ['zip', 'mov', 'xyz', 'top', 'click', 'link', 'gq', 'tk', 'ml', 'cf', 'ga', 'work', 'rest',
    'country', 'kim', 'cam', 'buzz', 'icu', 'monster', 'cyou', 'sbs', 'cfd', 'quest', 'bond', 'lol', 'mom', 'beauty',
    'hair', 'skin', 'makeup', 'boats', 'autos', 'yachts', 'today', 'surf', 'loan', 'win', 'bid', 'date', 'review', 'stream'];

  const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly',
    'shorturl.at', 'rb.gy', 'tiny.cc', 's.id', 'v.gd', 'bl.ink', 'short.io', 'tr.im', 'qr.co', 'lnkd.in', 'shorte.st'];

  // Legitimate email-marketing / click-tracking services. A link wrapped by these is normal in newsletters,
  // so "text says X, link goes to tracker" is not by itself treated as a mismatch.
  const TRACKING_DOMAINS = ['sendgrid.net', 'list-manage.com', 'mailchimp.com', 'mcusercontent.com', 'hubspotlinks.com',
    'hubspotemail.net', 'hs-sites.com', 'mandrillapp.com', 'mailgun.org', 'mailgun.net', 'exacttarget.com',
    'rs6.net', 'createsend.com', 'cmail19.com', 'cmail20.com', 'klclick.com', 'klclick1.com', 'klaviyomail.com',
    'braze.com', 'sparkpostmail.com', 'awstrack.me', 'mlsend.com', 'substack.com', 'mailjet.com', 'sendibt3.com',
    'sendinblue.com', 'brevo.com', 'constantcontact.com', 'marketo.com', 'mktoweb.com', 'mkt.com', 'pardot.com',
    'salesforce.com', 'iterable.com', 'customer.io', 'convertkit-mail.com', 'ck.page', 'beehiiv.com', 'medallia.com',
    'urldefense.com', 'mimecast.com', 'protection.outlook.com', 'linkedin.com', 'google.com'];

  // Multi-part public suffixes so "evil.co.uk" -> registrable "evil.co.uk", not "co.uk".
  const MULTI_SUFFIXES = ['co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk', 'ltd.uk', 'com.au', 'net.au', 'org.au',
    'co.nz', 'co.jp', 'ne.jp', 'or.jp', 'co.in', 'net.in', 'org.in', 'com.br', 'com.mx', 'com.ar', 'com.tr', 'com.cn',
    'com.hk', 'com.sg', 'com.my', 'co.za', 'co.kr', 'com.et', 'com.ng', 'com.pk', 'com.ph', 'com.vn', 'com.ua', 'com.co'];

  // Coercion & request phrases. Each pattern is a regex source matched case-insensitively against text.
  const PHRASES = {
    urgency: [
      'urgent', 'immediately', 'right away', 'act now', 'action required', 'immediate action', 'as soon as possible',
      'within (?:24|48|72|12|2) ?h(?:ou)?rs?', 'within \\d+ (?:hours|days)', 'final (?:notice|warning|reminder)',
      'last (?:chance|warning|notice)', 'expires? (?:today|tonight|soon)', 'time[- ]sensitive', 'respond now',
      'don\'t delay', 'do not delay', 'before it\'s too late', 'today only', 'deadline', 'failure to (?:respond|comply|verify)',
    ],
    fear: [
      'suspend(?:ed|sion)?', 'will be (?:closed|terminated|deleted|disabled|locked|deactivated)', 'account (?:has been |is )?(?:locked|limited|restricted|on hold|disabled|frozen)',
      'unauthori[sz]ed (?:access|activity|login|transaction|charge)', 'unusual (?:activity|sign[- ]?in|login)',
      'suspicious (?:activity|login|sign[- ]?in|transaction)', 'security (?:alert|breach|warning)', 'legal action',
      'arrest', 'warrant', 'lawsuit', 'penalt(?:y|ies)', 'compromised', 'been hacked', 'law enforcement',
      'permanently (?:lose|deleted|closed)', 'lose access', 'blocked',
    ],
    credentials: [
      'verify your (?:account|identity|information|details|email|login)', 'confirm your (?:account|identity|password|details|information|login)',
      'validate your (?:account|identity|email)', '(?:enter|provide|submit|send|share|update) your (?:password|login|credentials|pin|passcode)',
      'password (?:will )?expir(?:e|es|ed|ing)', 'your password expires', 'login (?:details|credentials|information)',
      'sign[- ]?in to (?:verify|confirm|restore|unlock|avoid)', 'log[- ]?in to (?:verify|confirm|restore|unlock|avoid)',
      'update your (?:account|billing|payment) (?:information|details)', 'security questions?', 'social security number',
      '\\bssn\\b', 'mother\'?s maiden name', '(?:send|share|reply with|give us|tell us) (?:the |your )?(?:verification |security |one[- ]time )?code',
      're-?enter your', 'reactivate your account', 'restore (?:your )?(?:account|access)', 'unlock your account',
    ],
    financial: [
      'wire transfer', 'gift ?cards?', 'bank (?:account|details|information)', 'credit card (?:number|details|information)',
      'card (?:number|details)', 'routing number', 'payment (?:details|information|failed|declined|overdue)',
      'update (?:your )?payment', 'outstanding (?:balance|invoice|payment)', 'overdue (?:invoice|payment|balance)',
      'bitcoin', 'crypto(?:currency)? (?:wallet|payment)', 'western union', 'moneygram', 'billing (?:information|problem|issue)',
      'refund (?:is )?(?:pending|available|waiting)', 'claim your refund', 'tax refund', 'send (?:me |us )?(?:the )?money',
      'pay (?:a |the )?(?:fee|fine)', 'processing fee', 'unpaid',
    ],
    prize: [
      'you(?:\'ve| have)? won', 'congratulations', 'lottery', 'claim your (?:prize|reward|gift)', 'free gift',
      'inheritance', 'million (?:dollars|usd)', 'beneficiary', 'selected (?:as|to receive)', 'exclusive reward', 'jackpot',
    ],
    greeting: [
      'dear (?:customer|user|client|member|account holder|valued|sir|madam|beneficiary|friend|email user|account owner)',
    ],
    secrecy: [
      'keep this (?:confidential|between us|private)', 'don\'t tell anyone', 'do not tell anyone', 'are you available\\?',
      'i need a favou?r', 'can you do me a favou?r', 'i\'m in a meeting', 'i am in a meeting',
    ],
  };

  const RISKY_ATTACHMENT = /\b[\w\- ]{1,60}\.(exe|scr|js|jse|vbs|vbe|bat|cmd|com|pif|msi|iso|img|hta|wsf|lnk|jar|ps1|docm|xlsm|pptm|html?|shtml)\b/i;

  // Tiny built-in list for demos & tests. The real list is downloaded from OpenPhish by the background worker
  // and compared locally. Users' own reports are added to a separate local list.
  const BUILTIN_BLOCKLIST = ['paypa1-security.com', 'appleid-verify-account.com', 'micros0ft-login.net',
    'secure-chase-alerts.com', 'amaz0n-billing.com', 'netflix-payment-update.top'];

  root.PG_DATA = { BRANDS, SERVICE_WORDS, PHISH_DOMAIN_WORDS, FREE_MAIL, SUSPICIOUS_TLDS, SHORTENERS,
    TRACKING_DOMAINS, MULTI_SUFFIXES, PHRASES, RISKY_ATTACHMENT, BUILTIN_BLOCKLIST };
})(typeof globalThis !== 'undefined' ? globalThis : this);
