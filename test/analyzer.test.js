// Run with: node --test        (Node 18+, no dependencies)
'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');

const root = join(__dirname, '..');
for (const f of ['src/data.js', 'src/analyzer.js', 'src/intel.js']) require(join(root, f));
const A = globalThis.PG_Analyzer, I = globalThis.PG_Intel;
const C = require('./cases.js');

const describe = (r) => `[${r.level} ${r.score}] ` + (r.signals.map((s) => `${s.id}(${s.weight})`).join(', ') || '-');

for (const [name, input, expected, lists] of C.EMAILS) {
  test(`email: ${name}`, () => {
    const r = A.analyzeEmail(Object.assign({ context: 'open' }, input), lists || {});
    const ok = Array.isArray(expected) ? expected.includes(r.level) : r.level === expected;
    assert.ok(ok, `expected ${expected}, got ${describe(r)}`);
  });
}

for (const [name, input, id] of C.SIGNALS) {
  test(`signal: ${name} -> ${id}`, () => {
    const r = A.analyzeEmail(Object.assign({ context: 'open' }, input), {});
    assert.ok(r.signals.some((s) => s.id === id), `missing ${id}: ${describe(r)}`);
  });
}

for (const [url, bad] of C.URLS) {
  test(`url: ${url}`, () => {
    const r = A.analyzeUrl(url, {});
    assert.equal(r.weight > 0, bad, `weight=${r.weight} ${r.signals.map((s) => s.id).join(',')}`);
  });
}

for (const [name, input, lists, cat] of C.THREATS) {
  test(`known threat: ${name}`, () => {
    const r = A.analyzeEmail(Object.assign({}, C.THREAT_BASE, input), lists);
    assert.equal(r.level, 'phishing', describe(r));
    assert.equal(r.threatCategory, cat);
    assert.equal(r.score, 0);
  });
}

for (const [raw, fields, domain, verdict] of C.AUTH_HEADERS) {
  test(`auth headers: ${raw.split('\n')[0].slice(0, 60)}… -> ${verdict}`, () => {
    const a = A.parseAuthResults(raw);
    if (fields === null) assert.equal(a, null);
    else for (const [k, v] of Object.entries(fields)) assert.equal(a[k], v, k);
    assert.equal(A.authVerdict(a, domain), verdict);
  });
}

test('forged brand address loses brand trust and is strongly suspicious', () => {
  const forged = C.EMAILS.find(([n]) => n.includes('DMARC FAIL'))[1];
  const r = A.analyzeEmail(Object.assign({ context: 'open' }, forged), {});
  assert.equal(r.verifiedBrand, null);
  assert.equal(r.forgedBrand, 'PayPal');
  assert.equal(r.auth, 'fail');
  assert.equal(r.level, 'phishing', describe(r)); // it also asks for the password
  assert.ok(r.signals.some((s) => s.id === 'asks-credentials'), describe(r));
});

test('brand address without an auth check gets less wording discount than a proven one', () => {
  const base = { context: 'open', senderName: 'PayPal', senderEmail: 'service@paypal.com', subject: 'Action required',
    body: 'Please confirm your details within 48 hours to avoid any interruption.', links: [] };
  const unknown = A.analyzeEmail(base, {});
  const proven = A.analyzeEmail(Object.assign({}, base, { auth: { dmarc: 'pass' } }), {});
  assert.equal(unknown.auth, 'unknown');
  assert.equal(proven.auth, 'pass');
  assert.ok(proven.score > unknown.score, `proven ${proven.score} should beat unknown ${unknown.score}`);
});

test('AI summary replaces the extractive summary and AI asks are merged', () => {
  const r = A.analyzeEmail({ context: 'open', senderName: 'A', senderEmail: 'a@b.example', subject: 's', body: 'Hola, por favor pague la factura hoy.',
    links: [], ai: { risk: 'medium', asks: ['payment'], reasons: [], summary: 'Asks you to pay an invoice today.' } }, {});
  assert.equal(r.summary, 'Asks you to pay an invoice today.');
  assert.ok(r.aiSummary);
  assert.ok(r.asks.includes('Make a payment or share payment details'));
});

test('attachment names reversed with an invisible right-to-left character are caught', () => {
  const sigs = A.analyzeAttachments([{ name: 'invoice‮fdp.exe' }, { name: 'report‎.pdf' }], '');
  assert.ok(sigs.some((s) => s.id === 'attachment-rtlo'), sigs.map((s) => s.id).join());
  assert.ok(!sigs.some((s) => s.evidence.includes('report')), 'a harmless invisible mark on a real PDF must not be flagged');
});

// ---------- raw-message tricks (tuned on the EPVME dataset; see tools/eval-dataset.mjs) ----------
const RAW = (headers, body) => headers.join('\r\n') + '\r\n\r\n' + body;
const flags = (raw) => A.inspectRawMessage(raw);
const SIG = 'MIIG' + 'A'.repeat(3000); // stands in for a real S/MIME signature (thousands of base64 characters)

test('raw message: forgery tricks are found', () => {
  assert.ok(flags(RAW(['From: alerts@bank.example', 'From: "Bank Security" <security@realbank.example>', 'Subject: hi'], 'x')).multipleFrom);
  assert.ok(flags(RAW(['  From: test@attack.example', 'From: ceo@company.example'], 'x')).multipleFrom, 'indented injected From');
  assert.ok(flags(RAW(['From: =?utf-8?b?bHVib3dza2lAdmlzYS5jb20==?='], 'x')).encodedAddress, 'address hidden in base64 with bad padding');
  assert.ok(flags(RAW(['From: a@b.example', 'To: <"victim<img src=1 onerror=alert(1)>@victim.example">'], 'x')).headerMarkup);
  assert.ok(flags(RAW(['From: a@b.example', 'Content-Type: text/html'], '<p>hi</p><img src=x onerror="steal()">')).script);
  const shortSig = RAW(['From: a@b.example', 'Content-Type: multipart/signed; protocol="application/x-pkcs7-signature"; boundary="B"'],
    'Buy now at cheap-pills.example, best prices!!!\r\n--B\r\nContent-Type: text/plain\r\n\r\nhello\r\n--B\r\nContent-Type: application/x-pkcs7-signature; name="smime.p7s"\r\nContent-Transfer-Encoding: base64\r\n\r\nMIIBqzCCAV\r\n--B--');
  assert.ok(flags(shortSig).brokenSignature, 'signature far too short');
  assert.ok(flags(shortSig).unsignedPreamble, 'text placed before the signed part');
  const hidden = RAW(['From: a@b.example', 'Content-Type: multipart/mixed; boundary="D"'],
    '--D\r\nContent-Type: text/html\r\n\r\n<p>Pay to account 123</p><style>br{display:none}</style><div style="display:none"><plaintext>\r\n' +
    '--D\r\nContent-Type: multipart/signed; boundary="S"; protocol="application/pgp-signature"\r\n\r\n--S\r\nContent-Type: text/plain\r\n\r\nreal signed text\r\n--S--\r\n--D--');
  assert.ok(flags(hidden).hiddenSignedPart, 'signed part hidden behind forged text');
});

test('raw message: ordinary mail structures are NOT flagged', () => {
  const none = (raw, what) => { const f = flags(raw); for (const [k, v] of Object.entries(f)) assert.ok(!v, `${what}: ${k} flagged`); };
  none(RAW(['From: =?utf-8?b?w4lsb2RpZSBEdXBvbnQ=?= <elodie@example.fr>', 'Subject: =?utf-8?q?R=C3=A9union_demain?='], 'Bonjour'), 'encoded non-English name');
  none(RAW(['From: dev@list.example', 'Subject: Re: <div> tags render oddly in Gmail', 'Content-Type: text/html'],
    '<div style="display:none">Preview text for the inbox</div><p>Use a table instead.</p>'), 'HTML talk + newsletter preheader');
  none(RAW(['From: "Sarah" <sarah@acme.example>', 'Content-Type: multipart/signed; protocol="application/x-pkcs7-signature"; micalg=sha-256; boundary="B"'],
    'This is an S/MIME signed message\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nSigned hello\r\n--B\r\nContent-Type: application/x-pkcs7-signature; name="smime.p7s"\r\n' +
    'Content-Transfer-Encoding: base64\r\n\r\n' + SIG + '\r\n--B--'), 'genuine S/MIME signed email');
  none(RAW(['From: alice@lists.example', 'Content-Type: multipart/mixed; boundary="M"'],
    '--M\r\nContent-Type: multipart/signed; boundary="S"; protocol="application/pgp-signature"\r\n\r\n--S\r\nContent-Type: text/plain\r\n\r\nSigned post\r\n' +
    '--S\r\nContent-Type: application/pgp-signature\r\n\r\n-----BEGIN PGP SIGNATURE-----\r\niQEz...\r\n-----END PGP SIGNATURE-----\r\n--S--\r\n' +
    '--M\r\nContent-Type: text/plain\r\n\r\n_______________\r\nlist footer: unsubscribe at lists.example\r\n--M--'), 'mailing list wrapping a signed post');
  none(RAW(['From: rw@example.at', 'Content-Type: multipart/signed; boundary="P"; protocol="application/pgp-signature"'],
    "This is a multi-part message in MIME format.\r\nIt has been signed conforming to RFC2015.\r\nYou'll need PGP or GPG to check the signature.\r\n\r\n" +
    '--P\r\nContent-Type: text/plain\r\n\r\nHello list\r\n--P\r\nContent-Type: application/pgp-signature\r\n\r\n-----BEGIN PGP SIGNATURE-----\r\niD8D...\r\n-----END PGP SIGNATURE-----\r\n--P--'),
    'PGP mail program\'s stock note before the signed part');
});

// Seen on real mailing-list mail (SpamAssassin corpus): web addresses aren't file attachments.
test('mentioned file names: web addresses are not risky files', () => {
  const att = (body) => A.analyzeEmail({ context: 'open', senderEmail: 'a@b.example', subject: 'x', body, links: [] }, {})
    .signals.some((s) => s.id === 'risky-attachment');
  assert.ok(!att('Download the file from example.com today'), '.com domain');
  assert.ok(!att('The document is at http://site.example/docs/index.html'), 'URL path');
  assert.ok(!att('Open the file at www.site.example/readme.html'), 'www address');
  assert.ok(att('Please open the attached invoice_2291.html to view it'), 'a real .html attachment mention');
  assert.ok(att('Open the attached file setup.exe now'), 'an .exe mention');
});

test('raw-message tricks change the verdict, and survive "trusted sender"', () => {
  const raw = RAW(['From: ceo@company.example', 'From: "CEO" <ceo.office@gmail.com>', 'Subject: Quick task'], 'Can you help with something today?');
  const r = A.analyzeEmail({ context: 'open', senderName: 'CEO', senderEmail: 'ceo@company.example', subject: 'Quick task', body: 'Can you help with something today?',
    links: [], rawMessage: raw }, { trusted: new Set(['ceo@company.example']) });
  assert.equal(r.level, 'suspicious', describe(r));
  assert.ok(r.signals.some((s) => s.id === 'multiple-from'));
});

// ---------- payment changes & reply-chain hijack ----------
test('bank details: valid IBAN / routing / sort code found, invalid numbers ignored', () => {
  const found = A.findBankDetails('IBAN GB82 WEST 1234 5698 7654 32, bad IBAN GB00 WEST 1234 5698 7654 32, ' +
    'routing number 021000021, routing 123456789, sort code 20-00-00 account number 55779911, order 4471.');
  const types = found.map((b) => b.type + ':' + b.id);
  assert.ok(types.includes('iban:GB82WEST12345698765432'), types.join());
  assert.ok(!types.some((t) => t.startsWith('iban:GB00')), 'invalid IBAN accepted');
  assert.ok(types.includes('routing:021000021'), types.join());
  assert.ok(!types.includes('routing:123456789'), 'bad routing checksum accepted');
  assert.ok(types.includes('sortcode:200000'), types.join());
  assert.ok(types.includes('account:55779911'), types.join());
});

test('look-alike candidates include the real domain or address', () => {
  assert.ok(A.lookalikeCandidates('dana@northwlnd-supplies.example').domains.includes('northwind-supplies.example'));
  assert.ok(A.lookalikeCandidates('billing@acrne.com').domains.includes('acme.com'));
  assert.ok(A.lookalikeCandidates('billing@acme.co').domains.includes('acme.com'));
  assert.ok(A.lookalikeCandidates('j.smlth@gmail.com').addresses.includes('j.smith@gmail.com'));
  assert.deepEqual(A.lookalikeCandidates('someone@gmail.com').domains, [], 'free-mail domains are compared by address, not domain');
});

test('hijacked thread with a payment change is very suspicious and gives specific advice', () => {
  const c = C.EMAILS.find(([n]) => n.startsWith('Hijacked thread'))[1];
  const r = A.analyzeEmail(Object.assign({ context: 'open' }, c), {});
  assert.equal(r.level, 'phishing', describe(r)); // a look-alike telling you to send the payment elsewhere
  assert.ok(r.signals.some((s) => s.id === 'thread-lookalike'));
  assert.ok(r.signals.some((s) => s.id === 'payment-change'));
  assert.ok(r.tips[0].startsWith('Before paying, call the company'));
  assert.equal(r.asks[0], 'Send money to a new or different bank account');
});

test('fake "Re:" from a stranger is flagged', () => {
  const r = A.analyzeEmail({ context: 'open', senderName: 'Kim', senderEmail: 'kim@unknown-vendor.example', subject: 'RE: your order',
    body: 'As discussed, please see the details below.', links: [], history: { seenBefore: false, mature: true } }, {});
  assert.ok(r.signals.some((s) => s.id === 'fake-reply'), describe(r));
});

test('every reason has a "Show me" target', () => {
  const inputs = C.EMAILS.filter(([, , level]) => level !== 'safe').map(([, input]) => Object.assign({ context: 'open' }, input));
  inputs.push({ context: 'open', senderName: 'X', senderEmail: 'x@y.example', subject: 's', body: 'b', links: [], hasForm: true,
    attachments: [{ name: 'a.pdf.html' }], qrCodes: [{ data: 'https://micros0ft-login.example/x', src: 'https://img.example/qr.png' }] });
  for (const input of inputs) {
    const r = A.analyzeEmail(input, {});
    for (const s of r.signals) if (s.category !== 'ai') assert.ok(s.target && s.target.type, `${s.id} in "${input.subject}" has no target`);
  }
  const qr = A.analyzeEmail(inputs[inputs.length - 1], {}).signals.find((s) => s.id === 'qr-code');
  assert.deepEqual(qr.target, { type: 'image', src: 'https://img.example/qr.png' });
});

// ---------- practice lessons agree with the analyzer ----------
require(join(root, 'practice/lessons.js'));
for (const l of globalThis.TW_LESSONS) {
  test(`practice lesson ${l.id} is judged ${l.id.startsWith('safe') ? 'safe' : 'risky'}`, () => {
    const x = l.extra || {};
    const r = A.analyzeEmail(Object.assign({ context: 'open' }, l.email, { auth: x.auth, attachments: x.attachments, qrCodes: x.qrCodes, history: x.history, thread: x.thread }),
      { expanded: new Map(x.expanded || []) });
    if (l.id.startsWith('safe')) assert.equal(r.level, 'safe', describe(r));
    else assert.notEqual(r.level, 'safe', describe(r));
  });
}

// ---------- manifest ----------
test('manifest grants every link shortener the background worker follows', () => {
  const m = JSON.parse(readFileSync(join(root, 'manifest.json'), 'utf8'));
  for (const s of globalThis.PG_DATA.SHORTENERS) assert.ok(m.host_permissions.includes(`*://${s}/*`), `missing host permission for ${s}`);
  assert.ok(!m.content_scripts.some((c) => c.matches.includes('<all_urls>')), 'content script must not run on every site');
});

// ---------- compact threat index ----------
test('compact index: round trip, duplicates keep the first description, misses return -1', () => {
  const idx = I.buildCompact([['evil.example', 3], ['url:host.example/p', 1], ['evil.example', 7], ['other.example', 0]]);
  const back = I.parseCompact(I.serializeCompact(idx).buffer);
  assert.equal(back.hi.length, 3);
  assert.equal(I.lookupCompact(back, 'evil.example'), 3);
  assert.equal(I.lookupCompact(back, 'url:host.example/p'), 1);
  assert.equal(I.lookupCompact(back, 'other.example'), 0);
  assert.equal(I.lookupCompact(back, 'clean.example'), -1);
});

test('compact index: merging drops replaced sources and adds fresh entries', () => {
  const bundled = I.buildCompact([['a.example', 0], ['b.example', 1]]);
  const merged = I.mergeCompact([I.compactRecords(bundled, (d) => d !== 1)], [['c.example', 1]]);
  assert.equal(I.lookupCompact(merged, 'a.example'), 0);
  assert.equal(I.lookupCompact(merged, 'b.example'), -1);
  assert.equal(I.lookupCompact(merged, 'c.example'), 1);
});

// ---------- the real bundled list ----------
const meta = JSON.parse(readFileSync(join(root, 'data/threat-intel.meta.json'), 'utf8'));
const bin = readFileSync(join(root, 'data/threat-intel.bin'));
const idx = I.parseCompact(bin.buffer.slice(bin.byteOffset, bin.byteOffset + bin.byteLength));
const isBad = (host) => I.hostAndParents(host).some((h) => I.lookupCompact(idx, h) >= 0);

test('bundled list loads and matches its metadata', () => {
  assert.equal(idx.hi.length, meta.total);
  assert.ok(meta.total > 1000, 'list looks too small');
  assert.ok(meta.descs.length <= 255);
});

const POPULAR = ['mail.google.com', 'www.google.com', 'drive.google.com', 'docs.google.com', 'github.com', 'raw.githubusercontent.com',
  'www.dropbox.com', 'outlook.live.com', 'login.microsoftonline.com', 'onedrive.live.com', 'www.paypal.com', 'www.amazon.com', 'www.chase.com',
  'www.bankofamerica.com', 'www.apple.com', 'www.facebook.com', 'www.linkedin.com', 'zoom.us', 'www.netflix.com', 'cdn.discordapp.com',
  'discord.com', 't.me', 'bit.ly', 'www.youtube.com', 'en.wikipedia.org', 'vercel.app', 'blogspot.com', 's3.amazonaws.com', 'sendgrid.net',
  'mail.yahoo.com', 'www.irs.gov', 'www.usps.com', 'www.fedex.com', 'www.ups.com', 'www.dhl.com', 'www.walmart.com', 'www.ebay.com'];
for (const h of POPULAR) test(`popular site is never flagged: ${h}`, () => assert.equal(isBad(h), false));

for (const s of meta.sources) {
  test(`source ${s.id} (${s.category}) contributes and its sample is detected`, () => {
    assert.ok(s.count > 0, 'no entries');
    if (s.sample) {
      const d = I.lookupCompact(idx, s.sample);
      assert.ok(d >= 0, `${s.sample} not found`); // may be credited to an earlier source that lists it too
    }
  });
}

test('direct requests: real asks are found, everyday wording is not', () => {
  const asks = [
    ['Please respond to this email with your email and password', 'credentials'],
    ['Reply with your username and password so I can fix it.', 'credentials'],
    ['Send us your SSN and date of birth.', 'credentials'],
    ['What is your PIN?', 'credentials'],
    ['We need your social security number to process this.', 'credentials'],
    ['Please send me $300 today.', 'money'],
    ['Wire the funds before noon.', 'money'],
    ['Buy three Apple gift cards and send me the codes.', 'money'],
    ['Zelle me when you can.', 'money'],
    ['Send 0.05 bitcoin to this wallet.', 'money'],
  ];
  for (const [text, kind] of asks) assert.ok(A.findDirectRequests(text)[kind].length, `${kind} not found in: ${text}`);
  const ordinary = [
    'We will never ask for your password by email.',
    'Do not share your one-time code with anyone.',
    'Click the link to enter your new password.',
    'Can you send me the slides?',
    'Please share your feedback on the draft.',
    'Your password was changed successfully.',
    'Enter your email to subscribe to our newsletter.',
    'We sent a verification code to your phone.',
    'Your refund of $20 has been sent to your card.',
    'Pin the post to the top of the channel.',
  ];
  for (const text of ordinary) {
    const r = A.findDirectRequests(text);
    assert.equal(r.credentials.length + r.money.length, 0, `false alarm on: ${text} -> ${JSON.stringify(r)}`);
  }
});
