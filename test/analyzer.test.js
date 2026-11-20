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
  assert.ok(r.high, describe(r));
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
  assert.ok(r.high, describe(r));
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
