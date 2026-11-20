#!/usr/bin/env node
// =====================================================================================================================
// Accuracy check: runs Tripwire's analyzer over a folder of .eml files and reports what it catches.
//
//   node tools/eval-dataset.mjs <folder> [--label malicious|benign] [--split train|test|all] [--json out.json]
//                                        [--no-raw] [--any-file] [--limit N]
//
// Each email is decoded the way a mail client shows it (headers, multipart, base64 / quoted-printable, HTML -> text,
// links with their visible text, attachment names) and analysed with the same code the extension runs, including
// the bundled threat list. The raw headers are also passed in, as the extension gets them from Gmail's "Show
// original". --split uses a fixed hash of the file name: 70% "train" (for tuning), 30% "test" (to check the tuning
// generalises). Nothing is sent anywhere; the dataset is only read.
// =====================================================================================================================
import { createRequire } from 'node:module';
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
for (const f of ['src/data.js', 'src/analyzer.js', 'src/intel.js']) require(join(root, f));
const A = globalThis.PG_Analyzer, I = globalThis.PG_Intel, D = globalThis.PG_DATA;

// ---------- arguments ----------
const args = process.argv.slice(2);
const opt = (name, dflt) => (args.includes(name) ? args[args.indexOf(name) + 1] : dflt);
const folder = args.find((a) => !a.startsWith('--') && args[args.indexOf(a) - 1]?.startsWith('--') !== true);
if (!folder) { console.error('usage: node tools/eval-dataset.mjs <folder> [--label malicious|benign] [--split train|test|all] [--json out.json]'); process.exit(2); }
const label = opt('--label', 'malicious');
const split = opt('--split', 'all');
const jsonOut = opt('--json', null);
const limit = Number(opt('--limit', '0')) || Infinity;
// --no-raw: analyse only what a webmail page shows (Outlook / Yahoo). By default the raw message is used too, as on Gmail.
const useRaw = !args.includes('--no-raw');
// --any-file: read every file as an email, not just *.eml (e.g. the SpamAssassin corpus, which has no extensions).
const anyFile = args.includes('--any-file');

// ---------- the threat list, exactly as the extension loads it ----------
const meta = JSON.parse(readFileSync(join(root, 'data/threat-intel.meta.json'), 'utf8'));
const bin = readFileSync(join(root, 'data/threat-intel.bin'));
const idx = I.parseCompact(bin.buffer.slice(bin.byteOffset, bin.byteOffset + bin.byteLength));
const NEVER = new Set([...D.BRANDS.flatMap((b) => b.domains), ...D.FREE_MAIL, ...D.TRACKING_DOMAINS]);
function threatsFor(hosts) {
  const m = new Map();
  for (const h of hosts) { const hit = I.lookupHost(idx, h, NEVER); m.set(h, hit ? Object.assign({ matched: hit.matched }, meta.descs[hit.desc]) : null); }
  return m;
}

// ---------- decoding an .eml ----------
// Header block -> [{ name (lowercase), value }] in order, with folded lines joined. Lines that start with
// whitespace before any header (an injection trick in this dataset) are kept as their own header line.
function parseHeaders(block) {
  const out = [];
  for (const line of block.split(/\r?\n/)) {
    if (/^[ \t]/.test(line) && out.length && !/^\s+[\w-]+:/.test(line)) { out[out.length - 1].value += ' ' + line.trim(); continue; }
    const m = line.trim().match(/^([\w-]+):\s?(.*)$/);
    if (m) out.push({ name: m[1].toLowerCase(), value: m[2], indented: /^[ \t]/.test(line) });
  }
  return out;
}
const header = (hs, name) => (hs.find((h) => h.name === name) || {}).value || '';
// RFC 2047 encoded words: =?utf-8?B?...?= and =?iso-8859-1?Q?...?=
function decodeWords(s) {
  return (s || '').replace(/=\?([^?]+)\?([bq])\?([^?]*)\?=/gi, (_, cs, enc, txt) => {
    try {
      const buf = enc.toLowerCase() === 'b' ? Buffer.from(txt, 'base64')
        : Buffer.from(txt.replace(/_/g, ' ').replace(/=([0-9a-f]{2})/gi, (m, h) => String.fromCharCode(parseInt(h, 16))), 'latin1');
      return new TextDecoder(/utf-?8/i.test(cs) ? 'utf-8' : 'latin1').decode(buf);
    } catch (e) { return txt; }
  });
}
function decodeBody(raw, encoding, charset) {
  let buf;
  if (/base64/i.test(encoding)) buf = Buffer.from(raw.replace(/\s+/g, ''), 'base64');
  else if (/quoted-printable/i.test(encoding)) buf = Buffer.from(raw.replace(/=\r?\n/g, '').replace(/=([0-9a-f]{2})/gi, (m, h) => String.fromCharCode(parseInt(h, 16))), 'latin1');
  else buf = Buffer.from(raw, 'latin1');
  try { return new TextDecoder(/utf-?8/i.test(charset || '') ? 'utf-8' : 'latin1').decode(buf); } catch (e) { return buf.toString('latin1'); }
}
const param = (v, name) => { const m = (v || '').match(new RegExp(name + '\\s*=\\s*"?([^";]+)"?', 'i')); return m ? m[1].trim() : ''; };
// Walks the MIME tree. Returns { text: [...], html: [...], attachments: [names], signed }.
function walk(raw, out, depth = 0) {
  const sep = raw.search(/\r?\n\r?\n/);
  const hs = parseHeaders(sep < 0 ? raw : raw.slice(0, sep));
  const body = sep < 0 ? '' : raw.slice(sep).replace(/^\r?\n\r?\n/, '');
  const ct = header(hs, 'content-type') || 'text/plain';
  const disp = header(hs, 'content-disposition');
  const name = decodeWords(param(disp, 'filename') || param(ct, 'name'));
  if (/multipart\/signed/i.test(ct)) out.signed = true;
  if (/^multipart\//i.test(ct) && depth < 8) {
    const b = param(ct, 'boundary');
    if (b) for (const part of body.split('--' + b).slice(1)) { if (!part.startsWith('--')) walk(part.replace(/^\r?\n/, ''), out, depth + 1); }
    return out;
  }
  if (name || /attachment/i.test(disp)) { out.attachments.push(name || '(unnamed)'); return out; }
  const decoded = decodeBody(body, header(hs, 'content-transfer-encoding'), param(ct, 'charset'));
  if (/text\/html/i.test(ct)) out.html.push(decoded); else if (/text\/plain/i.test(ct) || !/\//.test(ct)) out.text.push(decoded);
  return out;
}
const ENT = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };
const unent = (s) => s.replace(/&(#x?[0-9a-f]+|\w+);/gi, (m, e) => (e[0] === '#' ? String.fromCodePoint(parseInt(e.slice(1).replace(/^x/i, ''), /^#x/i.test(e) ? 16 : 10) || 32) : (ENT[e.toLowerCase()] ?? m)));
const htmlText = (h) => unent(h.replace(/<(script|style)[\s\S]*?<\/\1>/gi, ' ').replace(/<br\s*\/?>|<\/p>|<\/div>|<\/tr>/gi, '\n').replace(/<[^>]+>/g, ' ')).replace(/[ \t]+/g, ' ');

function readEmail(path) {
  const raw = readFileSync(path, 'latin1');
  const sep = raw.search(/\r?\n\r?\n/);
  const hs = parseHeaders(sep < 0 ? raw : raw.slice(0, sep));
  const parts = walk(raw, { text: [], html: [], attachments: [], signed: false });
  const html = parts.html.join('\n');
  const links = [];
  for (const m of html.matchAll(/<a\b[^>]*\bhref\s*=\s*["']?([^"'\s>]+)["']?[^>]*>([\s\S]*?)<\/a>/gi)) links.push({ href: unent(m[1]), text: htmlText(m[2]).trim() });
  const body = (parts.text.join('\n') || htmlText(html)).replace(/\r/g, '');
  if (!links.length) for (const m of body.matchAll(/\bhttps?:\/\/[^\s<>"')]+/gi)) links.push({ href: m[0], text: m[0] });
  // What a webmail page shows as the sender: the first From header that has an address.
  const froms = hs.filter((h) => h.name === 'from').map((h) => decodeWords(h.value));
  const shown = froms.find((f) => /@/.test(f)) || froms[0] || '';
  const em = shown.match(/<([^>]+@[^>]+)>/) || shown.match(/[^\s<>"]+@[^\s<>"]+/);
  const email = em ? (em[1] || em[0]).trim() : '';
  const name = shown.replace(/<[^>]*>/, '').replace(email, '').replace(/["']/g, '').trim();
  return { hs, froms, senderName: name, senderEmail: email, subject: decodeWords(header(hs, 'subject')), body: body.slice(0, 50000),
    html, links: links.slice(0, 300), attachments: parts.attachments.map((n) => ({ name: n })),
    hasForm: /<form\b|<input[^>]+type\s*=\s*["']?password/i.test(html), signed: parts.signed, raw };
}

// ---------- run ----------
const inSplit = (file) => {
  if (split === 'all') return true;
  const h = createHash('sha1').update(file).digest()[0]; // 0-255, fixed per file
  return split === 'train' ? h < 179 : h >= 179; // ~70% / 30%
};
function* files(dir) {
  for (const n of readdirSync(dir)) {
    const p = join(dir, n);
    if (statSync(p).isDirectory()) yield* files(p);
    else if ((anyFile ? n !== 'cmds' && !n.startsWith('.') : /\.eml$/i.test(n)) && inSplit(n)) yield p;
  }
}

const levels = { safe: 0, suspicious: 0, phishing: 0 };
const signalCounts = {};
const scores = new Array(11).fill(0);
const rows = [];
let n = 0, failed = 0, high = 0;
const started = Date.now();
for (const path of files(folder)) {
  if (n >= limit) break;
  let mail;
  try { mail = readEmail(path); } catch (e) { failed++; continue; }
  const hosts = [mail.senderEmail.split('@')[1], ...mail.links.map((l) => { try { return new URL(l.href).hostname; } catch (e) { return ''; } })].filter(Boolean).map((h) => h.toLowerCase());
  const r = A.analyzeEmail({ senderName: mail.senderName, senderEmail: mail.senderEmail, subject: mail.subject, body: mail.body, links: mail.links,
    hasForm: mail.hasForm, attachments: mail.attachments, auth: A.parseAuthResults(mail.raw),
    rawMessage: useRaw ? mail.raw : undefined, context: 'open' }, { threats: threatsFor(hosts) });
  n++;
  levels[r.level]++; if (r.high) high++;
  scores[Math.min(10, Math.floor(r.score / 10))]++;
  for (const s of new Set(r.signals.map((x) => x.id))) signalCounts[s] = (signalCounts[s] || 0) + 1;
  if (jsonOut) rows.push({ file: path.slice(folder.length + 1), level: r.level, score: r.score, signals: r.signals.map((x) => x.id) });
  if (n % 5000 === 0) process.stderr.write(`  ${n} emails...\n`);
}

const pct = (x) => (n ? (100 * x / n).toFixed(1) + '%' : '-');
const flagged = levels.suspicious + levels.phishing;
console.log(`\n${n} ${label} emails (split: ${split}) in ${((Date.now() - started) / 1000).toFixed(0)} s, ${failed} unreadable`);
console.log(`  red (confirmed):   ${String(levels.phishing).padStart(6)}  ${pct(levels.phishing)}`);
console.log(`  yellow:            ${String(levels.suspicious).padStart(6)}  ${pct(levels.suspicious)}   (very suspicious: ${pct(high)})`);
console.log(`  no warning:        ${String(levels.safe).padStart(6)}  ${pct(levels.safe)}`);
console.log(label === 'malicious' ? `  => caught: ${pct(flagged)}` : `  => wrongly flagged: ${pct(flagged)}`);
console.log('\nscore distribution (0-9, 10-19, ... 100):\n  ' + scores.map((c, i) => `${i * 10}:${c}`).join('  '));
console.log('\nmost common reasons:');
for (const [id, c] of Object.entries(signalCounts).sort((a, b) => b[1] - a[1]).slice(0, 30)) console.log(`  ${String(c).padStart(6)}  ${pct(c).padStart(6)}  ${id}`);
if (jsonOut) writeFileSync(jsonOut, JSON.stringify({ label, split, n, levels, high, signalCounts, rows }));
