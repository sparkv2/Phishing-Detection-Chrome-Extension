#!/usr/bin/env node
// =====================================================================================================================
// Browser tests: Tripwire loaded into a real Chrome (Chrome for Testing), on fake Gmail / Outlook / Yahoo pages.
//
//   CHROME_PATH=/path/to/chrome node test/e2e/run.mjs           (npm run test:e2e)
//   add --headed to watch it
//
// Checks what unit tests can't: that the manifest loads, the content scripts start on the right sites, the adapters
// find rows and emails in each site's page structure, the banner and link warning appear, compose boxes are left
// alone, Gmail's header and attachment fetches work, the background worker answers, the health check notices a
// redesign, and new layout rules fix it. Any JavaScript error on a page fails the run.
// =====================================================================================================================
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launchChrome, sleep } from './cdp.mjs';
import { gmail, gmailRedesigned, outlook, yahoo } from './fixtures.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const chromePath = process.env.CHROME_PATH;
if (!chromePath) { console.error('Set CHROME_PATH to a Chrome for Testing executable (regular Chrome no longer accepts --load-extension).'); process.exit(2); }

// Never hang a CI job: give up after 4 minutes, whatever is stuck.
const killer = setTimeout(() => { console.log('not ok - the whole run timed out after 240 s'); process.exit(1); }, 240000);
killer.unref();

const results = [];
// Each check gets 45 s at most, so one stuck check can't stall the rest.
async function check(name, fn) {
  const t = Date.now();
  let timer;
  try {
    await Promise.race([fn(), new Promise((_, rej) => { timer = setTimeout(() => rej(new Error('check timed out after 45 s')), 45000); })]);
    results.push({ name, ok: true }); console.log(`ok - ${name} (${Date.now() - t} ms)`);
  } catch (e) { results.push({ name, ok: false }); console.log(`not ok - ${name}\n  # ${e.message.split('\n').join('\n  # ')}`); }
  finally { clearTimeout(timer); }
}
const assert = (cond, msg) => { if (!cond) throw new Error(msg); };

// Helpers that read Tripwire's UI from the page (its banner lives in an open shadow root).
const BANNER = `(() => { const h = [...document.querySelectorAll('.pg-banner-host')]; return h.map((x) => {
  const sr = x.shadowRoot; return { title: sr.querySelector('.title').textContent, score: sr.querySelector('.num').textContent,
  reasons: [...sr.querySelectorAll('.reason b')].map((b) => b.textContent), before: x.nextElementSibling && x.nextElementSibling.id }; }); })()`;

console.log('# starting Chrome with the extension');
const chrome = await launchChrome({ chromePath, extensionDir: root, headless: !process.argv.includes('--headed'), log: (m) => console.log('# ' + m) });
console.log(`# extension ${chrome.extensionId} loaded`);
const errors = [];
chrome.conn.on((msg) => {
  if (msg.method === 'Runtime.exceptionThrown') errors.push(msg.params.exceptionDetails.exception?.description || msg.params.exceptionDetails.text);
});
const storage = (keys) => chrome.worker.eval(`return await chrome.storage.local.get(${JSON.stringify(keys)});`);
const closeTab = (page) => chrome.conn.send('Target.closeTarget', { targetId: page.targetId });

try {
  await check('extension loads and its background worker runs', async () => {
    const v = await chrome.worker.eval('return chrome.runtime.getManifest().version;');
    assert(/^\d+\.\d+\.\d+$/.test(v), 'no version: ' + v);
    // The worker's own threat index must load: the built-in list ships ~190k entries.
    const total = await chrome.worker.eval('return (await getIndex()).idx.hi.length;');
    assert(total > 100000, 'threat index has only ' + total + ' entries');
  });

  // ---------------- Gmail ----------------
  let page = await chrome.openPage(gmail.url, gmail.routes, gmail.hosts);
  await check('Gmail: inbox rows are coloured (known phishing red, suspicious yellow)', async () => {
    await page.waitFor(`document.querySelectorAll('tr.pg-row-phishing').length === 1 && document.querySelectorAll('tr.pg-row-suspicious').length >= 1`, 10000, 'row colours');
    const safe = await page.eval(`return [...document.querySelectorAll('tr.zA')].filter((r) => r.dataset.pgLevel === 'safe').length;`);
    assert(safe === 1, `expected the Amazon row to stay uncoloured, got ${safe} safe rows`);
  });
  await check('Gmail: banner on the opened email, not on the compose box', async () => {
    const b = await page.waitFor(`${BANNER}.length ? ${BANNER} : null`, 10000, 'banner');
    assert(b.length === 1, `expected exactly one banner, got ${b.length}`);
    assert(b[0].before === 'body', 'banner is not above the opened email');
    // Red: a look-alike of the supplier telling you to send the payment to a new account.
    assert(/danger/i.test(b[0].title), 'unexpected headline: ' + b[0].title);
  });
  await check('Gmail: reply-chain hijack and payment change are detected', async () => {
    const r = (await page.eval(`return ${BANNER};`))[0].reasons;
    for (const want of ['Reply comes from a copy of the other side\'s address', 'Asks you to send money to a new account'])
      assert(r.includes(want), `missing "${want}" in: ${r.join(' | ')}`);
  });
  await check('Gmail: "Show original" headers are fetched and the failed DMARC check is reported', async () => {
    await page.waitFor(`${BANNER}[0].reasons.includes('Sender address may be forged')`, 10000, 'auth-fail reason');
  });
  await check('Gmail: the HTML attachment is opened as text and its login form found', async () => {
    await page.waitFor(`${BANNER}[0].reasons.includes('Attachment contains a login form')`, 10000, 'attachment reason');
  });
  await check('Gmail: "Show me" highlights the part of the email a reason is about', async () => {
    const t = await page.eval(`const b = document.querySelector('.pg-banner-host').shadowRoot.querySelector('button.show'); b.click(); return b.textContent;`);
    assert(t === 'Shown ✓', 'button says: ' + t);
  });
  await check('Gmail: clicking a lying link shows the warning; "Go back" keeps you safe', async () => {
    const before = (await chrome.conn.send('Target.getTargets')).targetInfos.filter((t) => t.type === 'page').length;
    await page.eval(`document.getElementById('lying-link').click();`);
    const d = await page.waitFor(`(() => { const h = [...document.querySelectorAll('[data-pg-ui]')].find((x) => x.shadowRoot && x.shadowRoot.querySelector('.dialog'));
      return h && h.shadowRoot.querySelector('.dh').textContent; })()`, 5000, 'warning dialog');
    assert(/link/i.test(d), 'dialog headline: ' + d);
    await page.eval(`[...document.querySelectorAll('[data-pg-ui]')].find((x) => x.shadowRoot && x.shadowRoot.querySelector('.dialog')).shadowRoot.querySelector('.btn.primary').click();`);
    await sleep(500);
    const after = (await chrome.conn.send('Target.getTargets')).targetInfos.filter((t) => t.type === 'page').length;
    const open = await page.eval(`return !![...document.querySelectorAll('[data-pg-ui]')].find((x) => x.shadowRoot && x.shadowRoot.querySelector('.dialog'));`);
    assert(!open, 'dialog still open'); assert(after === before, 'a new tab was opened');
  });
  await check('Gmail: the health check reports the page as readable', async () => {
    await chrome.worker.waitFor(`(await chrome.storage.local.get('health')).health?.gmail?.ok === true`, 10000, 'health ok');
  });
  await closeTab(page);

  // ---------------- Gmail redesign + layout rules update ----------------
  page = await chrome.openPage(gmailRedesigned.url, gmailRedesigned.routes, gmailRedesigned.hosts);
  await check('Gmail redesign: the health check notices rows can no longer be found, and badges the icon', async () => {
    await chrome.worker.waitFor(`(await chrome.storage.local.get('health')).health?.gmail?.ok === false`, 25000, 'health failure reported');
    const badge = await chrome.worker.eval(`const [t] = await chrome.tabs.query({ url: 'https://mail.google.com/*' }); return await chrome.action.getBadgeText({ tabId: t.id });`);
    assert(badge === '!', 'badge: ' + JSON.stringify(badge));
  });
  await check('Gmail redesign: updated layout rules fix detection without a new extension version', async () => {
    // What the background worker stores after verifying a signed rules update (the download itself is tested in unit tests).
    await chrome.worker.eval(`await chrome.storage.local.set({ layoutRules: { version: 99, adapters: { gmail: { row: 'tr.qX9' } }, installed: Date.now() } });`);
    await page.waitFor(`document.querySelectorAll('tr.pg-row-phishing').length === 1`, 10000, 'rows coloured again');
    await chrome.worker.waitFor(`(await chrome.storage.local.get('health')).health?.gmail?.ok === true`, 10000, 'health back to ok');
    await chrome.worker.eval(`await chrome.storage.local.remove('layoutRules');`);
  });
  await closeTab(page);

  // ---------------- Outlook ----------------
  page = await chrome.openPage(outlook.url, outlook.routes, outlook.hosts);
  await check('Outlook: suspicious row coloured; banner on the email being read, none on the compose box', async () => {
    await page.waitFor(`document.querySelectorAll('.pg-row-suspicious').length >= 1`, 10000, 'row colour');
    const b = await page.waitFor(`${BANNER}.length ? ${BANNER} : null`, 10000, 'banner');
    assert(b.length === 1, `expected one banner, got ${b.length}`);
    assert(b[0].before === 'read-body', 'banner is not above the reading pane');
    assert(/danger/i.test(b[0].title), 'headline: ' + b[0].title); // red: "enter your password to confirm"
    assert(b[0].reasons.some((r) => /send a password/.test(r)), 'password-request reason missing: ' + b[0].reasons.join(' | '));
    assert(b[0].reasons.some((r) => /free email account/.test(r)), 'brand-on-free-mail reason missing: ' + b[0].reasons.join(' | '));
  });
  await closeTab(page);

  // ---------------- Yahoo ----------------
  page = await chrome.openPage(yahoo.url, yahoo.routes, yahoo.hosts);
  await check('Yahoo: DHL fee scam row coloured and banner shown', async () => {
    await page.waitFor(`document.querySelectorAll('.pg-row-suspicious').length === 1`, 10000, 'row colour');
    const b = await page.waitFor(`${BANNER}.length ? ${BANNER} : null`, 10000, 'banner');
    assert(/suspicious/i.test(b[0].title), 'headline: ' + b[0].title);
    assert(b[0].reasons.some((r) => /Fake DHL/.test(r)), 'lookalike reason missing: ' + b[0].reasons.join(' | '));
  });
  await closeTab(page);

  // ---------------- extension pages ----------------
  await check('Popup opens and shows the threat-list summary', async () => {
    const p = await chrome.openExtensionPage('popup/popup.html');
    await p.waitFor(`/known-bad sites/.test(document.getElementById('feedInfo').textContent)`, 10000, 'threat list summary');
    await closeTab(p);
  });
  await check('Practice mode shows a lesson', async () => {
    const p = await chrome.openExtensionPage('practice/practice.html');
    await p.waitFor(`document.querySelectorAll('.opts button').length >= 3`, 10000, 'lesson options');
    await closeTab(p);
  });

  await check('no JavaScript errors on any page', async () => {
    assert(!errors.length, errors.slice(0, 5).join('\n'));
  });
} finally {
  await chrome.close();
}

const failed = results.filter((r) => !r.ok).length;
console.log(`\n# ${results.length - failed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
