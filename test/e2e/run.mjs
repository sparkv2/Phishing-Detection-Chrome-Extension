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
import { gmail, gmailRedesigned, outlook, outlookUnsure, yahoo } from './fixtures.mjs';

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
  await check('Gmail: a javascript: link gets the warning but can never be opened from it', async () => {
    await page.eval(`const a = document.createElement('a'); a.id = 'js-link'; a.href = 'javascript:void(document.title="pwned")'; a.textContent = 'View invoice';
      document.getElementById('body').append(a); a.click(); return true;`);
    const dlg = await page.waitFor(`(() => { const x = [...document.querySelectorAll('[data-pg-ui]')].find((h) => h.shadowRoot && h.shadowRoot.querySelector('.dialog'));
      return x ? { anyway: !!x.shadowRoot.querySelector('.link-anyway'), text: x.shadowRoot.querySelector('.dialog').textContent } : null; })()`, 10000, 'link dialog');
    assert(!dlg.anyway, 'the dialog must not offer "open anyway" for a javascript: link');
    assert(/isn't a web address/.test(dlg.text), 'explains why: ' + dlg.text.slice(0, 200));
    await page.eval(`[...document.querySelectorAll('[data-pg-ui]')].find((x) => x.shadowRoot && x.shadowRoot.querySelector('.dialog')).shadowRoot.querySelector('.btn.primary').click(); document.getElementById('js-link').remove(); return true;`);
    assert(await page.eval(`return document.title;`) !== 'pwned', 'the javascript: link ran');
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
  await check('Outlook: scam row coloured red; banner on the email being read, none on the compose box', async () => {
    await page.waitFor(`document.querySelectorAll('.pg-row-phishing').length >= 1`, 10000, 'row colour');
    const b = await page.waitFor(`${BANNER}.length ? ${BANNER} : null`, 10000, 'banner');
    assert(b.length === 1, `expected one banner, got ${b.length}`);
    assert(b[0].before === 'read-body', 'banner is not above the reading pane');
    assert(/danger/i.test(b[0].title), 'headline: ' + b[0].title); // red: "enter your password to confirm"
    assert(b[0].reasons.some((r) => /send a password/.test(r)), 'password-request reason missing: ' + b[0].reasons.join(' | '));
    assert(b[0].reasons.some((r) => /free email account/.test(r)), 'brand-on-free-mail reason missing: ' + b[0].reasons.join(' | '));
  });
  await closeTab(page);

  // ---------------- "Not sure this is the official address" -> "I know this sender" ----------------
  page = await chrome.openPage(outlookUnsure.url, outlookUnsure.routes, outlookUnsure.hosts);
  await check('Unsure company address: yellow with a question; "I know this sender" re-checks it as known', async () => {
    const UNSURE = `(() => { const h = document.querySelector('.pg-banner-host'); const u = h && h.shadowRoot.querySelector('.unsure'); return u ? u.textContent : null; })()`;
    const text = await page.waitFor(UNSURE, 10000, 'unsure note');
    assert(/not sure hartwelllumbermail\.com is Hartwell Lumber's official email address/.test(text), 'note: ' + text);
    let b = await page.eval(`return ${BANNER};`);
    assert(/suspicious/i.test(b[0].title), 'headline before: ' + b[0].title);
    // Accept the "are you sure?" dialog the button opens, then click it.
    chrome.conn.on((msg) => { if (msg.sessionId === page.id && msg.method === 'Page.javascriptDialogOpening') page.send('Page.handleJavaScriptDialog', { accept: true }).catch(() => {}); });
    await page.eval(`document.querySelector('.pg-banner-host').shadowRoot.querySelector('.unsure button').click(); return true;`);
    const known = await page.waitFor(`${UNSURE} === null && ${BANNER}.length ? ${BANNER}[0] : null`, 10000, 'banner re-checked');
    assert(/no warning signs/i.test(known.title), 'headline after: ' + known.title);
    const s = await storage(['knownDomains']);
    assert(JSON.stringify(s.knownDomains) === '["hartwelllumbermail.com"]', 'stored: ' + JSON.stringify(s.knownDomains));
    await chrome.worker.eval(`await chrome.storage.local.remove('knownDomains');`);
  });
  await closeTab(page);

  // ---------------- Yahoo ----------------
  page = await chrome.openPage(yahoo.url, yahoo.routes, yahoo.hosts);
  await check('Yahoo: DHL fee scam row coloured and red banner shown', async () => {
    // The row only shows a snippet, so it may be yellow until the email is opened.
    await page.waitFor(`document.querySelectorAll('.pg-row-suspicious, .pg-row-phishing').length === 1`, 10000, 'row colour');
    const b = await page.waitFor(`${BANNER}.length ? ${BANNER} : null`, 10000, 'banner');
    assert(/danger/i.test(b[0].title), 'headline: ' + b[0].title); // strong signs of a scam: red
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

  await check('Popup "Play the game" opens Inbox Expedition in a new tab', async () => {
    const p = await chrome.openExtensionPage('popup/popup.html');
    // Wait for popup.js to attach the click handler, not just for the button to exist.
    await p.waitFor(`document.getElementById('gameBtn') && typeof document.getElementById('gameBtn').onclick === 'function'`, 10000, 'game button handler');
    await p.eval(`document.getElementById('gameBtn').click(); return true;`);
    const { targetInfos } = await chrome.conn.send('Target.getTargets');
    let found = null;
    for (let i = 0; i < 25 && !found; i++) {
      const t = (await chrome.conn.send('Target.getTargets')).targetInfos.find((x) => x.type === 'page' && x.url.endsWith('/game/game.html'));
      if (t) found = t; else await sleep(200);
    }
    assert(found, 'no game tab opened (targets: ' + targetInfos.map((t) => t.url).join(', ') + ')');
    await chrome.conn.send('Target.closeTarget', { targetId: found.targetId });
    await closeTab(p);
  });
  await check('Inbox Expedition: a whole game can be played to Secure Harbor', async () => {
    const p = await chrome.openExtensionPage('game/game.html');
    const click = (text) => p.eval(`const b = [...document.querySelectorAll('button')].find((x) => x.textContent.includes(${JSON.stringify(text)}) && !x.disabled); if (b) b.click(); return !!b;`);
    await p.waitFor(`document.querySelector('button')`, 10000, 'title screen');
    assert(await click('Start a new expedition'), 'start button');
    assert(await click('Hit the trail'), 'hit the trail button');
    // Answer every challenge correctly by reading the answer from the engine's own question bank.
    for (let turn = 0; turn < 80; turn++) {
      await sleep(50);
      const text = await p.eval(`return document.getElementById('app').textContent;`);
      if (/You reached Secure Harbor|Expedition over/.test(text)) break;
      const want = await p.eval(`
        const qText = [...document.querySelectorAll('.panel p')].map((x) => x.textContent).find((t) => TW_Game.QUESTIONS.some((q) => q.q === t));
        if (!qText || !document.querySelector('.choice:not(:disabled)')) return null;
        const q = TW_Game.QUESTIONS.find((x) => x.q === qText); return q.options[q.answer];`);
      if (want) {
        const ok = await p.eval(`const b = [...document.querySelectorAll('.choice')].find((x) => x.textContent.slice(2) === ${JSON.stringify(want)}); if (b) b.click(); return !!b;`);
        assert(ok, 'answer button for: ' + want);
        assert(await click('Continue') || await click('See what happened'), 'continue after answer');
        continue;
      }
      assert(await click('Continue on the trail'), 'continue on the trail: ' + text.slice(0, 200));
    }
    const final = await p.waitFor(`document.querySelector('.big') && document.querySelector('.big').textContent`, 5000, 'end screen');
    assert(/points/.test(final), 'expected a winning score, got: ' + final);
    const best = await storage(['gameBest']);
    assert(best.gameBest && best.gameBest.rank === 'Phish Hunter', 'best score saved: ' + JSON.stringify(best.gameBest));
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
