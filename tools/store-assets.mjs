#!/usr/bin/env node
// =====================================================================================================================
// Store screenshots and promo tile, generated from the real extension running in Chrome for Testing.
//
//   CHROME_PATH=/path/to/chrome-for-testing node tools/store-assets.mjs      (npm run store:assets)
//
// Writes store/screenshot-1..5.png (1280x800) and store/promo-small.png (440x280). The demo inbox
// (demo/demo-inbox.html, all made-up emails) is served at a webmail address the extension runs on, so what you see
// is exactly what Tripwire draws. No real mail site or account is involved, and the browser has no network access.
// =====================================================================================================================
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launchChrome, sleep } from '../test/e2e/cdp.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const out = join(root, 'store');
mkdirSync(out, { recursive: true });
if (!process.env.CHROME_PATH) { console.error('Set CHROME_PATH to a Chrome for Testing executable.'); process.exit(2); }

const killer = setTimeout(() => { console.error('timed out'); process.exit(1); }, 180000);
killer.unref();

const DEMO_HOST = 'mail.zoho.com'; // any webmail host from the manifest; never contacted (requests are intercepted)
const demo = readFileSync(join(root, 'demo/demo-inbox.html'), 'utf8');
const chrome = await launchChrome({ chromePath: process.env.CHROME_PATH, extensionDir: root });
const save = (name, png) => { writeFileSync(join(out, name), png); console.log('wrote store/' + name); };
// Every step gets 30 s, so a stuck step reports which one it was.
const step = async (label, p) => { console.log('# ' + label); let t;
  try { return await Promise.race([p, new Promise((_, rej) => { t = setTimeout(() => rej(new Error('stuck at: ' + label)), 30000); })]); } finally { clearTimeout(t); } };
const banner = `document.querySelector('.pg-banner-host')`;

try {
  const page = await chrome.openPage(`https://${DEMO_HOST}/`, () => ({ body: demo }), [DEMO_HOST]);
  const open = async (sender) => {
    await step('inbox ready', page.waitFor(`document.querySelectorAll('[role=option]').length > 5`));
    // The demo replaces the reading pane, so wait for a banner above *this* email (not the previous one).
    await step('open ' + sender, page.eval(`[...document.querySelectorAll('[role=option]')].find((r) => r.textContent.includes(${JSON.stringify(sender)})).click();`));
    await step('banner for ' + sender, page.waitFor(`(() => { const b = document.querySelector('.email-body'); const h = b && b.parentNode.querySelector('.pg-banner-host');
      return h && h.shadowRoot.querySelectorAll('.reason').length > 0 && document.querySelector('[role=main] .subject').textContent.length > 0; })()`, 15000, 'banner for ' + sender));
    await sleep(600); // let the inbox colours settle
  };

  // 1. Inbox colours + the invoice-fraud warning
  await open('Dana Reyes');
  save('screenshot-1.png', await step('screenshot 1', page.screenshot(1280, 800)));

  // 2. A confirmed phishing email, with its reasons
  await open('PayPal');
  save('screenshot-2.png', await step('screenshot 2', page.screenshot(1280, 800)));

  // 3. The warning shown before a dangerous link opens
  await step('click the dangerous link', page.eval(`document.querySelector('.email-body a[href*="198.51.100.23"]').click();`));
  await step('link dialog', page.waitFor(`[...document.querySelectorAll('[data-pg-ui]')].some((x) => x.shadowRoot && x.shadowRoot.querySelector('.dialog'))`, 5000, 'link dialog'));
  await sleep(300);
  save('screenshot-3.png', await step('screenshot 3', page.screenshot(1280, 800)));

  // 4. Practice mode, with an answer chosen
  const practice = await step('open practice', chrome.openExtensionPage('practice/practice.html'));
  await step('lesson', practice.waitFor(`document.querySelectorAll('.opts button').length >= 3`));
  // Pick the right answer (the one that isn't a harmless distractor), so the screenshot shows the explanation.
  await step('answer', practice.eval(`[...document.querySelectorAll('.opts button')].find((b) => !window.TW_DISTRACTORS.includes(b.textContent) && !/^Nothing/.test(b.textContent)).click();`));
  await sleep(300);
  save('screenshot-4.png', await step('screenshot 4', practice.screenshot(1280, 800)));

  // 5. The popup, centred on a plain backdrop
  const popup = await step('open popup', chrome.openExtensionPage('popup/popup.html'));
  await step('popup summary', popup.waitFor(`/known-bad sites/.test(document.getElementById('feedInfo').textContent)`, 15000, 'popup summary'));
  await step('style popup', popup.eval(`document.querySelectorAll('details').forEach((d, i) => { d.open = i < 2; });
    document.documentElement.style.cssText = 'background: linear-gradient(135deg, #1f2328, #3b2a2a); min-height: 100%;';
    document.body.style.cssText += ';margin: 40px auto; border-radius: 12px; box-shadow: 0 20px 60px rgba(0,0,0,.5); overflow: hidden;';`));
  save('screenshot-5.png', await step('screenshot 5', popup.screenshot(1280, 800)));

  // Small promo tile (440x280)
  const icon = readFileSync(join(root, 'icons/icon128.png')).toString('base64');
  const tile = `<!doctype html><html><body style="margin:0;width:440px;height:280px;display:flex;align-items:center;gap:22px;padding:0 34px;box-sizing:border-box;
    background:linear-gradient(135deg,#fdecea,#ffffff 60%);font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;color:#1f2328">
    <img src="data:image/png;base64,${icon}" width="104" height="104" style="border-radius:20px;box-shadow:0 6px 18px rgba(0,0,0,.18)">
    <div><div style="font-size:40px;font-weight:700;letter-spacing:-.5px">Trip<span style="color:#E24B4A">wire</span></div>
    <div style="font-size:17px;line-height:1.35;margin-top:6px;color:#3b4148">Spots phishing emails and stops risky clicks. Privately, on your device.</div></div></body></html>`;
  const t = await step('open tile', chrome.openPage(`https://${DEMO_HOST}/tile`, () => ({ body: tile }), [DEMO_HOST]));
  await step('tile image', t.waitFor(`document.images[0] && document.images[0].complete`));
  save('promo-small.png', await step('tile screenshot', t.screenshot(440, 280)));
} finally {
  await chrome.close();
}
process.exit(0);
