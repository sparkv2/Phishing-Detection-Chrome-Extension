#!/usr/bin/env node
// Screenshots of Inbox Expedition for checking the design:  CHROME_PATH=... node tools/game-shots.mjs [outDir]
// Loads the extension into Chrome for Testing (like the browser tests) and captures the main screens.
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launchChrome, sleep } from '../test/e2e/cdp.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const out = process.argv[2] || join(root, 'dist', 'game-shots');
mkdirSync(out, { recursive: true });
const killer = setTimeout(() => { console.error('timed out'); process.exit(1); }, 90000);
const chrome = await launchChrome({ chromePath: process.env.CHROME_PATH, extensionDir: root, log: (m) => console.log('# ' + m) });
const errors = [];
chrome.conn.on((m) => { if (m.method === 'Runtime.exceptionThrown') errors.push(m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text); });
try {
  const p = await chrome.openExtensionPage('game/game.html');
  const shot = async (name) => { writeFileSync(join(out, name + '.png'), await p.screenshot(1100, 820)); console.log('saved ' + name); };
  const click = (text) => p.eval(`const b = [...document.querySelectorAll('button')].find((x) => x.textContent.includes(${JSON.stringify(text)}) && !x.disabled); if (b) b.click(); return !!b;`);
  await p.waitFor(`document.querySelector('button')`, 10000, 'title');
  await shot('1-title');
  await click('Start a new expedition'); await sleep(200);
  await shot('2-setup');
  await click('Hit the trail'); await sleep(300);
  await shot('3-trail');
  console.log('trail text:', await p.eval(`return document.getElementById('app').innerText.slice(0, 600);`));
  await click('Continue on the trail'); await sleep(1100);
  await shot('4-after-continue');
  console.log('after continue:', await p.eval(`return document.getElementById('app').innerText.slice(0, 800);`));
  // Play on, answering right, and capture a fort, a wrong-answer screen and the ending.
  let shotFort = false, shotWrong = false;
  for (let turn = 0; turn < 80; turn++) {
    const text = await p.eval(`return document.getElementById('app').innerText;`);
    if (/You reached Secure Harbor|Expedition over/.test(text)) break;
    if (!shotFort && /Visit the fort/.test(text)) { await click('Visit the fort'); await sleep(150); await shot('6-store'); shotFort = true; await click('Leave the store'); continue; }
    const q = await p.eval(`const qText = [...document.querySelectorAll('.panel p')].map((x) => x.textContent).find((t) => TW_Game.QUESTIONS.some((q) => q.q === t));
      if (!qText || !document.querySelector('.choice:not(:disabled)')) return null; const q = TW_Game.QUESTIONS.find((x) => x.q === qText); return q.options[q.answer];`);
    if (q) {
      const ok = await p.eval(`const want = ${JSON.stringify(q)}; const bs = [...document.querySelectorAll('.choice')];
        const b = ${shotWrong ? 'bs.find((x) => x.textContent.slice(2) === want)' : 'bs.find((x) => x.textContent.slice(2) !== want)'}; if (b) b.click(); return !!b;`);
      if (!ok) { console.log('could not find answer button for', q, await p.eval(`return [...document.querySelectorAll('.choice')].map((x) => x.textContent);`)); break; }
      await sleep(100);
      if (!shotWrong) { await shot('5-wrong-answer'); shotWrong = true; }
      if (!(await click('Continue') || await click('See what happened'))) { console.log('no continue', text.slice(0, 300)); break; }
      continue;
    }
    if (!(await click('Continue on the trail'))) { console.log('stuck:', text.slice(0, 400)); break; }
    await sleep(50);
  }
  await sleep(1000);
  await shot('7-end');
  console.log('end:', await p.eval(`return document.getElementById('app').innerText.slice(-500);`));
} catch (e) { console.error('error:', e.message); }
console.log('page errors:', JSON.stringify(errors.slice(0, 5)));
clearTimeout(killer);
await chrome.close();
