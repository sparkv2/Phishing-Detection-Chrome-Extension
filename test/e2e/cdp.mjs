// =====================================================================================================================
// Minimal Chrome DevTools Protocol client for the browser tests (no dependencies: Node 22's built-in WebSocket).
//
// launchChrome() starts Chrome for Testing with Tripwire loaded and *no network access*. Pages are given fake
// webmail content: openPage() intercepts requests to the mail sites and answers them from test fixtures, so the
// browser believes it is on the real mail.google.com and the extension behaves exactly as it would there.
// =====================================================================================================================
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// One WebSocket connection to the browser; sessions (pages, the service worker) share it ("flatten" mode).
class Connection {
  constructor(ws) {
    this.ws = ws; this.nextId = 1; this.pending = new Map(); this.listeners = [];
    ws.addEventListener('message', (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id); this.pending.delete(msg.id);
        msg.error ? reject(new Error(`${msg.error.message} (${msg.error.code})`)) : resolve(msg.result);
      } else if (msg.method) for (const l of this.listeners) l(msg);
    });
  }
  static connect(url) {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(url);
      ws.addEventListener('open', () => resolve(new Connection(ws)));
      ws.addEventListener('error', () => reject(new Error('could not connect to Chrome')));
    });
  }
  send(method, params = {}, sessionId) {
    const id = this.nextId++;
    this.ws.send(JSON.stringify({ id, method, params, sessionId }));
    return new Promise((resolve, reject) => this.pending.set(id, { resolve, reject }));
  }
  on(fn) { this.listeners.push(fn); }
  close() { try { this.ws.close(); } catch (e) { /* already closed */ } }
}

// A page or worker we are attached to. eval() runs JavaScript there and returns the (JSON) result.
class Session {
  constructor(conn, sessionId, targetId) { this.conn = conn; this.id = sessionId; this.targetId = targetId; }
  send(method, params) { return this.conn.send(method, params, this.id); }
  async eval(expression) {
    const r = await this.send('Runtime.evaluate', { expression: `(async () => { ${expression} })()`, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error('page error: ' + (r.exceptionDetails.exception?.description || r.exceptionDetails.text));
    return r.result.value;
  }
  // Polls `expression` (which should return something truthy when ready) until it does, or fails after `timeout`.
  async waitFor(expression, timeout = 10000, label = expression) {
    const end = Date.now() + timeout;
    let last;
    while (Date.now() < end) {
      try { last = await this.eval(`return (${expression});`); if (last) return last; } catch (e) { last = e.message; }
      await sleep(200);
    }
    throw new Error(`timed out waiting for: ${label} (last: ${JSON.stringify(last)})`);
  }
  async screenshot(width, height) {
    await this.send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: false });
    const r = await this.send('Page.captureScreenshot', { format: 'png', clip: { x: 0, y: 0, width, height, scale: 1 } });
    return Buffer.from(r.data, 'base64');
  }
}

export async function launchChrome({ chromePath, extensionDir, headless = true, log = () => {} }) {
  const profile = mkdtempSync(join(tmpdir(), 'tw-e2e-'));
  const args = [
    `--user-data-dir=${profile}`, '--remote-debugging-port=0', '--no-first-run', '--no-default-browser-check',
    `--load-extension=${extensionDir}`, `--disable-extensions-except=${extensionDir}`,
    // No real network: every name fails to resolve. Mail-site pages are answered by openPage()'s interception.
    '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost', '--window-size=1280,800',
    '--disable-background-networking', '--disable-component-update', '--disable-sync',
  ];
  if (headless) args.push('--headless=new');
  if (process.platform === 'linux') args.push('--no-sandbox'); // CI containers
  const proc = spawn(chromePath, args, { stdio: 'ignore' });
  // Chrome writes its debugging port to DevToolsActivePort once it is ready.
  const portFile = join(profile, 'DevToolsActivePort');
  for (let i = 0; i < 150 && !existsSync(portFile); i++) await sleep(100);
  if (!existsSync(portFile)) { proc.kill(); throw new Error('Chrome did not start (no DevToolsActivePort)'); }
  const [port, path] = readFileSync(portFile, 'utf8').trim().split(/\r?\n/);
  log(`debugging port ${port}`);
  const conn = await Connection.connect(`ws://127.0.0.1:${port}${path}`);
  log('connected');

  // The extension's service worker: proves it loaded, and lets tests read storage / badges through chrome.* APIs.
  // Chrome for Testing has built-in extensions with a background.js too, so each candidate is checked by the
  // manifest name it reports.
  const wantName = JSON.parse(readFileSync(join(extensionDir, 'manifest.json'), 'utf8')).name;
  let worker = null, extensionId = null;
  const tried = new Set();
  for (let i = 0; i < 100 && !worker; i++) {
    const { targetInfos } = await conn.send('Target.getTargets');
    for (const t of targetInfos) {
      if (t.type !== 'service_worker' || !t.url.startsWith('chrome-extension://') || tried.has(t.targetId)) continue;
      tried.add(t.targetId);
      const { sessionId } = await conn.send('Target.attachToTarget', { targetId: t.targetId, flatten: true });
      const s = new Session(conn, sessionId, t.targetId);
      // An idle built-in worker may never answer; give each probe 2 seconds.
      const name = await Promise.race([s.eval('return chrome.runtime.getManifest().name;'), sleep(2000).then(() => null)]).catch(() => null);
      log(`worker ${t.url}: ${name}`);
      if (name === wantName) { worker = s; extensionId = new URL(t.url).host; break; }
      await conn.send('Target.detachFromTarget', { sessionId }).catch(() => {});
    }
    if (!worker) await sleep(100);
  }
  if (!worker) {
    const { targetInfos } = await conn.send('Target.getTargets');
    proc.kill();
    throw new Error('Tripwire\'s service worker never started; targets: ' + targetInfos.map((t) => `${t.type} ${t.url}`).join(', '));
  }
  log('service worker found');

  async function close() {
    conn.close(); proc.kill();
    await sleep(500);
    try { rmSync(profile, { recursive: true, force: true }); } catch (e) { /* Windows may still hold files */ }
  }

  // Opens a new tab. `routes(url)` returns { body, type?, status? } for requests it wants to answer, or null to fail
  // them. Every request to the given `hosts` goes through it, including the content script's own fetches.
  async function openPage(url, routes, hosts) {
    const { targetId } = await conn.send('Target.createTarget', { url: 'about:blank' });
    const { sessionId: sid } = await conn.send('Target.attachToTarget', { targetId, flatten: true });
    const page = new Session(conn, sid, targetId);
    conn.on(async (msg) => {
      if (msg.sessionId !== sid || msg.method !== 'Fetch.requestPaused') return;
      const { requestId, request } = msg.params;
      const r = routes(request.url, request);
      if (!r) return page.send('Fetch.failRequest', { requestId, errorReason: 'Failed' }).catch(() => {});
      page.send('Fetch.fulfillRequest', { requestId, responseCode: r.status || 200,
        responseHeaders: [{ name: 'Content-Type', value: r.type || 'text/html; charset=utf-8' }],
        body: Buffer.from(r.body).toString('base64') }).catch(() => {});
    });
    await page.send('Fetch.enable', { patterns: hosts.map((h) => ({ urlPattern: `https://${h}/*`, requestStage: 'Request' })) });
    await page.send('Page.enable');
    await page.send('Runtime.enable');
    await page.send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 800, deviceScaleFactor: 1, mobile: false });
    await page.send('Page.navigate', { url });
    return page;
  }

  // Opens one of the extension's own pages (popup, practice mode...).
  async function openExtensionPage(path) {
    const { targetId } = await conn.send('Target.createTarget', { url: `chrome-extension://${extensionId}/${path}` });
    const { sessionId: sid } = await conn.send('Target.attachToTarget', { targetId, flatten: true });
    const page = new Session(conn, sid, targetId);
    await page.send('Runtime.enable');
    return page;
  }

  return { conn, worker, extensionId, openPage, openExtensionPage, close };
}

export { sleep };
