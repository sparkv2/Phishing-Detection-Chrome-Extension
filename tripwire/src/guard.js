// Page guard (optional, off by default). Runs on ordinary websites only after the user turns on
// "Protect the pages I open" in the popup and grants Chrome's all-sites permission.
// - Blocks pages on the known-threat lists with a full-page warning.
// - Warns when a page that imitates a brand (or was opened from a risky email) asks for a password.
// - Password alert (separate opt-in): warns when you type your email password on a site that isn't your email provider.
//   Only a salted, slow, deliberately truncated hash (4 bytes) and the password length are stored, on this device.
//   That's enough to notice a match, but far too little to recover the password.
(function () {
  'use strict';
  if (window.top !== window || window.__tripwireGuard || !/^https?:$/.test(location.protocol)) return;
  window.__tripwireGuard = true;
  const A = window.PG_Analyzer, I = window.PG_Intel;
  const host = location.hostname.toLowerCase();

  const LOGIN_PROVIDERS = [
    { id: 'google', name: 'Google', hosts: ['accounts.google.com'], domains: ['google.com', 'gmail.com', 'youtube.com'] },
    { id: 'microsoft', name: 'Microsoft', hosts: ['login.live.com', 'login.microsoftonline.com'], domains: ['live.com', 'microsoftonline.com', 'microsoft.com', 'office.com', 'outlook.com'] },
    { id: 'yahoo', name: 'Yahoo', hosts: ['login.yahoo.com'], domains: ['yahoo.com'] },
  ];
  const reg = A.registrableDomain(host);
  const loginProvider = LOGIN_PROVIDERS.find((p) => p.hosts.includes(host));

  // ---------- tiny shadow-DOM UI ----------
  function shell(html, full) {
    const hostEl = document.createElement('div');
    hostEl.setAttribute('data-pg-ui', '');
    const sr = hostEl.attachShadow({ mode: 'closed' });
    sr.innerHTML = `<style>
      :host { all: initial; } * { box-sizing: border-box; }
      .wrap { position: fixed; z-index: 2147483647; font: 14px/1.5 -apple-system, "Segoe UI", Roboto, Arial, sans-serif; color: #1f2328; }
      .full { inset: 0; background: #7f1d1d; color: #fff; display: grid; place-items: center; padding: 24px; }
      .full .box { max-width: 560px; } .full h1 { font-size: 26px; margin: 0 0 10px; } .full p { margin: 0 0 12px; }
      .bar { top: 12px; right: 12px; max-width: 420px; background: #fff; border: 1px solid #d0d7de; border-left: 6px solid #c62828;
        border-radius: 10px; padding: 12px 14px; box-shadow: 0 8px 30px rgba(0,0,0,.25); }
      .bar b { display: block; color: #c62828; font-size: 15px; margin-bottom: 4px; }
      button { font: 600 13px inherit; font-family: inherit; padding: 8px 12px; border-radius: 6px; cursor: pointer; border: 1px solid #d0d7de; background: #f6f8fa; color: #1f2328; margin: 6px 6px 0 0; }
      button.primary { background: #fff; color: #7f1d1d; border-color: #fff; }
      .full button:not(.primary) { background: transparent; color: #fde2e2; border-color: #fca5a5; }
    </style><div class="wrap ${full ? 'full' : 'bar'}" role="alertdialog" aria-live="assertive">${html}</div>`;
    document.documentElement.append(hostEl);
    return { hostEl, sr };
  }
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

  function blockPage(threat) {
    const what = { phishing: 'a known phishing site (built to steal passwords and card details)', malware: 'a site known for spreading malware',
      c2: 'a server criminals use to control hacked computers', reported: 'a site you reported' }[threat.cat] || 'a known dangerous site';
    const { hostEl, sr } = shell(`<div class="box"><h1>⚠ Tripwire stopped this page</h1>
      <p><b>${esc(host)}</b> is ${what}${threat.source ? ` (source: ${esc(threat.source)})` : ''}.</p>
      <p>Don't sign in, download anything or enter payment details here.</p>
      <button class="primary" id="back">Take me back</button><button id="go">I understand the risk, continue</button></div>`, true);
    sr.getElementById('back').onclick = () => { if (history.length > 1) history.back(); else location.replace('about:blank'); };
    sr.getElementById('go').onclick = () => hostEl.remove();
  }

  let warned = false;
  function warnBar(title, text) {
    if (warned) return;
    warned = true;
    const { hostEl, sr } = shell(`<b>${esc(title)}</b>${esc(text)}<br><button id="close">Dismiss</button>`);
    sr.getElementById('close').onclick = () => hostEl.remove();
  }

  // ---------- page checks ----------
  const hasPassword = () => !!document.querySelector('input[type="password"]');
  function whenPasswordField(fn) {
    if (hasPassword()) return fn();
    const obs = new MutationObserver(() => { if (hasPassword()) { obs.disconnect(); fn(); } });
    obs.observe(document.documentElement, { childList: true, subtree: true });
    setTimeout(() => obs.disconnect(), 60000);
  }

  async function checkPage() {
    let ctx = null;
    try { ctx = await chrome.runtime.sendMessage({ type: 'pg-guard-context', host, urlKeys: I.urlKeys(location.href) }); } catch (e) { return; }
    if (!ctx) return;
    if (ctx.threat) return blockPage(ctx.threat);
    const look = A.lookalikeBrand(host);
    if (look) {
      whenPasswordField(() => warnBar(`This page imitates ${look.brand.name}`,
        `It asks for a password, but ${host} is not a ${look.brand.name} website. Don't type your password here.`));
    } else if (ctx.fromEmail) {
      whenPasswordField(() => warnBar('You opened this page from a suspicious email',
        `It's asking for a password. If you need to sign in, go to the company's website yourself instead of using the email's link.`));
    }
  }

  // ---------- password alert ----------
  async function pwHash(salt, pw) {
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: new TextEncoder().encode(salt), iterations: 150000, hash: 'SHA-256' }, key, 32);
    return [...new Uint8Array(bits)].map((b) => b.toString(16).padStart(2, '0')).join('');
  }
  async function pwSettings() { const s = await chrome.storage.local.get(['pwAlert']); return s.pwAlert || { enabled: false, entries: [] }; }

  async function captureOnLoginPage(provider) {
    const save = async (input) => {
      const pw = input.value;
      if (!pw || pw.length < 6) return;
      const s = await pwSettings();
      if (!s.enabled) return;
      const salt = [...crypto.getRandomValues(new Uint8Array(12))].map((b) => b.toString(16).padStart(2, '0')).join('');
      const entry = { provider: provider.id, name: provider.name, salt, hash: await pwHash(salt, pw), len: pw.length, domains: provider.domains };
      s.entries = (s.entries || []).filter((e) => e.provider !== provider.id).concat(entry);
      await chrome.storage.local.set({ pwAlert: s });
    };
    document.addEventListener('keydown', (e) => { if (e.key === 'Enter' && e.target.matches && e.target.matches('input[type="password"]')) save(e.target); }, true);
    document.addEventListener('click', (e) => {
      if (!e.target.closest || !e.target.closest('button, input[type="submit"], [role="button"]')) return;
      const pw = document.querySelector('input[type="password"]');
      if (pw) save(pw);
    }, true);
  }

  async function watchForReuse() {
    const s = await pwSettings();
    const entries = (s.entries || []).filter((e) => !e.domains.includes(reg));
    if (!s.enabled || !entries.length) return;
    const lens = new Set(entries.map((e) => e.len));
    let busy = false;
    document.addEventListener('input', async (e) => {
      const el = e.target;
      if (!el || !el.matches || !el.matches('input[type="password"]') || !lens.has(el.value.length) || busy) return;
      busy = true;
      try {
        for (const en of entries.filter((x) => x.len === el.value.length)) {
          if ((await pwHash(en.salt, el.value)) === en.hash) {
            warned = false;
            warnBar(`You just typed your ${en.name} password on ${host}`,
              `If this page isn't really ${en.name}, it may be a fake. Don't submit it, and if you already did, change your ${en.name} password now.`);
            break;
          }
        }
      } finally { busy = false; }
    }, true);
  }

  if (loginProvider) captureOnLoginPage(loginProvider);
  else { checkPage(); watchForReuse(); }
})();
