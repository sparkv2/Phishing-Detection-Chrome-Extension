const $ = (id) => document.getElementById(id);
const TIPS = [
  'Tip: hover over a link before clicking to see where it really goes.',
  'Tip: check the full sender address, not just the name shown.',
  'Tip: real companies never ask for your password or security codes by email.',
  'Tip: urgent threats ("your account will be closed!") are a classic scam trick. Slow down.',
  'Tip: report phishing instead of just deleting it. It helps protect others.',
  'Tip: not sure? Contact the company through their official app or website, not the email.',
];
$('tip').textContent = TIPS[Math.floor(Math.random() * TIPS.length)];

let currentHost = null;

const ALL_SITES = ['https://*/*', 'http://*/*'];

async function render() {
  const s = await chrome.storage.local.get(['enabled', 'stats', 'trusted', 'blocked', 'useFeed', 'communityEnabled', 'shareReports', 'enabledHosts', 'disabledHosts', 'layoutRules',
    'expandLinks', 'guardEnabled', 'pwAlert', 'aiEnabled', 'health']);
  renderExtras(s);
  const st = s.stats || {};
  $('enabled').checked = s.enabled !== false;
  $('sScanned').textContent = st.scanned || 0;
  $('sSusp').textContent = st.suspicious || 0;
  $('sPhish').textContent = st.phishing || 0;
  $('sWarn').textContent = st.warnings || 0;
  renderList('trustList', 'trustCount', s.trusted || [], 'trusted', 'No trusted senders yet.');
  renderList('blockList', 'blockCount', s.blocked || [], 'blocked', 'You haven\'t reported anyone yet.');
  $('useFeed').checked = s.useFeed !== false;
  const lr = s.layoutRules;
  $('rulesInfo').textContent = lr
    ? `Webmail layout rules: version ${lr.version}, updated ${new Date(lr.installed).toLocaleDateString()} (signed, checked on your device).`
    : `Webmail layout rules: built-in version ${PG_Selectors.BUILTIN.version}.`;
  $('communityEnabled').checked = s.communityEnabled !== false;
  $('shareReports').checked = !!s.shareReports;
  renderIntel(s); // don't wait on the (possibly large) list load
  await renderStatus(s);
}

const CAT_LABEL = { phishing: 'Phishing', malware: 'Malware', c2: 'C2 servers' };
async function renderIntel(s) {
  let info = null;
  try { info = await chrome.runtime.sendMessage({ type: 'pg-intel-status' }); } catch (e) { info = null; }
  const ul = $('intelList'); ul.textContent = '';
  if (!info) { $('feedInfo').textContent = 'Threat lists are unavailable right now.'; return; }
  const byCat = {};
  for (const x of info.stats) byCat[x.category] = (byCat[x.category] || 0) + x.count;
  $('feedInfo').textContent = `${info.total.toLocaleString()} known-bad sites and servers on file: ` +
    Object.entries(byCat).map(([c, n]) => `${n.toLocaleString()} ${CAT_LABEL[c] || c}`).join(', ') + '.';
  for (const x of info.stats) {
    const li = document.createElement('li');
    const name = document.createElement('span');
    name.textContent = `${x.name}`;
    const meta = document.createElement('span');
    meta.className = 'muted';
    meta.textContent = x.origin === 'missing' ? 'not loaded' :
      `${x.count.toLocaleString()} · ${({ live: 'updated', server: 'via Tripwire server' })[x.origin] || 'bundled'} ${x.updated ? new Date(x.updated).toLocaleDateString() : ''}`;
    li.append(name, meta); ul.append(li);
  }
}

function renderList(listId, countId, items, key, emptyText) {
  const ul = $(listId); ul.textContent = '';
  $(countId).textContent = items.length;
  if (!items.length) { const li = document.createElement('li'); li.className = 'empty'; li.textContent = emptyText; ul.append(li); return; }
  for (const it of items) {
    const li = document.createElement('li');
    const span = document.createElement('span'); span.textContent = it;
    const b = document.createElement('button'); b.textContent = 'Remove';
    b.onclick = async () => {
      const cur = (await chrome.storage.local.get([key]))[key] || [];
      await chrome.storage.local.set({ [key]: cur.filter((x) => x !== it) });
      render();
    };
    li.append(span, b); ul.append(li);
  }
}

async function renderStatus(s) {
  const status = $('status');
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let info = null;
  try { info = await chrome.tabs.sendMessage(tab.id, { type: 'pg-status' }); } catch (e) { info = null; }
  $('siteBox').hidden = true;
  renderHealth(s, info);
  if (s.enabled === false) { status.textContent = 'Protection is OFF'; status.className = 'status off'; return; }
  let url = null; try { url = new URL(tab.url); } catch (e) { url = null; }
  if (!info) {
    status.textContent = 'Not an email page'; status.className = 'status';
    // Tripwire only runs on well-known webmail sites until you turn it on for another one.
    if (url && /^https?:$/.test(url.protocol)) {
      showSite(`Is ${url.host} your email website? Let Tripwire check emails here.`, 'Check emails on this site', async () => {
        const origin = url.origin;
        const ok = await chrome.permissions.request({ origins: [origin + '/*'] });
        if (!ok) return;
        await chrome.runtime.sendMessage({ type: 'pg-enable-site', origin, tabId: tab.id });
      });
    }
    return;
  }
  currentHost = info.host;
  if (info.active) {
    status.textContent = `Protecting ${info.provider || 'this site'}`; status.className = 'status on';
    if (!info.known) showSite(`Tripwire is checking emails on ${info.host}.`, 'Stop checking this site', async () => {
      await toggleHost('disabledHosts', info.host, true);
      if (url && (s.enabledHosts || []).includes(info.host)) await chrome.runtime.sendMessage({ type: 'pg-disable-site', origin: url.origin });
    });
  } else {
    status.textContent = 'Not an email page'; status.className = 'status';
    showSite(`Is ${info.host} your email website? Turn on checking here.`, 'Check emails on this site', async () => {
      await toggleHost('disabledHosts', info.host, false); await toggleHost('enabledHosts', info.host, true);
    });
  }
}

function renderHealth(s, info) {
  const health = s.health || {};
  const label = { gmail: 'Gmail', outlook: 'Outlook', yahoo: 'Yahoo Mail' };
  const broken = Object.entries(health).filter(([id, h]) => !h.ok && Date.now() - h.lastFail < 3 * 86400000
    && (!info || !info.provider || label[id] === info.provider));
  $('healthBox').hidden = !broken.length;
  if (!broken.length) return;
  $('healthSite').textContent = broken.map(([id]) => label[id] || id).join(', ');
  $('healthDetail').textContent = broken.map(([, h]) => `Since ${new Date(h.lastFail).toLocaleString()}: ${h.detail}.`).join(' ');
}

// ---------- extra protection ----------
async function renderExtras(s) {
  $('expandLinks').checked = s.expandLinks !== false;
  const granted = await chrome.permissions.contains({ origins: ALL_SITES });
  $('guardEnabled').checked = !!s.guardEnabled && granted;
  $('pwAlert').checked = !!(s.pwAlert && s.pwAlert.enabled);
  $('pwAlert').disabled = !$('guardEnabled').checked;
  $('aiEnabled').checked = !!s.aiEnabled;
  const a = await PG_AI.availability();
  $('aiStatus').textContent = { unsupported: 'Not supported by this browser.', unavailable: 'Not available on this computer (needs Chrome 138+ and a capable device).',
    downloadable: 'The model will download (about 2 GB) when you turn this on.', downloading: 'The model is downloading…', available: 'Ready.' }[a] || '';
  $('aiEnabled').disabled = a === 'unsupported' || a === 'unavailable';
}
$('expandLinks').onchange = async (e) => { await chrome.storage.local.set({ expandLinks: e.target.checked }); };
$('guardEnabled').onchange = async (e) => {
  if (e.target.checked) {
    const ok = await chrome.permissions.request({ origins: ALL_SITES });
    if (!ok) { e.target.checked = false; return; }
    await chrome.storage.local.set({ guardEnabled: true });
  } else {
    await chrome.storage.local.set({ guardEnabled: false, pwAlert: { enabled: false, entries: [] } });
    try { await chrome.permissions.remove({ origins: ALL_SITES }); } catch (err) { /* still needed */ }
  }
  await chrome.runtime.sendMessage({ type: 'pg-sync-guard' });
  render();
};
$('pwAlert').onchange = async (e) => {
  // Turning it off also forgets the stored fragments. They're re-learnt next time you sign in to your email.
  const cur = (await chrome.storage.local.get(['pwAlert'])).pwAlert || { entries: [] };
  await chrome.storage.local.set({ pwAlert: { enabled: e.target.checked, entries: e.target.checked ? cur.entries || [] : [] } });
};
$('aiEnabled').onchange = async (e) => {
  if (e.target.checked) {
    $('aiStatus').textContent = 'Preparing the on-device model…';
    try { await PG_AI.session((p) => { $('aiStatus').textContent = `Downloading the model… ${Math.round(p * 100)}%`; }); } catch (err) {
      e.target.checked = false; $('aiStatus').textContent = 'Couldn\'t start the on-device model: ' + err.message; return;
    }
  }
  await chrome.storage.local.set({ aiEnabled: e.target.checked });
  render();
};
$('practiceLink').onclick = (e) => { e.preventDefault(); chrome.tabs.create({ url: chrome.runtime.getURL('practice/practice.html') }); };
function showSite(text, label, fn) {
  $('siteBox').hidden = false; $('siteText').textContent = text; $('siteBtn').textContent = label;
  $('siteBtn').onclick = async () => { await fn(); setTimeout(render, 400); };
}
async function toggleHost(key, host, add) {
  const cur = new Set((await chrome.storage.local.get([key]))[key] || []);
  add ? cur.add(host) : cur.delete(host);
  await chrome.storage.local.set({ [key]: [...cur] });
}

$('enabled').onchange = async (e) => { await chrome.storage.local.set({ enabled: e.target.checked }); render(); };
$('useFeed').onchange = async (e) => {
  await chrome.storage.local.set({ useFeed: e.target.checked });
  if (e.target.checked) await chrome.runtime.sendMessage({ type: 'pg-update-feed' });
  render();
};
$('communityEnabled').onchange = async (e) => {
  await chrome.storage.local.set({ communityEnabled: e.target.checked });
  await chrome.runtime.sendMessage({ type: 'pg-community-changed' });
};
$('shareReports').onchange = async (e) => { await chrome.storage.local.set({ shareReports: e.target.checked }); };
$('feedBtn').onclick = async () => {
  $('feedBtn').disabled = true; $('feedBtn').textContent = 'Updating…';
  const r = await chrome.runtime.sendMessage({ type: 'pg-update-feed' });
  $('feedBtn').disabled = false; $('feedBtn').textContent = r && r.ok ? 'Updated ✓' : 'Couldn\'t update — try later';
  render();
};
render();
