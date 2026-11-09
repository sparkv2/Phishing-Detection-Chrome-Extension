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

async function render() {
  const s = await chrome.storage.local.get(['enabled', 'stats', 'trusted', 'blocked', 'useFeed', 'enabledHosts', 'disabledHosts']);
  const st = s.stats || {};
  $('enabled').checked = s.enabled !== false;
  $('sScanned').textContent = st.scanned || 0;
  $('sSusp').textContent = st.suspicious || 0;
  $('sPhish').textContent = st.phishing || 0;
  $('sWarn').textContent = st.warnings || 0;
  renderList('trustList', 'trustCount', s.trusted || [], 'trusted', 'No trusted senders yet.');
  renderList('blockList', 'blockCount', s.blocked || [], 'blocked', 'You haven\'t reported anyone yet.');
  $('useFeed').checked = s.useFeed !== false;
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
      `${x.count.toLocaleString()} · ${x.origin === 'live' ? 'updated' : 'bundled'} ${x.updated ? new Date(x.updated).toLocaleDateString() : ''}`;
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
  if (s.enabled === false) { status.textContent = 'Protection is OFF'; status.className = 'status off'; return; }
  if (!info) { status.textContent = 'Not available on this page'; status.className = 'status'; return; }
  currentHost = info.host;
  if (info.active) {
    status.textContent = `Protecting ${info.provider || 'this site'}`; status.className = 'status on';
    if (!info.known) showSite(`Tripwire is checking emails on ${info.host}.`, 'Stop checking this site', async () => {
      await toggleHost('enabledHosts', info.host, false); await toggleHost('disabledHosts', info.host, true);
    });
  } else {
    status.textContent = 'Not an email page'; status.className = 'status';
    showSite(`Is ${info.host} your email website? Turn on checking here.`, 'Check emails on this site', async () => {
      await toggleHost('disabledHosts', info.host, false); await toggleHost('enabledHosts', info.host, true);
    });
  }
}
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
$('feedBtn').onclick = async () => {
  $('feedBtn').disabled = true; $('feedBtn').textContent = 'Updating…';
  const r = await chrome.runtime.sendMessage({ type: 'pg-update-feed' });
  $('feedBtn').disabled = false; $('feedBtn').textContent = r && r.ok ? 'Updated ✓' : 'Couldn\'t update — try later';
  render();
};
render();
