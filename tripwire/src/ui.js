// On-page UI: summary/score banner, click-warning dialog, and link hover tooltip.
// Rendered inside Shadow DOM so the email site's styles can't break it (and ours can't break the site).
(function (root) {
  'use strict';

  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : v);
    }
    for (const c of children.flat()) if (c != null && c !== false) el.append(c.nodeType ? c : document.createTextNode(String(c)));
    return el;
  }

  const CSS = `
  :host { all: initial; }
  * { box-sizing: border-box; }
  .card { font: 14px/1.5 -apple-system, "Segoe UI", Roboto, Arial, sans-serif; color: #1f2328; background: #fff;
    border: 1px solid #d0d7de; border-left: 6px solid var(--c); border-radius: 10px; margin: 0 0 16px; overflow: hidden;
    box-shadow: 0 1px 3px rgba(0,0,0,.08); max-width: 100%; }
  .safe { --c: #1a7f37; --bg: #e9f7ee; }
  .suspicious { --c: #b45309; --bg: #fff6d6; }
  .phishing { --c: #c62828; --bg: #fdecea; }
  .head { display: flex; align-items: center; gap: 12px; padding: 12px 16px; background: var(--bg); }
  .icon { flex: none; width: 36px; height: 36px; border-radius: 50%; background: var(--c); color: #fff; display: grid;
    place-items: center; font-size: 20px; font-weight: 700; }
  .htext { flex: 1; min-width: 0; }
  .title { font-size: 16px; font-weight: 700; color: var(--c); }
  .sub { font-size: 12.5px; color: #57606a; }
  .score { text-align: center; flex: none; }
  .num { font-size: 26px; font-weight: 800; color: var(--c); line-height: 1; }
  .of { font-size: 11px; color: #57606a; }
  .meter { position: relative; height: 8px; margin: 0 16px; border-radius: 4px;
    background: linear-gradient(90deg, #c62828 0%, #c62828 34%, #e6a700 35%, #e6a700 69%, #1a7f37 70%, #1a7f37 100%); opacity: .9; }
  .meterwrap { padding: 12px 0 4px; }
  .marker { position: absolute; top: -5px; width: 4px; height: 18px; background: #1f2328; border-radius: 2px; transform: translateX(-2px); }
  .scale { display: flex; justify-content: space-between; font-size: 11px; color: #57606a; margin: 4px 16px 0; }
  section { padding: 10px 16px; border-top: 1px solid #eaeef2; }
  h4 { margin: 0 0 6px; font-size: 13px; text-transform: uppercase; letter-spacing: .04em; color: #57606a; }
  p { margin: 0 0 6px; }
  ul { margin: 4px 0 0; padding-left: 20px; }
  li { margin: 2px 0; }
  .from { font-size: 13px; color: #57606a; word-break: break-all; }
  .ok { color: #1a7f37; font-weight: 600; }
  .reason { padding: 8px 10px; margin: 6px 0; border-radius: 8px; background: #f6f8fa; border-left: 3px solid var(--c); }
  .reason b { display: block; }
  .ev { display: inline-block; margin-top: 4px; font: 12px/1.4 ui-monospace, Consolas, monospace; background: #fff;
    border: 1px solid #d0d7de; border-radius: 4px; padding: 1px 6px; word-break: break-all; }
  .more { background: none; border: 0; color: #0969da; cursor: pointer; padding: 4px 0; font: inherit; }
  .actions { display: flex; flex-wrap: wrap; gap: 8px; padding: 10px 16px 12px; border-top: 1px solid #eaeef2; }
  button.btn { font: 600 13px/1 inherit; font-family: inherit; padding: 9px 14px; border-radius: 6px; cursor: pointer;
    border: 1px solid #d0d7de; background: #f6f8fa; color: #1f2328; }
  button.btn:hover { background: #eef1f4; }
  button.primary { background: var(--c); border-color: var(--c); color: #fff; }
  button.primary:hover { filter: brightness(.92); background: var(--c); }
  .note { margin: 0 16px 12px; padding: 10px 12px; background: #ddf4ff; border-radius: 8px; font-size: 13px; }
  .foot { display: flex; align-items: center; gap: 6px; font-size: 11.5px; color: #6e7781; padding: 0 16px 10px; }
  .foot svg { flex: none; width: 22px; height: 22px; }
  .foot b { color: #2C2C2A; font-weight: 600; } .foot .wire { color: #E24B4A; }
  .collapsed section, .collapsed .actions, .collapsed .meterwrap, .collapsed .foot, .collapsed .note { display: none; }
  .toggle { background: none; border: 0; cursor: pointer; color: #57606a; font-size: 12px; padding: 4px; }
  /* dialog */
  .overlay { position: fixed; inset: 0; background: rgba(15,20,25,.55); display: grid; place-items: center; z-index: 2147483647; padding: 16px; }
  .dialog { font: 15px/1.5 -apple-system, "Segoe UI", Roboto, Arial, sans-serif; color: #1f2328; background: #fff;
    border-radius: 12px; max-width: 480px; width: 100%; box-shadow: 0 10px 40px rgba(0,0,0,.35); overflow: hidden; border-top: 6px solid var(--c); }
  .dialog .dh { padding: 16px 20px 6px; font-size: 19px; font-weight: 800; color: var(--c); }
  .dialog .db { padding: 4px 20px 12px; }
  .dest { background: #f6f8fa; border: 1px solid #d0d7de; border-radius: 8px; padding: 8px 10px; margin: 8px 0; font-size: 13px; word-break: break-all; }
  .dest .lbl { color: #57606a; font-size: 12px; }
  .dest .val { font: 600 14px ui-monospace, Consolas, monospace; }
  .dialog .actions { justify-content: flex-end; }
  .link-anyway { background: none; border: 0; color: #57606a; text-decoration: underline; cursor: pointer; font: 13px inherit; font-family: inherit; margin-right: auto; }
  /* tooltip */
  .tip { position: fixed; z-index: 2147483646; pointer-events: none; font: 12.5px/1.4 -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
    background: #1f2328; color: #fff; border-radius: 6px; padding: 6px 9px; max-width: 360px; box-shadow: 0 4px 14px rgba(0,0,0,.3); }
  .tip .d { font-weight: 700; word-break: break-all; }
  .tip.bad { background: #b71c1c; } .tip.warn { background: #8a5300; }
  `;

  // Tripwire mark (from the brand logo pack), inlined so the email site can't block or restyle it.
  const MARK_SVG = '<svg viewBox="0 0 128 128" aria-hidden="true"><circle cx="64" cy="64" r="40" fill="none" stroke="#2C2C2A" stroke-width="7"/>' +
    '<circle cx="64" cy="64" r="21" fill="none" stroke="#888780" stroke-width="4" stroke-dasharray="6 6"/>' +
    '<line x1="10" y1="64" x2="118" y2="64" stroke="#E24B4A" stroke-width="7" stroke-linecap="round"/>' +
    '<circle cx="10" cy="64" r="8" fill="#E24B4A"/><circle cx="118" cy="64" r="8" fill="#E24B4A"/><circle cx="64" cy="64" r="10" fill="#E24B4A"/></svg>';

  function shadowHost(tag) {
    const host = document.createElement(tag || 'div');
    host.setAttribute('data-pg-ui', '');
    const sr = host.attachShadow({ mode: 'open' });
    sr.append(h('style', {}, CSS));
    return { host, sr };
  }

  const LEVEL_TEXT = {
    safe: { icon: '✓', title: 'No warning signs found', sub: 'This email passed our checks. Stay alert anyway.' },
    suspicious: { icon: '!', title: 'Be careful — this email looks suspicious', sub: 'Some warning signs were found. Read the reasons below before you act.' },
    phishing: { icon: '✕', title: 'Danger — this is likely a phishing scam', sub: 'Do not click links, open attachments, or reply.' },
  };
  const KNOWN_TEXTS = {
    phishing: { icon: '✕', title: 'Known phishing — confirmed scam', sub: 'This sender or link is on a list of confirmed phishing attacks.' },
    malware: { icon: '✕', title: 'Known malware — dangerous link', sub: 'A link in this email is on a list of sites that spread viruses or ransomware.' },
    c2: { icon: '✕', title: 'Known hacker server — dangerous', sub: 'This email points to a server criminals use to control hacked computers.' },
    reported: { icon: '✕', title: 'You reported this as phishing', sub: 'You reported this sender or site earlier on this computer.' },
  };
  const HIGH_TEXT = { icon: '!', title: 'Very suspicious — strong signs of phishing',
    sub: 'Not on a known-scam list yet, but it has serious warning signs. Don\'t click links, open attachments, or reply.' };

  const TIPS = {
    phishing: [
      'Don\'t click any links or open any attachments in this email.',
      'Don\'t reply, and never send passwords, codes or payment details.',
      'Report it with the button below (reporting protects others, ignoring doesn\'t), then delete it.',
      'Worried about your account? Open the company\'s app or type their web address yourself — never use the email\'s links.',
      'Already clicked or typed a password? Change that password now and contact the company using their official website.',
    ],
    suspicious: [
      'Hover over links (without clicking) to see where they really go.',
      'Check the sender\'s full email address, not just the name shown.',
      'Not expecting this? Confirm with the sender another way — phone them or use their official website.',
      'If in doubt, report it instead of just ignoring it.',
    ],
    safe: [
      'Good habit: hover over links before clicking to check where they go.',
      'Good habit: check the full sender address, not just the display name.',
      'Good habit: real companies never ask for your password by email.',
      'Good habit: if an email pressures you to act fast, slow down and verify.',
      'Good habit: report suspicious emails — it helps protect everyone.',
    ],
  };

  function renderBanner(result, opts) {
    const { host, sr } = shadowHost('div');
    host.className = 'pg-banner-host';
    const lt = result.known ? (KNOWN_TEXTS[result.threatCategory] || KNOWN_TEXTS.phishing) : result.high ? HIGH_TEXT : LEVEL_TEXT[result.level];
    const card = h('div', { class: 'card ' + result.level, role: 'region', 'aria-label': 'Tripwire email safety check' });
    const toggle = h('button', { class: 'toggle', title: 'Show / hide details', onclick: () => card.classList.toggle('collapsed') }, '▾');
    card.append(h('div', { class: 'head' },
      h('div', { class: 'icon', 'aria-hidden': 'true' }, lt.icon),
      h('div', { class: 'htext' }, h('div', { class: 'title' }, lt.title), h('div', { class: 'sub' }, lt.sub)),
      h('div', { class: 'score', title: '0 = confirmed phishing, 100 = completely safe' },
        h('div', { class: 'num' }, result.score), h('div', { class: 'of' }, 'safety / 100')),
      toggle));
    const marker = h('div', { class: 'marker' }); marker.style.left = result.score + '%';
    card.append(h('div', { class: 'meterwrap' }, h('div', { class: 'meter' }, marker),
      h('div', { class: 'scale' }, h('span', {}, '0 · Phishing'), h('span', {}, 'Suspicious'), h('span', {}, 'Safe · 100'))));

    // Summary
    const s = result.sender;
    const fromLine = h('p', { class: 'from' }, 'From: ', s.name ? s.name + ' ' : '', s.email ? `<${s.email}>` : '(address not shown)',
      result.verifiedBrand ? h('span', { class: 'ok' }, `  ✓ real ${result.verifiedBrand} address`) : null,
      result.trusted ? h('span', { class: 'ok' }, '  ✓ you marked this sender as trusted') : null);
    const sum = h('section', {}, h('h4', {}, 'Summary'), fromLine, h('p', {}, result.summary));
    if (result.asks.length) sum.append(h('p', {}, 'This email is asking you to:'), h('ul', {}, result.asks.map((a) => h('li', {}, a))));
    card.append(sum);

    // Why
    if (result.level !== 'safe' && result.signals.length) {
      const why = h('section', {}, h('h4', {}, result.level === 'phishing' ? 'Why this is dangerous' : 'Why this is suspicious'));
      const items = result.signals.map((x) => h('div', { class: 'reason' }, h('b', {}, x.title), x.explain,
        x.evidence ? h('div', {}, h('span', { class: 'ev' }, x.evidence)) : null));
      items.slice(0, 4).forEach((i) => why.append(i));
      if (items.length > 4) {
        const rest = h('div', { hidden: true }, items.slice(4));
        why.append(rest, h('button', { class: 'more', onclick: (e) => { rest.hidden = false; e.target.remove(); } }, `Show ${items.length - 4} more reason(s)`));
      }
      card.append(why);
    } else {
      const checked = [s.email ? 'the sender\'s address' : null, `${result.links.length} link(s)`, 'the wording for pressure tactics and requests for information'].filter(Boolean);
      const minor = result.signals.filter((x) => x.weight > 0);
      const sec = h('section', {}, h('h4', {}, 'What we checked'), h('p', {}, 'We checked ' + checked.join(', ') + '.'));
      if (minor.length) sec.append(h('p', { class: 'from' }, 'Minor notes (not enough to be a concern): ' + minor.map((m) => m.title.toLowerCase()).join('; ') + '.'));
      card.append(sec);
    }

    // What to do
    const tips = result.level === 'safe' ? [TIPS.safe[Math.floor(Math.random() * TIPS.safe.length)]] : TIPS[result.high ? 'phishing' : result.level];
    card.append(h('section', {}, h('h4', {}, result.level === 'safe' ? 'Safety tip' : 'What you should do'), h('ul', {}, tips.map((t) => h('li', {}, t)))));

    const note = h('div', { class: 'note', hidden: true });
    const actions = h('div', { class: 'actions' });
    if (result.level !== 'safe') {
      actions.append(h('button', { class: 'btn primary', onclick: () => {
        note.hidden = false; note.textContent = '';
        note.append(h('b', {}, 'How to report: '), opts.reportHelp, h('br'), h('br'),
          'Tripwire will also warn you about future emails from this sender on this computer.');
        opts.onReport && opts.onReport();
      } }, 'Report phishing'));
    } else {
      actions.append(h('button', { class: 'btn', onclick: () => {
        note.hidden = false; note.textContent = '';
        note.append(h('b', {}, 'How to report: '), opts.reportHelp);
        opts.onReport && opts.onReport();
      } }, 'Report as phishing anyway'));
    }
    if (!result.known && !result.trusted && s.email) {
      actions.append(h('button', { class: 'btn', onclick: () => {
        if (confirm(`Only trust ${s.email} if you are sure you know this sender.\n\nScammers often copy names of people and companies you know. Trust this sender?`)) opts.onTrust && opts.onTrust();
      } }, 'I know this sender'));
    }
    if (result.trusted) actions.append(h('button', { class: 'btn', onclick: () => opts.onUntrust && opts.onUntrust() }, 'Stop trusting this sender'));
    const foot = h('div', { class: 'foot' });
    foot.innerHTML = MARK_SVG; // static, trusted markup (no email content)
    foot.append(h('span', {}, 'Checked privately on your device by ', h('b', {}, 'Trip', h('span', { class: 'wire' }, 'wire')), ' — no email content was sent anywhere.'));
    card.append(note, actions, foot);
    sr.append(card);
    return host;
  }

  // Click warning. Resolves true if the user insists on opening the link.
  function confirmLink(info) {
    return new Promise((resolve) => {
      const { host, sr } = shadowHost('div');
      const level = info.known || info.emailLevel === 'phishing' ? 'phishing' : 'suspicious';
      const close = (v) => { host.remove(); document.removeEventListener('keydown', onKey, true); resolve(v); };
      const onKey = (e) => { if (e.key === 'Escape') { e.stopPropagation(); close(false); } };
      document.addEventListener('keydown', onKey, true);
      const reasons = info.signals.slice(0, 3);
      const back = h('button', { class: 'btn primary', onclick: () => close(false) }, 'Go back to safety');
      const dlg = h('div', { class: 'dialog ' + level, role: 'alertdialog', 'aria-modal': 'true', 'aria-label': 'Link warning' },
        h('div', { class: 'dh' }, level === 'phishing' ? '⚠ Stop — this link looks dangerous' : '⚠ Wait — check this link first'),
        h('div', { class: 'db' },
          info.text ? h('div', { class: 'dest' }, h('div', { class: 'lbl' }, 'The link says'), h('div', { class: 'val' }, info.text.slice(0, 120))) : null,
          h('div', { class: 'dest' }, h('div', { class: 'lbl' }, 'It really goes to'), h('div', { class: 'val' }, info.host || info.href.slice(0, 120))),
          reasons.length ? h('ul', {}, reasons.map((r) => h('li', {}, h('b', {}, r.title + ': '), r.explain))) :
            h('p', {}, info.emailLevel === 'phishing' ? 'This link is inside an email that looks like a phishing scam.' : 'This link is inside an email with warning signs.'),
          h('p', {}, 'If you need to visit this company, open their official app or type their address into your browser yourself.')),
        h('div', { class: 'actions' },
          h('button', { class: 'link-anyway', onclick: () => close(true) }, 'I understand the risk, open anyway'), back));
      const overlay = h('div', { class: 'overlay', onclick: (e) => { if (e.target === overlay) close(false); } }, dlg);
      sr.append(overlay);
      document.documentElement.append(host);
      back.focus();
    });
  }

  let tipHost = null, tipEl = null;
  function showTooltip(anchor, info) {
    if (!tipHost) {
      const s = shadowHost('div'); tipHost = s.host; tipEl = h('div', { class: 'tip' }); s.sr.append(tipEl);
      document.documentElement.append(tipHost);
    }
    tipEl.className = 'tip' + (info.known || info.emailLevel === 'phishing' ? ' bad' : info.weight > 0 || info.emailLevel === 'suspicious' ? ' warn' : '');
    tipEl.textContent = '';
    tipEl.append(h('div', {}, info.weight > 0 ? '⚠ This link really goes to:' : 'This link goes to:'), h('div', { class: 'd' }, info.host || info.href.slice(0, 80)));
    if (info.signals && info.signals[0]) tipEl.append(h('div', {}, info.signals[0].title));
    const r = anchor.getBoundingClientRect();
    tipHost.style.display = '';
    const top = r.bottom + 8 + 60 > innerHeight ? r.top - 8 - 60 : r.bottom + 8;
    tipEl.style.top = Math.max(4, top) + 'px';
    tipEl.style.left = Math.max(4, Math.min(r.left, innerWidth - 370)) + 'px';
  }
  function hideTooltip() { if (tipHost) tipHost.style.display = 'none'; }

  root.PG_UI = { renderBanner, confirmLink, showTooltip, hideTooltip };
})(typeof globalThis !== 'undefined' ? globalThis : this);
