// Inbox Expedition: the page. Draws each screen and passes the player's choices to the rules in engine.js.
// Screens: title -> setup (company, role, pace) -> trail (travel, rest, fort, questions) -> end.
// Keyboard: 1-4 pick a choice, Enter presses the main button.
(function () {
  'use strict';
  const G = window.TW_Game;
  const app = document.getElementById('app');
  let state = null;
  let primary = null; // the button Enter presses

  // ---------- tiny DOM helper (text only, never HTML strings) ----------
  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : v);
    }
    for (const k of kids.flat()) if (k != null && k !== false) el.append(k.nodeType ? k : document.createTextNode(String(k)));
    return el;
  }
  function screen(...kids) {
    app.textContent = '';
    app.append(...kids.filter(Boolean));
    primary = app.querySelector('[data-primary]');
    const first = primary || app.querySelector('button');
    if (first) first.focus({ preventScroll: true });
  }
  const btn = (label, onclick, opts) => h('button', Object.assign({ type: 'button', onclick }, opts || {}), label);

  // ---------- best score (on this computer only) ----------
  async function loadBest() {
    try { if (window.chrome && chrome.storage) return (await chrome.storage.local.get(['gameBest'])).gameBest || null; } catch (e) { /* not in the extension */ }
    try { return JSON.parse(localStorage.getItem('gameBest')); } catch (e) { return null; }
  }
  async function saveBest(best) {
    try { if (window.chrome && chrome.storage) { await chrome.storage.local.set({ gameBest: best }); return; } } catch (e) { /* not in the extension */ }
    try { localStorage.setItem('gameBest', JSON.stringify(best)); } catch (e) { /* storage blocked */ }
  }

  // ---------- title ----------
  async function title() {
    const best = await loadBest();
    screen(
      h('section', { class: 'panel' },
        h('h2', {}, 'The journey'),
        h('p', {}, 'Your company is moving its email to Secure Harbor, 1,200 miles down the trail. Along the way you\'ll meet look-alike addresses, lying links, fake invoices and gift-card hustlers.'),
        h('p', {}, 'Answer each challenge correctly to earn credits. Wrong answers cost your company\'s trust, unless you carry a 2FA security key. Run out of trust and the expedition is over.'),
        best ? h('p', { class: 'muted' }, `Best expedition on this computer: ${best.score} points (${best.rank}, ${best.role}).`) : null,
        h('div', { class: 'row' }, btn('Start a new expedition', setup, { 'data-primary': true }))));
  }

  // ---------- setup ----------
  function setup() {
    const pick = { role: 'manager', pace: 'steady' };
    const name = h('input', { type: 'text', id: 'company', maxlength: '40', placeholder: 'Your company', 'aria-label': 'Company name' });
    const group = (key, items) => {
      const box = h('div', { class: 'choices', role: 'radiogroup' });
      Object.entries(items).forEach(([id, it], i) => {
        const b = h('button', { type: 'button', class: 'choice' + (pick[key] === id ? ' picked' : ''), role: 'radio', 'aria-checked': String(pick[key] === id), 'data-id': id,
          onclick: () => { pick[key] = id; box.querySelectorAll('.choice').forEach((c) => { const on = c.dataset.id === id; c.classList.toggle('picked', on); c.setAttribute('aria-checked', String(on)); }); } },
        h('span', { class: 'k' }, `${i + 1}.`), it.label, h('small', {}, it.text));
        box.append(b);
      });
      return box;
    };
    screen(
      h('section', { class: 'panel' },
        h('h2', {}, 'Name your company'), name),
      h('section', { class: 'panel' },
        h('h2', {}, 'Choose your role'),
        h('p', { class: 'muted' }, 'Harder roles start with fewer supplies but multiply your final score.'),
        group('role', Object.fromEntries(Object.entries(G.ROLES).map(([k, r]) => [k, { label: `${r.label}: ${r.credits} credits, ${r.shields} security key${r.shields === 1 ? '' : 's'}`, text: r.text }])))),
      h('section', { class: 'panel' },
        h('h2', {}, 'Choose your pace'),
        group('pace', G.PACES)),
      h('div', { class: 'row' }, btn('Hit the trail', () => {
        state = G.create({ role: pick.role, pace: pick.pace, company: name.value.trim() || 'Your company' });
        trail([G.LANDMARKS[0].text, `${state.company} sets out with ${state.credits} credits, ${state.shields} security key${state.shields === 1 ? '' : 's'} and 1 patch kit.`]);
      }, { 'data-primary': true }), btn('Back', title, { class: 'ghost' })));
    name.focus();
  }

  // ---------- the trail ----------
  function stats() {
    const s = state;
    const cell = (v, label, low) => h('div', { class: 'stat' + (low ? ' low' : '') }, h('b', {}, v), h('span', {}, label));
    return h('div', { class: 'stats' },
      cell(`Day ${s.day}`, 'date'), cell(`${s.miles}/${G.DISTANCE}`, 'miles'), cell(s.trust, 'trust', s.trust <= 30),
      cell(s.shields, '2FA keys'), cell(s.patches, 'patch kits'), cell(s.credits, 'credits'));
  }
  const SVG = 'http://www.w3.org/2000/svg';
  function cartSvg() {
    const svg = document.createElementNS(SVG, 'svg');
    svg.setAttribute('viewBox', '0 0 48 36'); svg.setAttribute('class', 'cart'); svg.setAttribute('aria-hidden', 'true');
    const add = (tag, a) => { const e = document.createElementNS(SVG, tag); for (const [k, v] of Object.entries(a)) e.setAttribute(k, v); svg.append(e); };
    add('rect', { x: 4, y: 20, width: 40, height: 6, fill: '#5be08a' });          // cart bed
    add('rect', { x: 8, y: 6, width: 30, height: 14, fill: '#ffc857' });         // envelope
    add('polyline', { points: '8,6 23,15 38,6', fill: 'none', stroke: '#0b1210', 'stroke-width': 2 });
    add('rect', { x: 38, y: 12, width: 6, height: 8, fill: '#5be08a' });         // shield on the side
    add('circle', { cx: 13, cy: 29, r: 5, fill: '#0b1210', stroke: '#b9f5c8', 'stroke-width': 2 });
    add('circle', { cx: 35, cy: 29, r: 5, fill: '#0b1210', stroke: '#b9f5c8', 'stroke-width': 2 });
    return svg;
  }
  function trailView() {
    const pos = (m) => `${3 + (m / G.DISTANCE) * 94}%`;
    const box = h('div', { class: 'trail', role: 'img', 'aria-label': `${state.miles} of ${G.DISTANCE} miles travelled` },
      h('div', { class: 'ground' }), h('div', { class: 'path' }));
    for (const l of G.LANDMARKS) {
      const m = h('div', { class: 'mark' + (l.at <= state.miles ? ' done' : '') + (l.shop ? ' fort' : ''), title: l.name });
      m.style.left = pos(l.at);
      box.append(m);
    }
    const next = G.LANDMARKS[Math.min(state.next, G.LANDMARKS.length - 1)];
    box.append(h('div', { class: 'label' }, state.over ? '' : `Next stop: ${next.name} (${next.at - state.miles} miles)`));
    const cart = cartSvg();
    cart.style.left = pos(Math.max(0, state.miles - 1));
    box.append(cart);
    return box;
  }

  // lines: text to show in the log. atFort: the fort's shop can be visited.
  function trail(lines, atFort) {
    if (state.over) return end();
    screen(stats(), trailView(),
      h('section', { class: 'panel log' }, (lines || []).map((t) => h('p', { class: t.startsWith('!') ? 'event' : '' }, t.replace(/^!/, '')))),
      h('div', { class: 'row' },
        btn('Continue on the trail', go, { 'data-primary': true }),
        btn(state.patches > 0 ? 'Rest and patch (uses a patch kit)' : 'Rest (no patch kits left)', restDay, { class: 'ghost', disabled: state.trust >= 100 }),
        atFort ? btn('Visit the fort\'s store', () => shop(atFort), { class: 'ghost' }) : null));
  }

  function go() {
    const r = G.travel(state);
    if (!r) return end(); // the game was already over (a double click)
    const lines = [`You travel ${r.miles} miles.`];
    if (r.event) lines.push('!' + r.event);
    if (r.landmark) lines.push(`You reach ${r.landmark.name}. ${r.landmark.text}`);
    if (state.over) return end(lines);
    if (r.question) return ask(r.question, lines, r.shop ? r.landmark.name : null, !!r.landmark);
    trail(lines, null);
  }
  function restDay() {
    const r = G.rest(state);
    trail([r.used ? `Your team rests and patches every system. Trust +${r.gain}.` : `Your team rests, but without a patch kit it only helps a little. Trust +${r.gain}.`], null);
  }

  // ---------- a question ----------
  function ask(q, lines, fort, atLandmark) {
    const opts = h('div', { class: 'choices' });
    const done = h('div', {});
    let answered = false;
    q.options.forEach((o, i) => opts.append(h('button', { type: 'button', class: 'choice', 'data-i': String(i), onclick: () => choose(i) }, h('span', { class: 'k' }, `${i + 1}.`), o)));
    function choose(i) {
      if (answered) return;
      answered = true;
      const r = G.answer(state, q, i);
      opts.querySelectorAll('.choice').forEach((b) => { b.disabled = true; const n = Number(b.dataset.i); if (n === q.answer) b.classList.add('right'); else if (n === i) b.classList.add('wrong'); });
      const head = r.correct ? `Right! +15 credits.` : r.shieldUsed ? 'Not quite, but your 2FA security key blocked the attack (keys -1).' : `Not quite. The scammers got through: trust -${r.cost}.`;
      done.append(h('div', { class: 'feedback ' + (r.correct ? 'good' : 'bad') }, h('p', {}, h('b', {}, head)), h('p', {}, r.explain)));
      const next = btn(state.over ? 'See what happened' : 'Continue', () => (state.over ? end() : trail([r.correct ? 'You handled it well.' : 'You learn from the mistake and press on.'], fort)), { 'data-primary': true });
      done.append(h('div', { class: 'row' }, next));
      primary = next;
      next.focus({ preventScroll: true });
      done.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
    screen(stats(), trailView(),
      h('section', { class: 'panel log' }, lines.map((t) => h('p', { class: t.startsWith('!') ? 'event' : '' }, t.replace(/^!/, '')))),
      h('section', { class: 'panel' }, h('h2', {}, atLandmark ? 'Challenge' : 'A message arrives on the road'), h('p', {}, q.q), opts, done));
  }

  // ---------- the fort's store ----------
  function shop(fort) {
    const items = Object.entries(G.SHOP).map(([id, it]) => h('div', { class: 'shopitem' },
      h('div', {}, h('b', {}, `${it.label}: ${it.price} credits`), h('div', { class: 'muted' }, it.text)),
      btn('Buy', () => { G.buy(state, id); shop(fort); }, { disabled: state.credits < it.price })));
    screen(stats(), h('section', { class: 'panel' }, h('h2', {}, `${fort} store`), h('p', { class: 'muted' }, `You have ${state.credits} credits.`), items),
      h('div', { class: 'row' }, btn('Leave the store', () => trail(['You pack your supplies and head back to the trail.'], null), { 'data-primary': true })));
  }

  // ---------- the end ----------
  async function end(lines) {
    const s = state;
    const score = G.score(s), rank = G.rank(s);
    let best = await loadBest();
    const record = s.won && (!best || score > best.score);
    if (record) { best = { score, rank, role: G.ROLES[s.role].label, day: s.day }; await saveBest(best); }
    screen(stats(), trailView(),
      lines && lines.length ? h('section', { class: 'panel log' }, lines.map((t) => h('p', { class: t.startsWith('!') ? 'event' : '' }, t.replace(/^!/, '')))) : null,
      h('section', { class: 'panel' },
        h('h2', {}, s.won ? 'You reached Secure Harbor!' : 'Expedition over'),
        s.won
          ? h('p', {}, `${s.company} arrived on day ${s.day} with ${s.trust} trust, answering ${s.correct} of ${s.asked} challenges correctly.`)
          : h('p', {}, `Scammers wore down ${s.company}'s trust on day ${s.day}, ${G.DISTANCE - s.miles} miles from Secure Harbor. Every wrong answer is a lesson: try again with what you learned.`),
        h('p', { class: 'big' }, s.won ? `${score} points` : 'Breached'),
        h('p', {}, `Rank: ${rank}`),
        record ? h('p', { class: 'muted' }, 'A new best on this computer!') : best ? h('p', { class: 'muted' }, `Best on this computer: ${best.score} points.`) : null,
        h('div', { class: 'row' }, btn('Play again', setup, { 'data-primary': true }), btn('Title screen', title, { class: 'ghost' }))));
  }

  // ---------- keyboard ----------
  document.addEventListener('keydown', (e) => {
    if (e.target && e.target.tagName === 'INPUT') { if (e.key === 'Enter' && primary) primary.click(); return; }
    if (/^[1-4]$/.test(e.key)) {
      const choices = [...app.querySelectorAll('.choice:not(:disabled)')];
      const b = choices[Number(e.key) - 1];
      if (b) { e.preventDefault(); b.click(); }
    } else if (e.key === 'Enter' && primary && document.activeElement === document.body) { e.preventDefault(); primary.click(); }
  });

  title();
})();
