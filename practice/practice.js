// Practice mode: each lesson is judged by the real analyzer, so its answer and explanation match what
// Tripwire would show on a real email. Lessons about tricks you've actually received (counts only) come first.
(function () {
  'use strict';
  const A = window.PG_Analyzer;
  const app = document.getElementById('app');
  const NONE = 'Nothing. This email looks fine';
  const h = (tag, attrs, ...kids) => {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) { if (k === 'class') el.className = v; else if (k.startsWith('on')) el.addEventListener(k.slice(2), v); else el.setAttribute(k, v); }
    for (const c of kids.flat()) if (c != null) el.append(c.nodeType ? c : document.createTextNode(String(c)));
    return el;
  };
  const shuffle = (a) => { for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a; };

  // Runs the real analyzer on a lesson's made-up email (with its simulated headers, history, thread...).
  function judge(lesson) {
    const x = lesson.extra || {};
    const input = Object.assign({ context: 'open' }, lesson.email, { auth: x.auth, attachments: x.attachments, qrCodes: x.qrCodes, history: x.history, thread: x.thread });
    return A.analyzeEmail(input, { expanded: new Map(x.expanded || []) });
  }

  // Draws the email like a mail client would. Hovering a link or the QR code reveals where it really goes.
  function mailView(lesson) {
    const e = lesson.email, x = lesson.extra || {};
    const body = h('div', { class: 'bd' }, h('p', {}, e.body));
    for (const l of e.links || []) {
      const real = (new Map(x.expanded || [])).get(l.href) || l.href;
      body.append(h('p', {}, h('span', { class: 'fake-link', title: 'Really goes to: ' + real }, l.text)), h('div', { class: 'hint' }, 'Hover the link to see where it really goes.'));
    }
    if (lesson.qr) {
      const qr = h('div', { class: 'qr', title: 'QR code. Opens: ' + x.qrCodes[0].data });
      const pattern = '1111111100000110111011011101101110110000011111111';
      for (const c of pattern) qr.append(h('i', { class: c === '1' ? '' : 'w' }));
      body.append(qr, h('div', { class: 'hint' }, 'Hover the QR code to see the web address it opens.'));
    }
    for (const a of x.attachments || []) body.append(h('span', { class: 'att' }, '📎 ' + a.name));
    return h('div', { class: 'mail' }, h('div', { class: 'hd' }, h('div', { class: 'subj' }, e.subject), h('div', { class: 'from' }, `${e.senderName} <${e.senderEmail}>`)), body);
  }

  // Orders the lessons (tricks you've received first, the rest shuffled) and steps through them one at a time.
  async function start() {
    let counts = {};
    try { counts = (await chrome.storage.local.get(['signalCounts'])).signalCounts || {}; } catch (e) { /* opened outside the extension */ }
    const lessons = window.TW_LESSONS.map((l) => ({ l, r: judge(l) }));
    for (const x of lessons) x.yours = x.r.signals.reduce((n, s) => n + (counts[s.id] || 0), 0);
    const ordered = lessons.filter((x) => x.yours).sort((a, b) => b.yours - a.yours).concat(shuffle(lessons.filter((x) => !x.yours)));
    let i = 0, score = 0;

    // One lesson: the email, then "What is the biggest red flag?". The right answer is the analyzer's top reason (or
    // "Nothing" for a genuine email); the wrong ones are harmless details. Answering explains the trick.
    function show() {
      app.textContent = '';
      if (i >= ordered.length) {
        app.append(h('div', { class: 'done' }, h('div', { class: 'big' }, `${score} / ${ordered.length}`),
          h('p', {}, score === ordered.length ? 'Perfect. You spotted every trick.' : 'Nice work. Every lesson you missed is a trick worth remembering.'),
          h('button', { class: 'next', onclick: () => { i = 0; score = 0; shuffle(ordered); show(); } }, 'Practice again')));
        return;
      }
      const { l, r, yours } = ordered[i];
      const top = r.level === 'safe' ? null : r.signals[0];
      const correct = top ? top.title : NONE;
      const others = shuffle(window.TW_DISTRACTORS.slice()).slice(0, top ? 2 : 3);
      const options = shuffle([correct, ...others, ...(top ? [NONE] : [])]);
      app.append(h('div', { class: 'progress' }, h('span', {}, `Lesson ${i + 1} of ${ordered.length}`), h('span', {}, `Score: ${score}`)));
      if (yours) app.append(h('div', { class: 'yours' }, `You've received emails using this trick ${yours} time(s)`));
      app.append(mailView(l), h('p', { class: 'q' }, 'What is the biggest red flag in this email?'));
      const opts = h('div', { class: 'opts' });
      for (const o of options) {
        opts.append(h('button', { onclick: (ev) => {
          const right = o === correct;
          if (right) score++;
          [...opts.children].forEach((b) => { b.disabled = true; if (b.textContent === correct) b.classList.add('right'); });
          if (!right) ev.currentTarget.classList.add('wrong');
          const fb = h('div', { class: 'feedback ' + (right ? 'good' : 'bad') }, h('b', {}, right ? 'Correct! ' : 'Not quite. '));
          if (top) {
            fb.append(top.explain);
            const rest = r.signals.slice(1).filter((s) => s.weight >= 8);
            if (rest.length) fb.append(h('p', {}, 'Tripwire also noticed:'), h('ul', {}, rest.slice(0, 4).map((s) => h('li', {}, s.title))));
          } else fb.append('This one is genuine: the sender, links and wording all check out. Not every email is a trap, and knowing what normal looks like helps the fakes stand out.');
          if (l.note) fb.append(h('p', { class: 'hint' }, l.note));
          app.append(fb, h('button', { class: 'next', onclick: () => { i++; show(); } }, i + 1 < ordered.length ? 'Next lesson →' : 'See my score'));
        } }, o));
      }
      app.append(opts);
    }
    show();
  }
  start();
})();
