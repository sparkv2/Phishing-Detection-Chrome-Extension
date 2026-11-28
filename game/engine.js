// Inbox Expedition: game rules (no page code here, so the rules can be tested in Node; see test/game.test.js).
//
// You lead a mail cart from Sign-Up Springs to Secure Harbor. Each leg of the trip costs a day; landmarks ask a
// cybersecurity question about their theme, two forts sell supplies, and random events happen along the way.
//   trust     your company's health (0-100). A wrong answer costs trust; 0 ends the game.
//   shields   2FA security keys: each one blocks the cost of one wrong answer.
//   patches   patch kits: "Rest and patch" uses one to restore trust.
//   credits   earned for right answers, spent at forts.
(function (root) {
  'use strict';
  const QUESTIONS = (typeof module === 'object' && module.exports) ? require('./questions.js') : root.TW_GAME_QUESTIONS;

  const DISTANCE = 1200;
  const LANDMARKS = [
    { name: 'Sign-Up Springs', at: 0, topic: null, text: 'Your company just opened its first inboxes. Somewhere ahead lies Secure Harbor.' },
    { name: 'Password Pass', at: 110, topic: 'passwords', text: 'A narrow pass where travellers are asked for their passwords. Only some of the askers are honest.' },
    { name: 'Look-alike Lake', at: 230, topic: 'lookalike', text: 'The water reflects every sign on the shore, almost perfectly. Look closely at the spelling.' },
    { name: 'Fort Firewall', at: 340, topic: 'tripwire', shop: true, text: 'A trading post behind thick walls. Supplies are for sale.' },
    { name: 'Attachment Canyon', at: 460, topic: 'attachments', text: 'Parcels lie scattered along the canyon floor. Not all of them are what their labels say.' },
    { name: 'Link River', at: 570, topic: 'links', text: 'The river is crossed by a dozen bridges, each with a sign. Some signs point the wrong way.' },
    { name: 'QR Crossing', at: 680, topic: 'qr', text: 'Square codes are painted on every post. Scanning one takes you somewhere you can\'t see.' },
    { name: 'Gift Card Gulch', at: 790, topic: 'money', text: 'Urgent messages echo off the canyon walls: "Buy gift cards. Tell no one."' },
    { name: 'Fort Backup', at: 900, topic: 'tripwire', shop: true, text: 'The last trading post. Restock before the final stretch.' },
    { name: 'Relay Ridge', at: 1010, topic: 'sender', text: 'Messages arrive here from addresses you\'ve never seen. Who really sent them?' },
    { name: 'Report Rock', at: 1110, topic: 'tripwire', text: 'Travellers leave warnings carved into this rock for the ones who come after.' },
    { name: 'Secure Harbor', at: DISTANCE, topic: null, end: true, text: 'Calm water, locked doors, and an inbox you can trust. You made it.' },
  ];
  const ROLES = {
    analyst: { label: 'Security analyst', credits: 200, shields: 2, mult: 1, text: 'Well equipped, but expected to do well. Score x1.' },
    manager: { label: 'Office manager', credits: 120, shields: 1, mult: 2, text: 'Some supplies, some experience. Score x2.' },
    intern: { label: 'New intern', credits: 50, shields: 0, mult: 3, text: 'Few supplies, everything to prove. Score x3.' },
  };
  const PACES = {
    careful: { label: 'Careful', min: 60, max: 85, penalty: 14, text: 'Slow and steady. Wrong answers hurt less.' },
    steady: { label: 'Steady', min: 85, max: 110, penalty: 20, text: 'A normal pace.' },
    rushed: { label: 'Rushed', min: 115, max: 145, penalty: 28, text: 'Fewer days on the trail, but mistakes cost more.' },
  };
  const SHOP = {
    shield: { label: '2FA security key', price: 60, text: 'Blocks the cost of one wrong answer.' },
    patch: { label: 'Patch kit', price: 40, text: 'Restores 25 trust when you rest.' },
  };
  const REWARD = 15; // credits per right answer

  // Small seeded random number generator, so a game (and a test) can be replayed exactly.
  function rng(seed) {
    let a = seed >>> 0;
    return () => { a = (a + 0x6D2B79F5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  }

  function create(opts) {
    opts = opts || {};
    const role = ROLES[opts.role] ? opts.role : 'manager';
    const pace = PACES[opts.pace] ? opts.pace : 'steady';
    return {
      role, pace, company: (opts.company || 'Your company').slice(0, 40),
      day: 1, miles: 0, trust: 100, shields: ROLES[role].shields, patches: 1, credits: ROLES[role].credits,
      asked: 0, correct: 0, next: 1, used: [], over: false, won: false,
      seed: opts.seed == null ? (Date.now() & 0xffffffff) : opts.seed, rand: null,
    };
  }
  const random = (s) => { if (!s.rand) s.rand = rng(s.seed); return s.rand(); };

  // A question not asked yet in this game, preferring `topic`.
  function pickQuestion(s, topic) {
    let pool = QUESTIONS.filter((q) => !s.used.includes(q.id) && (!topic || q.topic === topic));
    if (!pool.length) pool = QUESTIONS.filter((q) => !s.used.includes(q.id));
    if (!pool.length) { s.used = []; pool = QUESTIONS.slice(); }
    const q = pool[Math.floor(random(s) * pool.length)];
    s.used.push(q.id);
    // Shuffle the options so the right answer isn't always in the same place.
    const order = q.options.map((_, i) => i);
    for (let i = order.length - 1; i > 0; i--) { const j = Math.floor(random(s) * (i + 1)); [order[i], order[j]] = [order[j], order[i]]; }
    return Object.assign({}, q, { options: order.map((i) => q.options[i]), answer: order.indexOf(q.answer) });
  }

  // Things that happen on the trail, good and bad. Each changes the state and returns the message to show.
  const EVENTS = [
    (s) => { s.credits += 20; return 'A coworker reported a phishing email before anyone clicked it. The team earns 20 credits.'; },
    (s) => { s.trust = Math.min(100, s.trust + 10); return 'Software updates installed overnight. Trust +10.'; },
    (s) => { s.day += 1; return 'A laptop needed urgent security updates. You lose a day.'; },
    (s) => {
      if (s.patches > 0) { s.patches -= 1; return 'A website your team uses was breached. A patch kit kept the damage small (patch kits -1).'; }
      s.trust -= 15; return 'A website your team uses was breached, and someone had reused that password. Trust -15.';
    },
    (s) => { s.trust -= 8; return 'A "tech support" caller talked an employee into installing remote-access software. IT caught it, but trust -8.'; },
    (s) => { s.credits += 10; return 'A password manager refused to fill in a password on a fake login page. Crisis avoided: 10 credits.'; },
  ];

  // One leg of the trip. Returns what happened: { miles, event?, landmark?, question?, shop? }.
  function travel(s) {
    if (s.over) return null;
    const p = PACES[s.pace];
    const dest = LANDMARKS[s.next];
    const step = Math.round(p.min + random(s) * (p.max - p.min));
    const out = { miles: 0 };
    s.day += 1;
    if (s.miles + step >= dest.at) { out.miles = dest.at - s.miles; s.miles = dest.at; s.next += 1; out.landmark = dest; }
    else { out.miles = step; s.miles += step; }
    if (random(s) < 0.3) out.event = EVENTS[Math.floor(random(s) * EVENTS.length)](s);
    if (out.landmark && out.landmark.end) { finish(s); return out; }
    if (s.trust <= 0) { finish(s); return out; }
    if (out.landmark) { out.question = pickQuestion(s, out.landmark.topic); out.shop = !!out.landmark.shop; }
    else if (random(s) < 0.55) out.question = pickQuestion(s, null); // a message arrives on the road
    return out;
  }

  // Answer a question. Returns { correct, cost, shieldUsed, explain }.
  function answer(s, q, choice) {
    s.asked += 1;
    if (choice === q.answer) { s.correct += 1; s.credits += REWARD; return { correct: true, cost: 0, shieldUsed: false, explain: q.explain }; }
    if (s.shields > 0) { s.shields -= 1; return { correct: false, cost: 0, shieldUsed: true, explain: q.explain }; }
    const cost = PACES[s.pace].penalty;
    s.trust -= cost;
    if (s.trust <= 0) finish(s);
    return { correct: false, cost, shieldUsed: false, explain: q.explain };
  }

  // Rest for a day: a patch kit restores 25 trust, resting without one restores 8.
  function rest(s) {
    if (s.over) return null;
    s.day += 1;
    const used = s.patches > 0;
    if (used) s.patches -= 1;
    const gain = Math.min(used ? 25 : 8, 100 - s.trust);
    s.trust += gain;
    return { used, gain };
  }

  function buy(s, item) {
    const it = SHOP[item];
    if (!it || s.credits < it.price) return false;
    s.credits -= it.price;
    if (item === 'shield') s.shields += 1; else s.patches += 1;
    return true;
  }

  function finish(s) {
    s.trust = Math.max(0, s.trust);
    s.over = true;
    s.won = s.trust > 0 && s.miles >= DISTANCE;
  }

  // Final score: trust, supplies and right answers, a bonus for a fast trip, times the role's multiplier.
  function score(s) {
    if (!s.won) return 0;
    const base = s.trust * 2 + s.credits + s.shields * 30 + s.patches * 15 + s.correct * 10 + Math.max(0, 30 - s.day) * 5;
    return Math.round(base * ROLES[s.role].mult);
  }
  function rank(s) {
    if (!s.won) return 'Breached';
    const pct = s.asked ? s.correct / s.asked : 1;
    if (pct >= 0.9) return 'Phish Hunter';
    if (pct >= 0.75) return 'Inbox Guardian';
    if (pct >= 0.5) return 'Careful Clicker';
    return 'Lucky Traveller';
  }

  const api = { DISTANCE, LANDMARKS, ROLES, PACES, SHOP, QUESTIONS, create, travel, answer, rest, buy, score, rank, pickQuestion };
  if (typeof module === 'object' && module.exports) module.exports = api;
  root.TW_Game = api;
})(typeof self !== 'undefined' ? self : globalThis);
