// Inbox Expedition: the question bank and the game rules (game/questions.js, game/engine.js).
'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const G = require('../game/engine.js');
const Q = require('../game/questions.js');

test('every question is well formed and the ids are unique', () => {
  const ids = new Set();
  for (const q of Q) {
    assert.ok(q.id && !ids.has(q.id), `duplicate or missing id: ${q.id}`); ids.add(q.id);
    assert.ok(q.q.length > 10, q.id);
    assert.ok(Array.isArray(q.options) && q.options.length >= 2 && q.options.length <= 4, `${q.id}: 2-4 options`);
    assert.ok(Number.isInteger(q.answer) && q.answer >= 0 && q.answer < q.options.length, `${q.id}: answer index`);
    assert.equal(new Set(q.options).size, q.options.length, `${q.id}: duplicate options`);
    assert.ok(q.explain && q.explain.length > 20, `${q.id}: explanation`);
  }
  assert.ok(Q.length >= 30, 'at least 30 questions');
});

test('every landmark with a topic has questions about it', () => {
  for (const l of G.LANDMARKS) if (l.topic) assert.ok(Q.some((q) => q.topic === l.topic), `${l.name}: no ${l.topic} questions`);
});

test('options are shuffled when asked, so the right answer moves around', () => {
  const s = G.create({ seed: 5 });
  const positions = new Set();
  for (let i = 0; i < 20; i++) {
    const q = G.pickQuestion(s, null);
    const orig = Q.find((x) => x.id === q.id);
    assert.equal(q.options[q.answer], orig.options[orig.answer], `${q.id}: answer still points at the right text`);
    assert.deepEqual([...q.options].sort(), [...orig.options].sort());
    positions.add(q.answer);
  }
  assert.ok(positions.size >= 3, `answers only at positions ${[...positions]}`);
});

// Plays a whole game with a fixed seed. `smart` answers everything right; otherwise everything wrong.
function play(smart, opts) {
  const s = G.create(Object.assign({ seed: 42 }, opts));
  let guard = 0;
  while (!s.over && guard++ < 200) {
    const r = G.travel(s);
    if (r && r.question) G.answer(s, r.question, smart ? r.question.answer : (r.question.answer + 1) % r.question.options.length);
  }
  return s;
}

test('answering everything right reaches Secure Harbor with a score', () => {
  const s = play(true);
  assert.ok(s.won, 'should win');
  assert.equal(s.miles, G.DISTANCE);
  assert.ok(G.score(s) > 0);
  assert.equal(G.rank(s), 'Phish Hunter');
  assert.equal(s.correct, s.asked);
});

test('answering everything wrong ends the expedition with no score', () => {
  const s = play(false, { role: 'intern', pace: 'rushed' });
  assert.ok(s.over && !s.won, 'should lose');
  assert.equal(s.trust, 0);
  assert.equal(G.score(s), 0);
  assert.equal(G.rank(s), 'Breached');
});

test('a 2FA key blocks the cost of a wrong answer', () => {
  const s = G.create({ role: 'analyst', seed: 1 });
  const q = Q[0];
  const r = G.answer(s, q, (q.answer + 1) % q.options.length);
  assert.ok(r.shieldUsed);
  assert.equal(s.trust, 100);
  assert.equal(s.shields, G.ROLES.analyst.shields - 1);
});

test('the store, resting, and the same seed giving the same game', () => {
  const s = G.create({ role: 'manager', seed: 7 });
  assert.ok(G.buy(s, 'shield'));
  assert.equal(s.credits, G.ROLES.manager.credits - G.SHOP.shield.price);
  assert.ok(!G.buy(s, 'shield') || s.credits >= 0);
  s.trust = 50;
  const r = G.rest(s);
  assert.ok(r.used && s.trust === 75);
  const a = G.create({ seed: 99 }), b = G.create({ seed: 99 });
  for (let i = 0; i < 5; i++) assert.deepEqual(G.travel(a), G.travel(b));
});

test('questions do not repeat within a game until the bank runs out', () => {
  const s = G.create({ seed: 3 });
  const seen = new Set();
  for (let i = 0; i < Q.length; i++) { const q = G.pickQuestion(s, null); assert.ok(!seen.has(q.id), `repeated ${q.id}`); seen.add(q.id); }
});
