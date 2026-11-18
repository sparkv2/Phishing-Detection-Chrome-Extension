// On-device AI check using Chrome's built-in model (Gemini Nano, Prompt API). Shared by the offscreen page and the popup.
// The model runs locally; the email text never leaves the computer.
(function (root) {
  'use strict';
  const ASKS = ['credentials', 'payment', 'gift_cards', 'personal_info', 'click_link', 'open_attachment', 'call_phone', 'reply', 'none'];
  const SCHEMA = {
    type: 'object',
    properties: {
      risk: { type: 'string', enum: ['low', 'medium', 'high'] },
      asks: { type: 'array', items: { type: 'string', enum: ASKS }, maxItems: 4 },
      reasons: { type: 'array', items: { type: 'string' }, maxItems: 2 },
      summary: { type: 'string' },
    },
    required: ['risk', 'asks', 'reasons', 'summary'],
  };
  const SYSTEM = 'You check emails for phishing and fraud. The email may be in any language. ' +
    'Judge the intent: does it pressure the reader, impersonate someone, or ask for passwords, codes, payment, gift cards or personal details? ' +
    'Ordinary newsletters, receipts and personal messages are low risk. ' +
    'Reply in English. "reasons": at most two short sentences a non-expert understands. "summary": one plain sentence saying what the email wants, at most 30 words.';

  const api = () => root.LanguageModel || null;

  async function availability() {
    const LM = api();
    if (!LM) return 'unsupported';
    try { return await LM.availability({ expectedOutputs: [{ type: 'text', languages: ['en'] }] }); } catch (e) {
      try { return await LM.availability(); } catch (e2) { return 'unsupported'; }
    }
  }

  let base = null;
  async function session(onProgress) {
    if (base) return base;
    const LM = api();
    const opts = { initialPrompts: [{ role: 'system', content: SYSTEM }], expectedOutputs: [{ type: 'text', languages: ['en'] }] };
    if (onProgress) opts.monitor = (m) => m.addEventListener('downloadprogress', (e) => onProgress(e.loaded));
    try { base = await LM.create(opts); } catch (e) { delete opts.expectedOutputs; base = await LM.create(opts); }
    return base;
  }

  async function check({ subject, sender, body }) {
    if (!api() || (await availability()) !== 'available') return null;
    const s = await session();
    const one = s.clone ? await s.clone() : s; // fresh context per email
    try {
      const text = `From: ${sender || '(unknown)'}\nSubject: ${subject || ''}\n\n${(body || '').replace(/\s+/g, ' ').slice(0, 4000)}`;
      const raw = await one.prompt(text, { responseConstraint: SCHEMA });
      const r = JSON.parse(raw);
      return { risk: ['low', 'medium', 'high'].includes(r.risk) ? r.risk : 'low', asks: (r.asks || []).filter((a) => ASKS.includes(a)),
        reasons: (r.reasons || []).map((x) => String(x).slice(0, 200)).slice(0, 2), summary: String(r.summary || '').slice(0, 300) };
    } finally { if (one !== s && one.destroy) one.destroy(); }
  }

  root.PG_AI = { availability, session, check };
})(typeof globalThis !== 'undefined' ? globalThis : this);
