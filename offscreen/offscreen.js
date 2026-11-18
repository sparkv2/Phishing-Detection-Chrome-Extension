// Offscreen page: runs the on-device AI check for the background worker (service workers can't use the Prompt API).
chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  if (!msg || msg.target !== 'offscreen' || msg.type !== 'pg-ai-run') return;
  PG_AI.check(msg.payload || {}).then(reply, () => reply(null));
  return true;
});
