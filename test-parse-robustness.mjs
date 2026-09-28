// A malformed number is a clean 400, not a crashed event (a 500 or a hang).
import { run, refused, post } from './test-helpers.mjs';

await run('parse-robustness', {}, async () => {
  const hang = AbortSignal.timeout(8000);
  const r = await Promise.race([post('/v1/mint/quote/bolt11', { amount: 1.5 }), new Promise((_, no) => hang.addEventListener('abort', () => no(new Error('no answer in 8 s'))))]);
  refused('a fractional amount', r, 400, 'invalid-amount');
});
