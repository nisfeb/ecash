// The self method (quotes paid on creation, for development) works only while
// the operator has it on, including for quotes made while it was on.
import { run, refused, check, setSelf, keyset, outputs, post } from './test-helpers.mjs';

await run('self-method', { auth: true, mutates: true }, async () => {
  const ks = await keyset();
  await setSelf(false);
  refused('off: a self mint quote', await post('/v1/mint/quote/self', { amount: 4 }), 400, 'self-method-disabled');
  refused('off: a self melt quote', await post('/v1/melt/quote/self', { amount: 4 }), 400, 'self-method-disabled');
  await setSelf(true);
  const q = await post('/v1/mint/quote/self', { amount: 4 });
  check('on: a self mint quote, PAID', q.status === 200 && q.body.state === 'PAID', q.body);
  await setSelf(false);
  // the closed CRITICAL hole: a self quote made while on must not mint once
  // off, whichever method the URL names
  refused('off again: that quote does not mint over self', await post('/v1/mint/self', { quote: q.body.quote, outputs: outputs([4], ks.id).msgs }), 400, 'self-method-disabled');
  refused('nor over bolt11', await post('/v1/mint/bolt11', { quote: q.body.quote, outputs: outputs([4], ks.id).msgs }), 400, 'self-method-disabled');
  await setSelf(true);
  const m = await post('/v1/mint/self', { quote: q.body.quote, outputs: outputs([4], ks.id).msgs });
  check('on again: it mints', m.status === 200, m.body);
});
