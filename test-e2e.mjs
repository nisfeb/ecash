// The self-method wallet lifecycle end to end: mint, swap, spend state
// (NUT-07), double-spend, and a melt that returns what the inputs paid beyond
// the amount as NUT-08 change.
import {
  run, check, refused, section, setSelf, keyset, selfMint, outputs, post, get, inputs, states, dleqValid, yHex, sum, split,
} from './test-helpers.mjs';

await run('e2e', { auth: true, mutates: true }, async () => {
  await setSelf(true);
  const ks = await keyset();

  section('mint');
  const q = await post('/v1/mint/quote/self', { amount: 5 });
  check('a self quote is PAID at once', q.status === 200 && q.body.state === 'PAID' && q.body.amount === 5, q.body);
  const o = outputs([4, 1], ks.id);
  const m = await post('/v1/mint/self', { quote: q.body.quote, outputs: o.msgs });
  check('the mint signs each output with a valid DLEQ proof',
    m.status === 200 && m.body.signatures.length === 2 && m.body.signatures.every((s, i) => dleqValid(s, o.msgs[i].B_, ks.keys)), m.body);
  const minted = o.proofs(m.body.signatures, ks.keys);
  check('the quote then reads ISSUED', (await get(`/v1/mint/quote/self/${q.body.quote}`)).body?.state === 'ISSUED');
  refused('and mints nothing more', await post('/v1/mint/self', { quote: q.body.quote, outputs: outputs([4, 1], ks.id).msgs }), 400, 'quote-not-paid');
  check('fresh proofs read UNSPENT', (await states(minted)).every((s) => s === 'UNSPENT'), await states(minted));

  section('swap');
  const o2 = outputs([2, 2, 1], ks.id);
  const s = await post('/v1/swap', { inputs: inputs(minted), outputs: o2.msgs });
  check('the swap signs outputs worth its inputs', s.status === 200 && sum(s.body.signatures) === 5, s.body);
  const swapped = o2.proofs(s.body.signatures, ks.keys);
  check('its inputs read SPENT', (await states(minted)).every((x) => x === 'SPENT'), await states(minted));
  const upper = await post('/v1/checkstate', { Ys: [yHex(minted[0].secret).toUpperCase()] });
  check('an uppercase Y reads SPENT and comes back lowercase',
    upper.body?.states?.[0]?.state === 'SPENT' && upper.body.states[0].Y === yHex(minted[0].secret), upper.body);
  refused('spending them again', await post('/v1/swap', { inputs: inputs(minted), outputs: outputs([4, 1], ks.id).msgs }),
    400, 'token-already-spent');

  section('melt with change (NUT-08)');
  const mq = await post('/v1/melt/quote/self', { amount: 2, request: 'lnbc20n1pnotboundtoaselfquote' });
  check('a self melt quote binds no invoice: request is self-melt, reserve 0',
    mq.status === 200 && mq.body.request === 'self-melt' && mq.body.fee_reserve === 0 && mq.body.state === 'UNPAID', mq.body);
  const blanks = outputs([0, 0, 0], ks.id);
  const r = await post('/v1/melt/self', { quote: mq.body.quote, inputs: inputs(swapped), outputs: blanks.msgs });
  check('inputs of 5 melt a 2-sat quote: PAID', r.status === 200 && r.body.state === 'PAID', r.body);
  const change = blanks.proofs(r.body.change ?? [], ks.keys);
  check('the 3 sat overpaid comes back as change 2 + 1',
    sum(change) === 3 && change.map((c) => c.amount).sort().join() === split(3).sort().join(), r.body.change);
  const back = await post('/v1/swap', { inputs: inputs(change), outputs: outputs(split(3), ks.id).msgs });
  check('and the change spends', back.status === 200, back.body);

  section('melt without change outputs (they are optional)');
  const fresh = await selfMint(ks, [1]);
  const mq1 = (await post('/v1/melt/quote/self', { amount: 1 })).body;
  const r1 = await post('/v1/melt/self', { quote: mq1.quote, inputs: inputs(fresh) });
  check('an exact melt with no outputs is PAID with no change', r1.body?.state === 'PAID' && r1.body.change?.length === 0, r1.body);
});
