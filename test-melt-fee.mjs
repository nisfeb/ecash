// A bolt11 melt's amounts: inputs must cover amount + fee reserve, and the
// NUT-08 change is the unused reserve plus whatever the inputs paid beyond
// amount + reserve. The mock reports the routing fee as LNbits does, as
// NEGATIVE msat (-2000 = 2 sat).
import {
  run, check, refused, section, setSelf, keyset, fund, outputs, post, get, inputs, dleqValid, forged, invoice, sum, split,
} from './test-helpers.mjs';

const FEE = 2;  // the mock's routing fee, in sat

await run('melt-fee', { auth: true, mutates: true, ln: true }, async () => {
  await setSelf(true);
  const ks = await keyset();
  const mq = (await post('/v1/melt/quote/bolt11', { request: invoice(10_000) })).body;
  check('a 10-sat invoice quotes amount 10, reserve 10 (the floor)', mq?.amount === 10 && mq.fee_reserve === 10, mq);

  section('inputs must cover amount + reserve, checked on the claimed amounts first');
  refused('forged inputs claiming 19 are refused for the amount, not the signature',
    await post('/v1/melt/bolt11', { quote: mq.quote, inputs: [forged(ks, 16), forged(ks, 2), forged(ks, 1)] }), 400, 'insufficient-inputs');

  section('change = unused reserve (10 - 2) + excess (5) = 13');
  const ins = await fund(ks, 25);
  const blanks = outputs(Array(6).fill(0), ks.id);
  const r = await post('/v1/melt/bolt11', { quote: mq.quote, inputs: inputs(ins), outputs: blanks.msgs });
  check('inputs of 25 melt the quote: PAID', r.body?.state === 'PAID', r.body);
  const sigs = r.body?.change ?? [];
  check(`the change is 13 = 10 - ${FEE} + 5, as 8 + 4 + 1`,
    sum(sigs) === 13 && sigs.map((c) => c.amount).sort((x, y) => x - y).join() === '1,4,8', sigs.map((c) => c.amount));
  check('every change signature carries a valid DLEQ proof', sigs.length > 0 && sigs.every((s, i) => dleqValid(s, blanks.msgs[i].B_, ks.keys)));
  const change = blanks.proofs(sigs, ks.keys);
  const spend = await post('/v1/swap', { inputs: inputs(change), outputs: outputs(split(13), ks.id).msgs });
  check('the change spends', spend.status === 200, spend.body);
  const polled = (await get(`/v1/melt/quote/bolt11/${mq.quote}`)).body;
  check('a later poll of the quote returns the same change', JSON.stringify(polled?.change?.map((c) => c.C_)) === JSON.stringify(sigs.map((c) => c.C_)), polled);
});
