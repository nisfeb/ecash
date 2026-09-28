// NUT-09 restore: a wallet that lost its proofs re-derives its blinded
// messages and gets back the signatures the mint issued for them.
import { run, check, section, setSelf, keyset, selfMint, blind, post, get, dleqValid } from './test-helpers.mjs';

await run('restore', { auth: true, mutates: true }, async () => {
  check('/v1/info advertises NUT-09', (await get('/v1/info')).body?.nuts?.['9']?.supported === true);
  await setSelf(true);
  const ks = await keyset();

  section('a B_ the mint signed comes back with its signature');
  const q = (await post('/v1/mint/quote/self', { amount: 3 })).body;
  const b = [blind(), blind()];
  const outs = [{ amount: 2, id: ks.id, B_: b[0].B_ }, { amount: 1, id: ks.id, B_: b[1].B_ }];
  const minted = (await post('/v1/mint/self', { quote: q.quote, outputs: outs })).body.signatures;
  const unknown = blind().B_;
  const r = (await post('/v1/restore', { outputs: [outs[0], { amount: 1, id: ks.id, B_: unknown }, outs[1]] })).body;
  check('an unknown B_ is left out; the two known come back in order',
    r?.outputs?.length === 2 && r.signatures?.length === 2 && r.outputs[0].B_ === b[0].B_ && r.outputs[1].B_ === b[1].B_, r);
  check('each with the signature first issued', r?.signatures?.every((s, i) => s.C_ === minted[i].C_ && s.amount === minted[i].amount));
  check('and a DLEQ proof that verifies', r?.signatures?.every((s, i) => dleqValid(s, outs[i].B_, ks.keys)));
  const upper = (await post('/v1/restore', { outputs: [{ ...outs[0], B_: outs[0].B_.toUpperCase() }] })).body;
  check('B_ matches case-insensitively', upper?.signatures?.[0]?.C_ === minted[0].C_, upper);

  section('NUT-08 change is restorable too');
  const [p] = await selfMint(ks, [4]);
  const mq = (await post('/v1/melt/quote/self', { amount: 1 })).body;
  const blank = blind().B_;
  const melt = (await post('/v1/melt/self', { quote: mq.quote, inputs: [{ amount: 4, id: ks.id, secret: p.secret, C: p.C }], outputs: [{ amount: 0, id: ks.id, B_: blank }] })).body;
  const back = (await post('/v1/restore', { outputs: [{ amount: 0, id: ks.id, B_: blank }] })).body;
  check('a change output restores to the change signature', melt?.change?.[0]?.C_ && back?.signatures?.[0]?.C_ === melt.change[0].C_, { melt, back });
});
