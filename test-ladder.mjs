// A fuzz of the mint's scalar multiplication (curve.hoon's ladder) through
// the wire: batches of random B_ across every denomination's key. Each
// signature's NUT-12 DLEQ proof must verify, which holds only if C_ = kB_
// for the k with K = kG (and the proof's own R2 = rB_ for its nonce), and
// every unblinded proof must then swap, which holds only if the mint's
// C = kY check agrees. A wrong product for any point fails one of the two.
// ROUNDS (default 2) batches of 99 outputs.
import {
  run, check, section, setSelf, keyset, outputs, post, inputs, dleqValid, sum,
} from './test-helpers.mjs';

await run('ladder', { auth: true, mutates: true }, async () => {
  await setSelf(true);
  const ks = await keyset();
  const denoms = Object.keys(ks.keys).map(Number).sort((a, b) => a - b);
  const amounts = Array.from({ length: 99 }, (_, i) => denoms[i % denoms.length]);
  for (let round = 1; round <= Number(process.env.ROUNDS || 2); round++) {
    section(`round ${round}: 99 random B_ over all ${denoms.length} keys`);
    const q = (await post('/v1/mint/quote/self', { amount: sum(amounts) })).body;
    const o = outputs(amounts, ks.id);
    const m = await post('/v1/mint/self', { quote: q.quote, outputs: o.msgs });
    const sigs = m.body?.signatures ?? [];
    const bad = sigs.map((s, i) => (dleqValid(s, o.msgs[i].B_, ks.keys) ? null : { amount: s.amount, B_: o.msgs[i].B_, sig: s })).filter(Boolean);
    check('every signature\'s DLEQ proof verifies', sigs.length === 99 && bad.length === 0, bad.length ? bad.slice(0, 3) : m.body);
    const s = await post('/v1/swap', { inputs: inputs(o.proofs(sigs, ks.keys)), outputs: outputs(amounts, ks.id).msgs });
    check('every unblinded proof swaps', s.status === 200 && s.body.signatures.length === 99, s.body);
  }
});
