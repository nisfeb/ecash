// The swap's refusals (NUT-03). A swap or mint signs every output or changes
// nothing: each refusal is a 400 with its exact detail, sent before anything
// is spent, so the proof it named still swaps afterwards. Also the order of
// the checks: the claimed amounts balance, and every cheap check covers the
// whole batch, before any elliptic-curve work.
import {
  run, check, refused, section, setSelf, keyset, selfMint, outputs, post, inputs, states,
  dleqValid, point, forged, newSecret, inactiveKeyset,
} from './test-helpers.mjs';

// offCurve: a well-formed compressed point whose x is not on secp256k1
function offCurve() {
  for (let x = 1n; ; x++) {
    const hex = '02' + x.toString(16).padStart(64, '0');
    try { point(hex); } catch { return hex; }
  }
}
// sized: a unique secret of exactly n bytes
const sized = (n) => newSecret('len').padEnd(n, 'x');

await run('swap-security', { auth: true, mutates: true }, async () => {
  await setSelf(true);
  const ks = await keyset();
  const [p4] = await selfMint(ks, [4]);
  const swap = (proofs, outs) => post('/v1/swap', { inputs: proofs, outputs: outs });
  // out: fresh outputs for these amounts, each optionally overridden
  const out = (amounts, over = []) => outputs(amounts, ks.id).msgs.map((m, i) => ({ ...m, ...over[i] }));

  section('an unsignable output refuses the whole swap');
  const twin = out([4, 0]);
  twin[1].B_ = point(twin[0].B_).negate().toHex(true);
  const cases = [
    ['a non-object output', [...out([4]), 'x'], 'invalid-msg'],
    ['an output without B_', [{ amount: 4, id: ks.id }], 'missing-B_'],
    ['a B_ that is not on the curve', out([4], [{ B_: offCurve() }]), 'invalid-B_-point'],
    ['B_ beside its negation -B_ (one x)', twin, 'duplicate-output'],
    ['a B_ the mint signed before', out([4], [{ B_: p4.B_ }]), 'output-already-signed'],
    ['an unknown keyset id', out([4], [{ id: '00' + 'ab'.repeat(7) }]), 'unknown-keyset'],
    ['an inactive keyset', out([4], [{ id: (await inactiveKeyset()).id }]), 'inactive-keyset'],
    ['amount 0 (once signed as a 64-sat token)', out([4, 0]), 'unknown-denomination'],
    ['amount 3, not a denomination', out([3, 1]), 'unknown-denomination'],
  ];
  for (const [label, outs, detail] of cases) refused(label, await swap(inputs([p4]), outs), 400, detail);
  check('none of those spent the proof', (await states([p4]))[0] === 'UNSPENT', await states([p4]));

  section('the claimed amounts balance before any curve work');
  refused('outputs worth less than the inputs', await swap(inputs([p4]), out([2])), 400, 'amounts-do-not-balance');
  refused('an unbalanced swap of a forged proof is refused for the amounts, not the signature',
    await swap([forged(ks, 4)], out([8])), 400, 'amounts-do-not-balance');
  const feeKs = await inactiveKeyset({ fee: true });
  refused('an input whose keyset fee exceeds its claimed amount',
    await swap([{ ...forged(ks, 0), id: feeKs.id }], []), 400, 'fee-exceeds-inputs');

  section('every cheap check covers the whole batch before any curve work');
  refused('one secret twice in a batch', await swap(inputs([p4, p4]), out([8])), 400, 'token-already-spent');
  const [atCap, overCap] = await selfMint(ks, [1, 1], [sized(2048), sized(2049)]);
  refused('a forged proof ahead of an oversized secret: the size check answers',
    await swap([forged(ks, 1), ...inputs([overCap])], out([2])), 400, 'secret-too-long');

  section('secrets are capped at 2048 bytes (room for multi-key P2PK)');
  refused('a 2049-byte secret', await swap(inputs([overCap]), out([1])), 400, 'secret-too-long');
  const rCap = await swap(inputs([atCap]), out([1]));
  check('a 2048-byte secret swaps', rCap.status === 200, rCap.body);

  section('after every refusal the proof still swaps');
  const o = outputs([4], ks.id);
  const ok = await swap(inputs([p4]), o.msgs);
  check('the swap signs its output with a valid DLEQ proof',
    ok.status === 200 && ok.body.signatures.length === 1 && dleqValid(ok.body.signatures[0], o.msgs[0].B_, ks.keys), ok.body);
  check('and spends the proof', (await states([p4]))[0] === 'SPENT');

  section('a mint signs every output or none');
  const q = (await post('/v1/mint/quote/self', { amount: 2 })).body;
  refused('a mint with an off-curve output', await post('/v1/mint/self', { quote: q.quote, outputs: out([2], [{ B_: offCurve() }]) }),
    400, 'invalid-B_-point');
  const m = await post('/v1/mint/self', { quote: q.quote, outputs: out([2]) });
  check('the same quote then mints', m.status === 200 && m.body.signatures?.length === 1, m.body);
});
