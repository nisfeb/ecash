// Wallet conformance: cashu-ts, a real Cashu wallet library, drives the mint
// through the flows wallets use: load the mint (NUT-01/02/06), mint over
// bolt11 (NUT-04) with every signature's DLEQ proof checked (NUT-12), send and
// receive (NUT-03), token state (NUT-07) and a melt with change (NUT-05/08).
import { Wallet, Mint, deriveKeysetId, hasValidDleq, getEncodedToken } from '@cashu/cashu-ts';
import { run, check, section, SHIP_URL, keyset, invoice, poll, sum } from './test-helpers.mjs';

// cashu-ts v4 hands amounts back as Amount objects
const num = (a) => (typeof a === 'number' ? a : a.toNumber());
const total = (proofs) => sum(proofs.map((p) => num(p.amount)));

await run('conformance', { auth: true, mutates: true, ln: true }, async ({ mock }) => {
  section('load the mint');
  const wallet = new Wallet(new Mint(SHIP_URL), { unit: 'sat' });
  await wallet.loadMint();
  const ks = await keyset();
  check('the wallet picks the active keyset, whose id is the NUT-02 id of its keys',
    wallet.keysetId === ks.id && deriveKeysetId(ks.keys) === ks.id, { wallet: wallet.keysetId, mint: ks.id });

  section('mint over bolt11');
  const q = await wallet.createMintQuoteBolt11(16);
  await mock.markPaid(q.request);
  const paid = await poll(() => wallet.checkMintQuoteBolt11(q.quote), (x) => x.state === 'PAID');
  check('the quote reads PAID once its invoice is paid', paid.state === 'PAID', paid);
  const proofs = await wallet.mintProofsBolt11(16, paid);
  check('it mints 16 sat of proofs', total(proofs) === 16, proofs.map((p) => num(p.amount)));
  check('each with a DLEQ proof cashu-ts verifies', proofs.every((p) => p.dleq && hasValidDleq(p, { id: ks.id, keys: ks.keys })));

  section('send and receive');
  const { send, keep } = await wallet.send(8, proofs);
  check('send splits off 8 sat and keeps 8', total(send) === 8 && total(keep) === 8, { send: send.length, keep: keep.length });
  const received = await wallet.receive(getEncodedToken({ mint: SHIP_URL, unit: 'sat', proofs: send }));
  check('receive swaps the token for 8 sat of fresh proofs', total(received) === 8);
  const sent = await wallet.checkProofsStates(send);
  check('the received token\'s proofs then read SPENT', sent.every((s) => s.state === 'SPENT'), sent);

  section('melt over bolt11');
  const mq = await wallet.createMeltQuoteBolt11(invoice(4000));
  check('a 4-sat invoice quotes 4 with reserve 10', num(mq.amount) === 4 && num(mq.fee_reserve) === 10, mq);
  const res = await wallet.meltProofsBolt11(mq, [...keep, ...received]);
  check('16 sat of proofs melt it: PAID', res.quote.state === 'PAID', res.quote);
  check('the change is 16 - 4 - 2 (fee) = 10', total(res.change) === 10, res.change.map((p) => num(p.amount)));
  const change = await wallet.receive(getEncodedToken({ mint: SHIP_URL, unit: 'sat', proofs: res.change }));
  check('and the change spends', total(change) === 10);
});
