// A bolt11 melt's pay is only a dispatch until Lightning proves it settled.
// The mint must never pay twice and never un-spend inputs on ambiguity: it
// settles on proof, rolls back on a refusal made before any HTLC existed (or
// an operator's forced abort), and otherwise stays PENDING with the inputs
// held (NUT-07 PENDING); and an answer about an attempt that was since rolled
// back and melted again touches nothing. The mock's pay modes stand in for
// each LNbits answer.
import {
  run, check, refused, section, onCleanup, setSelf, keyset, fund, outputs, post, get, admin, inputs, states, invoice, poll,
  sleep, sum,
} from './test-helpers.mjs';

const all = (xs, s) => xs.length > 0 && xs.every((x) => x === s);

await run('melt-pending', { auth: true, mutates: true, ln: true }, async ({ mock }) => {
  await setSelf(true);
  const ks = await keyset();
  const quote = (id) => get(`/v1/melt/quote/bolt11/${id}`);
  // a melt left pending is force-aborted at the end (while the mock is up),
  // so its inputs come back, and then deleted
  const pending = [];
  onCleanup(async () => {
    for (const id of pending) {
      await admin('/melt/abort', { quote_id: id, force: true });
      await admin('/quotes/delete', { quote_id: id, type: 'melt' });
    }
  });

  // melt: a fresh 10-sat quote, funded exactly, melted with the pay answering
  // in this mode. pays: how many pay requests reached the backend.
  async function melt(mode) {
    await mock.mode({ pay: mode });
    const mq = (await post('/v1/melt/quote/bolt11', { request: invoice(10_000) })).body;
    const ins = await fund(ks, mq.amount + mq.fee_reserve);
    const before = await mock.payCount();
    const r = await post('/v1/melt/bolt11', { quote: mq.quote, inputs: inputs(ins), outputs: outputs([0, 0, 0, 0], ks.id).msgs });
    return { mq, ins, r, pays: (await mock.payCount()) - before };
  }
  // remelt: melt the quote again with fresh inputs; answers the response and
  // how many pays that made
  async function remelt(mq) {
    const ins = await fund(ks, mq.amount + mq.fee_reserve);
    const before = await mock.payCount();
    const r = await post('/v1/melt/bolt11', { quote: mq.quote, inputs: inputs(ins) });
    return { r, pays: (await mock.payCount()) - before };
  }

  section('201 with a preimage settles at once');
  const ok = await melt('ok');
  check('PAID after exactly one pay', ok.r.body?.state === 'PAID' && ok.pays === 1, { body: ok.r.body, pays: ok.pays });
  let again = await remelt(ok.mq);
  refused('melting the paid quote again', again.r, 400, 'quote-already-paid');
  check('asks the backend for no second pay', again.pays === 0, again.pays);

  section('an ambiguous 500: PENDING, inputs held, never rolled back by itself');
  const amb = await melt('500');
  pending.push(amb.mq.quote);
  check('PENDING after exactly one pay', amb.r.body?.state === 'PENDING' && amb.pays === 1, { body: amb.r.body, pays: amb.pays });
  check('its inputs read PENDING', all(await states(amb.ins), 'PENDING'), await states(amb.ins));
  again = await remelt(amb.mq);
  refused('melting the pending quote again', again.r, 400, 'quote-pending');
  check('asks the backend for no second pay', again.pays === 0, again.pays);
  // each poll re-checks Lightning behind its answer; the check 404s
  await quote(amb.mq.quote);
  await sleep(500);
  await quote(amb.mq.quote);
  await sleep(500);
  const still = (await quote(amb.mq.quote)).body;
  check('polls whose check 404s leave it PENDING, inputs held',
    still?.state === 'PENDING' && all(await states(amb.ins), 'PENDING'), { state: still?.state, states: await states(amb.ins) });

  section('201 without a preimage (in flight) settles on a later poll');
  const fl = await melt('inflight');
  check('PENDING at dispatch, after exactly one pay', fl.r.body?.state === 'PENDING' && fl.pays === 1, { body: fl.r.body, pays: fl.pays });
  const settled = (await poll(() => quote(fl.mq.quote), (r) => r.body?.state === 'PAID')).body;
  check('a poll sees it PAID, with the preimage', settled?.state === 'PAID' && /^[0-9a-f]{64}$/.test(settled.payment_preimage), settled);
  check('with the unused reserve (10 - 2) as change', sum(settled?.change ?? []) === 8, settled?.change);
  check('its inputs then read SPENT', all(await states(fl.ins), 'SPENT'), await states(fl.ins));

  section('a pay LNbits refused before dispatch (400 naming no payment) rolls back');
  const rej = await melt('400');
  check('the quote is UNPAID again, after one pay request', rej.r.body?.state === 'UNPAID' && rej.pays === 1, { body: rej.r.body, pays: rej.pays });
  check('its inputs read UNSPENT', all(await states(rej.ins), 'UNSPENT'), await states(rej.ins));
  await mock.mode({ pay: 'ok' });
  const retry = await post('/v1/melt/bolt11', { quote: rej.mq.quote, inputs: inputs(rej.ins) });
  check('the same inputs then melt the same quote', retry.body?.state === 'PAID', retry.body);

  section('a 400 that names a payment is ambiguous: PENDING');
  const named = await melt('400-hash');
  pending.push(named.mq.quote);
  check('PENDING, inputs held', named.r.body?.state === 'PENDING' && all(await states(named.ins), 'PENDING'), named.r.body);
  refused('and it cannot be deleted', await admin('/quotes/delete', { quote_id: named.mq.quote, type: 'melt' }), 400, 'cannot-delete-pending-melt');
  await admin('/lightning/configure', { type: 'none' });
  const blind = (await admin('/melt/abort', { quote_id: named.mq.quote })).body;
  check('with no backend to ask, an unforced abort changes nothing',
    blind?.aborted === false && blind.result === 'in-flight-or-unconfirmed' && all(await states(named.ins), 'PENDING'), blind);
  await admin('/lightning/configure', { type: 'lnbits', url: mock.url, api_key: mock.key });

  section('a late answer about an older attempt cannot roll back a newer one');
  // attempt 1's pay is refused (400 naming no payment) but answers late; the
  // operator force-aborts it meanwhile and the wallet melts again (attempt 2)
  await mock.mode({ pay: '400', pay_delay: 4000 });
  const mqA = (await post('/v1/melt/quote/bolt11', { request: invoice(10_000) })).body;
  const insA = await fund(ks, 20);
  const n0 = await mock.payCount();
  const first = post('/v1/melt/bolt11', { quote: mqA.quote, inputs: inputs(insA) });   // answers with its pay
  await poll(() => mock.payCount(), (n) => n > n0, { ms: 100 });
  await mock.mode({ pay: 'inflight', pay_delay: 0 });
  const abA = (await admin('/melt/abort', { quote_id: mqA.quote, force: true })).body;
  const second = await post('/v1/melt/bolt11', { quote: mqA.quote, inputs: inputs(insA) });
  check('attempt 1 force-aborted while its pay is out, attempt 2 PENDING',
    abA?.result === 'aborted-forced' && second.body?.state === 'PENDING', { abort: abA, second: second.body });
  await first;
  // (states before the quote: a poll re-checks Lightning, which would settle attempt 2)
  const heldA = await states(insA);
  check('attempt 1\'s late refusal leaves attempt 2 PENDING, its inputs held',
    all(heldA, 'PENDING') && (await quote(mqA.quote)).body?.state === 'PENDING', heldA);
  check('and attempt 2 then settles', (await poll(() => quote(mqA.quote), (r) => r.body?.state === 'PAID')).body?.state === 'PAID');
  // an abort whose check left before the quote was melted again
  const b = await melt('500');
  await mock.mode({ status_delay: 4000 });
  const slow = admin('/melt/abort', { quote_id: b.mq.quote, force: true });
  await sleep(500);
  await mock.mode({ status_delay: 0, pay: '400-hash' });
  const abB = (await admin('/melt/abort', { quote_id: b.mq.quote, force: true })).body;
  const reB = await post('/v1/melt/bolt11', { quote: b.mq.quote, inputs: inputs(b.ins) });
  pending.push(b.mq.quote);
  check('attempt 1 force-aborted, attempt 2 PENDING', abB?.result === 'aborted-forced' && reB.body?.state === 'PENDING', { abort: abB, again: reB.body });
  const staleB = (await slow).body;
  check('the slow abort answers stale-attempt and rolls nothing back',
    staleB?.aborted === false && staleB.result === 'stale-attempt' && all(await states(b.ins), 'PENDING'), staleB);

  section('operator abort (/admin/api/melt/abort) re-checks Lightning first');
  const ab = (await admin('/melt/abort', { quote_id: amb.mq.quote })).body;
  check('unforced, a pay Lightning does not show settled or failed is left PENDING',
    ab?.aborted === false && ab.result === 'in-flight-or-unconfirmed' && all(await states(amb.ins), 'PENDING'), ab);
  const forced = (await admin('/melt/abort', { quote_id: amb.mq.quote, force: true })).body;
  check('forced, it rolls back: inputs UNSPENT, quote UNPAID',
    forced?.aborted === true && forced.result === 'aborted-forced' && all(await states(amb.ins), 'UNSPENT')
    && (await quote(amb.mq.quote)).body?.state === 'UNPAID', forced);
  refused('aborting it again', await admin('/melt/abort', { quote_id: amb.mq.quote }), 400, 'quote-not-pending');
  const done = await melt('inflight');
  const ab2 = (await admin('/melt/abort', { quote_id: done.mq.quote, force: true })).body;
  check('forced, a pay Lightning shows settled is settled instead',
    ab2?.aborted === false && ab2.result === 'settled-not-aborted' && all(await states(done.ins), 'SPENT')
    && (await quote(done.mq.quote)).body?.state === 'PAID', ab2);
  refused('an unknown quote', await admin('/melt/abort', { quote_id: 'nope' }), 404, 'quote-not-found');
  refused('no quote_id', await admin('/melt/abort', {}), 400, 'missing-quote_id');
});

