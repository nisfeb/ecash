// bolt11 deposits and withdrawals (NUT-04/05) against the mock LNbits: the
// quote lifecycle wallets drive, and every refusal the bolt11 routes promise.
import {
  run, check, refused, section, onCleanup, setSelf, keyset, fund, outputs, post, get, admin, inputs, states, invoice,
  poll, split, sum,
} from './test-helpers.mjs';

await run('lightning', { auth: true, mutates: true, ln: true }, async ({ mock }) => {
  await setSelf(true);   // funds the melts
  const ks = await keyset();
  // unpaid quotes this run makes are deleted at the end
  const made = [];
  onCleanup(async () => { for (const [type, id] of made) await admin('/quotes/delete', { quote_id: id, type }); });
  const meltQuote = async (request) => {
    const r = await post('/v1/melt/quote/bolt11', { request });
    if (r.body?.quote) made.push(['melt', r.body.quote]);
    return r;
  };

  section('deposit: a quote with an invoice, seen paid by a later poll');
  const q = (await post('/v1/mint/quote/bolt11', { amount: 100 })).body;
  check('the quote carries a backend invoice for 100 sat, UNPAID',
    q?.state === 'UNPAID' && q.amount === 100 && q.request?.startsWith('lnbc'), q);
  refused('minting it unpaid', await post('/v1/mint/bolt11', { quote: q.quote, outputs: outputs(split(100), ks.id).msgs }), 400, 'quote-not-paid');
  await mock.mode({ status_delay: 3000 });
  const t0 = Date.now();
  const slow = await get(`/v1/mint/quote/bolt11/${q.quote}`);
  check('a poll answers at once even while Lightning is slow to answer (< 1 s)', Date.now() - t0 < 1000 && slow.body?.state === 'UNPAID', Date.now() - t0);
  await mock.mode({ status_delay: 0 });
  await mock.markPaid(q.request);
  const seen = (await poll(() => get(`/v1/mint/quote/bolt11/${q.quote}`), (r) => r.body?.state === 'PAID')).body;
  check('once the invoice is paid, a later poll reads PAID', seen?.state === 'PAID', seen);
  const o = outputs(split(100), ks.id);
  const m = await post('/v1/mint/bolt11', { quote: q.quote, outputs: o.msgs });
  check('the paid quote mints 100 sat', m.status === 200 && sum(m.body.signatures) === 100, m.body);
  refused('and only once', await post('/v1/mint/bolt11', { quote: q.quote, outputs: outputs(split(100), ks.id).msgs }), 400, 'quote-not-paid');

  section('a failed invoice creation leaves no quote behind');
  const count = async () => (await admin('/quotes')).body.mint_quotes.length;
  const n = await count();
  await mock.mode({ invoice: '500' });
  refused('the quote request', await post('/v1/mint/quote/bolt11', { amount: 7 }), 502, 'lightning-invoice-creation-failed');
  await mock.mode({ invoice: 'ok' });
  check('and the mint keeps no orphan quote', (await count()) === n);

  section('withdraw: melt quotes');
  const mq = (await meltQuote(invoice(50_000))).body;
  check('a 50-sat invoice quotes 50 with reserve 10, UNPAID, echoing the request',
    mq?.amount === 50 && mq.fee_reserve === 10 && mq.state === 'UNPAID' && mq.request?.startsWith('lnbc500n1'), mq);
  check('a 1.5-sat invoice costs 2 sat (a part sat rounds up)', (await meltQuote(invoice(1500))).body?.amount === 2);
  refused('no request', await post('/v1/melt/quote/bolt11', {}), 400, 'missing-request-bolt11');
  refused('a request with characters outside bech32 (it lands in a backend URL)',
    await post('/v1/melt/quote/bolt11', { request: 'lnbc500n1p/../../v1/getinfo' }), 400, 'invalid-request');
  refused('text the backend cannot decode', await post('/v1/melt/quote/bolt11', { request: 'notaninvoice' }), 502, 'lightning-decode-failed');
  await mock.mode({ decode: 'nohash' });
  refused('a decode answer without a payment hash', await post('/v1/melt/quote/bolt11', { request: invoice(10_000) }), 502, 'lightning-decode-missing-hash');
  await mock.mode({ decode: 'ok' });

  section('withdraw: melt');
  const ins = await fund(ks, 60);
  const r = await post('/v1/melt/bolt11', { quote: mq.quote, inputs: inputs(ins) });
  check('inputs of amount + reserve melt it: PAID with a preimage', r.body?.state === 'PAID' && /^[0-9a-f]{64}$/.test(r.body.payment_preimage), r.body);
  check('the quote then reads PAID', (await get(`/v1/melt/quote/bolt11/${mq.quote}`)).body?.state === 'PAID');
  check('and its inputs SPENT', (await states(ins)).every((s) => s === 'SPENT'), await states(ins));

  section('a melt quote settles only by the method that made it');
  const sq = (await post('/v1/melt/quote/self', { amount: 1 })).body;
  made.push(['melt', sq.quote]);
  const bq = (await meltQuote(invoice(1000))).body;
  const one = await fund(ks, 1);
  const eleven = await fund(ks, 11);
  refused('a self quote melted over bolt11', await post('/v1/melt/bolt11', { quote: sq.quote, inputs: inputs(one) }), 400, 'method-mismatch');
  refused('a bolt11 quote melted over self (marked paid, with nothing paid)',
    await post('/v1/melt/self', { quote: bq.quote, inputs: inputs(eleven) }), 400, 'method-mismatch');
  check('neither spent its inputs', [...await states(one), ...await states(eleven)].every((s) => s === 'UNSPENT'));
  check('the bolt11 quote is still UNPAID', (await get(`/v1/melt/quote/bolt11/${bq.quote}`)).body?.state === 'UNPAID');

  section('the admin quote list names each quote\'s method');
  const sm = (await post('/v1/mint/quote/self', { amount: 1 })).body;
  const list = (await admin('/quotes')).body;
  const method = (kind, id) => list[`${kind}_quotes`].find((x) => x.quote_id === id)?.method;
  check('mint quotes: bolt11 and self', method('mint', q.quote) === 'bolt11' && method('mint', sm.quote) === 'self');
  check('melt quotes: bolt11 and self', method('melt', bq.quote) === 'bolt11' && method('melt', sq.quote) === 'self');
  await admin('/quotes/revoke', { quote_id: sm.quote });

  section('the admin connection test asks the backend');
  const t = (await admin('/lightning/test', {})).body;
  check('it answers ok with the backend wallet balance',
    t?.status === 'ok' && t.type === 'lnbits' && t.url === mock.url && t.http_status === 200 && t.balance_msat === 1_000_000_000, t);
  await admin('/lightning/configure', { type: 'lnbits', url: mock.url, api_key: 'wrong-key' });
  const bad = (await admin('/lightning/test', {})).body;
  check('with a wrong key: error, with the backend\'s status and detail', bad?.status === 'error' && bad.http_status === 401 && bad.detail === 'Invalid key', bad);
  await admin('/lightning/configure', { type: 'lnbits', url: mock.url, api_key: mock.key });
});
