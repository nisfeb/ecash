// What the mint advertises and enforces as its limits: the largest mint
// quote (max_amount, refused one sat above, mintable at the worst case below;
// a melt has no such cap), and /v1/info listing exactly the methods that
// work.
import {
  run, check, refused, section, onCleanup, setSelf, keyset, outputs, post, get, admin, invoice, split,
} from './test-helpers.mjs';

await run('limits', { auth: true, mutates: true, ln: true }, async ({ mock }) => {
  const ks = await keyset();
  // max_amount of the active keyset, whose top denomination is 2^m: at most
  // 100 outputs per request, and an amount below (100 - m) * 2^m takes at
  // most (99 - m) + m. A new keyset's top is 2^20: 80 * 2^20.
  const top = Math.max(...Object.keys(ks.keys).map(Number));
  const MAX = (100 - Math.log2(top)) * top;
  const made = [];
  onCleanup(async () => {
    for (const [type, id] of made) await admin(type === 'revoke' ? '/quotes/revoke' : '/quotes/delete', { quote_id: id, type });
  });

  section('/v1/info lists exactly the methods that work, each with max_amount');
  const listed = async () => {
    const info = (await get('/v1/info')).body;
    const ms = (n) => (info.nuts[n].methods ?? []).map((x) => x.method).sort().join();
    return { mint: ms('4'), melt: ms('5'), info };
  };
  const works = async (method) => {
    const r = await post(`/v1/mint/quote/${method}`, { amount: 1 });
    if (r.body?.quote) made.push([method === 'self' ? 'revoke' : 'mint', r.body.quote]);
    return r.status === 200;
  };
  for (const [self, ln, want] of [[false, true, 'bolt11'], [true, true, 'bolt11,self'], [true, false, 'self'], [false, false, '']]) {
    await setSelf(self);
    await admin('/lightning/configure', ln ? { type: 'lnbits', url: mock.url, api_key: mock.key } : { type: 'none' });
    const l = await listed();
    check(`self ${self ? 'on' : 'off'}, backend ${ln ? 'set' : 'none'}: lists [${want}] for mint and melt`, l.mint === want && l.melt === want, l.info.nuts);
    check(`  and exactly those quote`, (await works('self')) === self && (await works('bolt11')) === ln);
    if (!want) check('  with nuts 4 and 5 marked disabled', l.info.nuts['4'].disabled === true && l.info.nuts['5'].disabled === true, l.info.nuts);
  }
  await admin('/lightning/configure', { type: 'lnbits', url: mock.url, api_key: mock.key });
  await setSelf(true);
  const { info } = await listed();
  check(`mint methods: min_amount 1, max_amount ${MAX}`,
    info.nuts['4'].methods.every((x) => x.min_amount === 1 && x.max_amount === MAX), info.nuts['4']);
  check('melt methods: min_amount 1 and no max_amount (inputs bound a melt)',
    info.nuts['5'].methods.every((x) => x.min_amount === 1 && !('max_amount' in x)), info.nuts['5']);
  check('nuts 1 and 2 and a top-level pubkey are gone', !('1' in info.nuts) && !('2' in info.nuts) && !('pubkey' in info), info);

  section(`mint quotes: ${MAX} is accepted, one more is refused; melt quotes are not capped`);
  const pair = async (label, path, body) => {
    const atCap = await post(path, body(MAX));
    check(`${label} of max_amount`, atCap.status === 200 && atCap.body.amount === MAX, atCap.body);
    refused(`${label} of max_amount + 1`, await post(path, body(MAX + 1)), 400, 'amount-too-large');
    return atCap.body?.quote;
  };
  const selfMintQ = await pair('a self mint quote', '/v1/mint/quote/self', (a) => ({ amount: a }));
  made.push(['mint', await pair('a bolt11 mint quote', '/v1/mint/quote/bolt11', (a) => ({ amount: a }))]);
  for (const [label, path, body] of [['a self melt quote', '/v1/melt/quote/self', { amount: MAX + 1 }],
    ['a bolt11 melt quote', '/v1/melt/quote/bolt11', { request: invoice((MAX + 1) * 1000) }]]) {
    const r = await post(path, body);
    if (r.body?.quote) made.push(['melt', r.body.quote]);
    check(`${label} of max_amount + 1`, r.status === 200 && r.body.amount === MAX + 1, r.body);
  }
  made.push(['revoke', selfMintQ]);

  section('the worst amount under the cap still mints in one request');
  const worst = MAX - 1;   // (99 - m) * 2^m + (2^m - 1): 99 outputs
  const q = (await post('/v1/mint/quote/self', { amount: worst })).body;
  const o = outputs(split(worst, top), ks.id);
  const m = await post('/v1/mint/self', { quote: q.quote, outputs: o.msgs });
  check(`${worst} sat mints as ${o.msgs.length} outputs`, o.msgs.length === 99 && m.status === 200 && m.body.signatures.length === 99, m.body ?? m.text);
});
