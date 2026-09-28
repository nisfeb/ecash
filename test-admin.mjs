// The admin API's settings and keyset writes: a malformed setting changes
// nothing, and a fee change rotates the keyset without stranding old tokens.
import {
  run, check, refused, section, setSelf, keyset, selfMint, outputs, post, get, admin, inputs,
} from './test-helpers.mjs';

await run('admin', { auth: true, mutates: true }, async () => {
  section('settings: a malformed field is refused and nothing changes');
  const before = (await admin('/settings')).body;
  const bad = [
    ['fee_reserve_pct', -1], ['fee_reserve_pct', 1.5], ['fee_reserve_min', '10'],
    ['quote_ttl_secs', null], ['self_method_enabled', 'true'],
  ];
  for (const [field, value] of bad) {
    // with one valid change beside it, which must not land either
    const other = field === 'fee_reserve_min' ? { fee_reserve_pct: before.fee_reserve_pct + 1 } : { fee_reserve_min: before.fee_reserve_min + 1 };
    refused(`${field}: ${JSON.stringify(value)}`, await admin('/settings', { ...other, [field]: value }), 400, `invalid-${field}`);
  }
  const unchanged = (await admin('/settings')).body;
  check('the settings are as before', Object.keys(before).every((k) => unchanged[k] === before[k]), unchanged);
  const ok = await admin('/settings', { fee_reserve_min: before.fee_reserve_min + 1 });
  check('a valid change answers the full settings',
    ok.status === 200 && ok.body.fee_reserve_min === before.fee_reserve_min + 1
    && ['fee_reserve_pct', 'quote_ttl_secs', 'self_method_enabled'].every((k) => ok.body[k] === before[k]), ok.body);

  section('set-fee rotates to a fresh keyset; tokens of the old id still spend');
  await setSelf(true);
  const old = await keyset();
  const [p] = await selfMint(old, [1]);
  refused('no fee', await admin('/keysets/set-fee', { id: old.id }), 400, 'missing-input_fee_ppk');
  refused('a fractional fee', await admin('/keysets/set-fee', { id: old.id, input_fee_ppk: 1.5 }), 400, 'invalid-input_fee_ppk');
  refused('a fee as a string', await admin('/keysets/set-fee', { id: old.id, input_fee_ppk: '100' }), 400, 'invalid-input_fee_ppk');
  refused('an unknown keyset', await admin('/keysets/set-fee', { id: '00' + 'cd'.repeat(7), input_fee_ppk: 100 }), 404, 'keyset-not-found');
  const r = await admin('/keysets/set-fee', { id: old.id, input_fee_ppk: old.input_fee_ppk + 100 });
  check('the fee change answers a new keyset id', r.status === 200 && r.body.old_id === old.id && r.body.new_id && r.body.new_id !== old.id, r.body);
  const now = await keyset();
  check('which is now the active keyset, with the fee', now.id === r.body.new_id && now.input_fee_ppk === old.input_fee_ppk + 100, now.id);
  const denoms = Object.keys(now.keys);
  check('a keyset made now signs 2^0..2^20, its amounts in plain decimal ("1024", not "1.024")',
    denoms.length === 21 && Array.from({ length: 21 }, (_, i) => String(2 ** i)).every((d) => denoms.includes(d)), denoms);
  const listed = (await get('/v1/keysets')).body.keysets.find((k) => k.id === old.id);
  check('the old id stays listed, inactive', listed?.active === false, listed);
  const s = await post('/v1/swap', { inputs: inputs([p]), outputs: outputs([1], now.id).msgs });
  check('a token of the old id swaps, paying the old id\'s fee (0)', s.status === 200, s.body);
  // (the harness re-activates the original keyset)
});
