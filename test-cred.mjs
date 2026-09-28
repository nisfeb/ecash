// Zero-value credential tokens (/cred/v1 on %ecash-services): issue, verify,
// redeem once, and the admin keyset switch.
import {
  run, check, refused, section, onCleanup, outputs, get, post, svcAdmin, inputs, dleqValid, newSecret,
} from './test-helpers.mjs';

await run('cred', { auth: true, mutates: true }, async () => {
  // a plain credential keyset: an existing one (switched on if off), else a new one
  const listed = (await get('/cred/v1/keysets')).body.keysets;
  let kid = (listed.find((k) => k.active) ?? listed[0])?.id;
  if (!kid) kid = (await svcAdmin('/cred/keysets/generate', {})).body.id;
  const wasActive = listed.find((k) => k.id === kid)?.active ?? false;
  onCleanup(() => svcAdmin(`/cred/keysets/${wasActive ? 'activate' : 'deactivate'}`, { id: kid }));
  await svcAdmin('/cred/keysets/activate', { id: kid });

  section('keys');
  const byId = (await get(`/cred/v1/keys/${kid}`)).body?.keysets?.[0];
  check('GET /cred/v1/keys/{id}: a c0 keyset with one key, for amount 0', byId?.id === kid && kid.startsWith('c0') && Object.keys(byId.keys).join() === '0', byId);
  check('listed by /cred/v1/keys and, active, by /cred/v1/keysets',
    (await get('/cred/v1/keys')).body.keysets.some((k) => k.id === kid)
    && (await get('/cred/v1/keysets')).body.keysets.some((k) => k.id === kid && k.active));
  const keys = byId.keys;

  section('issue, verify, redeem');
  const before = (await svcAdmin('/cred/overview')).body;
  const o = outputs([0, 0, 0, 0, 0], kid);
  const issued = await post('/cred/v1/issue', { outputs: o.msgs });
  check('5 outputs get 5 signatures, each with a valid DLEQ proof',
    issued.body?.signatures?.length === 5 && issued.body.signatures.every((s, i) => dleqValid(s, o.msgs[i].B_, keys)), issued.body);
  const t = o.proofs(issued.body.signatures, keys);
  const verify = async (proofs) => (await post('/cred/v1/verify', { proofs: inputs(proofs) })).body?.valid ?? [];
  check('a fresh token verifies valid and unspent', (await verify([t[0]])).every((v) => v.valid && !v.spent));
  const r = await post('/cred/v1/redeem', { proofs: inputs([t[0]]) });
  check('redeem spends it', r.body?.redeemed?.[0]?.redeemed === true, r.body);
  check('it then verifies valid and spent', (await verify([t[0]])).every((v) => v.valid && v.spent));
  refused('redeeming it again', await post('/cred/v1/redeem', { proofs: inputs([t[0]]) }), 400, 'credential-already-spent');
  const two = await post('/cred/v1/redeem', { proofs: inputs([t[1], t[2]]) });
  check('two redeem in one batch', two.body?.redeemed?.length === 2, two.body);

  section('a redeem batch spends every token or none');
  const fake = { ...t[3], secret: newSecret('wrong') };
  check('a token with the wrong secret verifies invalid', (await verify([fake]))[0]?.valid === false);
  refused('a batch holding it', await post('/cred/v1/redeem', { proofs: inputs([t[3], fake]) }), 400, 'invalid-credential');
  refused('a batch naming one token twice', await post('/cred/v1/redeem', { proofs: inputs([t[3], t[3]]) }), 400, 'duplicate-credential');
  check('neither spent the good token', (await verify([t[3]])).every((v) => v.valid && !v.spent));
  const after = (await svcAdmin('/cred/overview')).body;
  check('the admin overview counts 5 issued and 3 spent', after.cred_issued - before.cred_issued === 5 && after.cred_spent - before.cred_spent === 3, { before, after });

  section('refused outputs get an error in their place');
  const bad = await post('/cred/v1/issue', { outputs: outputs([1], kid).msgs });
  check('a non-zero amount', bad.body?.signatures?.[0]?.error === 'credential-amount-must-be-zero', bad.body);
  await svcAdmin('/cred/keysets/deactivate', { id: kid });
  const off = await post('/cred/v1/issue', { outputs: outputs([0], kid).msgs });
  check('an inactive keyset', off.body?.signatures?.[0]?.error === 'credential-keyset-inactive', off.body);
  await svcAdmin('/cred/keysets/activate', { id: kid });
  check('switching it back on, unspent tokens still verify', (await verify([t[3], t[4]])).every((v) => v.valid && !v.spent));
});
