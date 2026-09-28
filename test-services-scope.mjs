// A service's keyset signs only through its gated /services path, never
// through public /cred (CRITICAL-6), and spent records are per keyset, so a
// secret spent under one keyset does not spend it under another (LOW-3).
import {
  run, check, refused, section, onCleanup, outputs, get, post, svcAdmin, inputs, TAG,
} from './test-helpers.mjs';

await run('services-scope', { auth: true, mutates: true }, async () => {
  const name = `${TAG}-scope`;
  const svc = (await svcAdmin('/services/create', { name, title: 'Scope', description: 'x' })).body;
  onCleanup(async () => { await svcAdmin('/services/deactivate', { name }); await svcAdmin('/services/delete', { name }); });
  await svcAdmin('/services/allowlist/add', { name, key: 'the-only-key' });
  const plain = (await svcAdmin('/cred/keysets/generate', {})).body.id;
  onCleanup(() => svcAdmin('/cred/keysets/deactivate', { id: plain }));

  section('a service keyset signs only through its service');
  const forge = await post('/cred/v1/issue', { outputs: outputs([0], svc.ks_id).msgs });
  check('/cred/v1/issue refuses a service keyset, with no signature',
    forge.body?.signatures?.[0]?.error === 'unknown-credential-keyset' && !forge.body.signatures[0].C_, forge.body);
  const o = outputs([0], svc.ks_id);
  const good = await post(`/services/v1/${name}/issue`, { access_key: 'the-only-key', outputs: o.msgs });
  check('the service itself signs, with its access key', !!good.body?.signatures?.[0]?.C_, good.body);
  check('/cred/v1/issue still signs a plain keyset', !!(await post('/cred/v1/issue', { outputs: outputs([0], plain).msgs })).body?.signatures?.[0]?.C_);

  section('spent records are per keyset');
  const keys = (await get(`/cred/v1/keys/${svc.ks_id}`)).body.keysets[0].keys;
  const [token] = o.proofs(good.body.signatures, keys);
  // anyone can have a plain keyset sign the same secret, and spend that
  const twin = outputs([0], plain, [token.secret]);
  const tsigs = (await post('/cred/v1/issue', { outputs: twin.msgs })).body.signatures;
  const [plainTwin] = twin.proofs(tsigs, (await get(`/cred/v1/keys/${plain}`)).body.keysets[0].keys);
  const spent = await post('/cred/v1/redeem', { proofs: inputs([plainTwin]) });
  check('a plain-keyset token with the service token\'s secret redeems at /cred', spent.body?.redeemed?.[0]?.redeemed === true, spent.body);
  const v = (await post(`/services/v1/${name}/verify`, { proofs: inputs([token]) })).body;
  check('and the service token is still unspent', v?.results?.[0]?.valid === true && v.results[0].spent === false, v);
  refused('/cred/v1/redeem refuses the token under its own (service) keyset',
    await post('/cred/v1/redeem', { proofs: inputs([token]) }), 400, 'invalid-credential');
  const r = (await post(`/services/v1/${name}/redeem`, { proofs: inputs([token]) })).body;
  check('its service redeems it: fresh', r?.redeemed?.[0]?.status === 'fresh', r);
});
