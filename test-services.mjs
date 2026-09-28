// Services (/services/v1 on %ecash-services): single-use access tokens under
// a service's own keyset, gated by the service's state, expiry, issuance cap
// and allowlist; redeem is idempotent per token.
import {
  run, check, refused, section, onCleanup, outputs, get, post, svcAdmin, inputs, dleqValid, TAG,
} from './test-helpers.mjs';

await run('services', { auth: true, mutates: true }, async () => {
  // every service made here is switched off, and deleted where it issued nothing
  const made = [];
  onCleanup(async () => {
    for (const name of made) {
      await svcAdmin('/services/deactivate', { name });
      await svcAdmin('/services/delete', { name });
    }
  });
  const create = async (name, extra = {}) => {
    const r = await svcAdmin('/services/create', { name, title: 'Test', description: 'x', ...extra });
    if (r.body?.name) made.push(name);
    return r;
  };
  const keysOf = async (kid) => (await get(`/cred/v1/keys/${kid}`)).body.keysets[0].keys;
  const issue = (name, msgs, extra = {}) => post(`/services/v1/${name}/issue`, { ...extra, outputs: msgs });

  section('create, list, detail');
  const name = `${TAG}-svc`;
  const c = (await create(name)).body;
  check('create answers an active single-use service with a c0 keyset', c?.name === name && c.active === true && c.ks_id?.startsWith('c0'), c);
  refused('the same name again', await create(name), 409, 'service-already-exists');
  refused('a name outside [a-z0-9_-]', await create(`${TAG}/Bad`), 400, 'invalid-service-name');
  check('the public list shows it', (await get('/services/v1/list')).body.services.some((s) => s.name === name));
  const detail = (await get(`/services/v1/${name}`)).body;
  check('its detail: single-use', detail?.name === name && detail.kind === 'single-use', detail);

  section('issue, verify, redeem');
  const keys = await keysOf(c.ks_id);
  const o = outputs([0, 0, 0], c.ks_id);
  const iss = await issue(name, o.msgs);
  check('3 outputs get 3 signatures with valid DLEQ proofs',
    iss.body?.signatures?.length === 3 && iss.body.signatures.every((s, i) => dleqValid(s, o.msgs[i].B_, keys)), iss.body);
  const t = o.proofs(iss.body.signatures, keys);
  const v = (await post(`/services/v1/${name}/verify`, { proofs: inputs(t) })).body;
  check('all verify valid and unspent', v?.results?.every((x) => x.valid && !x.spent), v);
  const r1 = (await post(`/services/v1/${name}/redeem`, { proofs: inputs([t[0]]) })).body;
  check('the first redeem is fresh', r1?.redeemed?.[0]?.status === 'fresh', r1);
  const r2 = (await post(`/services/v1/${name}/redeem`, { proofs: inputs([t[0]]) })).body;
  check('a repeat is a replay, still 200 (safe to retry)', r2?.redeemed?.[0]?.status === 'replay', r2);

  section('isolation and gates');
  const other = `${TAG}-other`;
  await create(other);
  refused('a token redeemed at another service', await post(`/services/v1/${other}/redeem`, { proofs: inputs([t[1]]) }), 400, 'invalid-service-token');
  await svcAdmin('/services/deactivate', { name });
  refused('an inactive service issues nothing', await issue(name, outputs([0], c.ks_id).msgs), 400, 'service-inactive');
  refused('nor can it be deleted with tokens issued', await svcAdmin('/services/delete', { name }), 400, 'service-has-issued-tokens');
  await svcAdmin('/services/deactivate', { name: other });
  const del = (await svcAdmin('/services/delete', { name: other })).body;
  check('an inactive service that issued nothing deletes', del?.deleted === true, del);
  made.splice(made.indexOf(other), 1);

  const exp = `${TAG}-exp`;
  const e = (await create(exp, { expires: Math.floor(Date.now() / 1000) - 3600 })).body;
  refused('an expired service issues nothing', await issue(exp, outputs([0], e.ks_id).msgs), 400, 'service-expired');

  const cap = `${TAG}-cap`;
  const k = (await create(cap, { max_issuance: 2 })).body;
  check('a service capped at 2 issues 2', (await issue(cap, outputs([0, 0], k.ks_id).msgs)).body?.signatures?.length === 2);
  refused('and no third', await issue(cap, outputs([0], k.ks_id).msgs), 400, 'service-issuance-cap-reached');

  section('allowlist');
  const gate = `${TAG}-gate`;
  const g = (await create(gate)).body;
  check('an empty allowlist issues to anyone', (await issue(gate, outputs([0], g.ks_id).msgs)).status === 200);
  const add = (await svcAdmin('/services/allowlist/add', { name: gate, key: 'secret-abc-123' })).body;
  check('adding a key requires one', add?.allowlist?.includes('secret-abc-123') && add.allowlist_required === true, add);
  refused('no key', await issue(gate, outputs([0], g.ks_id).msgs), 403, 'service-access-denied');
  refused('a wrong key', await issue(gate, outputs([0], g.ks_id).msgs, { access_key: 'wrong' }), 403, 'service-access-denied');
  check('the key', (await issue(gate, outputs([0], g.ks_id).msgs, { access_key: 'secret-abc-123' })).status === 200);
  const pub = (await get(`/services/v1/${gate}`)).body;
  check('the public detail shows the count, never the keys', !('allowlist' in pub) && pub.allowlist_count === 1 && pub.allowlist_required === true, pub);
  await svcAdmin('/services/allowlist/remove', { name: gate, key: 'secret-abc-123' });
  check('removing the last key opens it again', (await issue(gate, outputs([0], g.ks_id).msgs)).status === 200);
});
