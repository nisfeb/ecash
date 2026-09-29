// %tessera: each service is a NUT-22 auth mint at /tessera/<name>. A real
// cashu-ts AuthManager tops up and spends against one; resource servers
// redeem and check with a verifier key; the owner runs services through the
// admin API at /apps/tessera/api.
import { AuthManager } from '@cashu/cashu-ts';
import {
  run, check, refused, section, onCleanup, outputs, call, get, post, dleqValid, SHIP_URL, TAG, randomHex, sleep,
} from './test-helpers.mjs';

// tadmin: the %tessera admin API; a body makes it a POST
const tadmin = (act, body) =>
  call(`/apps/tessera/api/services${act ? `/${act}` : ''}`, { method: body === undefined ? 'GET' : 'POST', body, auth: true });
// authA: a proof as a token, unpadded (cashu-ts pads)
const authA = (p) => `authA${Buffer.from(JSON.stringify({ id: p.id, secret: p.secret, C: p.C })).toString('base64url')}`;
const G = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';

await run('tessera', { auth: true }, async () => {
  // every service made here is switched off, and deleted where it issued nothing
  const made = [];
  onCleanup(async () => {
    for (const name of made) {
      await tadmin('deactivate', { name });
      await tadmin('delete', { name });
    }
  });
  const create = async (name, extra = {}) => {
    const r = await tadmin('create', { name, title: 'Test', ...extra });
    if (r.body?.name) made.push(name);
    return r;
  };
  const base = (name) => `/tessera/${name}`;
  const VKEY = `${TAG}-verifier-${randomHex(8)}`;
  const redeem = (name, token, key = VKEY) => post(`${base(name)}/redeem`, { token, key });
  const checkTok = (name, token, key = VKEY) => post(`${base(name)}/check`, { token, key });
  const mint = (name, msgs, headers = {}, auth = false) =>
    call(`${base(name)}/v1/auth/blind/mint`, { method: 'POST', body: { outputs: msgs }, headers, auth });
  const bat = (am) => am.getBlindAuthToken({ method: 'POST', path: '/v1/swap' });

  section('a service is a NUT-22 auth mint');
  const name = `${TAG}-open`;
  const c = (await create(name, { open: true, verifier_keys: [VKEY] })).body;
  check('create answers the service: open, with a 01 keyset', c?.name === name && c.open === true && c.keyset?.startsWith('01'), c);
  refused('the same name again', await create(name), 409, 'service-already-exists');
  refused('a name outside [a-z0-9_-]', await create(`${TAG}-Bad`), 400, 'invalid-service-name');
  const info = (await get(`${base(name)}/v1/info`)).body;
  check('info: nuts.22 with bat_max_mint 10; no NUT-21 on an open service',
    info?.nuts?.['22']?.bat_max_mint === 10 && !info.nuts['21'] && info.name === 'Test', info);
  const ks = (await get(`${base(name)}/v1/auth/blind/keys`)).body?.keysets?.[0];
  check('keys: one auth keyset, one key, for amount 1',
    ks?.unit === 'auth' && ks.id === c.keyset && Object.keys(ks.keys).join() === '1', ks);
  const kss = (await get(`${base(name)}/v1/auth/blind/keysets`)).body?.keysets;
  check('keysets: the same id, active', kss?.length === 1 && kss[0].id === c.keyset && kss[0].active === true, kss);
  refused('an unknown service', await get(`/tessera/${TAG}-none/v1/info`), 404, 'service-not-found');
  const pre = await call(`${base(name)}/v1/auth/blind/mint`, { method: 'OPTIONS' });
  check('a CORS preflight lets a browser send Clear-auth',
    pre.status === 204 && /Clear-auth/.test(pre.headers.get('access-control-allow-headers')), pre.status);

  section('cashu-ts AuthManager, and a resource server');
  // it checks that the keys derive the keyset id, and each BAT's DLEQ proof
  const am = new AuthManager(SHIP_URL + base(name), { desiredPoolSize: 5 });
  const t1 = await bat(am);
  check('it tops up 5 and hands out an authA token', t1?.startsWith('authA') && am.poolSize === 4, { t1, pool: am.poolSize });
  check('the redeem is fresh', (await redeem(name, t1)).body?.status === 'fresh');
  const again = await redeem(name, t1);
  check('again: replay, still 200, so a retry is safe (only fresh grants)', again.status === 200 && again.body?.status === 'replay', again.body);
  check('check after the redeem: spent', (await checkTok(name, t1)).body?.spent === true);
  const t2 = await bat(am);
  const c1 = (await checkTok(name, t2)).body;
  const c2 = (await checkTok(name, t2)).body;
  check('check: unspent, and checking burns nothing', c1?.spent === false && c2?.spent === false, [c1, c2]);
  refused('a wrong verifier key', await redeem(name, t2, 'wrong'), 403, 'verifier-key-required');
  refused('no verifier key', await post(`${base(name)}/check`, { token: t2 }), 403, 'verifier-key-required');
  const t3 = await bat(am);
  check('an unpadded token is the same token', t3.endsWith('=') && (await redeem(name, t3.replace(/=+$/, ''))).body?.status === 'fresh', t3);
  check('the session of this ship needs no verifier key',
    (await call(`${base(name)}/check`, { method: 'POST', body: { token: t2 }, auth: true })).body?.spent === false);
  refused('but another site\'s page with its cookie does', await call(`${base(name)}/check`,
    { method: 'POST', body: { token: t2 }, auth: true, headers: { origin: 'https://evil.example' } }), 403, 'verifier-key-required');
  refused('a forged token', await redeem(name, authA({ id: c.keyset, secret: randomHex(32), C: G })), 400, 'invalid-token');
  refused('not a token', await redeem(name, 'authAnot-json'), 400, 'invalid-token');
  refused('a cashu token is not an auth token', await redeem(name, 'cashuAeyJ0b2tlbiI6W119'), 400, 'invalid-token');
  const other = `${TAG}-other`;
  await create(other, { open: true, verifier_keys: [VKEY] });
  refused("a token at another service", await redeem(other, t2), 400, 'unknown-keyset');

  section('mint: all or nothing');
  const one = () => outputs([1], c.keyset).msgs;
  refused('amount 2', await mint(name, outputs([2], c.keyset).msgs), 400, 'amount-must-be-1');
  refused('another keyset id', await mint(name, outputs([1], `01${'0'.repeat(64)}`).msgs), 400, 'unknown-keyset');
  refused('11 outputs, over bat_max_mint', await mint(name, outputs(Array(11).fill(1), c.keyset).msgs), 400, 'too-many-outputs');
  refused('no outputs', await mint(name, []), 400, 'empty-outputs');
  const dup = one();
  refused('one B_ twice', await mint(name, [dup[0], dup[0]]), 400, 'duplicate-output');
  refused('a B_ that is no point', await mint(name, [...one(), { amount: 1, id: c.keyset, B_: `02${'0'.repeat(64)}` }]), 400, 'invalid-B_');

  section('refresh: a handed-over token made its holder\'s own');
  const o = outputs([1], c.keyset);
  const rf = await post(`${base(name)}/refresh`, { tokens: [t2], outputs: o.msgs });
  check('one token in, one signature out, with a valid DLEQ proof',
    rf.body?.signatures?.length === 1 && dleqValid(rf.body.signatures[0], o.msgs[0].B_, ks.keys), rf.body);
  refused('the old token is spent', await post(`${base(name)}/refresh`, { tokens: [t2], outputs: one() }), 400, 'token-already-spent');
  const mine = authA(o.proofs(rf.body.signatures, ks.keys)[0]);
  check('the new one redeems', (await redeem(name, mine)).body?.status === 'fresh');
  const t4 = await bat(am);
  refused('counts must match', await post(`${base(name)}/refresh`, { tokens: [t4], outputs: outputs([1, 1], c.keyset).msgs }), 400, 'count-mismatch');
  refused('one token twice', await post(`${base(name)}/refresh`, { tokens: [t4, t4], outputs: outputs([1, 1], c.keyset).msgs }), 400, 'duplicate-token');
  check('a refused refresh burned nothing', (await checkTok(name, t4)).body?.spent === false);

  section('Clear-auth keys and quota');
  const kname = `${TAG}-keyed`;
  const KEY = `${TAG}-client-${randomHex(8)}`;
  const k = (await create(kname, { keys: [KEY], quota: { n: 3, per: 3600 } })).body;
  const kinfo = (await get(`${base(kname)}/v1/info`)).body;
  check('info marks minting as needing Clear-auth (NUT-21)',
    kinfo?.nuts?.['21']?.protected_endpoints?.[0]?.path === '/v1/auth/blind/mint', kinfo);
  refused('no key', await mint(kname, outputs([1], k.keyset).msgs), 401, 'clear-auth-required');
  refused('a wrong key', await mint(kname, outputs([1], k.keyset).msgs, { 'Clear-auth': 'nope' }), 401, 'invalid-clear-auth');
  const am2 = new AuthManager(SHIP_URL + base(kname), { desiredPoolSize: 2 });
  am2.setCAT(KEY);
  check('an AuthManager with the key as its CAT tops up', (await bat(am2))?.startsWith('authA') && am2.poolSize === 1, am2.poolSize);
  refused('quota 3: two more when one is left', await mint(kname, outputs([1, 1], k.keyset).msgs, { 'Clear-auth': KEY }), 429, 'quota-exceeded');
  check('the last one', (await mint(kname, outputs([1], k.keyset).msgs, { 'Clear-auth': KEY })).status === 200);
  refused('then none', await mint(kname, outputs([1], k.keyset).msgs, { 'Clear-auth': KEY }), 429, 'quota-exceeded');
  const KEY2 = `${TAG}-client2-${randomHex(8)}`;
  await tadmin('update', { name: kname, keys: [KEY, KEY2] });
  check('another key has its own quota', (await mint(kname, outputs([1], k.keyset).msgs, { 'Clear-auth': KEY2 })).status === 200);
  check('the owner has none', (await mint(kname, outputs([1, 1, 1, 1], k.keyset).msgs, {}, true)).status === 200);

  section('policy, cap, expiry, activity');
  const closed = `${TAG}-closed`;
  const cl = (await create(closed)).body;
  refused('a new service issues to no one', await mint(closed, outputs([1], cl.keyset).msgs), 403, 'issuance-closed');
  check('but to this ship\'s session', (await mint(closed, outputs([1], cl.keyset).msgs, {}, true)).status === 200);
  const evil = { origin: 'https://evil.example' };
  refused('not when another site\'s page sends the cookie', await mint(closed, outputs([1], cl.keyset).msgs, evil, true), 403, 'issuance-closed');
  const cap = `${TAG}-cap`;
  const cp = (await create(cap, { open: true, max_issuance: 2 })).body;
  check('capped at 2, it issues 2', (await mint(cap, outputs([1, 1], cp.keyset).msgs)).body?.signatures?.length === 2);
  refused('and no third', await mint(cap, outputs([1], cp.keyset).msgs), 403, 'issuance-cap-reached');
  refused('nor a batch', await tadmin('batch', { name: cap, n: 1 }), 403, 'issuance-cap-reached');
  const exp = `${TAG}-exp`;
  await create(exp, { open: true, expires: Math.floor(Date.now() / 1000) - 3600 });
  refused('an expired service answers nothing', await get(`${base(exp)}/v1/info`), 400, 'service-expired');
  await tadmin('deactivate', { name: other });
  refused('nor does an inactive one', await get(`${base(other)}/v1/info`), 400, 'service-inactive');

  section('check mode: a membership gate');
  const club = `${TAG}-club`;
  const cb = (await create(club, { open: true, mode: 'check', verifier_keys: [VKEY] })).body;
  const co = outputs([1], cb.keyset);
  const cks = (await get(`${base(club)}/v1/auth/blind/keys`)).body.keysets[0].keys;
  const card = authA(co.proofs((await mint(club, co.msgs)).body.signatures, cks)[0]);
  const u1 = (await redeem(club, card)).body;
  const u2 = (await redeem(club, card)).body;
  check('the same token is fresh each time it is shown', u1?.status === 'fresh' && u2?.status === 'fresh', [u1, u2]);

  section('windows: a keyset per window, dead when it closes');
  const W = 6;
  const win = `${TAG}-win`;
  await create(win, { open: true, window: W, verifier_keys: [VKEY] });
  const keysetOf = async (n) => (await get(`${base(n)}/v1/auth/blind/keysets`)).body?.keysets?.[0];
  let wk = await keysetOf(win);
  // windows are multiples of W seconds: start with most of one left
  if (wk.final_expiry - Date.now() / 1000 < W / 2) {
    await sleep(wk.final_expiry * 1000 - Date.now() + 200);
    wk = await keysetOf(win);
  }
  const now = Date.now() / 1000;
  check('its keyset closes at the end of the window (final_expiry, a multiple of it)',
    wk.final_expiry > now && wk.final_expiry <= now + W && wk.final_expiry % W === 0, { wk, now });
  const amw = new AuthManager(SHIP_URL + base(win), { desiredPoolSize: 2 });
  const w1 = await bat(amw);
  check('an AuthManager derives its id with final_expiry and tops up', w1?.startsWith('authA'), w1);
  check('a token of this window redeems', (await redeem(win, w1)).body?.status === 'fresh');
  const w2 = await bat(amw);
  await sleep(wk.final_expiry * 1000 - Date.now() + 300);
  refused('after the window, its tokens are dead', await redeem(win, w2), 400, 'unknown-keyset');
  const wk2 = await keysetOf(win);
  check('the next window has its own keyset', wk2.id !== wk.id && wk2.final_expiry === wk.final_expiry + W, wk2);
  const amw2 = new AuthManager(SHIP_URL + base(win), { desiredPoolSize: 1 });
  check('and a new AuthManager tops up under it', (await redeem(win, await bat(amw2))).body?.status === 'fresh');
  const unw = (await tadmin('update', { name: win, window: null })).body;
  check('taking the window away gives a keyset for good', unw?.keyset !== wk2.id && unw.window === null, unw);
  check('with no final_expiry', !('final_expiry' in await keysetOf(win)));

  section('pruning');
  const ov = async () => (await call('/apps/tessera/api/overview', { auth: true })).body;
  const o0 = await ov();
  check('the overview has the prune timer set', o0?.next_prune > Date.now() / 1000, o0);
  const qn = `${TAG}-brief`;
  const QK = `${TAG}-brief-${randomHex(8)}`;
  const qs = (await create(qn, { keys: [QK], quota: { n: 5, per: 2 } })).body;
  await mint(qn, outputs([1], qs.keyset).msgs, { 'Clear-auth': QK });
  const o1 = await ov();
  check('an issue under a quota leaves a count', o1.quota_counts === o0.quota_counts + 1, [o0, o1]);
  await sleep(2200);
  const o2 = (await call('/apps/tessera/api/prune', { method: 'POST', body: {}, auth: true })).body;
  check('once its quota window is over, a prune drops it', o2?.quota_counts === o0.quota_counts, o2);

  section('admin: batch export, fields, delete');
  const tix = `${TAG}-tickets`;
  await create(tix, { verifier_keys: [VKEY] });
  const b = (await tadmin('batch', { name: tix, n: 3 })).body;
  check('a batch of 3 authA tokens', b?.tokens?.length === 3 && b.tokens.every((t) => t.startsWith('authA')), b);
  const rs = await Promise.all(b.tokens.map((t) => redeem(tix, t)));
  check('each redeems fresh', rs.every((r) => r.body?.status === 'fresh'), rs.map((r) => r.body));
  refused('n = 0', await tadmin('batch', { name: tix, n: 0 }), 400, 'invalid-n');
  refused('n = 101', await tadmin('batch', { name: tix, n: 101 }), 400, 'invalid-n');
  const list = (await tadmin('')).body?.services?.find((s) => s.name === tix);
  check('the list counts 3 issued, 3 redeemed', list?.issued === 3 && list.redeemed === 3, list);
  refused('a quota of 0', await tadmin('update', { name: tix, quota: { n: 0, per: 60 } }), 400, 'invalid-quota');
  refused('a mode that is not burn or check', await tadmin('update', { name: tix, mode: 'free' }), 400, 'invalid-mode');
  refused('an empty key', await tadmin('update', { name: tix, keys: [''] }), 400, 'invalid-keys');
  refused('open that is not a boolean', await tadmin('update', { name: tix, open: 'yes' }), 400, 'invalid-open');
  refused('a window of 0', await tadmin('update', { name: tix, window: 0 }), 400, 'invalid-window');
  refused('an empty title', await tadmin('update', { name: tix, title: '' }), 400, 'missing-title');
  refused('an unknown service', await tadmin('update', { name: `${TAG}-none` }), 404, 'service-not-found');
  refused('an active service does not delete', await tadmin('delete', { name: tix }), 400, 'deactivate-before-delete');
  await tadmin('deactivate', { name: tix });
  refused('nor one that issued', await tadmin('delete', { name: tix }), 400, 'service-has-issued-tokens');
  const del = `${TAG}-del`;
  await create(del);
  await tadmin('deactivate', { name: del });
  check('an inactive service that issued nothing deletes', (await tadmin('delete', { name: del })).body?.deleted === true);
  made.splice(made.indexOf(del), 1);

  section('the admin API\'s boundary');
  refused('no session', await call('/apps/tessera/api/services'), 401, 'unauthorized');
  refused('a cross-origin POST', await call('/apps/tessera/api/services/create',
    { method: 'POST', body: { name: `${TAG}-x`, title: 'x' }, auth: true, headers: { origin: 'https://evil.example' } }), 403, 'forbidden-cross-origin');
});
