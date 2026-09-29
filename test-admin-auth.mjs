// The HTTP boundary of %ecash and %tessera: the admin surfaces need the
// ship's session and take only same-origin writes; the public routes serve
// any origin (CORS preflight answered); every response is no-store.
import { run, check, refused, section, call, hasAuth, SHIP_URL } from './test-helpers.mjs';

await run('admin-auth', {}, async () => {
  section('without a session the admin surfaces are closed');
  // bodies a real handler would refuse too, so a broken gate changes nothing
  for (const [method, path] of [
    ['GET', '/apps/ecash/admin'], ['GET', '/apps/ecash/admin/api/overview'],
    ['POST', '/apps/ecash/admin/api/lightning/configure'], ['POST', '/apps/ecash/admin/api/settings'],
    ['GET', '/apps/tessera/api/services'], ['GET', '/apps/tessera/api/wallet'],
    ['POST', '/apps/tessera/api/services/create'], ['OPTIONS', '/apps/ecash/admin/api/settings'],
  ]) {
    refused(`${method} ${path}`, await call(path, { method, body: method === 'POST' ? { fee_reserve_pct: -1 } : undefined }), 401, 'unauthorized');
  }
  const page = await fetch(`${SHIP_URL}/apps/tessera`, { redirect: 'manual' });
  check('the %tessera page sends a browser to log in', page.status === 303
    && page.headers.get('location') === '/~/login?redirect=/apps/tessera', page.status);

  section('every response is no-store and open to any origin');
  for (const [label, res] of [
    ['a public 200', await call('/v1/info')],
    ['a public 400', await call('/v1/swap', { method: 'POST', body: {} })],
    ['a public 404', await call('/v1/keys/00ffffffffffffff')],
    ['an admin 401', await call('/apps/ecash/admin/api/overview')],
    ['a %tessera 404', await call('/tessera/none/v1/info')],
  ]) {
    check(`${label}: cache-control no-store, Access-Control-Allow-Origin *`,
      res.headers.get('cache-control') === 'no-store' && res.headers.get('access-control-allow-origin') === '*',
      Object.fromEntries(res.headers));
  }

  section('CORS preflight is answered on the public routes');
  for (const path of ['/v1/swap', '/v1/mint/quote/bolt11', '/tessera/any/v1/auth/blind/mint']) {
    const r = await call(path, { method: 'OPTIONS', headers: { origin: 'https://wallet.example', 'access-control-request-method': 'POST' } });
    check(`OPTIONS ${path}: 204, allowing POST and Content-Type from any origin`,
      r.status === 204 && /\bPOST\b/.test(r.headers.get('access-control-allow-methods') ?? '')
      && /content-type/i.test(r.headers.get('access-control-allow-headers') ?? '') && r.headers.get('access-control-allow-origin') === '*',
      { status: r.status, headers: Object.fromEntries(r.headers) });
  }

  if (!hasAuth()) { console.log('  (no URBAUTH_COOKIE: the checks with a session are left out)'); return; }
  section('with the session');
  const ov = await call('/apps/ecash/admin/api/overview', { auth: true });
  check('the admin API answers', ov.status === 200 && typeof ov.body?.active_keyset === 'string', ov.status);
  for (const path of ['/apps/ecash/admin/api/settings', '/apps/tessera/api/services']) {
    refused(`OPTIONS ${path} is not answered`, await call(path, { method: 'OPTIONS', auth: true }), 404, 'not-found');
  }
  // an empty settings body changes nothing: it only answers the settings
  refused('a write from another origin is refused',
    await call('/apps/ecash/admin/api/settings', { method: 'POST', body: {}, auth: true, headers: { origin: 'https://evil.example' } }), 403, 'forbidden-cross-origin');
  refused('and naming the foreign host in X-Forwarded-Host does not make it same-origin',
    await call('/apps/ecash/admin/api/settings', { method: 'POST', body: {}, auth: true, headers: { origin: 'https://evil.example', 'x-forwarded-host': 'evil.example' } }),
    403, 'forbidden-cross-origin');
  const same = await call('/apps/ecash/admin/api/settings', { method: 'POST', body: {}, auth: true, headers: { origin: SHIP_URL } });
  check('a write from the ship\'s own origin passes', same.status === 200, same.body);
});
