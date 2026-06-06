import { adminFetch, hasAuth, SHIP_URL } from './test-helpers.mjs';
let pass = 0, fail = 0;
const check = (n, c) => { c ? (pass++, console.log('PASS', n)) : (fail++, console.log('FAIL', n)); };

check('unauth admin overview -> 401',
  (await fetch(`${SHIP_URL}/apps/ecash/admin/api/overview`)).status === 401);
check('unauth admin ln-configure -> 401',
  (await fetch(`${SHIP_URL}/apps/ecash/admin/api/lightning/configure`,
    { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"type":"none"}' })).status === 401);
check('unauth admin dashboard -> 401',
  (await fetch(`${SHIP_URL}/apps/ecash/admin`)).status === 401);
check('public /v1/keys -> 200',
  (await fetch(`${SHIP_URL}/v1/keys`)).status === 200);
if (hasAuth()) check('authed admin overview -> 200', (await adminFetch('/apps/ecash/admin/api/overview')).status === 200);
else console.log('SKIP authed admin (no URBAUTH_COOKIE)');

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
