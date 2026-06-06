import { adminFetch, hasAuth, SHIP_URL } from './test-helpers.mjs';
let pass = 0, fail = 0;
const check = (n, c) => { c ? (pass++, console.log('PASS', n)) : (fail++, console.log('FAIL', n)); };

check('GET /apps/ecash/admin unauth -> 401',
  (await fetch(`${SHIP_URL}/apps/ecash/admin`)).status === 401);
if (hasAuth()) {
  const r = await adminFetch('/apps/ecash/admin');
  check('GET /apps/ecash/admin auth -> 200 html',
    r.status === 200 && (r.headers.get('content-type') || '').includes('text/html'));
}
check('GET /apps/ecash-services/admin unauth -> 401',
  (await fetch(`${SHIP_URL}/apps/ecash-services/admin`)).status === 401);
if (hasAuth()) {
  const r = await adminFetch('/apps/ecash-services/admin');
  check('GET /apps/ecash-services/admin auth -> 200 html',
    r.status === 200 && (r.headers.get('content-type') || '').includes('text/html'));
}
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
