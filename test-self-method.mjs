import { hasAuth, adminFetch, SHIP_URL } from './test-helpers.mjs';
let pass = 0, fail = 0;
const check = (n, c) => { c ? (pass++, console.log('PASS', n)) : (fail++, console.log('FAIL', n)); };
const setSelf = (on) => adminFetch('/apps/ecash/admin/api/settings',
  { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ self_method_enabled: on }) });
const selfQuote = () => fetch(`${SHIP_URL}/v1/mint/quote/self`,
  { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"amount":4}' });

if (hasAuth()) await setSelf(false);
check('self disabled -> 400', (await selfQuote()).status === 400);
if (hasAuth()) {
  await setSelf(true);
  check('self enabled -> 200', (await selfQuote()).status === 200);
  // Regression for the closed CRITICAL hole: a %paid self-origin quote must NOT
  // be redeemable via the bolt11 verb once self is disabled.
  const q = await (await selfQuote()).json();   // fresh %paid self quote (self on)
  await setSelf(false);                          // disable self
  const redeem = await fetch(`${SHIP_URL}/v1/mint/bolt11`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ quote: q.quote, outputs: [] }),
  });
  const detail = (await redeem.json()).detail;
  check('stale self quote NOT redeemable via bolt11 when off',
    redeem.status === 400 && detail === 'self-method-disabled');
  await setSelf(false); // restore safe default (leave self OFF)
} else {
  console.log('SKIP enable/disable round-trip (no URBAUTH_COOKIE)');
}
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
