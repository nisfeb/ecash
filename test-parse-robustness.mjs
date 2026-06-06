const BASE = process.env.SHIP_URL || 'http://localhost:8080';
let pass = 0, fail = 0;
const check = (n, c) => { c ? (pass++, console.log('PASS', n)) : (fail++, console.log('FAIL', n)); };

// A non-integer amount must yield a clean 400 — not a crashed event (500 / hang).
let status = 0;
const ctrl = new AbortController();
const t = setTimeout(() => ctrl.abort(), 8000);
try {
  status = (await fetch(`${BASE}/v1/mint/quote/bolt11`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: '{"amount":1.5}', signal: ctrl.signal,
  })).status;
} catch (e) { status = -1; }
clearTimeout(t);
check(`amount 1.5 -> 400 (got ${status})`, status === 400);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
