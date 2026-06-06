const BASE = process.env.SHIP_URL || 'http://localhost:8080';
let pass = 0, fail = 0;
const check = (n, c) => { c ? (pass++, console.log('PASS', n)) : (fail++, console.log('FAIL', n)); };
const post = (p) => fetch(`${BASE}${p}`,
  { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"outputs":[]}' });
check('legacy POST /apps/ecash/mint -> 404', (await post('/apps/ecash/mint')).status === 404);
check('legacy POST /apps/ecash/melt -> 404', (await post('/apps/ecash/melt')).status === 404);
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
