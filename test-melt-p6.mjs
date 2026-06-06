// Phase 6 — melt reconciliation redesign.
// Verifies the fixes for the Phase-5-introduced critical (and friends):
//   1. A real-LNbits 201 dispatch with a preimage SETTLES to PAID (was: misread
//      as failure -> rollback -> retry -> double-pay).
//   2. An ambiguous failure (HTTP 500) leaves the quote PENDING, proofs SPENT,
//      and a re-submit is rejected -> NO double-pay (never auto-rolls-back).
//   3. The %pending recheck (GET quote) settles a genuinely-paid inflight melt
//      (201 with no preimage, settled only on a later status GET).
//   4. The recheck confirms failure (status 404) -> un-spends + %failed, then
//      the same proofs re-melt successfully.
//   5. admin /melt/abort recovers a stuck %pending melt.
//
// Spawns its own LNbits-faithful mock variants; keeps ship load light.
import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { spawn } from 'node:child_process';
import { adminFetch, hasAuth } from './test-helpers.mjs';

const MINT = process.env.SHIP_URL || 'http://localhost:8080';
const APIKEY = 'test-api-key';
if (!hasAuth()) { console.log('SKIP (needs URBAUTH_COOKIE)'); process.exit(0); }

let ok = true;
const fail = (m) => { ok = false; console.log('FAIL:', m); };
const pass = (m) => console.log('PASS:', m);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function hashToCurve(secret) {
  const ds = new TextEncoder().encode('Secp256k1_HashToCurve_Cashu_');
  const mb = new TextEncoder().encode(secret);
  const c = new Uint8Array(ds.length + mb.length); c.set(ds); c.set(mb, ds.length);
  const mh = sha256(c);
  for (let i = 0; i < 65536; i++) {
    const cb = new Uint8Array(4); new DataView(cb.buffer).setUint32(0, i, true);
    const p = new Uint8Array(36); p.set(mh); p.set(cb, 32);
    try { return secp.Point.fromHex('02' + bytesToHex(sha256(p))); } catch (e) {}
  }
  throw new Error('h2c');
}
const jpost = async (u, b) => (await fetch(u, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) })).json();
const jget = async (u) => (await fetch(u)).json();

async function selfMintProof(amount, ks) {
  const secret = `p6-${amount}-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const Y = hashToCurve(secret);
  const kBig = BigInt('0x' + bytesToHex(secp.utils.randomPrivateKey()));
  const B_ = Y.add(secp.Point.BASE.multiply(kBig));
  const q = await jpost(`${MINT}/v1/mint/quote/self`, { amount });
  const m = await jpost(`${MINT}/v1/mint/self`, { quote: q.quote, outputs: [{ B_: B_.toHex(true), amount }] });
  if (!m.signatures?.[0]) throw new Error('self-mint failed: ' + JSON.stringify(m));
  const C_ = secp.Point.fromHex(m.signatures[0]['C_']);
  const C = C_.subtract(secp.Point.fromHex(ks.keys[String(amount)]).multiply(kBig));
  return { amount, C: C.toHex(true), secret, id: ks.id };
}
async function fundInputs(total, ks) {
  const denoms = []; let rem = total;
  for (let bit = 9; bit >= 0; bit--) { const v = 1 << bit; while (rem >= v) { denoms.push(v); rem -= v; } }
  const inputs = []; for (const d of denoms) inputs.push(await selfMintProof(d, ks));
  return inputs;
}
const blanks = (n) => Array.from({ length: n }, (_, i) => {
  const Y = hashToCurve(`p6-ch-${Date.now()}-${i}-${Math.random()}`);
  const B_ = Y.add(secp.Point.BASE.multiply(BigInt('0x' + bytesToHex(secp.utils.randomPrivateKey()))));
  return { B_: B_.toHex(true), amount: 0 };
});

function startMock(port, mode) {
  const p = spawn('node', ['mock-lnbits-instrumented.mjs'], { env: { ...process.env, PORT: String(port), PAY_MODE: mode }, stdio: 'ignore' });
  return p;
}
async function setLN(port) {
  await adminFetch('/apps/ecash/admin/api/lightning/configure', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'lnbits', url: `http://localhost:${port}`, api_key: APIKEY }) });
}
async function meltQuote(port) {
  const inv = await (await fetch(`http://localhost:${port}/api/v1/payments`, { method: 'POST', headers: { 'X-Api-Key': APIKEY, 'Content-Type': 'application/json' }, body: JSON.stringify({ out: false, amount: 10, memo: 'p6' }) })).json();
  return jpost(`${MINT}/v1/melt/bolt11`.replace('/bolt11', '/quote/bolt11'), { request: inv.payment_request });
}
const paycount = async (port) => (await jget(`http://localhost:${port}/api/v1/internal/paycount`)).count ?? (await jget(`http://localhost:${port}/api/v1/internal/paycount`)).pay_count;
async function checkstateSpent(ys) {
  const r = await jpost(`${MINT}/v1/checkstate`, { Ys: ys });
  return (r.states || []).map((s) => s.state);
}
function inputYs(inputs) { return inputs.map((p) => hashToCurve(p.secret).toHex(true)); }

const mocks = [];
async function main() {
  await adminFetch('/apps/ecash/admin/api/settings', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ self_method_enabled: true }) });
  const ks = (await jget(`${MINT}/v1/keys`)).keysets[0];

  mocks.push(startMock(3340, '201'), startMock(3341, '500'), startMock(3342, 'inflight'));
  await sleep(800);

  // ---- Test 1: 201 dispatch + preimage settles to PAID (the Phase-5 killer) ----
  console.log('\n=== Test 1: LNbits 201 success settles to PAID (no rollback) ===');
  await setLN(3340);
  let mq = await meltQuote(3340);
  let inputs = await fundInputs(mq.amount + mq.fee_reserve, ks);
  let r = await jpost(`${MINT}/v1/melt/bolt11`, { quote: mq.quote, inputs, outputs: blanks(8) });
  if (r.state === 'PAID') pass('201 pay settled to PAID'); else fail(`201 pay not PAID: ${JSON.stringify(r).slice(0,200)}`);
  const pc1 = await paycount(3340);
  // re-submit same quote with fresh proofs -> must be rejected, no 2nd pay
  let inputs1b = await fundInputs(mq.amount + mq.fee_reserve, ks);
  let r1b = await jpost(`${MINT}/v1/melt/bolt11`, { quote: mq.quote, inputs: inputs1b, outputs: blanks(8) });
  const pc1b = await paycount(3340);
  if (r1b.detail === 'quote-already-paid' && pc1b === pc1) pass('re-melt of paid quote rejected, no second pay'); else fail(`double-pay risk: detail=${r1b.detail} paycount ${pc1}->${pc1b}`);

  // ---- Test 2: ambiguous 500 -> PENDING, proofs stay spent, no double-pay ----
  console.log('\n=== Test 2: ambiguous HTTP 500 -> PENDING, never rolls back ===');
  await setLN(3341);
  let mq2 = await meltQuote(3341);
  let inputs2 = await fundInputs(mq2.amount + mq2.fee_reserve, ks);
  let r2 = await jpost(`${MINT}/v1/melt/bolt11`, { quote: mq2.quote, inputs: inputs2, outputs: blanks(8) });
  const pc2 = await paycount(3341);
  if (r2.state === 'PENDING') pass('500 dispatch -> PENDING (not 502, not failed)'); else fail(`expected PENDING, got ${JSON.stringify(r2).slice(0,200)}`);
  const sp2 = await checkstateSpent(inputYs(inputs2));
  if (sp2.every((s) => s === 'SPENT')) pass('proofs remain SPENT during PENDING'); else fail(`proofs not all SPENT: ${sp2}`);
  let r2b = await jpost(`${MINT}/v1/melt/bolt11`, { quote: mq2.quote, inputs: await fundInputs(mq2.amount + mq2.fee_reserve, ks), outputs: blanks(8) });
  const pc2b = await paycount(3341);
  if (r2b.detail === 'quote-pending' && pc2b === pc2) pass('re-melt of pending quote rejected, no second dispatch'); else fail(`double-pay risk on pending: detail=${r2b.detail} paycount ${pc2}->${pc2b}`);

  // ---- Test 3: MELT-1 — a 404 auto-recheck must NOT roll back (no double-spend) ----
  console.log('\n=== Test 3: MELT-1 — 404 auto-recheck does NOT un-spend (stays PENDING) ===');
  // poll the quote: fires %melt-check (ln-check-payment -> LNbits 404). Phase 7:
  // the auto path NEVER rolls back on a 404 (a 404 may be an in-flight race).
  await jget(`${MINT}/v1/melt/quote/bolt11/${mq2.quote}`);
  await sleep(600);
  await jget(`${MINT}/v1/melt/quote/bolt11/${mq2.quote}`);
  await sleep(400);
  const sp3 = await checkstateSpent(inputYs(inputs2));
  if (sp3.every((s) => s === 'SPENT')) pass('404 auto-recheck left proofs SPENT (no auto-rollback)'); else fail(`MELT-1: 404 recheck un-spent proofs: ${sp3}`);
  const q3 = await jget(`${MINT}/v1/melt/quote/bolt11/${mq2.quote}`);
  if (q3.state === 'PENDING') pass('quote still PENDING after 404 recheck'); else fail(`expected PENDING, got ${q3.state}`);

  // ---- Test 4: inflight (201 no preimage) settles via recheck status GET ----
  console.log('\n=== Test 4: 201 inflight settles via recheck (async LNbits) ===');
  await setLN(3342);
  let mq4 = await meltQuote(3342);
  let inputs4 = await fundInputs(mq4.amount + mq4.fee_reserve, ks);
  let r4 = await jpost(`${MINT}/v1/melt/bolt11`, { quote: mq4.quote, inputs: inputs4, outputs: blanks(8) });
  if (r4.state === 'PENDING') pass('inflight dispatch -> PENDING'); else fail(`expected PENDING, got ${JSON.stringify(r4).slice(0,150)}`);
  await jget(`${MINT}/v1/melt/quote/bolt11/${mq4.quote}`);
  await sleep(600);
  let r4b = await jget(`${MINT}/v1/melt/quote/bolt11/${mq4.quote}`);
  if (r4b.state === 'PAID') pass('recheck settled inflight melt to PAID'); else fail(`inflight not settled: ${JSON.stringify(r4b).slice(0,200)}`);

  // ---- Test 5: THE HIGH (ABORT-INFLIGHT-ROLLBACK) — conservative abort of an
  //      ambiguous (404) pay must NOT roll back; only an explicit force does ----
  console.log('\n=== Test 5: conservative abort leaves ambiguous-404 PENDING; force rolls back ===');
  await setLN(3341);  // 500 mock: status GET 404s -> ambiguous (NOT a confirmed LNbits failure)
  const ab5 = await (await adminFetch('/apps/ecash/admin/api/melt/abort', { method: 'POST', headers: { 'content-type': 'application/json', origin: MINT }, body: JSON.stringify({ quote_id: mq2.quote }) })).json();
  const sp5a = await checkstateSpent(inputYs(inputs2));
  if (ab5.aborted === false && ab5.result === 'in-flight-or-unconfirmed' && sp5a.every((s) => s === 'SPENT')) pass('conservative abort of ambiguous 404 did NOT un-spend (no double-spend)'); else fail(`HIGH: conservative abort un-spent on ambiguity: ${JSON.stringify(ab5)} states=${sp5a}`);
  const ab5f = await (await adminFetch('/apps/ecash/admin/api/melt/abort', { method: 'POST', headers: { 'content-type': 'application/json', origin: MINT }, body: JSON.stringify({ quote_id: mq2.quote, force: true }) })).json();
  const sp5b = await checkstateSpent(inputYs(inputs2));
  if (ab5f.aborted === true && sp5b.every((s) => s === 'UNSPENT')) pass('force abort rolled back the ambiguous pay (operator-authorized)'); else fail(`force abort failed: ${JSON.stringify(ab5f)} states=${sp5b}`);

  // ---- Test 6: MELT-2 — abort of a pay that ACTUALLY settled must SETTLE, not roll back ----
  console.log('\n=== Test 6: MELT-2 — abort re-checks LN; a settled pay SETTLES (no loss) ===');
  await setLN(3342);  // inflight: pay 201 no preimage (-> PENDING) but recorded as paid
  let mq6 = await meltQuote(3342);
  let inputs6 = await fundInputs(mq6.amount + mq6.fee_reserve, ks);
  let r6 = await jpost(`${MINT}/v1/melt/bolt11`, { quote: mq6.quote, inputs: inputs6, outputs: blanks(8) });
  if (r6.state === 'PENDING') pass('inflight melt -> PENDING (abort target)'); else fail(`expected PENDING, got ${JSON.stringify(r6).slice(0,150)}`);
  // use force:true to prove even a FORCED abort never loses a settled pay
  const ab6 = await (await adminFetch('/apps/ecash/admin/api/melt/abort', { method: 'POST', headers: { 'content-type': 'application/json', origin: MINT }, body: JSON.stringify({ quote_id: mq6.quote, force: true }) })).json();
  const sp6 = await checkstateSpent(inputYs(inputs6));
  if (ab6.aborted === false && ab6.result === 'settled-not-aborted' && sp6.every((s) => s === 'SPENT')) pass('FORCED abort of settled pay still SETTLED (never loses a settled pay)'); else fail(`MELT-2: forced abort mishandled settled pay: ${JSON.stringify(ab6)} states=${sp6}`);

  // ---- Test 7: MIG-2 — admin-quote-delete must refuse a %pending melt ----
  console.log('\n=== Test 7: MIG-2 — delete of a %pending melt is refused (no stranding) ===');
  await setLN(3341);
  let mq7 = await meltQuote(3341);
  let inputs7 = await fundInputs(mq7.amount + mq7.fee_reserve, ks);
  await jpost(`${MINT}/v1/melt/bolt11`, { quote: mq7.quote, inputs: inputs7, outputs: blanks(8) });  // -> PENDING (500)
  const del7 = await (await adminFetch('/apps/ecash/admin/api/quotes/delete', { method: 'POST', headers: { 'content-type': 'application/json', origin: MINT }, body: JSON.stringify({ quote_id: mq7.quote, type: 'melt' }) })).json();
  const sp7 = await checkstateSpent(inputYs(inputs7));
  if (del7.detail === 'cannot-delete-pending-melt' && sp7.every((s) => s === 'SPENT')) pass('delete of pending melt refused; inputs not stranded'); else fail(`MIG-2: delete not refused: ${JSON.stringify(del7)} states=${sp7}`);
  // clean up: force-abort it (404 is ambiguous, so force is required to roll back)
  await (await adminFetch('/apps/ecash/admin/api/melt/abort', { method: 'POST', headers: { 'content-type': 'application/json', origin: MINT }, body: JSON.stringify({ quote_id: mq7.quote, force: true }) })).json();
  return ok;
}

main().then(async (passed) => {
  for (const m of mocks) try { m.kill(); } catch (_) {}
  await adminFetch('/apps/ecash/admin/api/lightning/configure', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'none' }) });
  await adminFetch('/apps/ecash/admin/api/settings', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ self_method_enabled: false }) });
  console.log(passed ? '\nAll Phase-6 melt tests passed!' : '\nPHASE-6 MELT TESTS FAILED');
  process.exit(passed ? 0 : 1);
}).catch(async (e) => {
  for (const m of mocks) try { m.kill(); } catch (_) {}
  console.error('ERROR:', e); process.exit(1);
});
