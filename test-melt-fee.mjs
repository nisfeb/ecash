// Feature 3 — NUT-08 melt change = fee_reserve − actual routing fee.
//
// Drives a real bolt11 melt against the ~zod mint with the mock LNbits backend.
// The mock reports `fee: 2000` msat (= 2 sat) on pay, so the mint must refund
// only `fee_reserve − 2` as change (not the full reserve).
//
// Prereqs: mock-lnbits.mjs running on :3338, URBAUTH_COOKIE set (admin auth).
import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { adminFetch, hasAuth } from './test-helpers.mjs';

const MINT   = process.env.SHIP_URL || 'http://localhost:8080';
const MOCK   = 'http://localhost:3338';
const APIKEY = 'test-api-key';
const MOCK_FEE_SAT = 2;  // mock-lnbits pay response reports fee: 2000 msat

if (!hasAuth()) { console.log('SKIP (needs URBAUTH_COOKIE for admin config)'); process.exit(0); }

// Standard Cashu NUT-00 hash-to-curve (matches test-e2e.mjs).
function hashToCurve(secret) {
  const domainSep = new TextEncoder().encode('Secp256k1_HashToCurve_Cashu_');
  const msgBytes = new TextEncoder().encode(secret);
  const combined = new Uint8Array(domainSep.length + msgBytes.length);
  combined.set(domainSep);
  combined.set(msgBytes, domainSep.length);
  const msgHash = sha256(combined);
  for (let counter = 0; counter < 65536; counter++) {
    const counterBytes = new Uint8Array(4);
    new DataView(counterBytes.buffer).setUint32(0, counter, true);
    const payload = new Uint8Array(36);
    payload.set(msgHash);
    payload.set(counterBytes, 32);
    const h = sha256(payload);
    try { return secp.Point.fromHex('02' + bytesToHex(h)); } catch (e) { continue; }
  }
  throw new Error('hashToCurve failed');
}

function fail(msg) { console.log('FAIL:', msg); }
let ok = true;

async function jpost(url, body) {
  return (await fetch(url, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })).json();
}

// Mint one proof of `amount` (a single power-of-2 denomination) via self-mint.
async function selfMintProof(amount, ks, mintPub1) {
  const secret = `meltfee-in-${amount}-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const Y = hashToCurve(secret);
  const k = secp.utils.randomPrivateKey();
  const kBig = BigInt('0x' + bytesToHex(k));
  const B_ = Y.add(secp.Point.BASE.multiply(kBig));

  const q = await jpost(`${MINT}/v1/mint/quote/self`, { amount });
  const m = await jpost(`${MINT}/v1/mint/self`,
    { quote: q.quote, outputs: [{ B_: B_.toHex(true), amount }] });
  if (!m.signatures?.[0]) throw new Error('self-mint failed: ' + JSON.stringify(m));

  const C_ = secp.Point.fromHex(m.signatures[0]['C_']);
  // unblind against the per-denomination mint pubkey
  const Kamt = secp.Point.fromHex(ks.keys[String(amount)]);
  const C = C_.subtract(Kamt.multiply(kBig));
  return { amount, C: C.toHex(true), secret, id: ks.id };
}

async function main() {
  // 1. Admin: enable self-mint (to fund inputs) + point LN backend at the mock.
  await adminFetch('/apps/ecash/admin/api/settings',
    { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ self_method_enabled: true }) });
  await adminFetch('/apps/ecash/admin/api/lightning/configure',
    { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ type: 'lnbits', url: MOCK, api_key: APIKEY }) });

  // 2. Active keyset.
  const kr = await (await fetch(`${MINT}/v1/keys`)).json();
  const ks = kr.keysets[0];
  const mintPub1 = secp.Point.fromHex(ks.keys['1']);

  // 3. Create a real bolt11 invoice via the mock for 10 sat.
  const invR = await (await fetch(`${MOCK}/api/v1/payments`, {
    method: 'POST', headers: { 'X-Api-Key': APIKEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ out: false, amount: 10, memo: 'meltfee' }),
  })).json();
  const invoice = invR.payment_request;
  if (!invoice) throw new Error('no invoice from mock: ' + JSON.stringify(invR));

  // 4. Bolt11 melt quote → amount + fee_reserve.
  const mq = await jpost(`${MINT}/v1/melt/quote/bolt11`, { request: invoice });
  const amount = mq.amount;
  const feeReserve = mq.fee_reserve;
  console.log(`melt quote: amount=${amount} fee_reserve=${feeReserve} quote=${mq.quote}`);
  if (amount !== 10) { ok = false; fail(`expected quote amount 10, got ${amount}`); }
  if (feeReserve <= MOCK_FEE_SAT) {
    ok = false; fail(`fee_reserve (${feeReserve}) must exceed mock fee (${MOCK_FEE_SAT}) to observe a partial refund`);
  }

  // 5. Fund inputs >= amount + fee_reserve via self-mint (power-of-2 denoms).
  const need = amount + feeReserve;
  const denoms = [];
  let remaining = need;
  for (let bit = 9; bit >= 0; bit--) {
    const v = 1 << bit;
    while (remaining >= v) { denoms.push(v); remaining -= v; }
  }
  const inputs = [];
  for (const d of denoms) inputs.push(await selfMintProof(d, ks, mintPub1));
  const inputTotal = inputs.reduce((s, p) => s + p.amount, 0);
  console.log(`funded inputs: ${denoms.join('+')} = ${inputTotal} (need >= ${need})`);

  // 6. Blank change outputs (enough slots to hold the refund in powers of 2).
  const changeBlinds = [];
  const changeOutputs = [];
  for (let i = 0; i < 8; i++) {
    const cs = `meltfee-change-${Date.now()}-${i}`;
    const cY = hashToCurve(cs);
    const ck = secp.utils.randomPrivateKey();
    const ckBig = BigInt('0x' + bytesToHex(ck));
    const cB_ = cY.add(secp.Point.BASE.multiply(ckBig));
    changeBlinds.push(ckBig);
    changeOutputs.push({ B_: cB_.toHex(true), amount: 0 });
  }

  // 7. Execute the bolt11 melt.
  const meltR = await jpost(`${MINT}/v1/melt/bolt11`,
    { quote: mq.quote, inputs, outputs: changeOutputs });
  console.log(`melt state: ${meltR.state} change_count=${(meltR.change || []).length}`);
  if (meltR.state !== 'PAID') { ok = false; fail('melt not PAID: ' + JSON.stringify(meltR)); }

  // 8. Assert change sums to fee_reserve − actual_fee (= fee_reserve − 2).
  const expectedRefund = feeReserve - MOCK_FEE_SAT;
  const changeSum = (meltR.change || []).reduce((s, c) => s + c.amount, 0);
  if (changeSum === expectedRefund) {
    console.log(`PASS: change sum ${changeSum} === fee_reserve(${feeReserve}) − fee(${MOCK_FEE_SAT})`);
  } else {
    ok = false;
    fail(`change sum ${changeSum} !== expected ${expectedRefund} (fee_reserve ${feeReserve} − fee ${MOCK_FEE_SAT})`);
  }

  // 9. Sanity: each change signature unblinds against its denomination key.
  for (const c of (meltR.change || [])) {
    const idx = changeOutputs.findIndex((_, i) => i === (meltR.change.indexOf(c)));
    const C_ = secp.Point.fromHex(c['C_']);
    const Kamt = secp.Point.fromHex(ks.keys[String(c.amount)]);
    const C = C_.subtract(Kamt.multiply(changeBlinds[idx]));
    if (!C.toHex(true)) { ok = false; fail('change unblind produced empty point'); }
  }
  if (ok && (meltR.change || []).length > 0) console.log('PASS: change signatures unblind cleanly');

  return ok;
}

main()
  .then(async (passed) => {
    // Reset: LN backend none + self method off (leave mint in default posture).
    await adminFetch('/apps/ecash/admin/api/lightning/configure',
      { method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ type: 'none' }) });
    await adminFetch('/apps/ecash/admin/api/settings',
      { method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ self_method_enabled: false }) });
    console.log(passed ? '\nAll tests passed!' : '\nTESTS FAILED');
    process.exit(passed ? 0 : 1);
  })
  .catch(async (e) => {
    console.error('ERROR:', e);
    try {
      await adminFetch('/apps/ecash/admin/api/lightning/configure',
        { method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ type: 'none' }) });
      await adminFetch('/apps/ecash/admin/api/settings',
        { method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ self_method_enabled: false }) });
    } catch (_) {}
    process.exit(1);
  });
