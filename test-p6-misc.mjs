// Phase 6 — P2PK parity-twin bypass + keyset-set-fee rebrick.
import * as secp from '@noble/secp256k1';
import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { adminFetch, hasAuth } from './test-helpers.mjs';

const MINT = process.env.SHIP_URL || 'http://localhost:8080';
if (!hasAuth()) { console.log('SKIP'); process.exit(0); }
let ok = true;
const fail = (m) => { ok = false; console.log('FAIL:', m); };
const pass = (m) => console.log('PASS:', m);

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

async function mintToken(secret, ks, amount = 1) {
  const Y = hashToCurve(secret);
  const kBig = BigInt('0x' + bytesToHex(secp.utils.randomPrivateKey()));
  const B_ = Y.add(secp.Point.BASE.multiply(kBig));
  const q = await jpost(`${MINT}/v1/mint/quote/self`, { amount });
  const m = await jpost(`${MINT}/v1/mint/self`, { quote: q.quote, outputs: [{ B_: B_.toHex(true), amount }] });
  if (!m.signatures?.[0]) throw new Error('mint failed: ' + JSON.stringify(m));
  const C_ = secp.Point.fromHex(m.signatures[0]['C_']);
  const C = C_.subtract(secp.Point.fromHex(ks.keys[String(amount)]).multiply(kBig));
  return { C: C.toHex(true), secret, amount, id: ks.id };
}
function blank() {
  const Y = hashToCurve(`p6m-${Date.now()}-${Math.random()}`);
  const B_ = Y.add(secp.Point.BASE.multiply(BigInt('0x' + bytesToHex(secp.utils.randomPrivateKey()))));
  return { B_: B_.toHex(true), amount: 1 };
}

async function main() {
  await adminFetch('/apps/ecash/admin/api/settings', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ self_method_enabled: true }) });
  const ks = (await jget(`${MINT}/v1/keys`)).keysets[0];

  // ---- Test 1: P2PK parity-twin 2-of-2 with one key must be REJECTED ----
  console.log('\n=== Test 1: P2PK parity-twin (02x/03x) 2-of-2 with one signature ===');
  {
    const k = secp.utils.randomPrivateKey();
    const x = bytesToHex(schnorr.getPublicKey(k));           // 32-byte x-only
    const pub02 = '02' + x, pub03 = '03' + x;                 // same key, both parities
    const nonce = bytesToHex(secp.utils.randomPrivateKey()).slice(0, 32);
    const secret = JSON.stringify(['P2PK', { nonce, data: pub02, tags: [['pubkeys', pub03], ['n_sigs', '2']] }]);
    const token = await mintToken(secret, ks);
    const sig = bytesToHex(schnorr.sign(sha256(new TextEncoder().encode(secret)), k));
    token.witness = JSON.stringify({ signatures: [sig] });    // one signature
    const r = await jpost(`${MINT}/v1/swap`, { inputs: [token], outputs: [blank()] });
    if (r.detail === 'insufficient-p2pk-signatures' && !r.signatures) pass('parity-twin 2-of-2 with one sig rejected'); else fail(`twin bypass: ${JSON.stringify(r).slice(0,200)}`);
  }

  // ---- Test 2: admin set-fee must NOT brick already-issued tokens ----
  console.log('\n=== Test 2: set-fee retains old keyset id (no token brick) ===');
  {
    const oldKs = (await jget(`${MINT}/v1/keys`)).keysets[0];
    const oldId = oldKs.id;
    const token = await mintToken(`p6m-rebrick-${Date.now()}`, oldKs, 1);  // carries oldId
    // change the fee -> new id; old id should be retained as inactive alias.
    // Use a unique fee so the recomputed keyset id never collides with one a
    // prior run already created (the collision guard correctly 409s duplicates).
    const newFee = 100 + Math.floor(Math.random() * 9000);
    const sf = await (await adminFetch('/apps/ecash/admin/api/keysets/set-fee', { method: 'POST', headers: { 'content-type': 'application/json', origin: MINT }, body: JSON.stringify({ id: oldId, input_fee_ppk: newFee }) })).json();
    const newId = sf.new_id;
    if (newId && newId !== oldId) pass(`set-fee forked keyset ${oldId.slice(0,12)} -> ${newId.slice(0,12)}`); else fail(`set-fee did not fork: ${JSON.stringify(sf).slice(0,160)}`);
    // the old-id token must still redeem (alias resolves; old fee 0 retained)
    const r = await jpost(`${MINT}/v1/swap`, { inputs: [token], outputs: [blank()] });
    if (r.signatures && !r.detail) pass('old-id token still spendable after set-fee (not bricked)'); else fail(`old token bricked: ${JSON.stringify(r).slice(0,200)}`);
    // restore: re-activate the original keyset so the dev ship keeps fee 0 active
    await adminFetch('/apps/ecash/admin/api/keysets/activate', { method: 'POST', headers: { 'content-type': 'application/json', origin: MINT }, body: JSON.stringify({ id: oldId }) });
  }
  return ok;
}

main().then(async (passed) => {
  await adminFetch('/apps/ecash/admin/api/settings', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ self_method_enabled: false }) });
  console.log(passed ? '\nAll Phase-6 misc tests passed!' : '\nFAILED');
  process.exit(passed ? 0 : 1);
}).catch((e) => { console.error('ERROR:', e); process.exit(1); });
