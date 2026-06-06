// Security test: amount-0 value output must NOT be silently upgraded to a
// denomination-64 token by ++sign-outputs.  See the 64-sat inflation bug.
//
// Theory: swap of outputs [{amount:1},{amount:0}] against a single 1-sat input
// balances (declared output-total 1 == input 1) yet, with the buggy
// `=?  amt  =(0 amt)  64` line, returns BOTH a 1-sat and a 64-sat signature.
//
// Run: URBAUTH_COOKIE='...' node test-swap-security.mjs
import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { adminFetch, hasAuth, SHIP_URL } from './test-helpers.mjs';

if (!hasAuth()) { console.log('SKIP (needs URBAUTH_COOKIE to enable self-mint)'); process.exit(0); }

async function setSelf(on) {
  await adminFetch('/apps/ecash/admin/api/settings',
    { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ self_method_enabled: on }) });
}

// Standard Cashu NUT-00 hash-to-curve (copied verbatim from test-e2e.mjs).
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
    try {
      return secp.Point.fromHex("02" + bytesToHex(h));
    } catch (e) { continue; }
  }
  throw new Error('failed');
}

// Build a valid blinded output B_ = Y + r*G for a given secret; returns the
// secret, the blinding scalar r (BigInt), and B_ hex.
function blind(secret) {
  const Y = hashToCurve(secret);
  const r = secp.utils.randomPrivateKey();
  const rBig = BigInt('0x' + bytesToHex(r));
  const B_ = Y.add(secp.Point.BASE.multiply(rBig));
  return { secret, rBig, B_hex: B_.toHex(true), Y };
}

async function main() {
  let failed = false;

  // 1. Enable self.
  await setSelf(true);

  // 2. Mint one 1-sat token.
  const kr = await (await fetch(`${SHIP_URL}/v1/keys`)).json();
  const ks = kr.keysets[0];
  const mintPub1 = secp.Point.fromHex(ks.keys['1']);

  const qr = await (await fetch(`${SHIP_URL}/v1/mint/quote/self`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ amount: 1 })
  })).json();

  const secret = 'security-input-' + Date.now();
  const Y = hashToCurve(secret);
  const k = secp.utils.randomPrivateKey();
  const kBig = BigInt('0x' + bytesToHex(k));
  const B_ = Y.add(secp.Point.BASE.multiply(kBig));

  const mr = await (await fetch(`${SHIP_URL}/v1/mint/self`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ quote: qr.quote, outputs: [{ B_: B_.toHex(true), amount: 1 }] })
  })).json();

  if (!mr.signatures?.[0]) {
    console.log('Mint FAILED:', JSON.stringify(mr));
    await setSelf(false);
    process.exit(1);
  }

  // Unblind to a spendable 1-sat proof.
  const C_ = secp.Point.fromHex(mr.signatures[0]['C_']);
  const C = C_.subtract(mintPub1.multiply(kBig));
  const proof = { amount: 1, C: C.toHex(true), secret, id: ks.id };
  console.log('Minted 1-sat proof, secret:', secret);

  // 3. Swap it: outputs [{amount:1},{amount:0}] against the 1-sat input.
  const out1 = blind('security-out1-' + Date.now());
  const out0 = blind('security-out0-' + Date.now());

  const sr = await (await fetch(`${SHIP_URL}/v1/swap`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      inputs: [proof],
      outputs: [
        { B_: out1.B_hex, amount: 1 },
        { B_: out0.B_hex, amount: 0 }
      ]
    })
  })).json();

  console.log('Swap response:', JSON.stringify(sr));

  // 4. Inspect signatures: there must be NO amount===64 signature.
  const sigs = Array.isArray(sr.signatures) ? sr.signatures : [];
  const amounts = sigs.map(s => s.amount);
  console.log('Returned signature amounts:', JSON.stringify(amounts));

  const has64 = sigs.some(s => s.amount === 64);
  if (has64) {
    console.log('FAIL: amount-0 output yielded a 64-sat signature (64-sat inflation reproduced).');
    failed = true;
  } else {
    console.log('PASS: no 64-sat signature from the amount-0 output.');
  }

  // After the fix the amount-0 output should produce an unknown-denomination
  // error entry (and the swap may be rejected upstream as not-balancing only if
  // declared totals differ -- here they balance, so we still get a per-element
  // error object). Report what came back for the amount-0 slot.
  const errEntries = sigs.filter(s => s && s.error);
  if (errEntries.length) {
    console.log('Per-element errors present:', JSON.stringify(errEntries));
  }

  // 5. Restore self to false.
  await setSelf(false);

  if (failed) {
    console.log('\n1 failed');
    process.exit(1);
  }
  console.log('\n1 passed');
}

main().catch(async (e) => {
  console.error(e);
  try { await setSelf(false); } catch (_) {}
  process.exit(1);
});
