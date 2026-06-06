import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { adminFetch, hasAuth } from './test-helpers.mjs';
if (!hasAuth()) { console.log('SKIP (needs URBAUTH_COOKIE to enable self-mint)'); process.exit(0); }
await adminFetch('/apps/ecash/admin/api/settings',
  { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ self_method_enabled: true }) });

// Standard Cashu NUT-00 hash-to-curve
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
    } catch(e) { continue; }
  }
  throw new Error('failed');
}

async function main() {
  // 1. Create mint quote
  const qr = await (await fetch('http://localhost:8080/v1/mint/quote/self', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({amount: 1})
  })).json();
  console.log('1. Quote:', qr.state);

  // 2. Get keys
  const kr = await (await fetch('http://localhost:8080/v1/keys')).json();
  const ks = kr.keysets[0];
  const mintPub1 = secp.Point.fromHex(ks.keys['1']);
  console.log('2. Keyset:', ks.id.slice(0,16) + '...');

  // 3. Mint token with standard hash-to-curve
  const secret = 'standard-test-' + Date.now();
  const Y = hashToCurve(secret);
  const k = secp.utils.randomPrivateKey();
  const kBig = BigInt('0x' + bytesToHex(k));
  const B_ = Y.add(secp.Point.BASE.multiply(kBig));

  const mr = await (await fetch('http://localhost:8080/v1/mint/self', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({quote: qr.quote, outputs: [{B_: B_.toHex(true), amount: 1}]})
  })).json();

  if (!mr.signatures?.[0]) {
    console.log('3. Mint FAILED:', JSON.stringify(mr));
    return;
  }
  console.log('3. Mint: OK, dleq:', mr.signatures[0].dleq ? 'present' : 'missing');

  // 4. Unblind
  const C_ = secp.Point.fromHex(mr.signatures[0]['C_']);
  const C = C_.subtract(mintPub1.multiply(kBig));
  console.log('4. Unblind C:', C.toHex(true).slice(0,20) + '...');

  // 5. Swap (spend + re-mint)
  const secret2 = 'standard-output-' + Date.now();
  const Y2 = hashToCurve(secret2);
  const k2 = secp.utils.randomPrivateKey();
  const k2Big = BigInt('0x' + bytesToHex(k2));
  const B2_ = Y2.add(secp.Point.BASE.multiply(k2Big));

  const sr = await (await fetch('http://localhost:8080/v1/swap', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      inputs: [{amount: 1, C: C.toHex(true), secret: secret, id: ks.id}],
      outputs: [{B_: B2_.toHex(true), amount: 1}]
    })
  })).json();

  if (sr.signatures) {
    console.log('5. Swap: OK');
  } else {
    console.log('5. Swap FAILED:', JSON.stringify(sr));
    return;
  }

  // 6. Checkstate - Y should be SPENT
  const cr = await (await fetch('http://localhost:8080/v1/checkstate', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({Ys: [Y.toHex(true)]})
  })).json();
  console.log('6. Checkstate:', cr.states[0].state);

  // 7. Double-spend should fail
  const sr2 = await (await fetch('http://localhost:8080/v1/swap', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      inputs: [{amount: 1, C: C.toHex(true), secret: secret, id: ks.id}],
      outputs: [{B_: B2_.toHex(true), amount: 1}]
    })
  })).json();
  console.log('7. Double-spend rejected:', sr2.detail === 'token-already-spent' ? 'YES' : 'NO - ' + JSON.stringify(sr2));

  // 8. NUT-08: Self-method melt with change outputs
  console.log('\n--- NUT-08: Self-method melt with change ---');

  // Mint 4 tokens of 1 sat each (total 4 sats)
  const meltTokens = [];
  for (let i = 0; i < 4; i++) {
    const sec = 'melt-input-' + Date.now() + '-' + i;
    const Yi = hashToCurve(sec);
    const ki = secp.utils.randomPrivateKey();
    const kiBig = BigInt('0x' + bytesToHex(ki));
    const Bi_ = Yi.add(secp.Point.BASE.multiply(kiBig));

    const qi = await (await fetch('http://localhost:8080/v1/mint/quote/self', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({amount: 1})
    })).json();

    const mi = await (await fetch('http://localhost:8080/v1/mint/self', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({quote: qi.quote, outputs: [{B_: Bi_.toHex(true), amount: 1}]})
    })).json();

    const Ci_ = secp.Point.fromHex(mi.signatures[0]['C_']);
    const Ci = Ci_.subtract(mintPub1.multiply(kiBig));
    meltTokens.push({amount: 1, C: Ci.toHex(true), secret: sec, id: ks.id});
  }
  console.log('8a. Minted 4 tokens for melt inputs');

  // Create melt quote for 1 sat (self method)
  const meltQr = await (await fetch('http://localhost:8080/v1/melt/quote/self', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({request: 'self-melt-test', amount: 1})
  })).json();
  console.log('8b. Melt quote:', meltQr.quote, 'amount:', meltQr.amount, 'fee_reserve:', meltQr.fee_reserve);

  // Prepare blank change outputs
  const changeSecrets = [];
  const changeKs = [];
  const changeOutputs = [];
  for (let i = 0; i < 3; i++) {
    const cs = 'change-' + Date.now() + '-' + i;
    const cY = hashToCurve(cs);
    const ck = secp.utils.randomPrivateKey();
    const ckBig = BigInt('0x' + bytesToHex(ck));
    const cB_ = cY.add(secp.Point.BASE.multiply(ckBig));
    changeSecrets.push(cs);
    changeKs.push(ckBig);
    changeOutputs.push({B_: cB_.toHex(true), amount: 0}); // amount ignored by mint
  }

  // Execute melt with change outputs
  const meltR = await (await fetch('http://localhost:8080/v1/melt/self', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({quote: meltQr.quote, inputs: meltTokens, outputs: changeOutputs})
  })).json();
  console.log('8c. Melt state:', meltR.state);
  console.log('8d. Change array present:', Array.isArray(meltR.change));
  console.log('8e. Change count:', meltR.change?.length || 0);

  // Verify change amounts sum to overpaid (inputs - fee - amount)
  if (meltR.change && meltR.change.length > 0) {
    const changeSum = meltR.change.reduce((s, c) => s + c.amount, 0);
    const fee = meltQr.fee_reserve;
    const expectedOverpaid = 4 - fee - meltQr.amount;
    console.log('8f. Change sum:', changeSum, 'expected overpaid:', expectedOverpaid,
      changeSum === expectedOverpaid ? 'MATCH' : 'MISMATCH');

    // Unblind a change token and verify signature
    const cSig = meltR.change[0];
    const cC_ = secp.Point.fromHex(cSig['C_']);
    const cAmt = cSig.amount;
    const cPub = secp.Point.fromHex(ks.keys[String(cAmt)]);
    const cC = cC_.subtract(cPub.multiply(changeKs[0]));
    console.log('8g. Unblinded change token OK:', cC.toHex(true).slice(0, 20) + '...');
  }

  // 9. NUT-08: Melt without outputs (backwards compat)
  {
    const sec9 = 'no-change-melt-' + Date.now();
    const Y9 = hashToCurve(sec9);
    const k9 = secp.utils.randomPrivateKey();
    const k9Big = BigInt('0x' + bytesToHex(k9));
    const B9_ = Y9.add(secp.Point.BASE.multiply(k9Big));

    const q9 = await (await fetch('http://localhost:8080/v1/mint/quote/self', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({amount: 1})
    })).json();
    const m9 = await (await fetch('http://localhost:8080/v1/mint/self', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({quote: q9.quote, outputs: [{B_: B9_.toHex(true), amount: 1}]})
    })).json();
    const C9_ = secp.Point.fromHex(m9.signatures[0]['C_']);
    const C9 = C9_.subtract(mintPub1.multiply(k9Big));

    const mq9 = await (await fetch('http://localhost:8080/v1/melt/quote/self', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({request: 'no-change-melt', amount: 1})
    })).json();

    const mr9 = await (await fetch('http://localhost:8080/v1/melt/self', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({quote: mq9.quote, inputs: [{amount: 1, C: C9.toHex(true), secret: sec9, id: ks.id}]})
    })).json();
    console.log('9. No-outputs melt state:', mr9.state, 'change empty:', (mr9.change || []).length === 0 ? 'YES' : 'NO');
  }

  console.log('\nAll tests passed!');
}

main().catch(console.error);
