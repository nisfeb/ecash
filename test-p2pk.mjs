import * as secp from '@noble/secp256k1';
import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { adminFetch, hasAuth } from './test-helpers.mjs';
if (!hasAuth()) { console.log('SKIP (needs URBAUTH_COOKIE to enable self-mint)'); process.exit(0); }
await adminFetch('/apps/ecash/admin/api/settings',
  { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ self_method_enabled: true }) });

const DOMAIN_SEP = new TextEncoder().encode('Secp256k1_HashToCurve_Cashu_');

function hashToCurve(secret) {
  const msgBytes = new TextEncoder().encode(secret);
  const combined = new Uint8Array(DOMAIN_SEP.length + msgBytes.length);
  combined.set(DOMAIN_SEP);
  combined.set(msgBytes, DOMAIN_SEP.length);
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

// BIP-340 Schnorr sign using noble/curves (standard implementation)
function schnorrSign(privKey, message) {
  const sig = schnorr.sign(message, privKey);
  return bytesToHex(sig);
}

async function mintToken(secret, amount = 1) {
  // Get keys
  const kr = await (await fetch('http://localhost:8080/v1/keys')).json();
  const ks = kr.keysets[0];
  const mintPub = secp.Point.fromHex(ks.keys[String(amount)]);

  const Y = hashToCurve(secret);
  const k = secp.utils.randomPrivateKey();
  const kBig = BigInt('0x' + bytesToHex(k));
  const B_ = Y.add(secp.Point.BASE.multiply(kBig));

  // Create quote + mint
  const qr = await (await fetch('http://localhost:8080/v1/mint/quote/self', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({amount})
  })).json();

  const mr = await (await fetch('http://localhost:8080/v1/mint/self', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({quote: qr.quote, outputs: [{B_: B_.toHex(true), amount}]})
  })).json();

  const C_ = secp.Point.fromHex(mr.signatures[0]['C_']);
  const C = C_.subtract(mintPub.multiply(kBig));
  return { C: C.toHex(true), secret, amount, id: ks.id };
}

async function swap(inputs, outputSecrets) {
  const kr = await (await fetch('http://localhost:8080/v1/keys')).json();
  const ks = kr.keysets[0];
  const mintPub1 = secp.Point.fromHex(ks.keys['1']);

  const outputs = outputSecrets.map(s => {
    const Y = hashToCurve(s);
    const k = secp.utils.randomPrivateKey();
    const kBig = BigInt('0x' + bytesToHex(k));
    const B_ = Y.add(secp.Point.BASE.multiply(kBig));
    return { B_: B_.toHex(true), amount: 1 };
  });

  return await (await fetch('http://localhost:8080/v1/swap', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ inputs, outputs })
  })).json();
}

async function main() {
  let passed = 0, failed = 0;
  function assert(name, cond) {
    if (cond) { console.log(`  PASS: ${name}`); passed++; }
    else { console.log(`  FAIL: ${name}`); failed++; }
  }

  // === Test 1: Basic P2PK - valid signature ===
  console.log('\n=== Test 1: P2PK with valid signature ===');
  {
    const recipientPriv = secp.utils.randomPrivateKey();
    const recipientPub = secp.Point.BASE.multiply(BigInt('0x' + bytesToHex(recipientPriv)));
    const recipientPubHex = recipientPub.toHex(true);

    // Create P2PK secret (NUT-10 well-known format)
    const nonce = bytesToHex(secp.utils.randomPrivateKey()).slice(0, 32);
    const p2pkSecret = JSON.stringify(["P2PK", {nonce, data: recipientPubHex, tags: []}]);

    // Mint a token with this P2PK secret
    const token = await mintToken(p2pkSecret);

    // Sign SHA256(secret) with recipient's private key
    const msgToSign = sha256(new TextEncoder().encode(p2pkSecret));
    const sig = schnorrSign(recipientPriv, msgToSign);

    // Create witness
    const witness = JSON.stringify({signatures: [sig]});

    // Swap with valid witness
    const sr = await swap(
      [{...token, witness}],
      ['output-p2pk-test1-' + Date.now()]
    );
    assert('Valid P2PK signature accepted', !!sr.signatures);
  }

  // === Test 2: P2PK - missing signature (should fail) ===
  console.log('\n=== Test 2: P2PK with missing signature ===');
  {
    const recipientPriv = secp.utils.randomPrivateKey();
    const recipientPub = secp.Point.BASE.multiply(BigInt('0x' + bytesToHex(recipientPriv)));
    const nonce = bytesToHex(secp.utils.randomPrivateKey()).slice(0, 32);
    const p2pkSecret = JSON.stringify(["P2PK", {nonce, data: recipientPub.toHex(true), tags: []}]);
    const token = await mintToken(p2pkSecret);

    // Try to swap WITHOUT witness
    const sr = await swap([token], ['output-p2pk-test2-' + Date.now()]);
    assert('Missing signature rejected', sr.detail === 'missing-witness-signatures');
  }

  // === Test 3: P2PK - wrong key signature (should fail) ===
  console.log('\n=== Test 3: P2PK with wrong key signature ===');
  {
    const recipientPriv = secp.utils.randomPrivateKey();
    const recipientPub = secp.Point.BASE.multiply(BigInt('0x' + bytesToHex(recipientPriv)));
    const wrongPriv = secp.utils.randomPrivateKey(); // different key
    const nonce = bytesToHex(secp.utils.randomPrivateKey()).slice(0, 32);
    const p2pkSecret = JSON.stringify(["P2PK", {nonce, data: recipientPub.toHex(true), tags: []}]);
    const token = await mintToken(p2pkSecret);

    // Sign with WRONG key
    const msgToSign = sha256(new TextEncoder().encode(p2pkSecret));
    const sig = schnorrSign(wrongPriv, msgToSign);
    const witness = JSON.stringify({signatures: [sig]});

    const sr = await swap([{...token, witness}], ['output-p2pk-test3-' + Date.now()]);
    assert('Wrong key signature rejected', sr.detail === 'insufficient-p2pk-signatures');
  }

  // === Test 4: P2PK multisig (2-of-3) ===
  console.log('\n=== Test 4: P2PK multisig 2-of-3 ===');
  {
    const keys = [0,1,2].map(() => secp.utils.randomPrivateKey());
    const pubs = keys.map(k => secp.Point.BASE.multiply(BigInt('0x' + bytesToHex(k))).toHex(true));

    const nonce = bytesToHex(secp.utils.randomPrivateKey()).slice(0, 32);
    // data = first pubkey, extra pubkeys in tags, n_sigs = 2
    const p2pkSecret = JSON.stringify(["P2PK", {
      nonce, data: pubs[0],
      tags: [["pubkeys", pubs[1], pubs[2]], ["n_sigs", "2"]]
    }]);
    const token = await mintToken(p2pkSecret);
    const msgToSign = sha256(new TextEncoder().encode(p2pkSecret));

    // Sign with keys 0 and 2 (2 of 3)
    const sig0 = schnorrSign(keys[0], msgToSign);
    const sig2 = schnorrSign(keys[2], msgToSign);
    const witness = JSON.stringify({signatures: [sig0, sig2]});

    const sr = await swap([{...token, witness}], ['output-p2pk-test4-' + Date.now()]);
    assert('2-of-3 multisig accepted', !!sr.signatures);
  }

  // === Test 5: P2PK multisig insufficient sigs (1-of-3 when 2 needed) ===
  console.log('\n=== Test 5: P2PK multisig insufficient sigs ===');
  {
    const keys = [0,1,2].map(() => secp.utils.randomPrivateKey());
    const pubs = keys.map(k => secp.Point.BASE.multiply(BigInt('0x' + bytesToHex(k))).toHex(true));

    const nonce = bytesToHex(secp.utils.randomPrivateKey()).slice(0, 32);
    const p2pkSecret = JSON.stringify(["P2PK", {
      nonce, data: pubs[0],
      tags: [["pubkeys", pubs[1], pubs[2]], ["n_sigs", "2"]]
    }]);
    const token = await mintToken(p2pkSecret);
    const msgToSign = sha256(new TextEncoder().encode(p2pkSecret));

    // Only 1 signature
    const sig0 = schnorrSign(keys[0], msgToSign);
    const witness = JSON.stringify({signatures: [sig0]});

    const sr = await swap([{...token, witness}], ['output-p2pk-test5-' + Date.now()]);
    assert('Insufficient multisig rejected', sr.detail === 'insufficient-p2pk-signatures');
  }

  // === Test 6: Regular secret (non-P2PK) still works ===
  console.log('\n=== Test 6: Regular (non-P2PK) secret ===');
  {
    const token = await mintToken('regular-secret-' + Date.now());
    const sr = await swap([token], ['output-regular-' + Date.now()]);
    assert('Regular secret swap works', !!sr.signatures);
  }

  // === Test 7: NUT-10 unknown kind REJECTED (not bearer-spendable) ===
  // A well-known NUT-10 secret with an unsupported kind must NOT be spent as a
  // plain bearer proof (that would let a wallet-believed-locked token be spent
  // by anyone). The mint now refuses with 'unsupported-spending-condition'.
  console.log('\n=== Test 7: Unknown spending condition kind ===');
  {
    const unknownSecret = JSON.stringify(["UNKNOWN_KIND", {nonce: bytesToHex(secp.utils.randomPrivateKey()).slice(0, 32), data: "xyz", tags: []}]);
    const token = await mintToken(unknownSecret);
    const sr = await swap([token], ['output-unknown-' + Date.now()]);
    assert('Unknown kind rejected', sr.detail === 'unsupported-spending-condition' && !sr.signatures);
  }

  // === Test 8: SIG_ALL flag rejected ===
  console.log('\n=== Test 8: SIG_ALL sigflag rejected ===');
  {
    const recipientPriv = secp.utils.randomPrivateKey();
    const recipientPub = secp.Point.BASE.multiply(BigInt('0x' + bytesToHex(recipientPriv)));
    const nonce = bytesToHex(secp.utils.randomPrivateKey()).slice(0, 32);
    const p2pkSecret = JSON.stringify(["P2PK", {
      nonce, data: recipientPub.toHex(true),
      tags: [["sigflag", "SIG_ALL"]]
    }]);
    const token = await mintToken(p2pkSecret);
    const msgToSign = sha256(new TextEncoder().encode(p2pkSecret));
    const sig = schnorrSign(recipientPriv, msgToSign);
    const witness = JSON.stringify({signatures: [sig]});

    const sr = await swap([{...token, witness}], ['output-sigall-' + Date.now()]);
    assert('SIG_ALL rejected', sr.detail === 'unsupported-sigflag');
  }

  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
}

main().catch(e => console.error('Fatal:', e));
