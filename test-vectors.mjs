import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

const DOMAIN_SEP = new TextEncoder().encode('Secp256k1_HashToCurve_Cashu_');

function hashToCurve(messageBytes) {
  // Step 1: msg_hash = SHA256(DOMAIN_SEPARATOR || message)
  const combined = new Uint8Array(DOMAIN_SEP.length + messageBytes.length);
  combined.set(DOMAIN_SEP);
  combined.set(messageBytes, DOMAIN_SEP.length);
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

// Official NUT-00 test vectors (inputs are hex byte strings)
const tests = [
  { input: '0000000000000000000000000000000000000000000000000000000000000000',
    expected: '024cce997d3b518f739663b757deaec95bcd9473c30a14ac2fd04023a739d1a725' },
  { input: '0000000000000000000000000000000000000000000000000000000000000001',
    expected: '022e7158e11c9506f1aa4248bf531298daa7febd6194f003edcd9b93ade6253acf' },
  { input: '0000000000000000000000000000000000000000000000000000000000000002',
    expected: '026cdbe15362df59cd1dd3c9c11de8aedac2106eca69236ecd9fbe117af897be4f' },
];

let allPassed = true;
for (const t of tests) {
  const msgBytes = hexToBytes(t.input);
  const pt = hashToCurve(msgBytes);
  const result = pt.toHex(true);
  const pass = result === t.expected;
  console.log(`Input: ${t.input.slice(0,16)}...`);
  console.log(`  Got:      ${result}`);
  console.log(`  Expected: ${t.expected}`);
  console.log(`  ${pass ? 'PASS' : 'FAIL'}`);
  if (!pass) allPassed = false;
}
console.log(allPassed ? '\nAll test vectors PASS!' : '\nSome tests FAILED!');
