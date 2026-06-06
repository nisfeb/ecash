import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

// Standard Cashu NUT-00 hash-to-curve (reference implementation)
function hashToCurveStandard(msg) {
  const prefix = new TextEncoder().encode('Secp256k1_HashToCurve_');
  const msgHash = sha256(new TextEncoder().encode(msg));
  for (let counter = 0; counter < 65536; counter++) {
    const counterBytes = new Uint8Array(4);
    new DataView(counterBytes.buffer).setUint32(0, counter, true); // LE
    const payload = new Uint8Array(prefix.length + 32 + 4);
    payload.set(prefix);
    payload.set(msgHash, prefix.length);
    payload.set(counterBytes, prefix.length + 32);
    const h = sha256(payload);
    const candidate = "02" + bytesToHex(h);
    try {
      return secp.Point.fromHex(candidate);
    } catch(e) { continue; }
  }
  throw new Error('failed');
}

// Test with known Cashu test vector
// From NUT-00 spec: hash_to_curve("test_message") 
const secrets = ["test_message", "hello", "secret", "a"];
for (const s of secrets) {
  const pt = hashToCurveStandard(s);
  console.log(`hash_to_curve("${s}") = ${pt.toHex(true)}`);
}
