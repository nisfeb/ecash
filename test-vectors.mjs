// The client crypto every suite grades the mint with (test-helpers.mjs, on
// cashu-ts) against the published Cashu test vectors (NUT-00, NUT-12). If
// the helpers drifted from the spec, a mint that drifted the same way would
// pass every other suite. Offline: no ship needed. (The mint's own Hoon is
// checked against these vectors by the Hoon tests.)
import { hash_e } from '@cashu/cashu-ts';
import { run, check, hashToCurve, blind, point } from './test-helpers.mjs';

const hex = (h) => Uint8Array.from(Buffer.from(h, 'hex'));

await run('vectors', { ship: false }, async () => {
  // NUT-00 hash_to_curve: messages are raw bytes
  for (const [msg, Y] of [
    ['00'.repeat(32), '024cce997d3b518f739663b757deaec95bcd9473c30a14ac2fd04023a739d1a725'],
    ['00'.repeat(31) + '01', '022e7158e11c9506f1aa4248bf531298daa7febd6194f003edcd9b93ade6253acf'],
    ['00'.repeat(31) + '02', '026cdbe15362df59cd1dd3c9c11de8aedac2106eca69236ecd9fbe117af897be4f'],
  ]) check(`hash_to_curve(0x${msg.slice(-4)})`, hashToCurve(hex(msg)).toHex(true) === Y, hashToCurve(hex(msg)).toHex(true));

  // NUT-00 blinded message: B_ = Y + rG for a string secret
  const b = blind('test_message', 1n);
  check('blind("test_message", r = 1)', b.B_ === '025cc16fe33b953e2ace39653efb3e7a7049711ae1d8a2f7a9108753f1cdea742b', b.B_);

  // NUT-12 hash_e(R1, R2, K, C_), which every DLEQ check hashes
  const one = point('020000000000000000000000000000000000000000000000000000000000000001');
  const C_ = point('02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2');
  const e = Buffer.from(hash_e([one, one, one, C_])).toString('hex');
  check('hash_e(R1, R2, K, C_)', e === 'a4dc034b74338c28c6bc3ea49731f2a24440fc7c4affc08b31a93fc9fbe6401e', e);
});
