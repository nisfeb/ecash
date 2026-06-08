// NUT-09 restore round-trip: mint a token, recover its signature via /v1/restore.
import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, randomBytes } from '@noble/hashes/utils';

const MINT = process.env.SHIP_URL || 'http://localhost:8080';
const COOKIE = process.env.URBAUTH_COOKIE || '';

function hashToCurve(secret) {
  const dom = new TextEncoder().encode('Secp256k1_HashToCurve_Cashu_');
  const msg = new TextEncoder().encode(secret);
  const buf = new Uint8Array(dom.length + msg.length); buf.set(dom); buf.set(msg, dom.length);
  const h0 = sha256(buf);
  for (let i = 0; i < 65536; i++) {
    const ctr = new Uint8Array(4); new DataView(ctr.buffer).setUint32(0, i, true);
    const p = new Uint8Array(36); p.set(h0); p.set(ctr, 32);
    try { return secp.Point.fromHex('02' + bytesToHex(sha256(p))); } catch {}
  }
  throw new Error('h2c');
}
const admin = (b) => fetch(`${MINT}/apps/ecash/admin/api/settings`, { method: 'POST', headers: { Cookie: COOKIE, 'content-type': 'application/json' }, body: JSON.stringify(b) });
const post = (p, b) => fetch(`${MINT}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) }).then(r => r.json());

let pass = 0, fail = 0;
const ok = (n, c, d) => (c ? (console.log('  PASS:', n), pass++) : (console.log('  FAIL:', n, d ?? ''), fail++));

const info = await (await fetch(`${MINT}/v1/info`)).json();
ok('NUT-09 advertised in /v1/info', !!info.nuts?.['9']?.supported);

await admin({ self_method_enabled: true });
const ks = (await (await fetch(`${MINT}/v1/keys`)).json()).keysets[0];
const amount = 1;
const secret = 'restore-test-' + bytesToHex(randomBytes(12));
const Y = hashToCurve(secret);
const rBig = BigInt('0x' + bytesToHex(secp.utils.randomPrivateKey()));
const Bhex = Y.add(secp.Point.BASE.multiply(rBig)).toHex(true);

const q = await post('/v1/mint/quote/self', { amount });
const mr = await post('/v1/mint/self', { quote: q.quote, outputs: [{ B_: Bhex, amount, id: ks.id }] });
const origC = mr.signatures?.[0]?.C_;
ok('minted (got a signature)', !!origC, JSON.stringify(mr).slice(0, 80));

// RESTORE the exact B_ we just minted
const rr = await post('/v1/restore', { outputs: [{ B_: Bhex, amount, id: ks.id }] });
ok('restore returns 1 output + 1 signature', rr.outputs?.length === 1 && rr.signatures?.length === 1, JSON.stringify(rr).slice(0, 120));
ok('restored C_ matches the originally-issued C_', rr.signatures?.[0]?.C_ === origC);
ok('restored signature carries DLEQ', !!rr.signatures?.[0]?.dleq?.e && !!rr.signatures?.[0]?.dleq?.s);
ok('restored output echoes B_', rr.outputs?.[0]?.B_ === Bhex);

// unknown B_ -> omitted
const fakeB = secp.Point.BASE.multiply(BigInt('0x' + bytesToHex(secp.utils.randomPrivateKey()))).toHex(true);
const ur = await post('/v1/restore', { outputs: [{ B_: fakeB, amount, id: ks.id }] });
ok('unknown B_ omitted (empty restore)', ur.outputs?.length === 0 && ur.signatures?.length === 0, JSON.stringify(ur).slice(0, 80));

await admin({ self_method_enabled: false });
console.log(`\n=== Restore: ${pass} passed, ${fail} failed ===`);
process.exit(fail ? 1 : 0);
