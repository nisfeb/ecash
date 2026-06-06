// Benchmark: time the mint signing N outputs (each = 1 blind-sign + 1 DLEQ proof).
import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
const BASE = process.env.SHIP_URL || 'http://localhost:8080';
const CK = process.env.URBAUTH_COOKIE || '';
const b2h = b => [...b].map(x => x.toString(16).padStart(2, '0')).join('');
function hashToCurve(secret) {
  const domain = new TextEncoder().encode('Secp256k1_HashToCurve_Cashu_');
  const msg = new TextEncoder().encode(secret);
  const mh = sha256(new Uint8Array([...domain, ...msg]));
  for (let c = 0; c < 65536; c++) {
    const cb = new Uint8Array(4); new DataView(cb.buffer).setUint32(0, c, true);
    const h = sha256(new Uint8Array([...mh, ...cb]));
    try { return secp.Point.fromHex('02' + b2h(h)); } catch {}
  }
  throw new Error('h2c');
}
const setSelf = on => fetch(`${BASE}/apps/ecash/admin/api/settings`, { method: 'POST',
  headers: { 'content-type': 'application/json', cookie: CK }, body: JSON.stringify({ self_method_enabled: on }) });
const N = Number(process.argv[2] || 32);
await setSelf(true);
const outs = [];
for (let i = 0; i < N; i++) {
  const Y = hashToCurve(`bench-${Date.now()}-${i}-${Math.random()}`);
  const k = secp.utils.randomPrivateKey();
  const B_ = Y.add(secp.Point.BASE.multiply(BigInt('0x' + b2h(k))));
  outs.push({ B_: B_.toHex(true), amount: 1 });
}
const qr = await (await fetch(`${BASE}/v1/mint/quote/self`, { method: 'POST',
  headers: { 'content-type': 'application/json' }, body: JSON.stringify({ amount: N }) })).json();
const t0 = performance.now();
const mr = await (await fetch(`${BASE}/v1/mint/self`, { method: 'POST',
  headers: { 'content-type': 'application/json' }, body: JSON.stringify({ quote: qr.quote, outputs: outs }) })).json();
const dt = performance.now() - t0;
console.log(`mint ${N} outputs: ${dt.toFixed(0)} ms total, ${(dt / N).toFixed(1)} ms/output, sigs=${mr.signatures?.length ?? 'ERR ' + JSON.stringify(mr).slice(0,80)}`);
await setSelf(false);
