// test-ladder-port.mjs
// Faithful JS port of the EXACT Hoon Montgomery ladder in desk/lib/curve.hoon
// (pt-mul k*P branch, jac-dbl, jac-add, jac-to-affine) — then fuzz it against
// noble across edge-case AND random scalars. This verifies the ALGORITHM the
// C8 rewrite uses (bit iteration order, fixed 256-bit width, jac formulas,
// infinity handling) reproduces the reference for scalars the wire path can't
// reach directly (k=1, k=2, k=n-1, single-bit, low/high patterns).
//
// The port mirrors curve.hoon line-for-line:
//   jac-inf  = [1,1,0]
//   jac-dbl  (dbl-2009-l), jac-add (add-2007-bl, a=0)
//   ladder: nbits=max(256,bitlen(k)); r0=inf, r1=base; for i=nbits-1..0:
//           bit==0 -> r1=add(r0,r1), r0=dbl(r0)
//           bit==1 -> r0=add(r0,r1), r1=dbl(r1)
//   to-affine via field inverse.

import { secp256k1 } from '@noble/curves/secp256k1.js';

const P = (1n << 256n) - (1n << 32n) - 977n;            // secp-p
const N = secp256k1.Point.Fn.ORDER;                     // secp-n
const Pt = secp256k1.Point, G = Pt.BASE;

const mod = (a, m) => ((a % m) + m) % m;
const fadd = (a, b) => mod(a + b, P);
const fsub = (a, b) => mod(a - b, P);
const fmul = (a, b) => mod(a * b, P);
function finv(a) { // Fermat, matches powmod(a,p-2,p)
  let r = 1n, b = mod(a, P), e = P - 2n;
  while (e > 0n) { if (e & 1n) r = mod(r * b, P); b = mod(b * b, P); e >>= 1n; }
  return r;
}

const JAC_INF = { x: 1n, y: 1n, z: 0n };
function jacDbl(j) {
  if (j.z === 0n) return j;
  if (j.y === 0n) return JAC_INF;
  const aa = fmul(j.x, j.x);
  const bb = fmul(j.y, j.y);
  const cc = fmul(bb, bb);
  const xb = fadd(j.x, bb);
  const dd = fmul(2n, fsub(fsub(fmul(xb, xb), aa), cc));
  const ee = fmul(3n, aa);
  const ff = fmul(ee, ee);
  const x3 = fsub(ff, fmul(2n, dd));
  const y3 = fsub(fmul(ee, fsub(dd, x3)), fmul(8n, cc));
  const z3 = fmul(2n, fmul(j.y, j.z));
  return { x: x3, y: y3, z: z3 };
}
function jacAdd(j1, j2) {
  if (j1.z === 0n) return j2;
  if (j2.z === 0n) return j1;
  const z1z1 = fmul(j1.z, j1.z);
  const z2z2 = fmul(j2.z, j2.z);
  const u1 = fmul(j1.x, z2z2);
  const u2 = fmul(j2.x, z1z1);
  const s1 = fmul(j1.y, fmul(j2.z, z2z2));
  const s2 = fmul(j2.y, fmul(j1.z, z1z1));
  if (u1 === u2) { return s1 === s2 ? jacDbl(j1) : JAC_INF; }
  const hh = fsub(u2, u1);
  const ii = fmul(fmul(2n, hh), fmul(2n, hh));
  const jj = fmul(hh, ii);
  const rr = fmul(2n, fsub(s2, s1));
  const vv = fmul(u1, ii);
  const x3 = fsub(fsub(fmul(rr, rr), jj), fmul(2n, vv));
  const y3 = fsub(fmul(rr, fsub(vv, x3)), fmul(2n, fmul(s1, jj)));
  const zz = fadd(j1.z, j2.z);
  const z3 = fmul(fsub(fsub(fmul(zz, zz), z1z1), z2z2), hh);
  return { x: x3, y: y3, z: z3 };
}
function jacToAffine(j) {
  if (j.z === 0n) throw new Error('jac-to-affine-infinity');
  const zi = finv(j.z);
  const zi2 = fmul(zi, zi);
  const zi3 = fmul(zi2, zi);
  return { x: fmul(j.x, zi2), y: fmul(j.y, zi3) };
}
function bitlen(k) { return k === 0n ? 0n : BigInt(k.toString(2).length); }
function ptMulLadder(k, Px, Py) {
  if (k === 0n) throw new Error('pt-mul k=0');
  const base = { x: Px, y: Py, z: 1n };
  let nbits = bitlen(k); if (nbits < 256n) nbits = 256n;
  let r0 = JAC_INF, r1 = base;
  for (let i = nbits; i > 0n; i--) {
    const bit = (k >> (i - 1n)) & 1n;
    if (bit === 0n) { const nr1 = jacAdd(r0, r1); const nr0 = jacDbl(r0); r0 = nr0; r1 = nr1; }
    else { const nr0 = jacAdd(r0, r1); const nr1 = jacDbl(r1); r0 = nr0; r1 = nr1; }
  }
  return jacToAffine(r0);
}

// Reference point P != G to multiply (use hash-to-curve of a fixed secret, like the mint does)
function refPoint() {
  // pick an arbitrary non-G base point deterministically
  return Pt.fromHex('024cce997d3b518f739663b757deaec95bcd9473c30a14ac2fd04023a739d1a725');
}

function check(k, basePt) {
  const aff = basePt.toAffine();
  const got = ptMulLadder(k, aff.x, aff.y);
  const exp = basePt.multiply(mod(k, N)).toAffine(); // noble reduces internally; ladder uses raw k (k<n here)
  return got.x === exp.x && got.y === exp.y;
}

function main() {
  const base = refPoint();
  let total = 0, fails = 0;
  const failList = [];
  const tryK = (k, label) => {
    if (k <= 0n || k >= N) return;
    total++;
    let ok;
    try { ok = check(k, base); } catch (e) { ok = false; failList.push(`${label} k=${k}: EXC ${e.message}`); fails++; return; }
    if (!ok) { fails++; failList.push(`${label} k=${k}`); }
  };

  // edge scalars
  tryK(1n, 'one'); tryK(2n, 'two'); tryK(3n, 'three'); tryK(4n, 'four');
  tryK(N - 1n, 'n-1'); tryK(N - 2n, 'n-2'); tryK(N - 3n, 'n-3');
  for (let b = 0n; b < 256n; b++) { tryK(1n << b, `2^${b}`); }                 // single-bit
  for (let b = 1n; b < 256n; b++) { tryK((1n << b) - 1n, `2^${b}-1`); }        // all-low-bits
  for (let b = 0n; b < 256n; b++) { tryK((1n << b) | 1n, `2^${b}|1`); }        // high+low bit
  // a few "all but one bit" patterns
  for (let b = 0n; b < 200n; b += 7n) { const m = (1n << 255n) - 1n; tryK(m ^ (1n << b), `255mask^${b}`); }
  // random scalars
  for (let i = 0; i < 400; i++) {
    let k = 0n; const bytes = secp256k1.utils.randomSecretKey();
    for (const x of bytes) k = (k << 8n) | BigInt(x);
    k = mod(k, N); if (k === 0n) k = 1n;
    tryK(k, 'rand');
  }

  console.log('=== Hoon-ladder JS port vs noble (edge + random scalars) ===');
  console.log('scalars checked:', total);
  console.log('mismatches:     ', fails);
  if (failList.length) { console.log('failures:'); failList.slice(0, 20).forEach(f => console.log('  ' + f)); }
  console.log('\nRESULT:', fails === 0 ? 'ALL MATCH noble' : 'MISMATCH');
  process.exit(fails === 0 ? 0 : 1);
}
main();
