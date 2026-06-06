// C4 regression: service-scoped keysets must NOT be signable via public /cred,
// and spent-record must be namespaced per keyset id.
//
//   SHIP_URL=http://localhost:8080 \
//   URBAUTH_COOKIE='urbauth-~zod=0v...' \
//   node test-services-scope.mjs
import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

const MINT = process.env.SHIP_URL || 'http://localhost:8080';
const COOKIE = process.env.URBAUTH_COOKIE || '';
const jsonHeaders = { 'Cookie': COOKIE, 'Content-Type': 'application/json' };
const ADMIN = `${MINT}/apps/ecash-services/admin/api/services`;
const SVCS = `${MINT}/services/v1`;
const CRED = `${MINT}/cred/v1`;

function hashToCurve(secret) {
  const domainSep = new TextEncoder().encode('Secp256k1_HashToCurve_Cashu_');
  const msgBytes = new TextEncoder().encode(secret);
  const combined = new Uint8Array(domainSep.length + msgBytes.length);
  combined.set(domainSep); combined.set(msgBytes, domainSep.length);
  const msgHash = sha256(combined);
  for (let counter = 0; counter < 65536; counter++) {
    const cb = new Uint8Array(4);
    new DataView(cb.buffer).setUint32(0, counter, true);
    const payload = new Uint8Array(36);
    payload.set(msgHash); payload.set(cb, 32);
    const h = sha256(payload);
    try { return secp.Point.fromHex('02' + bytesToHex(h)); } catch (e) { continue; }
  }
  throw new Error('hashToCurve failed');
}
function mkOutput(secret, ksId) {
  const Y = hashToCurve(secret);
  const k = secp.utils.randomPrivateKey();
  const kBig = BigInt('0x' + bytesToHex(k));
  const B_ = Y.add(secp.Point.BASE.multiply(kBig));
  return { out: { B_: B_.toHex(true), amount: 0, id: ksId }, kBig, secret };
}
let pass = 0, fail = 0;
const ok = (n, c, d) => { c ? (pass++, console.log('PASS', n)) : (fail++, console.log('FAIL', n, d || '')); };

async function main() {
  const suffix = Date.now();
  const svcName = `scope-${suffix}`;

  // Create a GATED service (allowlist set) so the legit path is locked down.
  const created = await (await fetch(`${ADMIN}/create`, {
    method: 'POST', headers: jsonHeaders,
    body: JSON.stringify({ name: svcName, title: 'Scope', description: 'x' }),
  })).json();
  ok('service created', !!created.ks_id, JSON.stringify(created));
  const svcKs = created.ks_id;
  await fetch(`${ADMIN}/allowlist/add`, {
    method: 'POST', headers: jsonHeaders,
    body: JSON.stringify({ name: svcName, key: 'the-only-valid-key' }),
  });

  // EXPLOIT 1 (CRITICAL-6): forge a signature under the service keyset via /cred/issue.
  const evil = mkOutput(`${svcName}-forge`, svcKs);
  const credForge = await (await fetch(`${CRED}/issue`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ outputs: [evil.out] }),
  })).json();
  // Per-element error object must be returned; no C_ signature.
  const sig0 = credForge.signatures?.[0];
  ok('EXPLOIT: /cred refuses service-scoped keyset',
     !!sig0 && !sig0['C_'] && /service|forbidden|unknown/i.test(sig0.error || ''),
     JSON.stringify(credForge));

  // REGRESSION 1: the legit service path still signs (with the access key).
  const good = mkOutput(`${svcName}-good`, svcKs);
  const svcIssue = await (await fetch(`${SVCS}/${svcName}/issue`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ access_key: 'the-only-valid-key', outputs: [good.out] }),
  })).json();
  ok('REGRESSION: service /issue still signs', Array.isArray(svcIssue.signatures) && !!svcIssue.signatures[0]['C_'],
     JSON.stringify(svcIssue));

  // REGRESSION 1b: a plain (non-service) cred keyset still signs via /cred.
  const genKs = await (await fetch(`${MINT}/apps/ecash-services/admin/api/cred/keysets/generate`, {
    method: 'POST', headers: jsonHeaders,
  })).json();
  const plainKs = genKs.id;
  const plain = mkOutput(`plain-${suffix}`, plainKs);
  const credPlain = await (await fetch(`${CRED}/issue`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ outputs: [plain.out] }),
  })).json();
  ok('REGRESSION: /cred still signs non-service keyset', !!credPlain.signatures?.[0]?.['C_'], JSON.stringify(credPlain));

  // Unblind the legit service token for the LOW-3 test.
  const ksKeys = await (await fetch(`${CRED}/keys/${svcKs}`)).json();
  const svcPub = secp.Point.fromHex(ksKeys.keysets[0].keys['0']);
  const C_ = secp.Point.fromHex(svcIssue.signatures[0]['C_']);
  const C = C_.subtract(svcPub.multiply(good.kBig));
  const token = { C: C.toHex(true), secret: good.secret, amount: 0, id: svcKs };

  // EXPLOIT 2 (LOW-3): pre-spend the victim's secret in the GENERIC /cred pool.
  // We cannot produce a valid /cred proof for it (no plain keyset signs that
  // secret), so cred-redeem will reject — confirming the secret is NOT marked
  // spent globally. The service token must therefore still verify as unspent.
  await fetch(`${CRED}/redeem`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ proofs: [{ C: token.C, secret: token.secret, amount: 0, id: plainKs }] }),
  });
  const vchk = await (await fetch(`${SVCS}/${svcName}/verify`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ proofs: [token] }),
  })).json();
  ok('EXPLOIT: cross-keyset pre-spend does not mark service token spent',
     vchk.results?.[0]?.valid === true && vchk.results?.[0]?.spent === false,
     JSON.stringify(vchk));

  // REGRESSION 2: legit redeem at the service still works and is idempotent.
  const r1 = await (await fetch(`${SVCS}/${svcName}/redeem`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ proofs: [token] }),
  })).json();
  ok('REGRESSION: service redeem fresh', r1.redeemed?.[0]?.status === 'fresh', JSON.stringify(r1));
  const r2 = await (await fetch(`${SVCS}/${svcName}/redeem`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ proofs: [token] }),
  })).json();
  ok('REGRESSION: service redeem replay', r2.redeemed?.[0]?.status === 'replay', JSON.stringify(r2));

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}
main().catch(e => { console.error(e); process.exit(1); });
