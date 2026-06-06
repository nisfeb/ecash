// E2E tests for credential token extension
// Tests: issue, verify, redeem flow for zero-value credential tokens
import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

const MINT = process.env.SHIP_URL || 'http://localhost:8080';
const COOKIE = process.env.URBAUTH_COOKIE || '';

// %ecash-services serves cred under the public /cred/v1 path only.
const CRED = `${MINT}/cred/v1`;
const ADMIN = `${MINT}/apps/ecash-services/admin/api`;

const authHeaders = { 'Cookie': COOKIE };
const jsonHeaders = { ...authHeaders, 'Content-Type': 'application/json' };

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
  throw new Error('hashToCurve failed');
}

async function main() {
  let passed = 0, failed = 0;
  function assert(name, cond, detail) {
    if (cond) { console.log(`  PASS: ${name}`); passed++; }
    else { console.log(`  FAIL: ${name}${detail ? ' — ' + detail : ''}`); failed++; }
  }

  // === Test 1: Get credential keysets ===
  console.log('=== Test 1: Get credential keysets ===');
  const keysResp = await (await fetch(`${CRED}/keys`, { headers: authHeaders })).json();
  assert('Has keysets array', Array.isArray(keysResp.keysets));
  assert('At least one keyset', keysResp.keysets.length > 0);

  const credKeyset = keysResp.keysets[0];
  const credKsId = credKeyset.id;
  const credPubKey = credKeyset.keys['0'];
  assert('Keyset ID starts with c0', credKsId.startsWith('c0'));
  assert('Has key at denomination 0', !!credPubKey);
  console.log(`  Credential keyset: ${credKsId.slice(0, 16)}...`);

  // === Test 2: Get credential keysets metadata ===
  console.log('\n=== Test 2: Get credential keysets metadata ===');
  const ksetsResp = await (await fetch(`${CRED}/keysets`, { headers: authHeaders })).json();
  assert('Has keysets list', Array.isArray(ksetsResp.keysets));
  assert('Keyset is active', ksetsResp.keysets.some(k => k.id === credKsId && k.active));

  // === Test 3: Get credential keyset by ID ===
  console.log('\n=== Test 3: Get credential keyset by ID ===');
  const ksByIdResp = await (await fetch(`${CRED}/keys/${credKsId}`, { headers: authHeaders })).json();
  assert('Keyset by ID returned', !!ksByIdResp.keysets);
  assert('Correct keyset', ksByIdResp.keysets[0]?.id === credKsId);

  // === Test 4: Issue credential tokens ===
  console.log('\n=== Test 4: Issue credential tokens ===');
  const mintPub = secp.Point.fromHex(credPubKey);
  const numTokens = 5;
  const secrets = [];
  const blindingKeys = [];
  const outputs = [];

  for (let i = 0; i < numTokens; i++) {
    const secret = `cred-test-${Date.now()}-${i}`;
    secrets.push(secret);
    const Y = hashToCurve(secret);
    const k = secp.utils.randomPrivateKey();
    const kBig = BigInt('0x' + bytesToHex(k));
    blindingKeys.push(kBig);
    const B_ = Y.add(secp.Point.BASE.multiply(kBig));
    outputs.push({ B_: B_.toHex(true), amount: 0, id: credKsId });
  }

  const issueResp = await (await fetch(`${CRED}/issue`, {
    method: 'POST', headers: jsonHeaders,
    body: JSON.stringify({ outputs })
  })).json();
  assert('Issue returned signatures', !!issueResp.signatures, JSON.stringify(issueResp).slice(0, 200));
  assert('Got correct number of signatures', issueResp.signatures?.length === numTokens);

  // Unblind the tokens
  const tokens = issueResp.signatures.map((sig, i) => {
    const C_ = secp.Point.fromHex(sig['C_']);
    const C = C_.subtract(mintPub.multiply(blindingKeys[i]));
    return { C: C.toHex(true), secret: secrets[i], amount: 0, id: credKsId };
  });
  console.log(`  Issued ${tokens.length} credential tokens`);

  // === Test 5: Verify credential tokens (not spent) ===
  console.log('\n=== Test 5: Verify credential tokens ===');
  const verifyResp = await (await fetch(`${CRED}/verify`, {
    method: 'POST', headers: jsonHeaders,
    body: JSON.stringify({ proofs: [tokens[0]] })
  })).json();
  assert('Verify returned results', !!verifyResp.valid, JSON.stringify(verifyResp));
  assert('Token is valid', verifyResp.valid[0]?.valid === true);
  assert('Token is not spent', verifyResp.valid[0]?.spent === false);

  // === Test 6: Redeem a credential token ===
  console.log('\n=== Test 6: Redeem a credential token ===');
  const redeemResp = await (await fetch(`${CRED}/redeem`, {
    method: 'POST', headers: jsonHeaders,
    body: JSON.stringify({ proofs: [tokens[0]] })
  })).json();
  assert('Redeem succeeded', !!redeemResp.redeemed, JSON.stringify(redeemResp));
  assert('Token marked redeemed', redeemResp.redeemed[0]?.redeemed === true);

  // === Test 7: Verify redeemed token shows as spent ===
  console.log('\n=== Test 7: Verify redeemed token is spent ===');
  const verify2Resp = await (await fetch(`${CRED}/verify`, {
    method: 'POST', headers: jsonHeaders,
    body: JSON.stringify({ proofs: [tokens[0]] })
  })).json();
  assert('Redeemed token still valid sig', verify2Resp.valid[0]?.valid === true);
  assert('Redeemed token is spent', verify2Resp.valid[0]?.spent === true);

  // === Test 8: Double-redeem fails ===
  console.log('\n=== Test 8: Double-redeem fails ===');
  const redeem2Resp = await (await fetch(`${CRED}/redeem`, {
    method: 'POST', headers: jsonHeaders,
    body: JSON.stringify({ proofs: [tokens[0]] })
  })).json();
  assert('Double redeem rejected', redeem2Resp.detail === 'credential-already-spent', redeem2Resp.detail);

  // === Test 9: Redeem multiple tokens at once ===
  console.log('\n=== Test 9: Redeem multiple tokens ===');
  const multiRedeemResp = await (await fetch(`${CRED}/redeem`, {
    method: 'POST', headers: jsonHeaders,
    body: JSON.stringify({ proofs: [tokens[1], tokens[2]] })
  })).json();
  assert('Multi-redeem succeeded', !!multiRedeemResp.redeemed);
  assert('Both tokens redeemed', multiRedeemResp.redeemed?.length === 2);

  // === Test 10: Non-zero amount rejected ===
  console.log('\n=== Test 10: Non-zero amount rejected ===');
  const badSecret = `cred-bad-${Date.now()}`;
  const badY = hashToCurve(badSecret);
  const badK = secp.utils.randomPrivateKey();
  const badKBig = BigInt('0x' + bytesToHex(badK));
  const badB_ = badY.add(secp.Point.BASE.multiply(badKBig));
  const badIssueResp = await (await fetch(`${CRED}/issue`, {
    method: 'POST', headers: jsonHeaders,
    body: JSON.stringify({ outputs: [{ B_: badB_.toHex(true), amount: 1, id: credKsId }] })
  })).json();
  // Should have an error in the signature response
  const hasError = badIssueResp.signatures?.[0]?.error === 'credential-amount-must-be-zero';
  assert('Non-zero amount rejected', hasError, JSON.stringify(badIssueResp).slice(0, 200));

  // === Test 11: Invalid credential fails verify ===
  console.log('\n=== Test 11: Invalid credential fails verify ===');
  const fakeToken = { C: tokens[3].C, secret: 'wrong-secret', amount: 0, id: credKsId };
  const verify3Resp = await (await fetch(`${CRED}/verify`, {
    method: 'POST', headers: jsonHeaders,
    body: JSON.stringify({ proofs: [fakeToken] })
  })).json();
  assert('Fake token is invalid', verify3Resp.valid[0]?.valid === false);

  // === Test 12: Admin overview shows stats ===
  console.log('\n=== Test 12: Admin credential overview ===');
  const overviewResp = await (await fetch(`${ADMIN}/cred/overview`, { headers: authHeaders })).json();
  assert('Shows credential keysets', overviewResp.cred_keysets >= 1);
  assert('Shows issued count', overviewResp.cred_issued >= numTokens);
  assert('Shows spent count', overviewResp.cred_spent >= 3); // tokens 0, 1, 2 redeemed

  // === Test 13: Deactivate keyset blocks issuance ===
  console.log('\n=== Test 13: Deactivate credential keyset ===');
  await fetch(`${ADMIN}/cred/keysets/deactivate`, {
    method: 'POST', headers: jsonHeaders,
    body: JSON.stringify({ id: credKsId })
  });
  const deactSecret = `cred-deact-${Date.now()}`;
  const deactY = hashToCurve(deactSecret);
  const deactK = secp.utils.randomPrivateKey();
  const deactKBig = BigInt('0x' + bytesToHex(deactK));
  const deactB_ = deactY.add(secp.Point.BASE.multiply(deactKBig));
  const deactIssue = await (await fetch(`${CRED}/issue`, {
    method: 'POST', headers: jsonHeaders,
    body: JSON.stringify({ outputs: [{ B_: deactB_.toHex(true), amount: 0, id: credKsId }] })
  })).json();
  const deactError = deactIssue.signatures?.[0]?.error === 'credential-keyset-inactive';
  assert('Inactive keyset blocks issuance', deactError, JSON.stringify(deactIssue).slice(0, 200));

  // Re-activate for remaining tokens
  await fetch(`${ADMIN}/cred/keysets/activate`, {
    method: 'POST', headers: jsonHeaders,
    body: JSON.stringify({ id: credKsId })
  });

  // === Test 14: Remaining unspent tokens still work ===
  console.log('\n=== Test 14: Remaining tokens still valid ===');
  const verify4Resp = await (await fetch(`${CRED}/verify`, {
    method: 'POST', headers: jsonHeaders,
    body: JSON.stringify({ proofs: [tokens[3], tokens[4]] })
  })).json();
  assert('Token 3 valid & unspent', verify4Resp.valid[0]?.valid && !verify4Resp.valid[0]?.spent);
  assert('Token 4 valid & unspent', verify4Resp.valid[1]?.valid && !verify4Resp.valid[1]?.spent);

  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
  process.exit(failed > 0 ? 1 : 0);
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
