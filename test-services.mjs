// E2E tests for the /services/v1 layer (non-value-bearing access tokens)
import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

const MINT = process.env.SHIP_URL || 'http://localhost:8080';
const COOKIE = process.env.URBAUTH_COOKIE || '';
const authHeaders = { 'Cookie': COOKIE };
const jsonHeaders = { ...authHeaders, 'Content-Type': 'application/json' };

const ADMIN = `${MINT}/apps/ecash-services/admin/api/services`;
const SVCS = `${MINT}/services/v1`;

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
    try { return secp.Point.fromHex("02" + bytesToHex(h)); } catch(e) { continue; }
  }
  throw new Error('hashToCurve failed');
}

let passed = 0, failed = 0;
function assert(name, cond, detail) {
  if (cond) { console.log(`  PASS: ${name}`); passed++; }
  else { console.log(`  FAIL: ${name}${detail ? ' — ' + detail : ''}`); failed++; }
}

async function main() {
  const suffix = Date.now();
  const serviceName = `test-${suffix}`;

  // === Test 1: Create service ===
  console.log(`=== Test 1: Create service "${serviceName}" ===`);
  const createResp = await (await fetch(`${ADMIN}/create`, {
    method: 'POST', headers: jsonHeaders,
    body: JSON.stringify({
      name: serviceName,
      title: 'Test Service',
      description: 'E2E test for services layer',
    }),
  })).json();
  assert('Create returned service', !!createResp.name, JSON.stringify(createResp));
  assert('Service active', createResp.active === true);
  assert('Keyset id present', typeof createResp.ks_id === 'string');
  assert('Keyset id starts with c0', createResp.ks_id.startsWith('c0'));
  const ksId = createResp.ks_id;

  // === Test 2: Public list includes new service ===
  console.log('\n=== Test 2: Public list ===');
  const listResp = await (await fetch(`${SVCS}/list`)).json();
  const found = listResp.services.find(s => s.name === serviceName);
  assert('Service appears in public list', !!found);

  // === Test 3: Get service detail ===
  console.log('\n=== Test 3: Get service detail ===');
  const detail = await (await fetch(`${SVCS}/${serviceName}`)).json();
  assert('Detail has matching name', detail.name === serviceName);
  assert('Detail has matching kind', detail.kind === 'single-use');

  // === Test 4: Fetch credential keyset to get the service's pubkey ===
  console.log('\n=== Test 4: Fetch cred keyset for service ===');
  const credKeys = await (await fetch(`${MINT}/cred/v1/keys/${ksId}`)).json();
  const pubHex = credKeys.keysets[0]?.keys['0'];
  assert('Got pub hex', !!pubHex);
  const servicePub = secp.Point.fromHex(pubHex);

  // === Test 5: Issue service tokens ===
  console.log('\n=== Test 5: Issue 3 tokens ===');
  const numTokens = 3;
  const secrets = [];
  const blindKeys = [];
  const outputs = [];
  for (let i = 0; i < numTokens; i++) {
    const secret = `${serviceName}-tok-${i}`;
    secrets.push(secret);
    const Y = hashToCurve(secret);
    const k = secp.utils.randomPrivateKey();
    const kBig = BigInt('0x' + bytesToHex(k));
    blindKeys.push(kBig);
    const B_ = Y.add(secp.Point.BASE.multiply(kBig));
    outputs.push({ B_: B_.toHex(true), amount: 0, id: ksId });
  }
  const issueResp = await (await fetch(`${SVCS}/${serviceName}/issue`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ outputs }),
  })).json();
  assert('Issue returned signatures', Array.isArray(issueResp.signatures), JSON.stringify(issueResp).slice(0,200));
  assert('Got correct count', issueResp.signatures?.length === numTokens);

  // Unblind
  const tokens = issueResp.signatures.map((sig, i) => {
    const C_ = secp.Point.fromHex(sig['C_']);
    const C = C_.subtract(servicePub.multiply(blindKeys[i]));
    return { C: C.toHex(true), secret: secrets[i], amount: 0, id: ksId };
  });

  // === Test 6: Verify tokens ===
  console.log('\n=== Test 6: Verify unspent tokens ===');
  const verifyResp = await (await fetch(`${SVCS}/${serviceName}/verify`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ proofs: tokens }),
  })).json();
  assert('All valid', verifyResp.results.every(r => r.valid === true));
  assert('None spent yet', verifyResp.results.every(r => r.spent === false));

  // === Test 7: Redeem one token (fresh) ===
  console.log('\n=== Test 7: Redeem first token (fresh) ===');
  const redeemResp = await (await fetch(`${SVCS}/${serviceName}/redeem`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ proofs: [tokens[0]] }),
  })).json();
  assert('Redeem succeeded', Array.isArray(redeemResp.redeemed));
  assert('First redemption status=fresh', redeemResp.redeemed[0]?.status === 'fresh', JSON.stringify(redeemResp));

  // === Test 8: Double-redeem is idempotent (replay) ===
  console.log('\n=== Test 8: Double-redeem is idempotent (replay) ===');
  const doubleResp = await (await fetch(`${SVCS}/${serviceName}/redeem`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ proofs: [tokens[0]] }),
  })).json();
  assert('Replay returned 200', Array.isArray(doubleResp.redeemed), JSON.stringify(doubleResp));
  assert('Replay status=replay', doubleResp.redeemed[0]?.status === 'replay', JSON.stringify(doubleResp));

  // === Test 9: Cross-service isolation ===
  console.log('\n=== Test 9: Cross-service isolation ===');
  const otherName = `${serviceName}-other`;
  await fetch(`${ADMIN}/create`, {
    method: 'POST', headers: jsonHeaders,
    body: JSON.stringify({ name: otherName, title: 'Other', description: 'x' }),
  });
  // Try to redeem our chat token against the other service — should fail.
  const crossResp = await (await fetch(`${SVCS}/${otherName}/redeem`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ proofs: [tokens[1]] }),
  })).json();
  assert('Cross-service token rejected', crossResp.detail === 'invalid-service-token', JSON.stringify(crossResp));

  // === Test 10: Deactivate blocks issue ===
  console.log('\n=== Test 10: Deactivate blocks issue ===');
  await fetch(`${ADMIN}/deactivate`, {
    method: 'POST', headers: jsonHeaders,
    body: JSON.stringify({ name: serviceName }),
  });
  const issueDead = await (await fetch(`${SVCS}/${serviceName}/issue`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ outputs: [outputs[0]] }),
  })).json();
  assert('Inactive blocks issue', issueDead.detail === 'service-inactive', JSON.stringify(issueDead));

  // === Test 11: Cannot delete while issued > 0 ===
  console.log('\n=== Test 11: Cannot delete while issued > 0 ===');
  const deleteResp = await (await fetch(`${ADMIN}/delete`, {
    method: 'POST', headers: jsonHeaders,
    body: JSON.stringify({ name: serviceName }),
  })).json();
  assert('Delete blocked', deleteResp.detail === 'service-has-issued-tokens', JSON.stringify(deleteResp));

  // cleanup: delete the otherName service (no issuance)
  await fetch(`${ADMIN}/deactivate`, {
    method: 'POST', headers: jsonHeaders,
    body: JSON.stringify({ name: otherName }),
  });
  const cleanupResp = await (await fetch(`${ADMIN}/delete`, {
    method: 'POST', headers: jsonHeaders,
    body: JSON.stringify({ name: otherName }),
  })).json();
  assert('Delete inactive+unissued service succeeds', cleanupResp.deleted === true);

  // === Test 12: Expiration enforcement ===
  console.log('\n=== Test 12: Expiration blocks issue ===');
  const expName = `exp-${suffix}`;
  const longAgo = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago
  await fetch(`${ADMIN}/create`, {
    method: 'POST', headers: jsonHeaders,
    body: JSON.stringify({ name: expName, title: 'Expired', description: 'x', expires: longAgo }),
  });
  const expIssue = await (await fetch(`${SVCS}/${expName}/issue`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ outputs: [outputs[0]] }),
  })).json();
  assert('Expired service blocks issue', expIssue.detail === 'service-expired', JSON.stringify(expIssue));

  // clean up expired service
  await fetch(`${ADMIN}/deactivate`, {
    method: 'POST', headers: jsonHeaders, body: JSON.stringify({ name: expName }),
  });
  await fetch(`${ADMIN}/delete`, {
    method: 'POST', headers: jsonHeaders, body: JSON.stringify({ name: expName }),
  });

  // === Test 13: Max issuance cap ===
  console.log('\n=== Test 13: Max issuance cap ===');
  const capName = `cap-${suffix}`;
  const capCreate = await (await fetch(`${ADMIN}/create`, {
    method: 'POST', headers: jsonHeaders,
    body: JSON.stringify({ name: capName, title: 'Capped', description: 'x', max_issuance: 2 }),
  })).json();
  const capKs = capCreate.ks_id;
  const capKeys = await (await fetch(`${MINT}/cred/v1/keys/${capKs}`)).json();
  const capPub = secp.Point.fromHex(capKeys.keysets[0].keys['0']);
  const makeCapOutput = (n) => {
    const sec = `${capName}-${n}`;
    const Y = hashToCurve(sec);
    const k = secp.utils.randomPrivateKey();
    const kBig = BigInt('0x' + bytesToHex(k));
    const B_ = Y.add(secp.Point.BASE.multiply(kBig));
    return { B_: B_.toHex(true), amount: 0, id: capKs };
  };
  const capIssue1 = await (await fetch(`${SVCS}/${capName}/issue`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ outputs: [makeCapOutput(0), makeCapOutput(1)] }),
  })).json();
  assert('Issue at cap succeeds', Array.isArray(capIssue1.signatures), JSON.stringify(capIssue1));

  const capIssue2 = await (await fetch(`${SVCS}/${capName}/issue`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ outputs: [makeCapOutput(2)] }),
  })).json();
  assert('Over-cap blocked', capIssue2.detail === 'service-issuance-cap-reached', JSON.stringify(capIssue2));

  // === Test 14: Allowlist gating ===
  console.log('\n=== Test 14: Allowlist gating ===');
  const gateName = `gate-${suffix}`;
  const gateCreate = await (await fetch(`${ADMIN}/create`, {
    method: 'POST', headers: jsonHeaders,
    body: JSON.stringify({ name: gateName, title: 'Gated', description: 'x' }),
  })).json();
  const gateKs = gateCreate.ks_id;
  const gateKeys = await (await fetch(`${MINT}/cred/v1/keys/${gateKs}`)).json();
  const gatePubHex = gateKeys.keysets[0].keys['0'];
  secp.Point.fromHex(gatePubHex);  // sanity-check it parses
  const makeGateOutput = (n) => {
    const sec = `${gateName}-${n}`;
    const Y = hashToCurve(sec);
    const k = secp.utils.randomPrivateKey();
    const kBig = BigInt('0x' + bytesToHex(k));
    const B_ = Y.add(secp.Point.BASE.multiply(kBig));
    return { B_: B_.toHex(true), amount: 0, id: gateKs };
  };

  // 14a: with empty allowlist, issue is public
  const openIssue = await (await fetch(`${SVCS}/${gateName}/issue`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ outputs: [makeGateOutput(0)] }),
  })).json();
  assert('Empty allowlist = public issue', Array.isArray(openIssue.signatures), JSON.stringify(openIssue));

  // 14b: add an access key
  const addResp = await (await fetch(`${ADMIN}/allowlist/add`, {
    method: 'POST', headers: jsonHeaders,
    body: JSON.stringify({ name: gateName, key: 'secret-abc-123' }),
  })).json();
  assert('Allowlist add returns updated service', Array.isArray(addResp.allowlist), JSON.stringify(addResp));
  assert('Key present in allowlist', addResp.allowlist.includes('secret-abc-123'));
  assert('allowlist_required flag set', addResp.allowlist_required === true);

  // 14c: issue without a key now returns 403
  const noKeyIssue = await (await fetch(`${SVCS}/${gateName}/issue`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ outputs: [makeGateOutput(1)] }),
  })).json();
  assert('Missing key → 403', noKeyIssue.detail === 'service-access-denied', JSON.stringify(noKeyIssue));

  // 14d: issue with wrong key → 403
  const wrongKeyIssue = await (await fetch(`${SVCS}/${gateName}/issue`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ access_key: 'wrong-key', outputs: [makeGateOutput(2)] }),
  })).json();
  assert('Wrong key → 403', wrongKeyIssue.detail === 'service-access-denied', JSON.stringify(wrongKeyIssue));

  // 14e: issue with correct key → 200
  const okKeyIssue = await (await fetch(`${SVCS}/${gateName}/issue`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ access_key: 'secret-abc-123', outputs: [makeGateOutput(3)] }),
  })).json();
  assert('Correct key allows issue', Array.isArray(okKeyIssue.signatures), JSON.stringify(okKeyIssue));

  // 14f: remove key → back to public
  await fetch(`${ADMIN}/allowlist/remove`, {
    method: 'POST', headers: jsonHeaders,
    body: JSON.stringify({ name: gateName, key: 'secret-abc-123' }),
  });
  const reopenedIssue = await (await fetch(`${SVCS}/${gateName}/issue`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ outputs: [makeGateOutput(4)] }),
  })).json();
  assert('Empty allowlist reopens public issue', Array.isArray(reopenedIssue.signatures), JSON.stringify(reopenedIssue));

  // 14g: verify the public /services/v1/{name} response does NOT leak keys.
  // Re-add a key first.
  await fetch(`${ADMIN}/allowlist/add`, {
    method: 'POST', headers: jsonHeaders,
    body: JSON.stringify({ name: gateName, key: 'should-not-leak' }),
  });
  const publicDetail = await (await fetch(`${SVCS}/${gateName}`)).json();
  assert('Public detail omits plaintext allowlist', !Array.isArray(publicDetail.allowlist), JSON.stringify(publicDetail));
  assert('Public detail shows allowlist_count', typeof publicDetail.allowlist_count === 'number');
  assert('Public detail shows allowlist_required', publicDetail.allowlist_required === true);

  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
  if (failed > 0) process.exit(1);
}

main().catch(e => { console.error(e); process.exit(1); });
