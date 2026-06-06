// E2E tests for bolt11 Lightning integration (NUT-04/05)
// Requires: mock-lnbits.mjs running on port 3338, ecash mint on port 8080
// Setup: configure mint with [%lnbits 'http://localhost:3338' 'test-api-key']
import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

const MINT = 'http://localhost:8080';
const MOCK = 'http://localhost:3338';
const API_KEY = 'test-api-key';

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
  throw new Error('failed');
}

async function mintToken(secret, amount = 1) {
  const kr = await (await fetch(`${MINT}/v1/keys`)).json();
  const ks = kr.keysets[0];
  const mintPub = secp.Point.fromHex(ks.keys[String(amount)]);
  const Y = hashToCurve(secret);
  const k = secp.utils.randomPrivateKey();
  const kBig = BigInt('0x' + bytesToHex(k));
  const B_ = Y.add(secp.Point.BASE.multiply(kBig));

  const qr = await (await fetch(`${MINT}/v1/mint/quote/self`, {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({amount})
  })).json();

  const mr = await (await fetch(`${MINT}/v1/mint/self`, {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({quote: qr.quote, outputs: [{B_: B_.toHex(true), amount}]})
  })).json();

  const C_ = secp.Point.fromHex(mr.signatures[0]['C_']);
  const C = C_.subtract(mintPub.multiply(kBig));
  return { C: C.toHex(true), secret, amount, id: ks.id };
}

async function main() {
  let passed = 0, failed = 0;
  function assert(name, cond, detail) {
    if (cond) { console.log(`  PASS: ${name}`); passed++; }
    else { console.log(`  FAIL: ${name}${detail ? ' — ' + detail : ''}`); failed++; }
  }

  // Pre-check: verify mock LNbits is running
  try {
    await fetch(`${MOCK}/api/v1/internal/invoices`, {headers: {'X-Api-Key': API_KEY}});
  } catch {
    console.error('ERROR: Mock LNbits not running on port 3338. Start it with: node mock-lnbits.mjs');
    process.exit(1);
  }

  // Pre-check: verify mint is running and has bolt11 support
  const info = await (await fetch(`${MINT}/v1/info`)).json();
  const hasBolt11 = info.nuts?.['4']?.methods?.some(m => m.method === 'bolt11') ||
                    info.nuts?.['5']?.methods?.some(m => m.method === 'bolt11');
  if (!hasBolt11) {
    console.error('ERROR: Mint does not advertise bolt11 method.');
    console.error('Configure LN backend first:');
    console.error('  :ecash [%lnbits \'http://localhost:3338\' \'test-api-key\']');
    process.exit(1);
  }
  console.log('Mint has bolt11 support configured.\n');

  // === Test 1: bolt11 mint quote creates invoice ===
  console.log('=== Test 1: Create bolt11 mint quote ===');
  {
    const qr = await (await fetch(`${MINT}/v1/mint/quote/bolt11`, {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({amount: 100})
    })).json();
    assert('Quote returned', !!qr.quote, JSON.stringify(qr));
    assert('Has bolt11 request', qr.request?.startsWith('lnbc'), qr.request);
    assert('State is UNPAID', qr.state === 'UNPAID', qr.state);
    assert('Amount is 100', qr.amount === 100, String(qr.amount));

    // === Test 2: Check unpaid quote ===
    console.log('\n=== Test 2: Check unpaid bolt11 mint quote ===');
    const check1 = await (await fetch(`${MINT}/v1/mint/quote/bolt11/${qr.quote}`)).json();
    assert('Quote still UNPAID', check1.state === 'UNPAID', check1.state);

    // === Test 3: Mark invoice paid via mock, then check ===
    console.log('\n=== Test 3: Mark invoice paid and check ===');
    // Get the checking_id from the internal endpoint
    const invoices = await (await fetch(`${MOCK}/api/v1/internal/invoices`, {
      headers: {'X-Api-Key': API_KEY}
    })).json();
    // Find the invoice for this quote (most recent 100-sat invoice).
    // Use the LAST match: the mock map accumulates invoices across runs, so
    // find() would pick a stale one. Insertion order makes the last the newest.
    const invoiceIds = Object.keys(invoices);
    const targetId = invoiceIds.filter(id => invoices[id].amount === 100).pop();
    assert('Found invoice in mock', !!targetId);

    if (targetId) {
      // Mark as paid
      await fetch(`${MOCK}/api/v1/internal/mark-paid/${targetId}`, {
        method: 'POST', headers: {'X-Api-Key': API_KEY}
      });

      const check2 = await (await fetch(`${MINT}/v1/mint/quote/bolt11/${qr.quote}`)).json();
      assert('Quote now PAID', check2.state === 'PAID', check2.state);

      // === Test 4: Mint tokens from paid bolt11 quote ===
      console.log('\n=== Test 4: Mint tokens from paid bolt11 quote ===');
      const kr = await (await fetch(`${MINT}/v1/keys`)).json();
      const ks = kr.keysets[0];
      const mintPub = secp.Point.fromHex(ks.keys['1']);

      // Create 100 outputs of 1 sat each
      const outputs = [];
      const blindingKeys = [];
      const secrets = [];
      for (let i = 0; i < 100; i++) {
        const secret = `bolt11-mint-test-${Date.now()}-${i}`;
        secrets.push(secret);
        const Y = hashToCurve(secret);
        const k = secp.utils.randomPrivateKey();
        const kBig = BigInt('0x' + bytesToHex(k));
        blindingKeys.push(kBig);
        const B_ = Y.add(secp.Point.BASE.multiply(kBig));
        outputs.push({B_: B_.toHex(true), amount: 1});
      }

      const mr = await (await fetch(`${MINT}/v1/mint/bolt11`, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({quote: qr.quote, outputs})
      })).json();
      assert('Mint returned signatures', !!mr.signatures, JSON.stringify(mr).slice(0, 200));
      assert('Got 100 signatures', mr.signatures?.length === 100);

      // Unblind tokens for later use
      if (mr.signatures) {
        const tokens = mr.signatures.map((sig, i) => {
          const C_ = secp.Point.fromHex(sig['C_']);
          const C = C_.subtract(mintPub.multiply(blindingKeys[i]));
          return { C: C.toHex(true), secret: secrets[i], amount: 1, id: ks.id };
        });

        // === Test 5: Try to mint again from issued quote (should fail) ===
        console.log('\n=== Test 5: Re-mint from issued quote (should fail) ===');
        const mr2 = await (await fetch(`${MINT}/v1/mint/bolt11`, {
          method: 'POST', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({quote: qr.quote, outputs: outputs.slice(0, 1)})
        })).json();
        assert('Re-mint rejected', mr2.detail === 'quote-not-paid', mr2.detail);

        // === Test 6: bolt11 melt quote ===
        console.log('\n=== Test 6: Create bolt11 melt quote ===');
        // Create a fake bolt11 invoice to "pay"
        const meltBolt11 = 'lnbc50n1pfakemelttestinvoice';
        const mqr = await (await fetch(`${MINT}/v1/melt/quote/bolt11`, {
          method: 'POST', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({request: meltBolt11})
        })).json();
        assert('Melt quote returned', !!mqr.quote, JSON.stringify(mqr));
        assert('Melt amount is 50', mqr.amount === 50, String(mqr.amount));
        assert('Has fee_reserve', mqr.fee_reserve > 0, String(mqr.fee_reserve));
        assert('State is UNPAID', mqr.state === 'UNPAID', mqr.state);

        // === Test 7: Execute bolt11 melt (pay invoice) ===
        console.log('\n=== Test 7: Execute bolt11 melt ===');
        // Need enough tokens to cover amount + fee
        const needed = mqr.amount + mqr.fee_reserve;
        const inputTokens = tokens.slice(0, needed);

        const meltr = await (await fetch(`${MINT}/v1/melt/bolt11`, {
          method: 'POST', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({quote: mqr.quote, inputs: inputTokens})
        })).json();
        assert('Melt succeeded', meltr.state === 'PAID', meltr.state);
        assert('Has preimage', !!meltr.payment_preimage, meltr.payment_preimage);

        // === Test 8: Check melt quote shows PAID ===
        console.log('\n=== Test 8: Check melt quote status ===');
        const mcheck = await (await fetch(`${MINT}/v1/melt/quote/bolt11/${mqr.quote}`)).json();
        assert('Melt quote is PAID', mcheck.state === 'PAID', mcheck.state);

        // === Test 9: Tokens used in melt are now spent ===
        console.log('\n=== Test 9: Melted tokens are spent ===');
        const spentYs = inputTokens.map(t => hashToCurve(t.secret).toHex(true));
        const csr = await (await fetch(`${MINT}/v1/checkstate`, {
          method: 'POST', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({Ys: spentYs.slice(0, 3)})
        })).json();
        const allSpent = csr.states?.every(s => s.state === 'SPENT');
        assert('Melted tokens marked SPENT', allSpent, JSON.stringify(csr.states));
      }
    }
  }

  // === Test 10: bolt11 without LN config returns error ===
  // (Can't easily test this without resetting config, skip if backend is set)
  console.log('\n=== Test 10: Self method still works alongside bolt11 ===');
  {
    const token = await mintToken('self-alongside-bolt11-' + Date.now());
    const kr = await (await fetch(`${MINT}/v1/keys`)).json();
    const ks = kr.keysets[0];
    const secret2 = 'self-output-' + Date.now();
    const Y2 = hashToCurve(secret2);
    const k2 = secp.utils.randomPrivateKey();
    const k2Big = BigInt('0x' + bytesToHex(k2));
    const B2_ = Y2.add(secp.Point.BASE.multiply(k2Big));
    const sr = await (await fetch(`${MINT}/v1/swap`, {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        inputs: [token],
        outputs: [{B_: B2_.toHex(true), amount: 1}]
      })
    })).json();
    assert('Self method swap still works', !!sr.signatures, JSON.stringify(sr));
  }

  // === Test 11: Melt with insufficient inputs fails ===
  console.log('\n=== Test 11: Melt with insufficient inputs ===');
  {
    const meltBolt11 = 'lnbc200n1pfakebigmelttestinvoice';
    const mqr = await (await fetch(`${MINT}/v1/melt/quote/bolt11`, {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({request: meltBolt11})
    })).json();
    assert('Melt quote for 200 sats created', mqr.amount === 200, String(mqr.amount));

    // Only provide 1 sat input
    const token = await mintToken('insufficient-melt-' + Date.now());
    const meltr = await (await fetch(`${MINT}/v1/melt/bolt11`, {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({quote: mqr.quote, inputs: [token]})
    })).json();
    assert('Insufficient inputs rejected', meltr.detail === 'insufficient-inputs', meltr.detail);
  }

  // === Test 12: Missing bolt11 in melt quote ===
  console.log('\n=== Test 12: Melt quote without bolt11 ===');
  {
    const mqr = await (await fetch(`${MINT}/v1/melt/quote/bolt11`, {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({})
    })).json();
    assert('Missing bolt11 rejected', mqr.detail === 'missing-request-bolt11', mqr.detail);
  }

  // === Test 13: NUT-08 bolt11 melt with change outputs ===
  console.log('\n=== Test 13: NUT-08 bolt11 melt with change ===');
  {
    // Mint enough tokens for melt + fee
    const meltBolt11 = 'lnbc50n1pfakenut08testinvoice';
    const mqr = await (await fetch(`${MINT}/v1/melt/quote/bolt11`, {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({request: meltBolt11})
    })).json();
    assert('NUT-08 melt quote created', !!mqr.quote, JSON.stringify(mqr));
    const needed = mqr.amount + mqr.fee_reserve;

    // Mint individual tokens
    const tokens = [];
    for (let i = 0; i < needed; i++) {
      tokens.push(await mintToken('nut08-bolt11-' + Date.now() + '-' + i));
    }

    // Prepare blank change outputs (enough for fee_reserve decomposition)
    const changeOutputs = [];
    const changeKs = [];
    const kr = await (await fetch(`${MINT}/v1/keys`)).json();
    const ks = kr.keysets[0];
    for (let i = 0; i < 10; i++) {
      const cs = 'bolt11-change-' + Date.now() + '-' + i;
      const cY = hashToCurve(cs);
      const ck = secp.utils.randomPrivateKey();
      const ckBig = BigInt('0x' + bytesToHex(ck));
      const cB_ = cY.add(secp.Point.BASE.multiply(ckBig));
      changeKs.push(ckBig);
      changeOutputs.push({B_: cB_.toHex(true), amount: 0});
    }

    // Execute melt with change outputs
    const meltr = await (await fetch(`${MINT}/v1/melt/bolt11`, {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({quote: mqr.quote, inputs: tokens, outputs: changeOutputs})
    })).json();
    assert('NUT-08 melt succeeded', meltr.state === 'PAID', meltr.state);
    assert('NUT-08 change array present', Array.isArray(meltr.change), JSON.stringify(meltr.change));

    if (meltr.change && meltr.change.length > 0) {
      const changeSum = meltr.change.reduce((s, c) => s + c.amount, 0);
      // NUT-08 refund = fee_reserve − actual routing fee. The mock charges
      // 2000 msat (= 2 sat), so the change is fee_reserve − 2, not the full
      // reserve. (test-melt-fee asserts this same corrected value.)
      const MOCK_FEE_SAT = 2;
      assert('NUT-08 change = fee_reserve − mock fee', changeSum === mqr.fee_reserve - MOCK_FEE_SAT,
        `got ${changeSum}, expected ${mqr.fee_reserve - MOCK_FEE_SAT}`);

      // Verify we can unblind a change token
      const cSig = meltr.change[0];
      const cAmt = cSig.amount;
      const cPub = secp.Point.fromHex(ks.keys[String(cAmt)]);
      const cC_ = secp.Point.fromHex(cSig['C_']);
      const cC = cC_.subtract(cPub.multiply(changeKs[0]));
      assert('NUT-08 change token unblindable', !!cC.toHex(true), cC.toHex(true));

      // Check that melt-quote-check also returns change
      const mcheck = await (await fetch(`${MINT}/v1/melt/quote/bolt11/${mqr.quote}`)).json();
      assert('NUT-08 check returns change', Array.isArray(mcheck.change) && mcheck.change.length > 0,
        `change length: ${mcheck.change?.length}`);
    }
  }

  // === Test 14: NUT-08 bolt11 melt without outputs (backwards compat) ===
  console.log('\n=== Test 14: NUT-08 melt without outputs ===');
  {
    const meltBolt11 = 'lnbc50n1pfakenochangetestinvoice';
    const mqr = await (await fetch(`${MINT}/v1/melt/quote/bolt11`, {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({request: meltBolt11})
    })).json();
    const needed = mqr.amount + mqr.fee_reserve;
    const tokens = [];
    for (let i = 0; i < needed; i++) {
      tokens.push(await mintToken('nochange-bolt11-' + Date.now() + '-' + i));
    }

    const meltr = await (await fetch(`${MINT}/v1/melt/bolt11`, {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({quote: mqr.quote, inputs: tokens})
    })).json();
    assert('No-outputs melt succeeded', meltr.state === 'PAID', meltr.state);
    assert('No-outputs change is empty', Array.isArray(meltr.change) && meltr.change.length === 0,
      `change: ${JSON.stringify(meltr.change)}`);
  }

  // === Test 15: NUT-08 in NUT-06 info ===
  console.log('\n=== Test 15: NUT-08 advertised in info ===');
  {
    const info = await (await fetch(`${MINT}/v1/info`)).json();
    assert('NUT-08 in info', info.nuts?.['8']?.supported === true,
      JSON.stringify(info.nuts?.['8']));
  }

  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
  process.exit(failed > 0 ? 1 : 0);
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
