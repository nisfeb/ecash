/**
 * test-conformance.mjs
 *
 * Cashu wallet-conformance harness for the Urbit ecash mint.
 * Drives @cashu/cashu-ts 4.5.1 against the live mint at localhost:8080
 * and reports PASS/FAIL for each stage with conformance-gap analysis.
 *
 * Usage: node test-conformance.mjs
 * Prerequisite: node mock-lnbits.mjs must be running (or harness will start it).
 */

import { spawn, execSync } from 'node:child_process';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { sha256 } from '@noble/hashes/sha256';
import {
  Wallet,
  Mint,
  deriveKeysetId,
  blindMessage,
  hasValidDleq,
  getEncodedToken,
  hash_e,
} from '@cashu/cashu-ts';

// ─── Config ─────────────────────────────────────────────────────────────────

const MINT     = 'http://localhost:8080';
const MOCK     = 'http://localhost:3338';
const API_KEY  = 'test-api-key';
const COOKIE   = process.env.URBAUTH_COOKIE || '';  // ship admin session cookie

// ─── Helpers ─────────────────────────────────────────────────────────────────

let mockProc = null;

async function ensureMockLnbits() {
  try {
    const r = await fetch(`${MOCK}/api/v1/internal/invoices`, {
      headers: { 'X-Api-Key': API_KEY },
    });
    if (r.ok) return; // already up
  } catch { /* not up */ }

  console.log('[setup] Starting mock-lnbits.mjs ...');
  mockProc = spawn('node', ['mock-lnbits.mjs'], {
    cwd: process.cwd(),
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: false,
  });
  mockProc.stdout.on('data', () => {});
  mockProc.stderr.on('data', () => {});

  // Wait up to 3 s for it to listen
  for (let i = 0; i < 15; i++) {
    await sleep(200);
    try {
      const r = await fetch(`${MOCK}/api/v1/internal/invoices`, {
        headers: { 'X-Api-Key': API_KEY },
      });
      if (r.ok) { console.log('[setup] mock-lnbits ready.'); return; }
    } catch { /* still starting */ }
  }
  throw new Error('mock-lnbits did not start within 3 s');
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function adminFetch(path, opts = {}) {
  const headers = { ...(opts.headers || {}), Cookie: COOKIE };
  return fetch(`${MINT}${path}`, { ...opts, headers });
}

async function configureLnbits() {
  const r = await adminFetch('/apps/ecash/admin/api/lightning/configure', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'lnbits', url: MOCK, api_key: API_KEY }),
  });
  const body = await r.json();
  if (!body.configured) throw new Error('Failed to configure LNbits: ' + JSON.stringify(body));
}

async function resetLnbackend() {
  await adminFetch('/apps/ecash/admin/api/lightning/configure', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'none' }),
  });
}

/** Pay a mint quote via the admin quote list + mock mark-paid. */
async function simulateMintPayment(quoteId) {
  // Step 1: find checking_id in admin quotes
  const r = await adminFetch('/apps/ecash/admin/api/quotes');
  const data = await r.json();
  const q = (data.mint_quotes || []).find(q => q.quote_id === quoteId);
  if (!q) throw new Error(`Quote ${quoteId} not found in admin list`);
  const checkingId = q.checking_id;
  if (!checkingId) throw new Error(`Quote ${quoteId} has no checking_id`);

  // Step 2: mark paid in mock
  const markR = await fetch(`${MOCK}/api/v1/internal/mark-paid/${checkingId}`, {
    method: 'POST', headers: { 'X-Api-Key': API_KEY },
  });
  if (!markR.ok) throw new Error(`mark-paid failed: ${await markR.text()}`);

  // Step 3: poll once so the mint flips state
  await fetch(`${MINT}/v1/mint/quote/bolt11/${quoteId}`);
}

/** Create a real bolt11 invoice via the mock and return it. */
async function createMockInvoice(amountSats) {
  const r = await fetch(`${MOCK}/api/v1/payments`, {
    method: 'POST',
    headers: { 'X-Api-Key': API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ out: false, amount: amountSats, memo: 'conformance-melt' }),
  });
  const data = await r.json();
  if (!data.payment_request) throw new Error('No payment_request: ' + JSON.stringify(data));
  return data.payment_request;
}

/** Manually unblind a signature (bypasses cashu-ts's DLEQ check). */
function manualUnblind(C_hex, r_bigint, mintPubHex) {
  const C_ = secp256k1.Point.fromHex(C_hex);
  const K  = secp256k1.Point.fromHex(mintPubHex);
  return C_.subtract(K.multiply(r_bigint)).toHex(true);
}

/** Manually mint proofs bypassing cashu-ts DLEQ verification. */
async function manualMintProofs(amount) {
  const keysResp = await fetch(`${MINT}/v1/keys`).then(r => r.json());
  const ks = keysResp.keysets[0];

  // Compute denomination decomposition (powers of 2)
  const denoms = [];
  let remaining = amount;
  for (let bit = 29; bit >= 0; bit--) {
    const v = 1 << bit;
    while (remaining >= v) { denoms.push(v); remaining -= v; }
  }

  // Build blinded outputs
  const outputs = [];
  const blindingData = [];
  for (const d of denoms) {
    const secret = `conf-test-${Date.now()}-${d}-${Math.random().toString(36).slice(2)}`;
    const { B_, r } = await blindMessage(new TextEncoder().encode(secret));
    outputs.push({ amount: d, id: ks.id, B_: B_.toHex(true) });
    blindingData.push({ secret, r, amount: d });
  }

  // Create + pay quote
  const qResp = await fetch(`${MINT}/v1/mint/quote/bolt11`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ amount, unit: 'sat' }),
  }).then(r => r.json());

  await simulateMintPayment(qResp.quote);

  const mintResp = await fetch(`${MINT}/v1/mint/bolt11`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ quote: qResp.quote, outputs }),
  }).then(r => r.json());

  if (!mintResp.signatures) throw new Error('No signatures: ' + JSON.stringify(mintResp));

  return mintResp.signatures.map((sig, i) => ({
    amount: sig.amount,
    id: ks.id,
    secret: blindingData[i].secret,
    C: manualUnblind(sig.C_, blindingData[i].r, ks.keys[String(sig.amount)]),
  }));
}

// ─── DLEQ manual verification (Hoon convention) ──────────────────────────────

/**
 * Verify DLEQ proof from the Urbit mint.
 * The mint uses: e = SHA256(compressed R1 || compressed R2 || compressed K || compressed C_)
 * where K is the mint public key for the denomination, and the sign convention is
 * s = r - a*e (so verify reconstructs R1 = G*s + K*e, R2 = B_*s + C_*e).
 * This is NONCONFORMING with NUT-12 which uses uncompressed points and B_ instead of K.
 */
function verifyDleqHoonStyle(dleq, B_hex, C_hex, mintPubHex) {
  const s = BigInt('0x' + dleq.s);
  const e = BigInt('0x' + dleq.e);
  const K  = secp256k1.Point.fromHex(mintPubHex);
  const B  = secp256k1.Point.fromHex(B_hex);
  const C  = secp256k1.Point.fromHex(C_hex);
  const G  = secp256k1.Point.BASE;

  // Mint sign convention: s = r - a*e → verify with R1 = G*s + K*e
  const R1 = G.multiply(s).add(K.multiply(e));
  const R2 = B.multiply(s).add(C.multiply(e));

  // Mint hashes compressed points in order R1, R2, K, C_
  const bufs = [R1, R2, K, C].map(p => hexToBytes(p.toHex(true)));
  const total = bufs.reduce((a, b) => a + b.length, 0);
  const buf = new Uint8Array(total);
  let off = 0;
  for (const b of bufs) { buf.set(b, off); off += b.length; }
  const computed = bytesToHex(sha256(buf));
  return computed === dleq.e;
}

// ─── Results tracking ─────────────────────────────────────────────────────────

const results = [];
function pass(stage, note) {
  console.log(`PASS  [${stage}]${note ? '  ' + note : ''}`);
  results.push({ stage, pass: true });
}
function fail(stage, err, mintJson, hypothesis) {
  console.log(`FAIL  [${stage}]`);
  if (err) console.log(`  Error: ${err.constructor?.name} — ${err.message}`);
  if (mintJson) console.log(`  Mint JSON: ${JSON.stringify(mintJson)}`);
  console.log(`  Gap hypothesis: ${hypothesis}`);
  results.push({ stage, pass: false });
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  console.log('=== Cashu Conformance Harness ===\n');

  // ── Setup ──────────────────────────────────────────────────────────────────
  await ensureMockLnbits();
  await configureLnbits();
  console.log('[setup] LNbits backend configured.\n');

  // ── Stage 1: loadMint ──────────────────────────────────────────────────────
  console.log('--- Stage 1: loadMint ---');
  let wallet, activeKeyset;
  try {
    const mint = new Mint(MINT);
    wallet = new Wallet(mint, { unit: 'sat' });
    await wallet.loadMint();

    if (!wallet.keysetId) throw new Error('keysetId is not set after loadMint');

    // Get active keyset from /v1/keys
    const keysResp = await fetch(`${MINT}/v1/keys`).then(r => r.json());
    activeKeyset = keysResp.keysets?.find(k => k.id === wallet.keysetId);
    if (!activeKeyset) throw new Error('Active keyset not found in /v1/keys');

    const derived = deriveKeysetId(activeKeyset.keys);
    if (derived !== wallet.keysetId) {
      throw new Error(`deriveKeysetId mismatch: derived=${derived} reported=${wallet.keysetId}`);
    }

    pass('1-loadMint', `keysetId=${wallet.keysetId.slice(0, 20)}... deriveKeysetId matches`);
  } catch (e) {
    fail('1-loadMint', e, null, 'loadMint or keysetId derivation failed');
    console.log('\nABORTING: cannot continue without loadMint');
    await cleanup(); return;
  }

  // ── Stage 2: Mint via bolt11 ───────────────────────────────────────────────
  console.log('\n--- Stage 2: Mint (bolt11) ---');
  let mintedProofs = null;
  let mintRawSigs = null;
  let mintRawB_ = null;
  try {
    const quote = await wallet.createMintQuote('bolt11', { amount: 16 });
    if (!quote.quote) throw new Error('No quote id returned');

    await simulateMintPayment(quote.quote);

    // Hook fetch to capture raw mint/bolt11 response before cashu-ts processes it
    const origFetch = globalThis.fetch;
    let capturedSigs = null;
    let capturedB_ = null;
    globalThis.fetch = async (url, opts) => {
      const resp = await origFetch(url, opts);
      if (typeof url === 'string' && url.includes('/v1/mint/bolt11') && opts?.method === 'POST') {
        const body = await resp.json();
        capturedSigs = body.signatures;
        // Also capture the B_ values from the request
        try {
          const reqBody = JSON.parse(opts.body);
          capturedB_ = reqBody.outputs?.map(o => o.B_) || [];
        } catch { /* ignore */ }
        return new Response(JSON.stringify(body), {
          status: resp.status,
          headers: { 'content-type': 'application/json' },
        });
      }
      return resp;
    };

    let proofs = null;
    let mintErr = null;
    try {
      proofs = await wallet.mintProofs('bolt11', 16, quote);
    } catch (e) {
      mintErr = e;
      mintRawSigs = capturedSigs;
      mintRawB_ = capturedB_;
    } finally {
      globalThis.fetch = origFetch;
    }

    if (proofs) {
      mintedProofs = proofs;
      pass('2-mint', `Got ${proofs.length} proofs totaling ${proofs.reduce((s, p) => s + p.amount, 0)} sat`);
    } else {
      fail('2-mint', mintErr, mintRawSigs?.slice(0, 2),
        'mintProofs throws: DLEQ verification failed — see Stage 3 for root cause');
      // Mint proofs manually to allow downstream stages to run
      mintedProofs = await manualMintProofs(16);
      console.log(`  [fallback] Manually minted ${mintedProofs.length} proofs for downstream stages`);
    }
  } catch (e) {
    fail('2-mint', e, null, 'mint quote or payment simulation failed');
  }

  // ── Stage 3: DLEQ ──────────────────────────────────────────────────────────
  console.log('\n--- Stage 3: DLEQ ---');
  try {
    if (!activeKeyset) throw new Error('No active keyset (loadMint failed)');

    // Get a fresh raw signature to inspect
    const secret3 = `dleq-test-${Date.now()}`;
    const { B_, r } = await blindMessage(new TextEncoder().encode(secret3));

    const q3 = await fetch(`${MINT}/v1/mint/quote/bolt11`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ amount: 8, unit: 'sat' }),
    }).then(r => r.json());
    await simulateMintPayment(q3.quote);

    const mintR3 = await fetch(`${MINT}/v1/mint/bolt11`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        quote: q3.quote,
        outputs: [{ amount: 8, id: activeKeyset.id, B_: B_.toHex(true) }],
      }),
    }).then(r => r.json());

    const sig3 = mintR3.signatures?.[0];
    if (!sig3) throw new Error('No signatures in raw mint response');
    if (!sig3.dleq) throw new Error('Missing dleq field in signature');

    const mintPubFor8 = activeKeyset.keys['8'];

    // Test 3a: cashu-ts hasValidDleq (NUT-12 conformant)
    // Unblind the proof manually first
    const C3 = manualUnblind(sig3.C_, r, mintPubFor8);
    const proof3 = { amount: 8, id: activeKeyset.id, secret: secret3, C: C3, dleq: { e: sig3.dleq.e, s: sig3.dleq.s, r: r.toString(16).padStart(64, '0') } };
    const keyset3 = { id: activeKeyset.id, keys: activeKeyset.keys };

    let nut12Valid = false;
    try {
      nut12Valid = hasValidDleq(proof3, keyset3);
    } catch (e) {
      // expected to fail
    }

    // Test 3b: Hoon-style verify (what the mint actually produces)
    const hoonValid = verifyDleqHoonStyle(sig3.dleq, B_.toHex(true), sig3.C_, mintPubFor8);

    if (nut12Valid) {
      pass('3-dleq', 'hasValidDleq returns true — mint is NUT-12 conformant');
    } else {
      // Determine the specific divergence
      const sScalar = BigInt('0x' + sig3.dleq.s);
      const eScalar = BigInt('0x' + sig3.dleq.e);
      const K  = secp256k1.Point.fromHex(mintPubFor8);
      const B  = secp256k1.Point.fromHex(B_.toHex(true));
      const C  = secp256k1.Point.fromHex(sig3.C_);
      const G  = secp256k1.Point.BASE;

      // NUT-12 standard: R1=G*s-K*e, R2=B*s-C*e, e=hash_e(R1,R2,K,C) uncompressed
      const R1_std = G.multiply(sScalar).subtract(K.multiply(eScalar));
      const R2_std = B.multiply(sScalar).subtract(C.multiply(eScalar));
      const e_std = bytesToHex(hash_e([R1_std, R2_std, K, C]));
      const stdValid = e_std === sig3.dleq.e;

      fail('3-dleq', new Error('hasValidDleq returns false'),
        { dleq: sig3.dleq, C_: sig3.C_ },
        `Mint DLEQ nonconforming with NUT-12: (1) sign convention — Hoon uses s=r-a*e so ` +
        `verify must use R1=G*s+K*e, but NUT-12/cashu-ts expect s=r+a*e (R1=G*s-K*e); ` +
        `(2) point encoding — Hoon hashes SHA256(compressed 33-byte R1||R2||K||C_) while ` +
        `cashu-ts hash_e uses uncompressed 65-byte points. ` +
        `Hoon-style verify=${hoonValid}, NUT-12-style verify=${stdValid}.`);
    }
  } catch (e) {
    fail('3-dleq', e, null, 'DLEQ test setup failed');
  }

  // ── Stage 4: Send/Swap ─────────────────────────────────────────────────────
  console.log('\n--- Stage 4: Send/Swap ---');
  let sendProofs = null;
  try {
    if (!mintedProofs) throw new Error('No proofs to send (Stage 2 failed)');

    const sendResult = await wallet.send(8, mintedProofs);
    if (!sendResult.send || sendResult.send.length === 0) {
      throw new Error('send returned no send proofs');
    }
    sendProofs = sendResult.send;
    pass('4-send', `send returned ${sendResult.send.length} send + ${sendResult.keep?.length || 0} keep proofs`);
  } catch (e) {
    fail('4-send', e,
      e.message?.includes('DLEQ') ? { note: 'cashu-ts rejects swap signatures due to DLEQ' } : null,
      e.message?.includes('DLEQ')
        ? 'swap (POST /v1/swap) returns signatures with same DLEQ bug as mint — cashu-ts rejects them'
        : 'wallet.send failed for unexpected reason');
    // Make send proofs manually for Stage 5
    if (mintedProofs) {
      const keysResp = await fetch(`${MINT}/v1/keys`).then(r => r.json());
      const ks = keysResp.keysets[0];
      // Create manual swap to get send proofs
      const swapOut1 = { secret: `send-s1-${Date.now()}`, r: null, amount: 8 };
      const swapOut2 = { secret: `send-s2-${Date.now()}`, r: null, amount: 8 };
      const out1blinded = await blindMessage(new TextEncoder().encode(swapOut1.secret));
      const out2blinded = await blindMessage(new TextEncoder().encode(swapOut2.secret));
      swapOut1.r = out1blinded.r;
      swapOut2.r = out2blinded.r;

      const swapResp = await fetch(`${MINT}/v1/swap`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          inputs: mintedProofs,
          outputs: [
            { amount: 8, id: ks.id, B_: out1blinded.B_.toHex(true) },
            { amount: 8, id: ks.id, B_: out2blinded.B_.toHex(true) },
          ],
        }),
      }).then(r => r.json());

      if (swapResp.signatures?.length >= 1) {
        sendProofs = swapResp.signatures.slice(0, 1).map((sig, i) => ({
          amount: sig.amount,
          id: ks.id,
          secret: [swapOut1, swapOut2][i].secret,
          C: manualUnblind(sig.C_, [swapOut1, swapOut2][i].r, ks.keys[String(sig.amount)]),
        }));
        console.log(`  [fallback] Manual swap got ${sendProofs.length} proofs for Stage 5`);
      }
    }
  }

  // ── Stage 5: Receive ───────────────────────────────────────────────────────
  // wallet.receive(token) calls /v1/swap internally — independently test this
  // using a manually-minted token so this stage is not a cascade of Stage 4.
  console.log('\n--- Stage 5: Receive ---');
  try {
    // Build a valid token from manually-minted proofs (bypassing DLEQ on mint)
    const rcvProofs = await manualMintProofs(8);
    const token = getEncodedToken({ mint: MINT, proofs: rcvProofs });
    const receivedProofs = await wallet.receive(token);
    if (!receivedProofs || receivedProofs.length === 0) {
      throw new Error('receive returned no proofs');
    }
    pass('5-receive', `received ${receivedProofs.length} proofs from token`);
  } catch (e) {
    const mintJson = e.message?.includes('DLEQ')
      ? { note: 'receive calls /v1/swap which returns DLEQ-nonconforming signatures' } : null;
    fail('5-receive', e, mintJson,
      e.message?.includes('DLEQ')
        ? 'wallet.receive calls /v1/swap internally — cashu-ts rejects the swap response ' +
          'signatures for the same DLEQ reason as Stage 3 (independent failure, not cascade from Stage 4)'
        : `wallet.receive failed: ${e.message}`);
  }

  // ── Stage 6: Melt via bolt11 ───────────────────────────────────────────────
  console.log('\n--- Stage 6: Melt (bolt11) ---');
  try {
    // Create fresh proofs for melt. The mint requires inputs >= amount +
    // fee_reserve; with a 10-sat invoice and fee_reserve_min=10 that is 20.
    const invoice = await createMockInvoice(10);
    const meltAmount = 20;
    const meltProofsForSend = await manualMintProofs(meltAmount);

    // Test createMeltQuote via cashu-ts
    let meltQuoteRaw = null;
    let meltQuoteErr = null;
    try {
      const mq = await wallet.createMeltQuote('bolt11', { request: invoice });
      // Unlikely to get here given the 'request' field bug, but handle it
      meltQuoteRaw = mq;
    } catch (e) {
      meltQuoteErr = e;
    }

    if (!meltQuoteErr && meltQuoteRaw) {
      // Melt via cashu-ts
      try {
        const meltResult = await wallet.meltProofs('bolt11', meltQuoteRaw, meltProofsForSend);
        pass('6-melt', `melt paid=${meltResult.quote?.state === 'PAID'} preimage=${!!meltResult.quote?.payment_preimage}`);
      } catch (e2) {
        // Get raw melt quote from mint for reporting
        const rawMQ = await fetch(`${MINT}/v1/melt/quote/bolt11`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ request: invoice }),
        }).then(r => r.json());
        fail('6-melt', e2, rawMQ,
          'meltProofs failed — likely DLEQ in change signatures or other protocol error');
      }
    } else {
      // createMeltQuote failed — get raw quote from mint for reporting
      const rawMQ = await fetch(`${MINT}/v1/melt/quote/bolt11`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ request: invoice }),
      }).then(r => r.json());

      fail('6-melt', meltQuoteErr, rawMQ,
        `createMeltQuote fails validation: mint /v1/melt/quote/bolt11 response ` +
        `is missing the required "request" field (the bolt11 string) — cashu-ts ` +
        `normalizeMeltBoltFields asserts typeof e.request === "string" but the ` +
        `mint omits this field from its response (only returns state, quote, fee_reserve, amount, expiry, unit)`);
    }
  } catch (e) {
    fail('6-melt', e, null, `melt stage setup failed: ${e.message}`);
  }

  // ── Summary ─────────────────────────────────────────────────────────────────
  console.log('\n═══════════════════════════════════════');
  console.log('CONFORMANCE SUMMARY');
  console.log('═══════════════════════════════════════');
  for (const r of results) {
    console.log(`  ${r.pass ? 'PASS' : 'FAIL'}  ${r.stage}`);
  }
  const nPass = results.filter(r => r.pass).length;
  const nFail = results.filter(r => !r.pass).length;
  console.log(`\n  Total: ${nPass} PASS, ${nFail} FAIL`);
  console.log('═══════════════════════════════════════\n');

  // ── Cleanup ─────────────────────────────────────────────────────────────────
  await cleanup();
  process.exit(nFail > 0 ? 1 : 0);
}

async function cleanup() {
  try {
    await resetLnbackend();
    console.log('[cleanup] LN backend reset to none.');
  } catch (e) {
    console.warn('[cleanup] Failed to reset LN backend:', e.message);
  }
  if (mockProc) {
    mockProc.kill();
    mockProc = null;
    console.log('[cleanup] mock-lnbits stopped.');
  }
}

main().catch(async (e) => {
  console.error('Fatal error:', e);
  await cleanup();
  process.exit(1);
});
