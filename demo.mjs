#!/usr/bin/env node
// demo.mjs — a narrated walkthrough of the Urbit Cashu mint.
//
// Tells the full ecash story against the live mint + mock Lightning backend:
//   1. Meet the mint
//   2. Alice deposits sats over Lightning and receives blind-signed ecash
//   3. Alice pays Bob (a swap — the mint can't tell it's "Alice paying Bob")
//   4. A double-spend is rejected
//   5. Bob cashes out back to Lightning (with NUT-08 change)
//
// No real money moves — the mock LNbits backend simulates the Lightning side.
//
// Prereqs (already true on the dev ship):
//   - %ecash mint serving at SHIP_URL          (default http://localhost:8080)
//   - bolt11 backend configured to the mock     (default http://localhost:3338)
//   - mock-lnbits.mjs running                    (npm run mock:lnbits)
//
// Usage:
//   node demo.mjs            # narrated, paced for presenting to a room
//   node demo.mjs --fast     # same flow, no pauses
//   SHIP_URL=… MOCK_URL=… API_KEY=… node demo.mjs

import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, randomBytes } from '@noble/hashes/utils';

const SHIP_URL = process.env.SHIP_URL || 'http://localhost:8080';
const MOCK_URL = process.env.MOCK_URL || 'http://localhost:3338';
const API_KEY  = process.env.API_KEY  || 'test-api-key';
const FAST = process.argv.includes('--fast') || process.env.FAST === '1';

// ───────────────────────── terminal niceties ─────────────────────────
const C = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  red: '\x1b[31m', grn: '\x1b[32m', yel: '\x1b[33m',
  blu: '\x1b[34m', mag: '\x1b[35m', cyn: '\x1b[36m', gry: '\x1b[90m',
};
const sleep = (ms) => new Promise((r) => setTimeout(r, FAST ? 0 : ms));
const beat = (ms = 750) => sleep(ms);
const sat = (n) => `${C.yel}${C.bold}${n}${C.reset}${C.dim} sat${C.reset}`;
const short = (s, n = 12) => (s && s.length > n ? s.slice(0, n) + '…' : s);

function act(n, title) {
  const t = ` ACT ${n}  ·  ${title} `;
  const line = '━'.repeat(t.length);
  console.log(`\n${C.cyn}${C.bold}┏${line}┓\n┃${t}┃\n┗${line}┛${C.reset}`);
}
function narr(s) { console.log(`${C.gry}  ›  ${s}${C.reset}`); }
function step(s) { console.log(`${C.blu}  •  ${s}${C.reset}`); }
function ok(s)   { console.log(`${C.grn}  ✓  ${s}${C.reset}`); }
function note(s) { console.log(`${C.mag}  ◆  ${s}${C.reset}`); }
function fail(s) { console.log(`${C.red}  ✗  ${s}${C.reset}`); }

function wallet(name, proofs) {
  const total = proofs.reduce((a, p) => a + p.amount, 0);
  const by = {};
  for (const p of proofs) by[p.amount] = (by[p.amount] || 0) + 1;
  const breakdown = Object.keys(by).map(Number).sort((a, b) => b - a)
    .map((d) => `${by[d]}×${d}`).join('  ');
  console.log(`     ${C.bold}${name}${C.reset}: ${sat(total)}   ${C.dim}[${breakdown}]   ${proofs.length} token(s)${C.reset}`);
}

// ───────────────────────── BDHKE crypto ─────────────────────────
// Blind-signature math: the wallet blinds a secret, the mint signs the blind,
// the wallet unblinds to a token the mint never saw in the clear.
function hashToCurve(secret) {
  const dom = new TextEncoder().encode('Secp256k1_HashToCurve_Cashu_');
  const msg = new TextEncoder().encode(secret);
  const buf = new Uint8Array(dom.length + msg.length);
  buf.set(dom); buf.set(msg, dom.length);
  const h0 = sha256(buf);
  for (let i = 0; i < 65536; i++) {
    const ctr = new Uint8Array(4);
    new DataView(ctr.buffer).setUint32(0, i, true);
    const p = new Uint8Array(36); p.set(h0); p.set(ctr, 32);
    try { return secp.Point.fromHex('02' + bytesToHex(sha256(p))); } catch { /* retry */ }
  }
  throw new Error('hashToCurve failed');
}
const randScalar = () => BigInt('0x' + bytesToHex(secp.utils.randomPrivateKey()));
const mintPub = (ks, amount) => secp.Point.fromHex(ks.keys[String(amount)]);

// One blinded output for a given denomination.
function blind(amount) {
  const secret = `demo:${amount}:${bytesToHex(randomBytes(16))}`;
  const r = randScalar();
  const B_ = hashToCurve(secret).add(secp.Point.BASE.multiply(r));
  return { amount, secret, r, B_hex: B_.toHex(true) };
}
const toOutput = (ks, b) => ({ amount: b.amount, B_: b.B_hex, id: ks.id });
const toInput = (p) => ({ amount: p.amount, secret: p.secret, C: p.C, id: p.id });

// Unblind the mint's signatures back into spendable proofs (index-matched to the
// blinds we sent; the change amount is taken from the signature for NUT-08).
function proofsFromSigs(ks, sigs, blinds) {
  return sigs.map((sig, i) => {
    const K = mintPub(ks, sig.amount);
    const C = secp.Point.fromHex(sig.C_).subtract(K.multiply(blinds[i].r));
    return { amount: sig.amount, secret: blinds[i].secret, C: C.toHex(true), id: ks.id };
  });
}

// Greedy power-of-two decomposition (how Cashu wallets pick denominations).
function denoms(n) {
  const out = [];
  for (let d = 512; d >= 1; d >>= 1) if (n & d) out.push(d);
  return out;
}
// A descending set of denominations that can hold any change up to `max`.
function changeDenoms(max) {
  let d = 1; while (d * 2 <= max) d <<= 1;
  const out = []; for (; d >= 1; d >>= 1) out.push(d);
  return out;
}

// ───────────────────────── HTTP ─────────────────────────
const jget = (path) => fetch(SHIP_URL + path).then((r) => r.json());
const jpost = (path, body) =>
  fetch(SHIP_URL + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }).then((r) => r.json());
const mock = (path, opts = {}) =>
  fetch(MOCK_URL + path, { ...opts, headers: { 'X-Api-Key': API_KEY, ...(opts.headers || {}) } });

let KS = null;
async function keyset() { if (!KS) KS = (await jget('/v1/keys')).keysets[0]; return KS; }

// ───────────────────────── prerequisites ─────────────────────────
async function preflight() {
  let info;
  try { info = await jget('/v1/info'); }
  catch {
    fail(`Can't reach the mint at ${SHIP_URL}.`);
    narr('Is the ship up and the %ecash agent installed?');
    process.exit(1);
  }
  const bolt11 = ['4', '5'].some((n) => info.nuts?.[n]?.methods?.some((m) => m.method === 'bolt11'));
  if (!bolt11) {
    fail('The mint has no Lightning (bolt11) backend configured.');
    narr('Configure one, e.g. the mock:');
    narr(`  curl -X POST -H 'Cookie: <ship-cookie>' -H 'content-type: application/json' \\`);
    narr(`    -d '{"type":"lnbits","url":"${MOCK_URL}","api_key":"${API_KEY}"}' \\`);
    narr(`    ${SHIP_URL}/apps/ecash/admin/api/lightning/configure`);
    process.exit(1);
  }
  try { await mock('/api/v1/internal/invoices'); }
  catch {
    fail(`The mock Lightning backend isn't running at ${MOCK_URL}.`);
    narr('Start it with:  npm run mock:lnbits   (or: node mock-lnbits.mjs)');
    process.exit(1);
  }
  return info;
}

// "Pay" a bolt11 mint-quote invoice through the mock, the way a real user would
// pay the Lightning invoice — then poll until the mint sees it settle.
async function payInvoice(amount, quoteId) {
  const inv = await (await mock('/api/v1/internal/invoices')).json();
  const id = Object.keys(inv).filter((k) => inv[k].amount === amount).pop();
  await mock('/api/v1/internal/mark-paid/' + id, { method: 'POST' });
  for (let i = 0; i < 15; i++) {
    const st = await jget(`/v1/mint/quote/bolt11/${quoteId}`);
    if (st.state === 'PAID') return true;
    await sleep(200);
  }
  return false;
}

// ───────────────────────── the show ─────────────────────────
async function main() {
  console.clear?.();
  console.log(`${C.bold}${C.cyn}\n   ⚡ Cashu ecash on Urbit — live demo${C.reset}`);
  console.log(`${C.dim}   mint: ${SHIP_URL}   ·   lightning(mock): ${MOCK_URL}${C.reset}`);
  console.log(`${C.dim}   No real money moves. Lightning is simulated by a local mock.${C.reset}`);
  await beat(900);

  const info = await preflight();
  const ks = await keyset();

  // ───── ACT 1 ─────────────────────────────────────────────────────
  act(1, 'Meet the mint');
  narr('A Cashu mint is like a bank that issues bearer tokens — but it cannot');
  narr('see who holds them or what anyone\'s balance is. Tokens are just numbers.');
  await beat();
  const nuts = Object.keys(info.nuts || {}).sort((a, b) => +a - +b).join(', ');
  step(`Name: ${C.bold}${info.name}${C.reset}   ·   version: ${info.version}`);
  step(`Speaks Cashu NUTs: ${nuts}`);
  const denomList = Object.keys(ks.keys).map(Number).sort((a, b) => a - b).join(', ');
  step(`Active keyset ${C.bold}${short(ks.id, 10)}${C.reset} — denominations (sats): ${denomList}`);
  narr('Each denomination has its own signing key, so a token proves its value.');
  await beat();

  // ───── ACT 2 ─────────────────────────────────────────────────────
  act(2, 'Alice deposits over Lightning');
  const DEPOSIT = 100;
  narr(`Alice wants ${DEPOSIT} sats of ecash. She asks the mint for a Lightning invoice.`);
  const q = await jpost('/v1/mint/quote/bolt11', { amount: DEPOSIT });
  step(`Mint issued invoice: ${C.gry}${short(q.request, 28)}${C.reset}   ${C.dim}(quote ${short(q.quote, 8)})${C.reset}`);
  await beat();
  narr('Before she pays, her wallet prepares blinded outputs — each a secret');
  narr('hidden behind a random blinding factor. The mint will sign blindly.');
  const aliceBlinds = denoms(DEPOSIT).map(blind);
  step(`Alice blinds ${aliceBlinds.length} outputs for ${sat(DEPOSIT)}: ${C.dim}[${denoms(DEPOSIT).join(', ')}]${C.reset}`);
  await beat();
  step('Alice pays the Lightning invoice…');
  const paid = await payInvoice(DEPOSIT, q.quote);
  if (!paid) { fail('Invoice never settled (is the mock running?)'); process.exit(1); }
  ok('Mint saw the payment confirm on Lightning — quote is PAID.');
  await beat();
  const mintRes = await jpost('/v1/mint/bolt11', { quote: q.quote, outputs: aliceBlinds.map((b) => toOutput(ks, b)) });
  if (mintRes.detail) { fail(`mint failed: ${mintRes.detail}`); process.exit(1); }
  let alice = proofsFromSigs(ks, mintRes.signatures, aliceBlinds);
  ok('Mint returned blind signatures; Alice unblinds them into tokens.');
  if (mintRes.signatures[0]?.dleq) note('Each signature carries a DLEQ proof (NUT-12): Alice can verify the mint used the real key — no tagging.');
  wallet('Alice', alice);
  await beat();

  // ───── ACT 3 ─────────────────────────────────────────────────────
  act(3, 'Alice pays Bob');
  const SEND = 40;
  narr(`Alice pays Bob ${SEND} sats. In Cashu this is a "swap": Alice hands her`);
  narr('tokens to the mint, which burns them and issues fresh ones — some for Bob,');
  narr('the rest as Alice\'s change. The mint just sees tokens in, tokens out.');
  await beat();
  const bobBlinds = denoms(SEND).map(blind);
  const changeBlinds = denoms(DEPOSIT - SEND).map(blind);   // fee is 0 on this keyset
  const swap = await jpost('/v1/swap', {
    inputs: alice.map(toInput),
    outputs: [...bobBlinds, ...changeBlinds].map((b) => toOutput(ks, b)),
  });
  if (swap.detail) { fail(`swap failed: ${swap.detail}`); process.exit(1); }
  const spentAlice = alice;                                  // keep for the double-spend act
  const bob = proofsFromSigs(ks, swap.signatures.slice(0, bobBlinds.length), bobBlinds);
  alice = proofsFromSigs(ks, swap.signatures.slice(bobBlinds.length), changeBlinds);
  ok('Swap done. Fresh tokens issued.');
  wallet('Bob  ', bob);
  wallet('Alice', alice);
  narr('Bob can now hand these tokens to anyone, or redeem them. They\'re bearer cash.');
  await beat();

  // ───── ACT 4 ─────────────────────────────────────────────────────
  act(4, 'Double-spending is impossible');
  narr('The tokens Alice gave Bob are now spent. What if Alice tries to spend');
  narr('her old copies again — say, pay someone else with the same tokens?');
  await beat();
  const replayBlinds = denoms(DEPOSIT).map(blind);
  const replay = await jpost('/v1/swap', {
    inputs: spentAlice.map(toInput),
    outputs: replayBlinds.map((b) => toOutput(ks, b)),
  });
  if (replay.detail === 'token-already-spent') {
    ok(`Mint rejected it: ${C.bold}token-already-spent${C.reset}. Each token spends exactly once.`);
  } else {
    fail(`Expected token-already-spent, got: ${JSON.stringify(replay).slice(0, 80)}`);
  }
  await beat();
  step('Anyone can check a token\'s status without spending it (NUT-07):');
  const aliceYs = spentAlice.map((p) => hashToCurve(p.secret).toHex(true));
  const bobYs = bob.map((p) => hashToCurve(p.secret).toHex(true));
  const cs = await jpost('/v1/checkstate', { Ys: [...aliceYs.slice(0, 2), ...bobYs.slice(0, 2)] });
  const states = cs.states.map((s) => s.state);
  ok(`Alice's old tokens: ${C.red}${states.slice(0, 2).join(', ')}${C.reset}   ·   Bob's tokens: ${C.grn}${states.slice(2).join(', ')}${C.reset}`);
  await beat();

  // ───── ACT 5 ─────────────────────────────────────────────────────
  act(5, 'Bob cashes out to Lightning');
  const bobTotal = bob.reduce((a, p) => a + p.amount, 0);
  narr(`Bob has ${bobTotal} sats of ecash and wants real Lightning back. He gives the`);
  narr('mint a Lightning invoice; the mint melts his tokens and pays it.');
  await beat();
  // Pick an amount so inputs == amount + fee_reserve (no overpayment lost).
  const fakeInvoice = (amt) => `lnbc${amt}n1pdemo${bytesToHex(randomBytes(6))}`;
  let meltAmount = bobTotal - 10;                            // 10 = default fee_reserve_min
  let mq = await jpost('/v1/melt/quote/bolt11', { request: fakeInvoice(meltAmount) });
  if (mq.amount + mq.fee_reserve !== bobTotal) {             // adjust if reserve differs
    meltAmount = bobTotal - mq.fee_reserve;
    mq = await jpost('/v1/melt/quote/bolt11', { request: fakeInvoice(meltAmount) });
  }
  step(`Melt quote: pay ${sat(mq.amount)}, fee reserve ${sat(mq.fee_reserve)}  →  needs ${sat(mq.amount + mq.fee_reserve)} in tokens`);
  narr('The reserve covers worst-case routing fees; whatever isn\'t used comes back as change (NUT-08).');
  await beat();
  const meltChangeBlinds = changeDenoms(mq.fee_reserve).map(blind);
  const melt = await jpost('/v1/melt/bolt11', {
    quote: mq.quote,
    inputs: bob.map(toInput),
    outputs: meltChangeBlinds.map((b) => toOutput(ks, b)),
  });
  if (melt.state !== 'PAID') { fail(`melt did not settle: ${JSON.stringify(melt).slice(0, 120)}`); process.exit(1); }
  ok(`Mint paid the Lightning invoice. Preimage: ${C.gry}${short(melt.payment_preimage, 16)}${C.reset}`);
  const bobChange = melt.change?.length ? proofsFromSigs(ks, melt.change, meltChangeBlinds) : [];
  const changeTotal = bobChange.reduce((a, p) => a + p.amount, 0);
  const actualFee = mq.fee_reserve - changeTotal;
  ok(`Routing fee was ${sat(actualFee)}; unused reserve returned as change: ${sat(changeTotal)}.`);
  if (bobChange.length) wallet('Bob  ', bobChange);
  narr(`Bob spent ${meltAmount} (invoice) + ${actualFee} (fee) = ${meltAmount + actualFee} sats, and got ${changeTotal} back. Books balance.`);
  await beat();

  // ───── curtain ─────────────────────────────────────────────────────
  act('★', 'What you just saw');
  ok('Lightning in  →  blind-signed ecash  (the mint never linked tokens to Alice)');
  ok('Peer-to-peer payment via swap  (Alice → Bob, unlinkable)');
  ok('Cryptographic double-spend protection');
  ok('ecash  →  Lightning out, with exact fee accounting and change');
  console.log(`\n${C.dim}   All of it served by a Gall agent written in pure Hoon on Urbit. ⚡${C.reset}\n`);
}

main().catch((e) => { console.error(`\n${C.red}demo crashed:${C.reset}`, e); process.exit(1); });
