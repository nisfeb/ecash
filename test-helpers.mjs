// Shared by every suite: the harness, the ship's HTTP API, the Cashu client
// crypto and the mock LNbits backend. The client crypto is cashu-ts, a real
// wallet library, so the suites drive the mint the way wallets do and never
// grade the mint with arithmetic of their own.
//
// Env:
//   SHIP_URL           the ship, e.g. http://localhost:8080. No default: a
//                      wrong port can be somebody else's service.
//   URBAUTH_COOKIE     the Cookie header value for the ship's admin API
//   ALLOW_DESTRUCTIVE  =1 lets a suite change settings on a ship that is not
//                      on this machine (it still restores them)
//   REQUIRE_AUTH       =1 (set by run-tests.mjs): a suite that would SKIP
//                      fails instead, so a green run is never a run of skips
//   MOCK_PORT          the mock LNbits port (default 3338)
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import {
  hashToCurve as h2c, blindMessage, unblindSignature, verifyDLEQProof, pointFromHex,
  schnorrSignMessage,
} from '@cashu/cashu-ts';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { hexToBytes } from '@noble/curves/utils.js';

export const SHIP_URL = (process.env.SHIP_URL || '').replace(/\/+$/, '');
const COOKIE = process.env.URBAUTH_COOKIE || '';
export const hasAuth = () => !!COOKIE;
// Everything a run creates carries this, so it can be found and cleaned up.
export const TAG = `jst${Date.now().toString(36)}`;
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export const randomHex = (n) => randomBytes(n).toString('hex');

// ─── harness ─────────────────────────────────────────────────────────────────

let passed = 0, failed = 0;
const show = (d) => (typeof d === 'string' ? d : JSON.stringify(d, (k, v) => (typeof v === 'bigint' ? `${v}n` : v)))?.slice(0, 600);

export function check(label, ok, detail) {
  if (ok) { passed++; console.log(`  PASS  ${label}`); }
  else { failed++; console.log(`  FAIL  ${label}${detail === undefined ? '' : `  -- ${show(detail)}`}`); }
  return !!ok;
}
// refused: the response is exactly this error status and detail
export const refused = (label, res, status, detail) =>
  check(label, res.status === status && res.body?.detail === detail, { status: res.status, body: res.body ?? res.text });
export const section = (title) => console.log(`\n=== ${title}`);

const cleanups = [];
// onCleanup: run fn when the suite ends, pass or fail (last registered first)
export const onCleanup = (fn) => cleanups.push(fn);

function skip(name, why) {
  if (process.env.REQUIRE_AUTH === '1') { console.log(`FAIL ${name}: ${why} (required under run-tests)`); process.exit(1); }
  console.log(`SKIP ${name}: ${why}`);
  process.exit(0);
}
const isLoopback = (u) => /^(localhost|127\.\d+\.\d+\.\d+|\[::1\])$/.test(new URL(u).hostname);

// run: one suite. ship: needs SHIP_URL. auth: needs the admin cookie.
// mutates: changes mint settings, so it runs only against a loopback ship
// (or with ALLOW_DESTRUCTIVE=1) and restores what it found. ln: also points
// the mint at a fresh mock LNbits, handed to body as { mock }. The exit code
// is the verdict: 1 if any check failed or body threw.
export async function run(name, { ship = true, auth = false, mutates = false, ln = false } = {}, body) {
  console.log(`# ${name}`);
  if ((ship || auth) && !SHIP_URL) skip(name, 'set SHIP_URL');
  if (auth && !COOKIE) skip(name, 'set URBAUTH_COOKIE');
  if (mutates && !isLoopback(SHIP_URL) && process.env.ALLOW_DESTRUCTIVE !== '1') {
    console.log(`REFUSED ${name}: it changes mint settings and ${SHIP_URL} is not this machine; set ALLOW_DESTRUCTIVE=1 to run it anyway`);
    process.exit(1);
  }
  let finishing = null;
  const finish = async () => {
    for (const fn of cleanups.splice(0).reverse()) {
      try { await fn(); } catch (e) { check('cleanup step', false, e.message); }
    }
  };
  process.once('SIGINT', async () => { await (finishing ??= finish()); process.exit(130); });
  const ctx = {};
  try {
    if (mutates) onCleanup(await snapshot({ ln }));
    if (ln) {
      ctx.mock = await startMock();
      const r = await admin('/lightning/configure', { type: 'lnbits', url: ctx.mock.url, api_key: ctx.mock.key });
      if (!r.body?.configured) throw new Error(`could not configure the mock: ${show(r.body)}`);
    }
    await body(ctx);
  } catch (e) {
    check(`${name} ran to the end`, false, e.stack ?? String(e));
  } finally {
    await (finishing ??= finish());
  }
  console.log(`\n${name}: ${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
}

// snapshot: record the settings a suite may change; answer the restore step.
// Lightning can only be put back if it was off: the API never returns the
// stored key, so a suite that needs the mock refuses to replace a backend.
async function snapshot({ ln }) {
  const read = async () => ({
    settings: (await admin('/settings')).body,
    ln: (await admin('/lightning')).body,
    active: (await admin('/overview')).body?.active_keyset,
  });
  const before = await read();
  if (!before.settings || !before.ln || !before.active) throw new Error('could not read the mint settings (is the cookie valid?)');
  if (ln && before.ln.type !== 'none') {
    console.log(`REFUSED: a ${before.ln.type} backend at ${before.ln.url} is configured. This suite points the mint at a mock and could not put the key back; POST {"type":"none"} to /apps/ecash/admin/api/lightning/configure first.`);
    process.exit(1);
  }
  return async () => {
    await admin('/settings', before.settings);
    if (ln) await admin('/lightning/configure', { type: 'none' });
    if ((await admin('/overview')).body?.active_keyset !== before.active) await admin('/keysets/activate', { id: before.active });
    const after = await read();
    const same = Object.keys(before.settings).every((k) => after.settings?.[k] === before.settings[k]);
    check('mint settings, Lightning and active keyset restored',
      same && after.active === before.active && after.ln?.type === before.ln.type, after);
  };
}

// ─── the ship's HTTP API ─────────────────────────────────────────────────────

// call: { status, body (parsed JSON or undefined), text, headers }
export async function call(path, { method = 'GET', body, auth = false, headers = {} } = {}) {
  const h = { ...headers };
  if (body !== undefined) h['content-type'] = 'application/json';
  if (auth) h.cookie = COOKIE;
  const r = await fetch(SHIP_URL + path, {
    method, headers: h, body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
  });
  const text = await r.text();
  let json;
  try { json = JSON.parse(text); } catch { json = undefined; }
  return { status: r.status, body: json, text, headers: r.headers };
}
export const get = (path) => call(path);
export const post = (path, body) => call(path, { method: 'POST', body });
// admin: the %ecash admin API; a body makes it a POST
export const admin = (path, body) =>
  call(`/apps/ecash/admin/api${path}`, { method: body === undefined ? 'GET' : 'POST', body, auth: true });

export async function setSelf(on) {
  const r = await admin('/settings', { self_method_enabled: on });
  if (r.body?.self_method_enabled !== on) throw new Error(`could not set self_method_enabled=${on}: ${show(r.body)}`);
}

// poll: call fn until done(result), at most tries times; answer the last result
export async function poll(fn, done, { tries = 40, ms = 250 } = {}) {
  let r;
  for (let i = 0; i < tries; i++) {
    r = await fn();
    if (done(r)) return r;
    await sleep(ms);
  }
  return r;
}

// ─── Cashu client crypto (cashu-ts) ──────────────────────────────────────────

const G = secp256k1.Point.BASE;
export const point = pointFromHex;
const utf8 = (s) => new TextEncoder().encode(s);
// hashToCurve: NUT-00 Y for a secret string
export const hashToCurve = (secret) => h2c(typeof secret === 'string' ? utf8(secret) : secret);
export const yHex = (secret) => hashToCurve(secret).toHex(true);
export const newSecret = (label = 's') => `${TAG}-${label}-${randomHex(12)}`;
// blind: B_ = Y + rG, as a wallet makes it
export function blind(secret = newSecret(), r) {
  const b = blindMessage(utf8(secret), r);
  return { secret, r: b.r, B_: b.B_.toHex(true) };
}
// dleqValid: the NUT-12 proof on a signature, checked against the mint's key
export function dleqValid(sig, B_, keys) {
  if (!sig?.dleq?.e || !sig?.dleq?.s || !keys?.[sig.amount]) return false;
  return verifyDLEQProof({ e: hexToBytes(sig.dleq.e), s: hexToBytes(sig.dleq.s) },
    point(B_), point(sig.C_), point(keys[sig.amount]));
}
// p2pkSign: a NUT-11 witness signature (Schnorr over sha256(secret))
export const p2pkSign = (secret, priv) => schnorrSignMessage(secret, priv);
export const randomKey = () => secp256k1.utils.randomSecretKey();
export const pubHex = (priv) => bytesHex(secp256k1.getPublicKey(priv, true));
const bytesHex = (b) => Buffer.from(b).toString('hex');

// split: an amount as powers of two up to top, largest first
export const split = (n, top = 2 ** 20) => { const out = []; for (let d = top; d >= 1; d /= 2) while (n >= d) { out.push(d); n -= d; } return out; };
export const sum = (xs) => xs.reduce((a, x) => a + (x.amount ?? x), 0);

// outputs: blinded messages for these amounts (0 = a NUT-08 blank), and the
// way back from the mint's signatures to proofs
export function outputs(amounts, id, secrets = []) {
  const blinds = amounts.map((_, i) => blind(secrets[i]));
  return {
    blinds,
    msgs: amounts.map((amount, i) => ({ amount, id, B_: blinds[i].B_ })),
    // proofs carry the B_ they were signed for (inputs() leaves it out)
    proofs: (sigs, keys) => sigs.map((s, i) => ({
      amount: s.amount, id: s.id, secret: blinds[i].secret, B_: blinds[i].B_,
      C: unblindSignature(point(s.C_), blinds[i].r, point(keys[s.amount])).toHex(true),
    })),
  };
}

// keyset: the active keyset, with keys
export async function keyset() {
  const r = await get('/v1/keys');
  const ks = r.body?.keysets?.[0];
  if (!ks) throw new Error(`no active keyset: ${show(r.body)}`);
  return ks;
}

// selfMint: proofs for these amounts through the self method (which must be
// on), optionally with chosen secrets
export async function selfMint(ks, amounts, secrets = []) {
  const q = await post('/v1/mint/quote/self', { amount: sum(amounts) });
  if (!q.body?.quote) throw new Error(`self quote: ${show(q.body ?? q.text)}`);
  const o = outputs(amounts, ks.id, secrets);
  const m = await post('/v1/mint/self', { quote: q.body.quote, outputs: o.msgs });
  if (m.status !== 200) throw new Error(`self mint: ${m.status} ${show(m.body ?? m.text)}`);
  return o.proofs(m.body.signatures, ks.keys);
}
// fund: proofs worth exactly total
export const fund = (ks, total) => selfMint(ks, split(total));
// forged: a proof claiming amount with a valid point for C but no signature
export const forged = (ks, amount) => ({ amount, id: ks.id, secret: newSecret('forged'), C: G.toHex(true) });

// inactiveKeyset: an inactive keyset (with a fee, if asked), reusing one a
// past run made: keysets can't be deleted, so each would stay forever
export async function inactiveKeyset({ fee = false } = {}) {
  const all = (await get('/v1/keysets')).body.keysets;
  const found = all.find((k) => !k.active && (!fee || k.input_fee_ppk > 0));
  if (found) return found;
  const made = (await admin('/keysets/generate', {})).body;
  if (!fee) return made;
  const r = await admin('/keysets/set-fee', { id: made.id, input_fee_ppk: 1000 });
  return { id: r.body.new_id, input_fee_ppk: 1000, active: false };
}

export const inputs = (proofs) => proofs.map(({ amount, id, secret, C, witness }) => ({ amount, id, secret, C, ...(witness ? { witness } : {}) }));
// states: NUT-07 state of each proof
export async function states(proofs) {
  const r = await post('/v1/checkstate', { Ys: proofs.map((p) => yHex(p.secret)) });
  return (r.body?.states ?? []).map((s) => s.state);
}

// ─── bolt11 and the mock LNbits ──────────────────────────────────────────────

// invoice: a fake bolt11 for msat. The HRP encodes the amount as real bolt11
// does (nano-BTC is 100 msat) and the data uses bech32's alphabet, which has
// no '1', so wallets find the HRP; nothing checks a signature or checksum.
const BECH32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const bech32Data = (n = 52) => Array.from(randomBytes(n), (b) => BECH32[b & 31]).join('');
export const invoice = (msat) =>
  msat % 100 === 0 ? `lnbc${msat / 100}n1p${bech32Data()}` : `lnbc${msat * 10}p1p${bech32Data()}`;

// startMock: spawn mock-lnbits.mjs on MOCK_PORT and wait until it answers as
// the process we started (not something already on the port). It stops with
// the suite.
async function startMock(payMode = 'ok') {
  const port = Number(process.env.MOCK_PORT || 3338);
  const url = `http://localhost:${port}`;
  const key = 'test-api-key';
  const child = spawn(process.execPath, [fileURLToPath(new URL('./mock-lnbits.mjs', import.meta.url))], {
    env: { ...process.env, PORT: String(port), PAY_MODE: payMode }, stdio: ['ignore', 'ignore', 'inherit'],
  });
  // stopping waits for the exit, so the next suite finds the port free
  process.once('exit', () => child.kill());
  onCleanup(() => child.exitCode === null && new Promise((r) => { child.once('exit', r); child.kill(); }));
  const req = async (path, body) => {
    const r = await fetch(url + path, {
      method: body === undefined ? 'GET' : 'POST',
      headers: { 'X-Api-Key': key, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: r.status, body: await r.json().catch(() => undefined) };
  };
  for (let i = 0; ; i++) {
    if (child.exitCode !== null) throw new Error(`mock-lnbits exited (${child.exitCode}); is port ${port} taken?`);
    const s = await req('/api/v1/internal/state').catch(() => null);
    if (s?.body?.pid === child.pid) break;
    if (s?.body?.pid) throw new Error(`port ${port} answers as another mock (pid ${s.body.pid})`);
    if (i > 50) throw new Error('mock-lnbits did not start');
    await sleep(100);
  }
  return {
    url, key,
    // mode: how the next pays, invoice creations or decodes answer (see mock-lnbits.mjs)
    mode: (m) => req('/api/v1/internal/mode', m),
    payCount: async () => (await req('/api/v1/internal/state')).body.payCount,
    // markPaid: the payer paid this invoice, which the mock issued
    markPaid: (bolt11) => req('/api/v1/internal/mark-paid', { bolt11 }),
  };
}
