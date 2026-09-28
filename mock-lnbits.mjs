// mock-lnbits.mjs: a stand-in LNbits for the Lightning suites and the demo.
// It answers the way real LNbits does wherever the mint's money safety
// depends on it:
//   - a pay (POST /api/v1/payments {out:true}) answers 201 Created and names
//     the invoice's own payment_hash; an outgoing fee is NEGATIVE msat;
//   - an invoice already paid is refused, not paid twice;
//   - decode refuses text that isn't an invoice (400);
//   - only a status GET (/api/v1/payments/{hash}) proves a pay settled.
// Invoices are fake: ln<net><amount><multiplier>1<data>, with the amount in
// the HRP as in real bolt11 (1n = 100 msat), and payment_hash =
// sha256(invoice). The mint checks no invoice signature.
//
// How a pay answers (env PAY_MODE, or POST /api/v1/internal/mode {pay}):
//   ok        201 with the preimage and fee: settled at dispatch
//   inflight  201 with no preimage; the next status GET shows it settled
//   500       500 and no payment record, so a status GET 404s: ambiguous
//   400       400 {detail} naming no payment: refused before any HTLC
//             (LNbits' answer for e.g. insufficient balance)
//   400-hash  400 {detail, payment_hash}: names a payment, so ambiguous; no
//             record, so a status GET 404s
// Also {invoice: 'ok'|'500'} (invoice creation fails), {decode:
// 'ok'|'nohash'} (a decode answer without payment_hash), and {pay_delay: ms}
// and {status_delay: ms}: pays or status GETs answer that late, like a slow
// node. A request keeps the modes it arrived under.
//
// Test routes: GET /api/v1/internal/state (no key: {pid, payCount, payLog,
// modes}), POST /api/v1/internal/mode, POST /api/v1/internal/mark-paid
// {bolt11} (the payer paid an invoice this mock issued).
//
// Usage: node mock-lnbits.mjs   (PORT, default 3338; API key test-api-key)
import http from 'node:http';
import crypto from 'node:crypto';

const PORT = Number(process.env.PORT || 3338);
const API_KEY = 'test-api-key';
const FEE_MSAT = 2000;              // the routing fee every settled pay reports
const modes = { pay: process.env.PAY_MODE || 'ok', invoice: 'ok', decode: 'ok', pay_delay: 0, status_delay: 0 };
const later = (ms) => new Promise((r) => setTimeout(r, ms));

const invoices = new Map();          // hash -> {bolt11, msat, paid}: issued by us
const payments = new Map();          // hash -> {bolt11, msat, preimage}: paid by us
let payCount = 0;                    // every pay request that arrived
const payLog = [];

const hashOf = (bolt11) => crypto.createHash('sha256').update(bolt11.toLowerCase()).digest('hex');
const MSAT_PER = { m: 1e8, u: 1e5, n: 100, p: 0.1 };
// amountMsat: the invoice's amount, 0 for an amount-less one, null if it
// isn't an invoice
function amountMsat(bolt11) {
  const m = /^ln(?:bc|tb|bcrt)(?:(\d+)([munp]))?1[0-9a-z]+$/.exec(String(bolt11).toLowerCase());
  if (!m) return null;
  return m[1] ? Number(m[1]) * MSAT_PER[m[2]] : 0;
}

function body(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => { try { resolve(JSON.parse(data)); } catch { resolve(null); } });
  });
}

const server = http.createServer(async (req, res) => {
  const path = new URL(req.url, `http://localhost:${PORT}`).pathname;
  const send = (code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(obj)); };

  if (req.method === 'GET' && path === '/api/v1/internal/state') {
    return send(200, { pid: process.pid, payCount, payLog, modes });
  }
  if (req.headers['x-api-key'] !== API_KEY) return send(401, { detail: 'Invalid key' });

  if (req.method === 'GET' && path === '/api/v1/wallet') {
    return send(200, { id: 'mock-wallet', name: 'mock', balance: 1_000_000_000 });
  }

  if (req.method === 'POST' && path === '/api/v1/internal/mode') {
    Object.assign(modes, await body(req));
    return send(200, modes);
  }
  if (req.method === 'POST' && path === '/api/v1/internal/mark-paid') {
    const inv = invoices.get(hashOf((await body(req))?.bolt11 ?? ''));
    if (!inv) return send(404, { detail: 'no such invoice' });
    inv.paid = true;
    return send(200, { ok: true });
  }

  if (req.method === 'POST' && path === '/api/v1/payments/decode') {
    const bolt11 = (await body(req))?.data ?? '';
    const msat = amountMsat(bolt11);
    if (msat === null) return send(400, { detail: 'Failed to decode invoice' });
    return send(200, {
      amount_msat: msat, description: 'mock invoice', expiry: 3600,
      ...(modes.decode === 'nohash' ? {} : { payment_hash: hashOf(bolt11) }),
    });
  }

  if (req.method === 'POST' && path === '/api/v1/payments') {
    const b = await body(req);
    if (!b) return send(400, { detail: 'bad request' });
    if (b.out === true) return pay(b.bolt11 ?? '', send);
    // create an invoice (out:false); amount in sats
    if (modes.invoice === '500') return send(500, { detail: 'backend unavailable (simulated)' });
    const msat = Math.round(Number(b.amount) * 1000);
    if (!(msat > 0)) return send(400, { detail: 'invalid amount' });
    // bech32's alphabet has no '1', so the HRP ends at the one after the amount
    const bolt11 = `lnbc${msat / 100}n1p${Array.from(crypto.randomBytes(52), (x) => 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'[x & 31]).join('')}`;
    const hash = hashOf(bolt11);
    invoices.set(hash, { bolt11, msat, paid: false });
    return send(201, { payment_hash: hash, checking_id: hash, payment_request: bolt11, bolt11 });
  }

  if (req.method === 'GET' && path.startsWith('/api/v1/payments/')) {
    const hash = path.split('/').pop();
    await later(modes.status_delay);
    // the payer's view first: this key's wallet made the payment
    const p = payments.get(hash);
    if (p) {
      return send(200, { paid: true, status: 'success', preimage: p.preimage,
        details: { payment_hash: hash, bolt11: p.bolt11, amount: -p.msat, fee: -FEE_MSAT, status: 'success' } });
    }
    const inv = invoices.get(hash);
    if (inv) {
      return send(200, { paid: inv.paid, status: inv.paid ? 'success' : 'pending',
        details: { payment_hash: hash, bolt11: inv.bolt11, amount: inv.msat, fee: 0, status: inv.paid ? 'success' : 'pending' } });
    }
    return send(404, { detail: 'Payment does not exist.' });
  }

  send(404, { detail: 'Not Found' });
});

async function pay(bolt11, send) {
  const mode = modes.pay;
  payCount += 1;
  payLog.push({ ts: Date.now(), bolt11, mode });
  await later(modes.pay_delay);
  const msat = amountMsat(bolt11);
  if (msat === null) return send(400, { detail: 'Failed to decode invoice' });
  const hash = hashOf(bolt11);
  if (payments.has(hash)) return send(400, { detail: 'Invoice already paid.' });
  switch (mode) {
    case '500': return send(500, { detail: 'payment failed (simulated)' });
    case '400': return send(400, { detail: 'Insufficient balance.' });
    case '400-hash': return send(400, { detail: 'Payment failed.', payment_hash: hash });
  }
  const preimage = crypto.randomBytes(32).toString('hex');
  payments.set(hash, { bolt11, msat, preimage });
  if (mode === 'inflight') {
    return send(201, { payment_hash: hash, checking_id: hash, amount: -msat, fee: 0, status: 'pending', preimage: null });
  }
  return send(201, { payment_hash: hash, checking_id: hash, amount: -msat, fee: -FEE_MSAT, status: 'success', preimage });
}

server.listen(PORT, () => console.log(`mock LNbits on http://localhost:${PORT} (key ${API_KEY}, pay mode ${modes.pay})`));
