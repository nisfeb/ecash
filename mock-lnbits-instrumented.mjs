// Instrumented mock LNbits — like mock-lnbits.mjs but counts outgoing pays
// (out:true) so a double-pay can be detected. Pay-count exposed at
// GET /api/v1/internal/paycount. Optional env PAY_MODE:
//   'ok'   (default) -> 200 success
//   '500'  -> HTTP 500 on pay (simulate definitive failure)
import http from 'node:http';
import crypto from 'node:crypto';

const PORT = parseInt(process.env.PORT || '3340');
const API_KEY = 'test-api-key';
const PAY_MODE = process.env.PAY_MODE || 'ok';

const invoices = new Map();
const payments = new Map();
let payCount = 0;          // total POST payments with out:true that we ACTED on
let payOkCount = 0;        // pays that returned 200
const payLog = [];         // {ts, bolt11, mode}

function fakeBolt11(amount) {
  const rand = crypto.randomBytes(16).toString('hex');
  return `lnbc${amount}n1p${rand}`;
}
function parseBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', c => data += c);
    req.on('end', () => { try { resolve(JSON.parse(data)); } catch { resolve(null); } });
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const path = url.pathname;
  const method = req.method;

  if (path === '/api/v1/internal/paycount' && method === 'GET') {
    res.writeHead(200, {'Content-Type':'application/json'});
    res.end(JSON.stringify({ payCount, payOkCount, payLog }));
    return;
  }

  if (req.headers['x-api-key'] !== API_KEY) {
    res.writeHead(401, {'Content-Type': 'application/json'});
    res.end(JSON.stringify({detail: 'unauthorized'}));
    return;
  }
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Connection', 'close');

  if (method === 'POST' && path === '/api/v1/payments') {
    const body = await parseBody(req);
    if (!body) { res.writeHead(400); res.end(JSON.stringify({detail:'bad request'})); return; }

    if (body.out === true) {
      payCount += 1;
      payLog.push({ ts: Date.now(), bolt11: body.bolt11, mode: PAY_MODE });
      if (PAY_MODE === '500') {
        // ambiguous failure: 500 and NO payment record (status GET -> 404)
        res.writeHead(500);
        res.end(JSON.stringify({detail: 'payment failed (simulated)'}));
        return;
      }
      payOkCount += 1;
      const bolt11 = body.bolt11;
      // LNbits-faithful: payment_hash is the invoice hash (== decode hash),
      // so a later status GET by the quote's stored payment_hash resolves.
      const payHash = crypto.createHash('sha256').update(bolt11).digest('hex');
      const preimage = crypto.randomBytes(32).toString('hex');
      if (PAY_MODE === 'inflight') {
        // real-LNbits async: 201 Created, NO preimage yet (in flight). The
        // settlement is only observable via a later status GET.
        payments.set(payHash, {bolt11, paid: true, preimage});
        res.writeHead(201);
        res.end(JSON.stringify({ payment_hash: payHash, checking_id: payHash, fee: 2000 }));
        return;
      }
      payments.set(payHash, {bolt11, paid: true, preimage});
      // PAY_MODE=201 mimics real LNbits returning 201 Created on success.
      res.writeHead(PAY_MODE === '201' ? 201 : 200);
      res.end(JSON.stringify({ payment_hash: payHash, checking_id: payHash, payment_preimage: preimage, fee: 2000 }));
      return;
    }

    const amount = body.amount || 0;
    const memo = body.memo || '';
    const checkingId = crypto.randomBytes(32).toString('hex');
    const bolt11 = fakeBolt11(amount);
    invoices.set(checkingId, {amount, memo, bolt11, paid: false});
    res.writeHead(201);  // real LNbits returns 201 Created on invoice creation
    res.end(JSON.stringify({ payment_hash: checkingId, checking_id: checkingId, payment_request: bolt11, bolt11 }));
    return;
  }

  if (method === 'GET' && path.startsWith('/api/v1/payments/')) {
    const id = path.split('/').pop();
    const inv = invoices.get(id);
    if (inv) { res.writeHead(200); res.end(JSON.stringify({paid: inv.paid, amount: inv.amount*1000, details:{amount: inv.amount*1000}})); return; }
    const pay = payments.get(id);
    if (pay) { res.writeHead(200); res.end(JSON.stringify({paid: pay.paid, preimage: pay.preimage})); return; }
    res.writeHead(404); res.end(JSON.stringify({detail:'not found'})); return;
  }

  if (method === 'POST' && path === '/api/v1/payments/decode') {
    const body = await parseBody(req);
    const bolt11 = body?.data || '';
    const match = bolt11.match(/^lnbc(\d+)n1p/);
    const amountSats = match ? parseInt(match[1]) : 1000;
    const payHash = crypto.createHash('sha256').update(bolt11).digest('hex');
    res.writeHead(200);
    res.end(JSON.stringify({ amount_msat: amountSats*1000, payment_hash: payHash, description: 'mock decoded invoice' }));
    return;
  }

  res.writeHead(404); res.end(JSON.stringify({detail:'not found'}));
});

server.listen(PORT, () => {
  console.log(`Instrumented mock LNbits on http://localhost:${PORT} PAY_MODE=${PAY_MODE}`);
});
