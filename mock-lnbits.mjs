// Mock LNbits server for e2e testing of bolt11 Lightning integration
// Simulates: create invoice, check invoice, decode invoice, pay invoice
import http from 'node:http';
import crypto from 'node:crypto';

const PORT = 3338;
const API_KEY = 'test-api-key';

// In-memory state
const invoices = new Map();  // checking_id -> {amount, memo, bolt11, paid}
const payments = new Map();  // payment_hash -> {bolt11, paid, preimage}

// Generate fake bolt11 string
function fakeBolt11(amount) {
  const rand = crypto.randomBytes(16).toString('hex');
  return `lnbc${amount}n1p${rand}`;
}

function parseBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', c => data += c);
    req.on('end', () => {
      try { resolve(JSON.parse(data)); }
      catch { resolve(null); }
    });
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const path = url.pathname;
  const method = req.method;

  // Check API key
  if (req.headers['x-api-key'] !== API_KEY) {
    res.writeHead(401, {'Content-Type': 'application/json'});
    res.end(JSON.stringify({detail: 'unauthorized'}));
    return;
  }

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Connection', 'close');

  // POST /api/v1/payments — create invoice (out=false) or pay (out=true)
  if (method === 'POST' && path === '/api/v1/payments') {
    const body = await parseBody(req);
    if (!body) {
      res.writeHead(400);
      res.end(JSON.stringify({detail: 'bad request'}));
      return;
    }

    if (body.out === true) {
      // Pay an invoice
      const bolt11 = body.bolt11;
      const payHash = crypto.randomBytes(32).toString('hex');
      const preimage = crypto.randomBytes(32).toString('hex');
      payments.set(payHash, {bolt11, paid: true, preimage});
      res.writeHead(200);
      res.end(JSON.stringify({
        payment_hash: payHash,
        checking_id: payHash,
        payment_preimage: preimage,
        fee: 2000,
      }));
      return;
    }

    // Create invoice
    const amount = body.amount || 0;
    const memo = body.memo || '';
    const checkingId = crypto.randomBytes(32).toString('hex');
    const bolt11 = fakeBolt11(amount);
    invoices.set(checkingId, {amount, memo, bolt11, paid: false});
    res.writeHead(200);
    res.end(JSON.stringify({
      payment_hash: checkingId,
      checking_id: checkingId,
      payment_request: bolt11,
      bolt11: bolt11,
    }));
    return;
  }

  // GET /api/v1/payments/:id — check invoice status
  if (method === 'GET' && path.startsWith('/api/v1/payments/')) {
    const id = path.split('/').pop();
    const inv = invoices.get(id);
    if (inv) {
      res.writeHead(200);
      // include settled amount (msat) like real LNbits so the mint can
      // cross-check the paid amount before flipping a quote to PAID.
      res.end(JSON.stringify({
        paid: inv.paid,
        amount: inv.amount * 1000,
        details: { amount: inv.amount * 1000 },
      }));
      return;
    }
    const pay = payments.get(id);
    if (pay) {
      res.writeHead(200);
      res.end(JSON.stringify({paid: pay.paid, preimage: pay.preimage}));
      return;
    }
    res.writeHead(404);
    res.end(JSON.stringify({detail: 'not found'}));
    return;
  }

  // POST /api/v1/payments/decode — decode bolt11
  if (method === 'POST' && path === '/api/v1/payments/decode') {
    const body = await parseBody(req);
    const bolt11 = body?.data || '';
    // Extract amount from our fake bolt11 format: lnbc{amount}n1p...
    const match = bolt11.match(/^lnbc(\d+)n1p/);
    const amountSats = match ? parseInt(match[1]) : 1000;
    const payHash = crypto.createHash('sha256').update(bolt11).digest('hex');
    res.writeHead(200);
    res.end(JSON.stringify({
      amount_msat: amountSats * 1000,
      payment_hash: payHash,
      description: 'mock decoded invoice',
    }));
    return;
  }

  // POST /api/v1/internal/mark-paid/:id — test helper to simulate payment
  if (method === 'POST' && path.startsWith('/api/v1/internal/mark-paid/')) {
    const id = path.split('/').pop();
    const inv = invoices.get(id);
    if (inv) {
      inv.paid = true;
      res.writeHead(200);
      res.end(JSON.stringify({ok: true}));
      return;
    }
    res.writeHead(404);
    res.end(JSON.stringify({detail: 'not found'}));
    return;
  }

  // GET /api/v1/internal/invoices — test helper to list invoices
  if (method === 'GET' && path === '/api/v1/internal/invoices') {
    const all = {};
    for (const [id, inv] of invoices) all[id] = inv;
    res.writeHead(200);
    res.end(JSON.stringify(all));
    return;
  }

  res.writeHead(404);
  res.end(JSON.stringify({detail: 'not found'}));
});

server.listen(PORT, () => {
  console.log(`Mock LNbits running on http://localhost:${PORT}`);
  console.log('Endpoints:');
  console.log('  POST /api/v1/payments          — create invoice / pay');
  console.log('  GET  /api/v1/payments/:id       — check status');
  console.log('  POST /api/v1/payments/decode    — decode bolt11');
  console.log('  POST /api/v1/internal/mark-paid/:id — mark invoice paid (test helper)');
  console.log('  GET  /api/v1/internal/invoices  — list all invoices (test helper)');
});
