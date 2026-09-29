# Installing the ecash mint for public use

From a clean clone to a public Cashu mint. The money-safety detail is in
[`operator-runbook.md`](operator-runbook.md); this page is install and go-public.

## 0. What "public" means here

A Cashu wallet talks to your mint at a **base URL**; the protocol lives under `/v1/*`. If your
ship is reachable at `https://mint.example.com`, that URL *is* your mint: wallets call
`https://mint.example.com/v1/info`, `/v1/keys`, and so on. `/v1` is public and unauthenticated
by design. The operator dashboard at `/apps/ecash/admin` needs your ship login (the Landscape
tile opens it).

Four steps: **install the desks → expose the ship over HTTPS → configure for real value →
verify**.

## 1. Prerequisites

- A **real ship** (planet or moon) you control, not a fakeship. The desks declare
  `[%zuse 408]`; if your `%base` is on another kelvin (409 included), the `|commit` fails
  with a kelvin error.
- A **Lightning backend**. Use **LNbits** for real funds: a dedicated wallet and its key that
  can pay invoices. LND is supported in code but **has never been tested against a real LND
  node** (see the runbook §5).
- A **domain and TLS** for the ship (§3).
- Shell access to the pier host, with **[peru](https://github.com/buildinspace/peru)**
  installed (it fetches the shared base-dev files).

## 2. Build and install the desks

```bash
git clone https://github.com/nisfeb/ecash
cd ecash
./build.sh              # builds dist/ (%ecash) and dist-tessera/ (%tessera)
```

`build.sh` pulls the base-dev files with peru and copies the shared libraries (`curve`, `bdhke`,
`ecash-http`, `blind`) into the tessera desk, producing complete desks. Always deploy with
`build.sh`; copying `desk/` by hand leaves out the base-dev files.

**The value mint (`%ecash`)**, in the ship's dojo:

```
|new-desk %ecash
|mount %ecash
```
```bash
# from the repo: wipe the mounted desk and copy the built one in
./build.sh -p /path/to/your/pier/ecash
```
```
|commit %ecash          ::  watch for build errors
|install our %ecash
```

**Access tokens (`%tessera`)**, optional (no value; see [`tessera.md`](tessera.md)):

```
|new-desk %tessera
|mount %tessera
```
```bash
./build.sh tessera -p /path/to/your/pier/tessera
```
```
|commit %tessera
|install our %tessera
```

`build.sh -p` refuses a path without a `sys.kelvin` (so it only ever wipes a mounted desk). On
first install `%ecash` generates a keyset with denominations 1, 2, 4 … 2^20, sets Lightning to
`none` and leaves `self` **off**: it is inert until you configure Lightning. The **Cashu Mint**
tile appears in Landscape.

## 3. Expose the ship over HTTPS

Wallets need a stable public `https://` URL. Put a **reverse proxy that terminates TLS** in
front of the ship's loopback HTTP port (8080 by default).

The proxy must:

- **Forward the `Host` header.** A state-changing admin request that sends `Origin` must match
  `Host`, or the mint answers `403 forbidden-cross-origin`. nginx does not forward `Host` unless
  told to. (`X-Forwarded-Host` is not trusted: a page on an origin approved with
  `|cors-approve` could set it.)
- **Rate-limit `/v1/`.** The mint has no rate limit of its own, and its elliptic-curve math is
  pure Hoon: a 100-proof swap takes seconds of ship CPU, and the ship handles one event at a
  time. The proxy rate limit is your main abuse control.
- **Not add CORS headers.** The mint sends `Access-Control-Allow-Origin: *` and answers
  preflight itself; a second header from the proxy breaks browser wallets.

nginx (20 requests/s per IP, bursts of 40, on `/v1/`):

```nginx
# http context (a file in conf.d/ or sites-enabled/ is included there)
limit_req_zone $binary_remote_addr zone=mint:10m rate=20r/s;

server {
    listen 443 ssl;
    server_name mint.example.com;
    # ssl_certificate / ssl_certificate_key: from certbot or your CA

    location /v1/ {
        limit_req zone=mint burst=40;
        limit_req_status 429;
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
    }
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
    }
}
```

Caddy forwards `Host` by default, but **stock Caddy has no rate limiting**. You need a Caddy
built with the [caddy-ratelimit](https://github.com/mholt/caddy-ratelimit) plugin
(`xcaddy build --with github.com/mholt/caddy-ratelimit`) and an `order` line:

```
{
    order rate_limit before reverse_proxy
}

mint.example.com {
    rate_limit {
        zone v1 {
            match {
                path /v1/*
            }
            key {remote_host}
            events 20
            window 1s
        }
    }
    reverse_proxy 127.0.0.1:8080
}
```

Your **mint URL for wallets** is then `https://mint.example.com`.

## 4. Configure for real value

From the admin dashboard (`/apps/ecash/admin`) or the admin API. Details in
[`operator-runbook.md`](operator-runbook.md) §2.

1. **Lightning backend.** Dashboard → Lightning, or
   `POST /apps/ecash/admin/api/lightning/configure
   {"type":"lnbits","url":"https://your-lnbits","api_key":"<key>"}`. The credential is stored in
   pier state, so use a wallet that holds only what the mint needs. Then **Test connection**
   (`POST .../lightning/test`): it calls the backend and shows its HTTP status and, for LNbits,
   the wallet balance.
2. **Keep `self` OFF** (the default). It mints for free, and free tokens can be melted over
   Lightning for real sats.
3. **Fees and TTL:** `POST .../settings
   {"fee_reserve_pct":100,"fee_reserve_min":10,"quote_ttl_secs":3600}` (the defaults).
   `fee_reserve_pct` is in **basis points** (100 = 1%). The server rejects anything but
   non-negative integers and floors the TTL at 60 s, but it accepts a zero fee reserve: choose
   sane values.
4. **Keyset.** A fresh install already has a current keyset. A mint installed before
   denominations went to 2^20 still has a 1..512 keyset, which caps quotes at 46,592 sats; rotate
   it (runbook §8).
5. **Back up the pier**, encrypted. It holds the keyset **private keys** and the Lightning
   credential. A stale restore reintroduces double-spend risk (runbook §10).

## 5. Verify

```bash
curl https://mint.example.com/v1/info
curl https://mint.example.com/v1/keys
```

In `/v1/info`, nuts `4` and `5` should list only `bolt11` (not `self`); nut `4` with
`max_amount` 83886080 for a current keyset (melts name no maximum). Then point a real Cashu wallet at `https://mint.example.com`,
mint a small amount over Lightning, send and receive, and melt back out.

`demo.mjs` runs the same flow for a dry run on a **test** ship (it needs the mint's Lightning
backend pointed at a mock LNbits). Never run the test suites against a mint holding real value:
they change its settings.

## 6. Before you take other people's money

Read [`operator-runbook.md`](operator-runbook.md), especially §3–4 (melt safety and
stuck-payment recovery, the one place an operator can lose funds), §12 (monitoring) and
§10/§14/§15 (backup, compromise, double-pay). Do a small live test against your real Lightning
backend before announcing the mint URL.
