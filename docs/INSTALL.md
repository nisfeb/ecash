# Installing the ecash mint for public use

This is the path from a clean clone to a publicly-usable Cashu mint. The
money-safety depth lives in [`operator-runbook.md`](operator-runbook.md) — this
is the install + go-public layer on top of it.

## 0. What "public" means here

A Cashu wallet talks to your mint at a **base URL**; the protocol lives under
`/v1/*`. So if your ship is reachable at `https://mint.example.com`, that URL *is*
your mint — wallets hit `https://mint.example.com/v1/info`, `/v1/keys`, etc. The
`/v1` surface is intentionally public and unauthenticated. The operator dashboard
at `/apps/ecash/admin` is gated by your ship login (the Landscape tile opens it).

Four steps: **install the desks → expose the ship over HTTPS → configure for real
value → verify**.

## 1. Prerequisites

- A **real ship** (planet or moon) you control — not a fakeship. Its `%base`
  should be on **zuse kelvin 409** (what the desks pin); watch the `|commit` for
  kelvin build errors and align `desk/sys.kelvin` to your base if it differs.
- A **Lightning backend**: an LNbits instance (URL + an invoice/pay API key) **or**
  an LND node (REST URL + a *pay/invoice-scoped* macaroon — not a node-admin one).
- A **domain + TLS** for the ship (see §3).
- Shell access to the pier host.

## 2. Get and install the desks

```bash
git clone https://github.com/nisfeb/ecash
cd ecash
make sync-libs          # REQUIRED: generates desk-services/lib/{curve,bdhke}.hoon
```

Then, in the ship's **dojo**, install each desk by seeding from `%base` (so it
picks up the base libs/marks) and overlaying the repo files.

**The value mint (`%ecash`):**

```
|merge %ecash our %base
|mount %ecash
```
```bash
# in a shell, copy the repo's desk over the mount:
cp -r desk/* /path/to/your/pier/ecash/
```
```
|commit %ecash          ::  watch for build errors
|install our %ecash
```

**The access/credentials layer (`%ecash-services`) — optional**, install only if
you want zero-value credential / service-access tokens:

```
|merge %ecash-services our %base
|mount %ecash-services
```
```bash
cp -r desk-services/* /path/to/your/pier/ecash-services/
```
```
|commit %ecash-services
|install our %ecash-services
```

On first install, `%ecash` auto-generates a keyset (denominations 1…512), sets
`ln-config` to `%none`, and leaves `self-method` **off** — it comes up safe and
inert until you configure Lightning. The **Cashu Mint** tile appears in Landscape.

> **Alternative build path:** the repo ships `build.sh` (uses [`peru`](https://github.com/buildinspace/peru))
> which bundles the base-dev dependencies into `dist/` for a minimal desk —
> `./build.sh && ./build.sh -p /path/to/pier/ecash`. The merge-from-base path
> above needs no extra tooling and works for both desks.

## 3. Expose the ship over HTTPS

Wallets need a stable public `https://` URL. The standard setup is a **reverse
proxy terminating TLS** in front of the ship's HTTP port:

- Point your domain (`mint.example.com`) at the host.
- Run Caddy or nginx: TLS (Let's Encrypt) → proxy to the ship's loopback HTTP
  port (default `:8080`), **forwarding the `Host` header**.
- The proxy is also where you add **rate limiting** on `/v1/*` — the mint has none
  built in (runbook §13). Cap requests per IP; quote-creation especially (each
  makes an outbound LN call and grows the event log).

Caddy example:

```
mint.example.com {
    reverse_proxy 127.0.0.1:8080
    rate_limit {
        zone v1 { match path /v1/* ; key {remote_host} ; events 60 ; window 1m }
    }
}
```

Your **mint URL for wallets** is then `https://mint.example.com`.

## 4. Configure for real value

Do these from the admin dashboard (`/apps/ecash/admin`) or via the admin API.
Full detail and rationale in [`operator-runbook.md`](operator-runbook.md) §2.

1. **Lightning backend.** Admin → Lightning → configure, or:
   `POST /apps/ecash/admin/api/lightning/configure
   {"type":"lnbits","url":"https://your-lnbits","api_key":"<pay/invoice key>"}`
   (or `{"type":"lnd","url":...,"macaroon":...}`). Use a **least-privilege**
   credential — it is stored in pier state.
2. **Confirm `self-method` is OFF** (the default). Never enable it on a value mint
   — it mints/melts for free.
3. **Set fees / TTL:** `POST .../settings
   {"fee_reserve_pct":100,"fee_reserve_min":10,"quote_ttl_secs":3600}` (these are
   the defaults). ⚠️ The server does **not** bounds-check these — set sane values.
4. **Keyset:** start on the freshly-generated one; rotate later via generate →
   activate.
5. **Back up the pier** (encrypted) — it holds your keyset **private keys** and the
   LN credential. A stale restore reintroduces double-spend risk (runbook
   §10/§11/§14).

## 5. Verify

```bash
# public, no auth — once LN is configured this lists 'bolt11' under nut 4/5:
curl https://mint.example.com/v1/info
curl https://mint.example.com/v1/keys
```

Then point a real Cashu wallet at `https://mint.example.com`, mint a small amount
over Lightning, send/receive, and melt back out. The repo's `demo.mjs`
(`npm run demo`) mirrors that whole flow against a mock if you want a scripted
dry-run first.

## 6. Before you take other people's money

Read [`operator-runbook.md`](operator-runbook.md) — especially §3–4 (melt safety
and stuck-payment recovery, the one place an operator can lose funds), §12
(monitoring: stuck `PENDING` melts, liability, disk/event-log), and §10/§14/§15
(backup, key/pier-compromise, double-pay incident response). Do a small live
shakedown against your real Lightning node before announcing the mint URL.
