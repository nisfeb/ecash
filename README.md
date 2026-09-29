# ecash

A Cashu ecash mint implemented in Hoon, running as a Gall agent on Urbit.

## Overview

A [Cashu](https://cashu.space) mint with blind Diffie-Hellman key exchange (BDHKE) over
secp256k1, written in Hoon. It mints, melts and swaps ecash tokens, pays and receives over
Lightning (LNbits or LND), and has an admin dashboard.

The mint runs inside your Urbit identity, is served by your ship's HTTP server, and keeps all
state in the ship's event log. The elliptic-curve math for BDHKE, DLEQ and hash-to-curve is
**pure Hoon** (`lib/curve.hoon`, `lib/bdhke.hoon`), with no jets. P2PK signature checks use
zuse's BIP-340 verify, which the runtime jets.

Next to the mint, a second desk, **`%tessera`**, issues **access tokens** rather than money:
passes, credits, tickets and invites, as Cashu NUT-22 blind auth tokens. Each service is its
own auth mint that a cashu-ts `AuthManager` works against, and ships get, present, check and
hand over tokens over Ames. See [`docs/tessera.md`](docs/tessera.md).

## Supported NUTs

| NUT | Name | Status |
|-----|------|--------|
| 00 | Cryptography | BDHKE on secp256k1, DLEQ proofs |
| 01 | Mint public keys | `GET /v1/keys` |
| 02 | Keysets and fees | `GET /v1/keysets`, `GET /v1/keys/{id}`, per-keyset `input_fee_ppk` |
| 03 | Swap | `POST /v1/swap` |
| 04 | Mint (bolt11, self) | `POST /v1/mint/quote/{method}`, `POST /v1/mint/{method}` |
| 05 | Melt (bolt11, self) | `POST /v1/melt/quote/{method}`, `POST /v1/melt/{method}` |
| 06 | Mint info | `GET /v1/info` |
| 07 | Token state check | `POST /v1/checkstate` (`UNSPENT`, `PENDING`, `SPENT`) |
| 08 | Lightning fee return | Melt change: unused fee reserve plus any overpayment |
| 09 | Restore | `POST /v1/restore` (seed-phrase recovery for NUT-13 wallets) |
| 10 | Spending conditions | Well-known secrets `["kind", {nonce, data, tags}]`; only `P2PK` is accepted |
| 11 | P2PK | Schnorr signatures, multisig, locktime, refund keys (`SIG_INPUTS` only) |
| 12 | DLEQ proofs | On every signature the mint returns |

## Project structure

The mint and the access tokens are **two Gall agents on two desks**. They share the crypto,
blind-signature and HTTP libraries, whose single source is `desk/lib`.

```
desk/                      installs as %ecash (the value mint)
  app/ecash.hoon           agent: state and I/O (Cashu /v1/*, /apps/ecash/admin)
  app/dashboard.txt        admin dashboard HTML/JS
  sur/ecash.hoon           shared types (keyset, quotes, ln-backend, ...)
  lib/ecash-rules.hoon     the mint's rules as pure arms (checks, signing, P2PK, Lightning answers)
  lib/blind.hoon           keys, keyset ids, signing with DLEQ, token checks (shared)
  lib/ecash-http.hoon      HTTP/JSON plumbing and request caps          (shared)
  lib/bdhke.hoon           BDHKE, hash-to-curve, DLEQ, BIP-340 verify    (shared)
  lib/curve.hoon           secp256k1 point arithmetic                    (shared)
desk-tessera/              installs as %tessera (access tokens, no value)
  app/tessera.hoon         agent: /tessera/<service>/*, Ames pokes, /apps/tessera
  app/tessera-demo.hoon    a guestbook gated by tokens: the integration example
  lib/tessera-rules.hoon   its rules as pure arms
  sur/tessera.hoon, mar/tessera/action.hoon
  lib/, mar/ shared files  copied from desk/ by build.sh or `make sync-libs` (gitignored)
tests/lib/*.hoon           Hoon unit suites (see docs/hoon-testing.md)
test-*.mjs, run-tests.mjs  JS suites against a running ship
mock-lnbits.mjs            mock LNbits for the Lightning suites and the demo
```

## Installation

Build the desks (requires [peru](https://github.com/buildinspace/peru)), then install on your
ship. The desks declare `[%zuse 408]`.

```bash
git clone https://github.com/nisfeb/ecash && cd ecash
./build.sh          # builds dist/ (%ecash) and dist-tessera/ (%tessera)
```

In the dojo, create and mount the desk; then deploy the built desk into the mount and commit:

```
|new-desk %ecash
|mount %ecash
```
```bash
./build.sh -p /path/to/your/pier/ecash    # wipes the mounted desk and copies dist/ into it
```
```
|commit %ecash
|install our %ecash
```

On first install the mint generates a keyset with 21 denominations (1, 2, 4, … 2^20 sats), sets
Lightning to `none` and leaves the free `self` method off, so it is inert until you configure it.

To also issue access tokens, install **`%tessera`** the same way (`./build.sh tessera -p
<pier>/tessera`); see [`docs/tessera.md`](docs/tessera.md).

**Running a public mint?** Read [`docs/INSTALL.md`](docs/INSTALL.md) (HTTPS, reverse proxy, rate
limiting, Lightning, pre-production checks) and
[`docs/operator-runbook.md`](docs/operator-runbook.md).

---

## Demo

`demo.mjs` is a narrated walkthrough of the ecash lifecycle against a running mint: deposit over
Lightning, pay a peer with a swap, a refused double-spend, and a melt back to Lightning with
NUT-08 change. The crypto is real; a mock LNbits stands in for Lightning, so run it on a test
ship, never on a mint holding real value.

```
npm run mock:lnbits                          # mock Lightning backend on :3338
# point the mint's Lightning backend at it (the demo prints the command), then:
SHIP_URL=http://localhost:8080 npm run demo  # paced for a live audience
SHIP_URL=http://localhost:8080 node demo.mjs --fast --amount 250   # no pauses; 12–1000 sats
```

`SHIP_URL` is required. `MOCK_URL` and `API_KEY` override the mock's address and key.

---

## Cashu protocol endpoints

All public, no authentication:

| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/info` | Mint info (NUT-06) |
| GET | `/v1/keys` | Active keysets with public keys (NUT-01) |
| GET | `/v1/keys/{keyset_id}` | One keyset, active or not (NUT-02) |
| GET | `/v1/keysets` | All keysets, metadata only (NUT-02) |
| POST | `/v1/swap` | Swap tokens (NUT-03) |
| POST | `/v1/mint/quote/{method}` | Create mint quote (NUT-04) |
| GET | `/v1/mint/quote/{method}/{quote_id}` | Check mint quote (NUT-04) |
| POST | `/v1/mint/{method}` | Mint tokens from a paid quote (NUT-04) |
| POST | `/v1/melt/quote/{method}` | Create melt quote (NUT-05) |
| GET | `/v1/melt/quote/{method}/{quote_id}` | Check melt quote (NUT-05) |
| POST | `/v1/melt/{method}` | Melt tokens to pay an invoice (NUT-05) |
| POST | `/v1/checkstate` | Token state (NUT-07) |
| POST | `/v1/restore` | Signatures for re-derived blinded messages (NUT-09) |

Every response carries `Access-Control-Allow-Origin: *` and `cache-control: no-store`, and the
mint answers CORS preflight (`OPTIONS`) on the public routes, so browser wallets work without
proxy CORS config. Errors are `{"detail": "<code>"}` with a 4xx/5xx status.

### Limits

| Limit | Value | Error |
|-------|-------|-------|
| Inputs, outputs, `Ys` or restore outputs per request | 100 | `batch-too-large` |
| Request body | 1 MiB | `body-too-large` |
| Proof secret | 2048 bytes | `secret-too-long` |
| Mint amount | `max_amount` in `/v1/info` (nut 4) | `amount-too-large` |
| P2PK keys in a lock, signatures in a witness | 10 | the spend fails |

The secret cap leaves room for the largest P2PK lock the key limits allow (about 1.6 KB): the
mint can't see a secret before it is spent, so a smaller cap would freeze tokens it issued.
`max_amount` is the most the active keyset can mint in 100 outputs: `(100 − m) × 2^m` when its
largest denomination is 2^m. That is 83,886,080 sats for a keyset made now (2^0..2^20) and 46,592
sats for an older 1..512 keyset. Melts name no maximum: they are bounded by the inputs a wallet
can send. `/v1/info` lists `self` only while it is enabled and `bolt11` only while a Lightning
backend is configured.

### Swap and mint are all-or-nothing

Every output is checked before anything is spent. An output that can't be signed refuses the
whole request with a 400: `invalid-msg`, `missing-B_`, `invalid-B_-point`, `duplicate-output`,
`output-already-signed` (that B_ was signed before; NUT-13 wallets use this to recover their
counter), `unknown-keyset`, `inactive-keyset`, `unknown-denomination`. Swaps and melts whose
claimed amounts don't balance are refused (`amounts-do-not-balance`, `insufficient-inputs`,
`fee-exceeds-inputs`) before any elliptic-curve work.

### Mint methods

- **`bolt11`**: Lightning. Needs a configured backend.
- **`self`**: mints and melts with no payment at all. **Off by default.** Enable it
  (`self_method_enabled`) only on a test mint: on a mint with a real Lightning backend, free
  `self` tokens can be melted over bolt11 for real sats. A melt quote settles only by the method
  that created it (`method-mismatch`).

### Flows

**Mint (deposit):**
```
POST /v1/mint/quote/bolt11   {"amount": 100, "unit": "sat"}
→ {"quote": "abc…", "request": "lnbc1u1…", "unit": "sat", "amount": 100, "state": "UNPAID", "expiry": 1760000000}

# pay the invoice, then poll:
GET /v1/mint/quote/bolt11/abc…
→ {"state": "PAID", …}

POST /v1/mint/bolt11   {"quote": "abc…", "outputs": [{"amount": 64, "id": "01…", "B_": "02…"}, …]}
→ {"signatures": [{"C_": "03…", "amount": 64, "id": "01…", "dleq": {"e": "…", "s": "…"}}, …]}
```

A quote poll answers at once with the stored state and asks Lightning in the background; a later
poll sees the change. A `PAID` quote can be minted even after it expires.

**Melt (withdraw):**
```
POST /v1/melt/quote/bolt11   {"request": "lnbc500n1…", "unit": "sat"}
→ {"quote": "def…", "amount": 50, "fee_reserve": 10, "state": "UNPAID", …}

POST /v1/melt/bolt11   {"quote": "def…", "inputs": [proofs…], "outputs": [blank outputs…]}
→ {"state": "PAID", "payment_preimage": "…", "change": [signatures…], …}
```

- Inputs must cover `amount + fee_reserve` after input fees.
- The `request` must be letters and digits only (`invalid-request`). With LNbits, an invoice
  for a fraction of a sat is quoted at the next whole sat.
- Change (NUT-08) is the unused fee reserve **plus** anything the inputs paid beyond
  `amount + fee_reserve` and the input fee. It is split into powers of two, largest first, and signed onto the
  blank outputs in order. **Send enough blank outputs**: change that doesn't fit is kept by the
  mint.
- If the payment's outcome is not yet known the answer is `"state": "PENDING"`. Poll the quote;
  don't re-submit (`quote-pending`). While a melt is `PENDING`, `/v1/checkstate` reports its
  proofs as `PENDING`: they come back if the payment fails.

**Swap:**
```
POST /v1/swap
{"inputs":  [{"amount": 4, "id": "01…", "secret": "…", "C": "03…"}],
 "outputs": [{"amount": 2, "id": "01…", "B_": "02…"}, {"amount": 2, "id": "01…", "B_": "02…"}]}
→ {"signatures": [{"C_": "03…", "amount": 2, "id": "01…", "dleq": {…}}, …]}
```
`sum(inputs) − fee == sum(outputs)`, where fee is `ceil(sum of each input's keyset input_fee_ppk / 1000)`.

**P2PK (NUT-11):**
```
secret  = '["P2PK", {"nonce": "…", "data": "02<recipient pubkey>", "tags": []}]'
witness = '{"signatures": ["<BIP-340 signature over SHA256(secret)>"]}'   # a JSON string
```
Multisig (`n_sigs`, `pubkeys`), `locktime` and `refund` / `n_sigs_refund` tags work. Only
`SIG_INPUTS` is supported (`unsupported-sigflag`), and other NUT-10 kinds such as HTLC are refused
(`unsupported-spending-condition`). **Keep locks to 10 keys:** if the `data` key plus `pubkeys`
number more than 10, those keys can never spend the token (likewise more than 10 `refund`
keys), and a witness with more than 10 signatures is refused.

---

## Lightning backend

- **LNbits**: `{"type": "lnbits", "url": "…", "api_key": "…"}`. The key must be able to pay
  invoices. **Use LNbits for real funds.**
- **LND**: `{"type": "lnd", "url": "…", "macaroon": "…"}`. The LND path has **never been tested
  against a real LND node**, and its payment-status lookup (`GET /v1/payment/{hash}`) is
  unverified: a melt left `PENDING` on LND may resolve only through the admin abort (see the
  runbook).

Configure it from the dashboard, the admin API, or the dojo:
```
:ecash [%lnbits 'https://your-lnbits' 'your-api-key']
```

### Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `fee_reserve_pct` | 100 | Melt fee reserve in **basis points** of the amount (100 = 1%) |
| `fee_reserve_min` | 10 | Minimum fee reserve, sats |
| `quote_ttl_secs` | 3600 | Quote and invoice lifetime; the server floors it at 60 |
| `self_method_enabled` | false | The no-payment `self` method (test mints only) |

`POST /settings` accepts any subset. Numbers must be bare non-negative integers and
`self_method_enabled` a boolean, else `400 invalid-<field>` and nothing changes.

---

## Admin dashboard

`GET /apps/ecash/admin` (your ship's login) has six tabs: Overview (liability, quote counts,
settings), Keysets (generate, activate, deactivate, set fee), Quotes (delete, revoke, abort and
force-abort stuck melts), Tokens (spent lookups), Lightning (configure, test) and Info (NUT-06
name and description). Its CSP runs only its own nonce'd script and allows no form posts.

`%tessera` has its own dashboard at `/apps/tessera`.

## Admin API (`%ecash`)

Base path `/apps/ecash/admin/api`. Every call needs your ship's session cookie
(`401 unauthorized` without it). A state-changing request that sends `Origin` or `Referer` must
name the same host as `Host` (`403 forbidden-cross-origin`); requests sending neither (curl,
scripts) pass. Behind a proxy, forward the `Host` header (`X-Forwarded-Host` is not trusted).

| Method | Path | Body | Description |
|--------|------|------|-------------|
| GET | `/overview` | — | Keyset, counters, `total_issued_sats` / `total_redeemed_sats`, quote tallies, backend |
| GET | `/keysets` | — | All keysets: `id`, `active`, `input_fee_ppk`, `key_count`, `denominations`, `created` |
| GET | `/keysets/{id}` | — | One keyset with its public keys |
| GET | `/quotes` | — | `mint_quotes` and `melt_quotes`, each with `method`, `state`, `expiry` |
| GET | `/spent` | — | Spent secret and Y counts |
| GET | `/lightning` | — | `{type, configured, url, api_key_set}`; the credential is never returned |
| GET | `/info` | — | Same as `/v1/info` |
| GET | `/settings` | — | `{fee_reserve_pct, fee_reserve_min, quote_ttl_secs, self_method_enabled}` |
| POST | `/keysets/generate` | — | New **inactive** keyset (2^0..2^20) → `{id, active, key_count}` |
| POST | `/keysets/activate` | `{id}` | Make it the active keyset; the previous one goes inactive |
| POST | `/keysets/deactivate` | `{id}` | Refuses the active keyset (`cannot-deactivate-active`) |
| POST | `/keysets/set-fee` | `{id, input_fee_ppk}` | **Forks** to fresh keys under a new id; the old id stays as an inactive alias. Max 100000 → `{old_id, new_id, input_fee_ppk}` |
| POST | `/quotes/delete` | `{quote_id, type}` | `type` is `mint` or `melt`. Refused for PAID/ISSUED mint quotes and PAID/PENDING melts |
| POST | `/quotes/revoke` | `{quote_id}` | **Destructive.** Deletes any mint quote, even PAID or ISSUED; an ISSUED quote's amount comes off total issued |
| POST | `/melt/abort` | `{quote_id, force?, secrets?, ys?}` | Resolve a stuck PENDING bolt11 melt (runbook §4) |
| POST | `/spent/check` | `{secret}` or `{Y}` | Is it spent? |
| POST | `/lightning/configure` | `{type:"none"}`, `{type:"lnbits", url, api_key}` or `{type:"lnd", url, macaroon}` | Set the backend |
| POST | `/lightning/test` | — | Calls the backend (LNbits `GET /api/v1/wallet`, LND `GET /v1/getinfo`) → `{status, type, url, http_status, detail?, balance_msat?}` |
| POST | `/info/update` | `{name?, description?}` | NUT-06 name and description |
| POST | `/settings` | any of the settings | Validated (see above); answers the full settings |

A revoked PAID quote is a customer's deposit that was never minted: revoking it means they can
never mint it. Only do that after refunding them some other way.

---

## Access tokens (`%tessera`)

Services, policies (open, client keys, ships, ship rank), quotas, windows, check and burn
modes, the NUT-22 routes, the Ames holder API and gating an app are in
[`docs/tessera.md`](docs/tessera.md).

---

## Cryptography

### secp256k1

All point arithmetic is pure Hoon in `lib/curve.hoon`. Every scalar multiplication, public keys
included, runs a fixed-length Montgomery ladder in Jacobian coordinates (257 steps for every
scalar). zuse's `priv-to-pub` is not used. Because none of this is jetted, each signature or
proof check costs real CPU on the ship (`npm run bench` times signing, on a test ship: it turns
on the `self` method).

### BDHKE

```
Wallet:  Y  = hashToCurve(secret)
         B_ = Y + r·G                  (blinded message)
Mint:    C_ = k·B_                     (blind signature)
Wallet:  C  = C_ − r·K                 (unblind; K = k·G)
Verify:  C == k·hashToCurve(secret)
```

### DLEQ proofs

Every blind signature carries a NUT-12 DLEQ proof that the mint used the key it publishes. The
proof nonce is bound to the full B_ and C_ points.

### Hash-to-curve

```
msg_hash = SHA256("Secp256k1_HashToCurve_Cashu_" || secret)
for counter = 0, 1, 2, …:
  x = SHA256(msg_hash || counter as 4 little-endian bytes)
  if 02||x is a point on the curve: return it
```

---

## Testing

**JS suites** run against a live ship. They need Node.js (the version in `package.json`
`engines`) and `npm install`:

```bash
npm install
SHIP_URL=http://localhost:8080 URBAUTH_COOKIE='urbauth-~zod=0v…' npm run test:all
npm run test:p2pk        # one suite
```

- They need both `%ecash` and `%tessera` installed on the ship. `test-tessera-ships.mjs` needs
  three ships and runs on its own (see [`docs/tessera.md`](docs/tessera.md#testing)).
- The Lightning suites use a mock LNbits (`mock-lnbits.mjs`).
- Suites that change mint settings refuse a `SHIP_URL` that isn't this machine unless
  `ALLOW_DESTRUCTIVE=1`. **Never run the suites against a mint holding real value.**

**Hoon unit suites** live in `tests/lib/*.hoon` and run on a separate `%ecash-test` desk with the
vendored hoon-test-kit: `scripts/hoon-test-kit/hoon-test.sh <pier>` (config in `hoon-test.conf`).
See [`docs/hoon-testing.md`](docs/hoon-testing.md).

---

## State

The `%ecash` agent is at **state 15**. It loads state 13 or later; a mint below 13 must first
upgrade through commit `eb7b56a`. Access tokens live in `%tessera` (state 0).

| Field | Type | Description |
|-------|------|-------------|
| `keysets` | `(map @t keyset)` | Value keysets (public and private keys, unit, fee) |
| `active-keyset` | `@t` | The keyset new outputs are signed with |
| `spent` / `spent-ys` | `(set @t)` | Spent secrets and Y points |
| `counter` | `@ud` | Value signatures issued |
| `mint-quotes` / `melt-quotes` | `(map @t …-quote)` | Quotes |
| `ln-config` | `ln-backend` | Lightning backend (`lnbits`, `lnd` or `none`) |
| `pending` | `(map @ta pending-req-v2)` | In-flight Lightning HTTP requests |
| `total-issued-sats` / `total-redeemed-sats` | `@ud` | Liability counters |
| `mint-name` / `mint-description` | `@t` | NUT-06 metadata |
| `fee-reserve-pct` / `fee-reserve-min` | `@ud` | Melt fee reserve (basis points, sats) |
| `quote-ttl-secs` | `@ud` | Quote lifetime |
| `melt-change` | `(map @t (list json))` | NUT-08 change signatures by melt quote id |
| `self-method-enabled` | `?` | The no-payment `self` method (default off) |
| `melt-inflight` | `(map @t melt-inflight-entry)` | Per PENDING bolt11 melt: the secrets and Ys it spent, input total, blank change outputs, overpayment. Survives restarts |
| `restore` | `(map @t restored-sig)` | Every issued signature by its B_, for NUT-09 restore and `output-already-signed` |

## License

[PolyForm Noncommercial License 1.0.0](LICENSE.md): source-available, free for noncommercial
use. See `LICENSE.md`.

## Security

This mint handles value. Before running it against real money, read
[`docs/operator-runbook.md`](docs/operator-runbook.md) (melt safety, stuck-payment recovery,
backup, incident response), start on a freshly generated keyset, and do a small live test
against your Lightning backend. Known limits:

- **CPU is the attack surface.** Pure-Hoon elliptic-curve math makes each request expensive (a
  100-proof swap takes seconds of ship CPU) and the ship handles one event at a time. There is
  no rate limit in the mint; a rate-limiting reverse proxy is the main abuse control
  ([`docs/INSTALL.md`](docs/INSTALL.md)).
- **LND is untested** against a real node. Use LNbits for real funds.
- **`self` method**: never enable it on a mint with a real Lightning backend.
- **Response readable by another ship.** An agent can't tell eyre's requests from a remote
  ship's subscription, so a foreign ship that guessed an in-flight request id could read that
  response.
