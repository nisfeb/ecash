# ecash

A Cashu ecash mint implemented in Hoon, running as a Gall agent on Urbit.

## Overview

A fully functional [Cashu](https://cashu.space) mint that implements blind Diffie-Hellman key exchange (BDHKE) with real secp256k1 cryptography, entirely in Hoon. It supports minting, melting, and swapping ecash tokens with Lightning Network integration and an admin dashboard.

The mint is self-sovereign: it runs inside your Urbit identity, is accessible via your ship's HTTP interface, and stores all state in Urbit's event log (crash-recoverable). The cryptography is implemented in **pure Hoon** with no external dependencies or native jets for BDHKE operations.

Beyond standard Cashu, the mint includes two extensions for non-value-bearing use cases:

- **Credential token extension** — raw `/cred/v1` endpoints for issuing zero-value blind-signed tokens (power-user / library consumers).
- **Services layer** — a higher-level access-control layer built on top of credentials. Each service is a named scope with its own keyset, optional expiration, issuance cap, and per-service API-key allowlist. The dashboard surfaces services as a distinct tab and visually delineates "value-bearing" (sats) vs "access" (services) everywhere.

## Supported NUTs

| NUT | Name | Status |
|-----|------|--------|
| 00 | Cryptography | BDHKE with secp256k1, DLEQ proofs |
| 01 | Mint public keys | `GET /v1/keys` |
| 02 | Keysets | `GET /v1/keysets`, `GET /v1/keys/{id}`, per-keyset `input_fee_ppk` |
| 03 | Swap | `POST /v1/swap` |
| 04 | Mint (bolt11 + self) | `POST /v1/mint/quote/{method}`, `POST /v1/mint/{method}` |
| 05 | Melt (bolt11 + self) | `POST /v1/melt/quote/{method}`, `POST /v1/melt/{method}` |
| 06 | Mint info | `GET /v1/info` |
| 07 | Token state check | `POST /v1/checkstate` |
| 10 | Well-known secrets | Structured secret format `["kind", {nonce, data, tags}]` |
| 11 | P2PK | Pay-to-public-key with Schnorr signatures, multisig, locktime, refund |
| 12 | DLEQ proofs | Included in all mint/swap responses |

## Project Structure

The mint and the access-control extensions are **two separate Gall agents**:
`%ecash` (the value mint) and `%ecash-services` (zero-value credentials + the services
layer). They share the secp256k1/BDHKE crypto, whose single source of truth is `desk/lib`.

```
desk/                    → installs as %ecash (the value mint)
  app/ecash.hoon         Main Gall agent (Cashu /v1/* + /apps/ecash/admin)
  app/dashboard.txt      Admin dashboard HTML/JS, imported via /* at build time
  sur/ecash.hoon         Shared types (keyset, quote, ln-backend, ...)
  lib/bdhke.hoon         BDHKE protocol, hash-to-curve, DLEQ proofs   (canonical)
  lib/curve.hoon         secp256k1 point arithmetic (pure Hoon)       (canonical)
  mar/txt.hoon           Override for %txt mark (handles raw HTML asset import)
  tests/test.hoon        Hoon unit tests
desk-services/           → installs as %ecash-services (cred + services, non-value)
  app/ecash-services.hoon  Serves /cred/v1/*, /services/v1/*, /apps/ecash-services/admin
  sur/ecash-services.hoon  cred-keyset / service types
  lib/{curve,bdhke}.hoon   generated from desk/lib (gitignored; `make sync-libs`)
test-e2e.mjs             End-to-end mint/swap/checkstate/melt flow (9 assertions)
test-vectors.mjs         NUT-00 hash-to-curve official test vectors (3 vectors)
test-p2pk.mjs            P2PK/NUT-11 coverage (8 tests)
test-cred.mjs            Credential extension (31 tests)
test-services.mjs        Services layer: creation, allowlist, expiry, replay (34 tests)
test-lightning.mjs       bolt11 Lightning integration (requires mock-lnbits)
mock-lnbits.mjs          Mock LNbits server for Lightning testing
```

## Installation

Build both desks (requires [peru](https://github.com/buildinspace/peru)), then
install on your ship:

```bash
git clone https://github.com/nisfeb/ecash && cd ecash
./build.sh          # builds dist/ (%ecash) and dist-services/ (%ecash-services)
```

In the dojo, create and mount the desk; then deploy the built desk into the mount
and commit:

```
|new-desk %ecash
|mount %ecash
```
```bash
./build.sh -p /path/to/your/pier/ecash    # copies the built desk into the mount
```
```
|commit %ecash
|install our %ecash
```

The mint generates a keyset with 10 denominations (1, 2, 4, 8, 16, 32, 64, 128, 256, 512 sats) on first install — with Lightning off (`%none`) and the free `self` method disabled, so it's safe until you configure it.

To also run the zero-value credentials/access layer, install **`%ecash-services`** the same way:

```
|new-desk %ecash-services
|mount %ecash-services
```
```bash
./build.sh services -p /path/to/your/pier/ecash-services
```
```
|commit %ecash-services
|install our %ecash-services
```

**Running a public mint?** See [`docs/INSTALL.md`](docs/INSTALL.md) for the full
walkthrough — installing both desks, exposing the ship over HTTPS with a
rate-limiting reverse proxy, configuring the Lightning backend, and the
pre-production safety checklist.

---

## Demo

`demo.mjs` is a narrated, presentation-paced walkthrough of the whole ecash
lifecycle against a running mint — useful for showing the system to others. In
five acts (Alice & Bob) it: meets the mint, deposits sats over Lightning to
receive blind-signed ecash, pays a peer via a swap, shows that double-spending is
rejected, and cashes out back to Lightning with NUT-08 change. The crypto is real
BDHKE; no real money moves (a mock LNbits backend simulates the Lightning side).

```
npm run mock:lnbits        # start the mock Lightning backend on :3338
# configure the mint to use it (admin), then:
npm run demo               # narrated, paced for a live audience
node demo.mjs --fast       # same flow, no pauses
node demo.mjs --amount 250 # vary Alice's deposit (12–1000 sats)
```

If a prerequisite is missing (mint unreachable, no Lightning backend, mock not
running) the demo prints the exact command to fix it instead of failing. Override
endpoints with `SHIP_URL`, `MOCK_URL`, and `API_KEY` env vars.

---

## Cashu Protocol Endpoints

All standard Cashu endpoints are unauthenticated, served at `/v1/*`:

| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/info` | Mint info (NUT-06) |
| GET | `/v1/keys` | Active keyset public keys (NUT-01) |
| GET | `/v1/keys/{keyset_id}` | Keys for specific keyset (NUT-02) |
| GET | `/v1/keysets` | Keyset metadata (NUT-02) |
| POST | `/v1/swap` | Swap tokens (NUT-03) |
| POST | `/v1/mint/quote/{method}` | Create mint quote (NUT-04) |
| GET | `/v1/mint/quote/{method}/{quote_id}` | Check mint quote (NUT-04) |
| POST | `/v1/mint/{method}` | Mint tokens from paid quote (NUT-04) |
| POST | `/v1/melt/quote/{method}` | Create melt quote (NUT-05) |
| GET | `/v1/melt/quote/{method}/{quote_id}` | Check melt quote (NUT-05) |
| POST | `/v1/melt/{method}` | Melt tokens to pay invoice (NUT-05) |
| POST | `/v1/checkstate` | Check token spent state (NUT-07) |

### Mint Methods

- **`self`** — Instant minting/melting with no Lightning required. Useful for testing and on-ship token operations. **Disabled by default** on a value-bearing mint; enable it via the admin Settings (`self_method_enabled`) for testing.
- **`bolt11`** — Lightning Network integration. Requires a configured Lightning backend.

### Standard Flows

**Minting tokens (deposit):**
```
POST /v1/mint/quote/bolt11   {"amount": 100}
→ {"quote": "abc123", "request": "lnbc100n1...", "state": "UNPAID", ...}

# User pays the Lightning invoice, then:
GET /v1/mint/quote/bolt11/abc123
→ {"state": "PAID", ...}

POST /v1/mint/bolt11   {"quote": "abc123", "outputs": [{B_: "02...", amount: 1}, ...]}
→ {"signatures": [{C_: "03...", amount: 1, dleq: {...}}, ...]}
```

**Melting tokens (withdraw):**
```
POST /v1/melt/quote/bolt11   {"request": "lnbc50n1..."}
→ {"quote": "def456", "amount": 50, "fee_reserve": 10, "state": "UNPAID", ...}

POST /v1/melt/bolt11   {"quote": "def456", "inputs": [{C: "03...", secret: "...", amount: 1, id: "01..."}, ...]}
→ {"state": "PAID", "payment_preimage": "abc..."}
```

**Swapping tokens:**
```
POST /v1/swap
{
  "inputs": [{C: "03...", secret: "old-secret", amount: 4, id: "01..."}],
  "outputs": [{B_: "02...", amount: 2}, {B_: "02...", amount: 2}]
}
→ {"signatures": [{C_: "03...", amount: 2, dleq: {...}}, ...]}
```

**P2PK tokens (NUT-11):**
```
# Secret locks token to recipient's public key:
secret = '["P2PK", {"nonce": "abc", "data": "02recipient_pubkey...", "tags": []}]'

# Recipient signs SHA256(secret) with their private key to spend:
witness = '{"signatures": ["schnorr_sig_hex"]}'

POST /v1/swap
{"inputs": [{C: "...", secret: "...", amount: 1, id: "...", witness: "..."}], "outputs": [...]}
```

Supports multisig (`n_sigs` + `pubkeys` tags), locktime, and refund keys.

---

## Lightning Backend

The mint supports two Lightning backends:

- **LNbits** — `{type: "lnbits", url: "...", api_key: "..."}`
- **LND** — `{type: "lnd", url: "...", macaroon: "..."}`

Configure via the admin dashboard, admin API, or dojo:
```
:ecash [%lnbits 'http://your-lnbits:5000' 'your-api-key']
```

### Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `fee_reserve_pct` | 100 (1%) | Fee reserve percentage in basis points |
| `fee_reserve_min` | 10 | Minimum fee reserve in sats |
| `quote_ttl_secs` | 3600 | Quote time-to-live in seconds |
| `self_method_enabled` | false | Enable the no-payment `self` mint/melt method (testing only) |

---

## Admin Dashboard

`GET /apps/ecash/admin` serves a single-page admin UI (authenticated via the ship cookie) with six tabs:

- **Overview** — Mint/melt quote summaries, active keyset, liability counters, settings form
- **Keysets** — List, generate, activate/deactivate, set fees, view denomination keys
- **Quotes** — Filterable list (all/mint/melt/unpaid/paid/issued), delete
- **Tokens** — Spent counts, check secret/Y-point status
- **Lightning** — Backend status, configure/remove, connection info
- **Info** — NUT-06 mint name/description, edit form

Stats bar shows: tokens issued/spent, issued/redeemed/outstanding sats, LN backend, pending requests.

Service and credential management lives in the separate `%ecash-services` agent, which serves its own dashboard at `/apps/ecash-services/admin` (see the Credential and Services sections below).

## Admin API

All admin endpoints require the ship's auth cookie. Unauthenticated requests receive `401 unauthorized`. Base path: `/apps/ecash/admin/api`

### Read endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/overview` | Mint stats (keysets, quotes, issued/redeemed sats, LN status) |
| GET | `/keysets` | All keysets with full detail |
| GET | `/keysets/{id}` | Single keyset detail |
| GET | `/quotes` | All mint and melt quotes |
| GET | `/spent` | Spent token counts |
| GET | `/lightning` | Lightning backend status |
| GET | `/info` | Mint name and description |
| GET | `/settings` | Fee reserve and quote TTL settings |

### Write endpoints

| Method | Path | Body | Description |
|--------|------|------|-------------|
| POST | `/keysets/generate` | — | Generate new keyset (inactive) |
| POST | `/keysets/activate` | `{id}` | Activate keyset (deactivates previous) |
| POST | `/keysets/deactivate` | `{id}` | Deactivate keyset |
| POST | `/keysets/set-fee` | `{id, fee}` | Set `input_fee_ppk` (recomputes keyset ID) |
| POST | `/quotes/delete` | `{type, id}` | Delete a quote |
| POST | `/spent/check` | `{secret}` or `{Y}` | Check if secret/Y-point is spent |
| POST | `/lightning/configure` | `{type, url, api_key\|macaroon}` | Configure LN backend |
| POST | `/lightning/test` | — | Test LN connection |
| POST | `/info/update` | `{name, description}` | Update mint name/description |
| POST | `/settings` | `{fee_reserve_pct, fee_reserve_min, quote_ttl_secs}` | Update settings |
| GET | `/services` | — | List all services with full allowlist keys |
| GET | `/services/{name}` | — | Service detail including allowlist |
| POST | `/services/create` | `{name, title, description, expires?, max_issuance?}` | Create service (auto-generates backing cred keyset) |
| POST | `/services/update` | `{name, title?, description?, expires?, max_issuance?}` | Patch metadata |
| POST | `/services/activate` | `{name}` | Reopen a deactivated service |
| POST | `/services/deactivate` | `{name}` | Close issue/verify/redeem for a service |
| POST | `/services/delete` | `{name}` | Delete (only when inactive and never issued) |
| POST | `/services/allowlist/add` | `{name, key}` | Add an API access key to a service |
| POST | `/services/allowlist/remove` | `{name, key}` | Remove an API access key |

---

## Credential Token Extension

> **Phase 3:** the credential and services layers run as a **separate `%ecash-services` agent**
> (desk `desk-services/`). Public endpoints are `/cred/v1/*` and `/services/v1/*`; the admin API
> base is `/apps/ecash-services/admin/api/`. Install with `|install our %ecash-services`. The
> sections below describe its behavior.

The credential extension enables issuing **zero-value tokens** that serve as access credentials rather than value-bearing ecash. This is a non-standard extension that does not affect Cashu protocol compliance.

### Use Case

A "space" or application gates access behind payment:

1. **User pays** — sends real ecash tokens to the space application
2. **Space redeems payment** — swaps/verifies the value tokens via the standard Cashu API
3. **Space issues credentials** — requests N credential tokens (e.g., 30 daily login passes) from the mint via `/cred/v1/issue`
4. **User presents credentials** — one token per day; the space app verifies via `/cred/v1/verify` and consumes via `/cred/v1/redeem`

### Design Principles

- Credential keysets are **completely separate** from value keysets
- Credential keyset IDs use prefix `c0` (value keysets use `01`) — no collision possible
- All credential tokens have `amount: 0` — non-zero amounts are rejected
- Credential spent set is separate from the value token spent set
- Same BDHKE + DLEQ cryptography as value tokens
- No modification to any `/v1/*` Cashu endpoint

### Credential Endpoints

Accessible at `/cred/v1/*` (authenticated) and `/cred/v1/*` (when Eyre binding is active):

| Method | Path | Description |
|--------|------|-------------|
| GET | `/cred/v1/keys` | Active credential keyset public keys |
| GET | `/cred/v1/keys/{keyset_id}` | Specific credential keyset keys |
| GET | `/cred/v1/keysets` | Credential keyset metadata (IDs + active status) |
| POST | `/cred/v1/issue` | Issue credential tokens (blind sign) |
| POST | `/cred/v1/verify` | Check validity + spent status (read-only) |
| POST | `/cred/v1/redeem` | Verify and mark as spent |

### Credential Admin Endpoints

Under `/apps/ecash-services/admin/api/cred/*`:

| Method | Path | Description |
|--------|------|-------------|
| POST | `/cred/keysets/generate` | Generate new credential keyset (active by default) |
| POST | `/cred/keysets/activate` | Activate credential keyset `{id}` |
| POST | `/cred/keysets/deactivate` | Deactivate credential keyset `{id}` |
| GET | `/cred/overview` | Credential stats (keysets, issued, spent) |

### Credential Flow

**1. Setup (one-time, by mint admin or space app):**
```
POST /apps/ecash-services/admin/api/cred/keysets/generate
→ {"id": "c0abc...", "active": true, "keys": {"0": "02pubkey..."}}
```

**2. Issuing credentials (space app, after verifying payment):**
```javascript
// Get credential keyset public key
GET /cred/v1/keys
→ {"keysets": [{"id": "c0abc...", "keys": {"0": "02pubkey..."}}]}

// Create blinded outputs (client-side BDHKE)
// For each credential:
//   secret = random unique string
//   Y = hashToCurve(secret)
//   k = random blinding factor
//   B_ = Y + k*G
outputs = [
  {"B_": "02blinded...", "amount": 0, "id": "c0abc..."},
  // ... repeat for N credentials
]

// Request blind signatures
POST /cred/v1/issue
{"outputs": [...]}
→ {"signatures": [{"C_": "02signed...", "amount": 0, "id": "c0abc...", "dleq": {...}}, ...]}

// Unblind each token (client-side):
// C = C_ - k * pubkey
```

**3. Verifying a credential (space app, on each access request):**
```
POST /cred/v1/verify
{"proofs": [{"C": "02unblinded...", "secret": "...", "amount": 0, "id": "c0abc..."}]}
→ {"valid": [{"secret": "...", "valid": true, "spent": false}]}
```

**4. Consuming a credential (space app, marks as permanently used):**
```
POST /cred/v1/redeem
{"proofs": [{"C": "02unblinded...", "secret": "...", "amount": 0, "id": "c0abc..."}]}
→ {"redeemed": [{"secret": "...", "redeemed": true}]}
```

A redeemed credential cannot be redeemed again — the mint returns `credential-already-spent`.

### Error Responses

| Error | Cause |
|-------|-------|
| `credential-amount-must-be-zero` | Output has non-zero amount |
| `missing-keyset-id` | Output missing `id` field |
| `unknown-credential-keyset` | Keyset ID not found in credential keysets |
| `credential-keyset-inactive` | Keyset has been deactivated |
| `invalid-credential` | Signature verification failed |
| `credential-already-spent` | Token was already redeemed |

---

## Services Layer (non-value-bearing access control)

The services layer builds on the credential extension to provide named, scoped access-control tokens. Where `/cred/v1/*` exposes raw credential keysets for power users, `/services/v1/*` gives each application its own named scope with policy: an expiration, an issuance cap, an optional API-key allowlist, and per-service metadata you can surface in a UI.

### Model

A **service** is a named wrapper around a dedicated `cred-keyset`:

| Field | Meaning |
|---|---|
| `name` | URL slug (e.g. `chat`, `vip`, `api-tier-1`) |
| `title` / `description` | Human-readable metadata |
| `kind` | `single-use` (phase 1 / phase 2 only kind) |
| `ks_id` | Backing credential keyset ID — auto-generated on `create`, never shared between services |
| `active` | If false, issue/verify/redeem return 400 `service-inactive` |
| `expires` | Optional hard cutoff (unix seconds). Past-expiry → 400 `service-expired` across all endpoints |
| `max_issuance` | Optional cap on tokens ever issued; over-cap → 400 `service-issuance-cap-reached` |
| `issued` / `redeemed` | Running counters |
| `allowlist` | Set of plaintext API keys. Empty → `/issue` is public. Non-empty → caller must supply matching `access_key` in the issue body |

Because each service has a **dedicated keyset** auto-generated at `create` time, cross-service token reuse is impossible at the crypto layer: a chat token is signed by chat's private key and simply won't verify against vip's keyset. You don't need additional binding logic to enforce scoping.

### Public Endpoints

Under `/services/v1/*` (unauthenticated):

| Method | Path | Description |
|---|---|---|
| GET | `/services/v1/list` | Active services only. Each entry shows `name`, `title`, `description`, `kind`, `ks_id`, `active`, `issued`, `redeemed`, `allowlist_count`, `allowlist_required`, `expires`, `max_issuance`, `created`. No plaintext keys are ever returned on this endpoint. |
| GET | `/services/v1/{name}` | Service detail (public view — same shape as list entry, no plaintext keys) |
| POST | `/services/v1/{name}/issue` | Blind-sign outputs. Body: `{access_key?, outputs: [{B_, amount: 0, id}]}`. Returns `{signatures: [...]}`. Gated by allowlist when set. |
| POST | `/services/v1/{name}/verify` | Verify proofs without spending. Body: `{proofs: [...]}`. Returns `{results: [{secret, valid, spent}]}`. Always public. |
| POST | `/services/v1/{name}/redeem` | Verify and idempotently mark as spent. Body: `{proofs: [...]}`. Returns `{redeemed: [{secret, status}]}` where `status` is `fresh` (first redemption) or `replay` (already spent — retry after network drop). Always public. |

### Redemption Semantics (idempotent replay)

Redeem is safe to retry:

- All proofs valid and fresh → 200, each marked `status: fresh`, `cred-spent` updated, `service.redeemed` incremented
- All proofs valid, already spent via this service → 200, each marked `status: replay`, **no state change**
- Any proof fails crypto verification (bad signature or wrong keyset) → 400 `invalid-service-token` for the whole batch

Callers that want to know whether a token was first-use vs retry can inspect the per-token `status` field. Callers that don't care can treat any 200 as "token accepted."

### Allowlist Gating

Each service has an `allowlist` set. When empty (the default on create), `/issue` is public — any caller can mint credentials for the service. When non-empty, the caller must include `access_key` in the request body, and its value must be in the allowlist, else 403 `service-access-denied`. `/verify` and `/redeem` are never gated — anyone with a valid token can use it.

The admin dashboard renders plaintext keys (admin-only). Public GET endpoints only expose `allowlist_count` and `allowlist_required`, never the keys themselves.

```bash
# Operator creates a gated service:
curl -X POST http://localhost:8080/apps/ecash-services/admin/api/services/create \
  -H "Cookie: urbauth-~zod=..." -H "Content-Type: application/json" \
  -d '{"name": "vip", "title": "VIP", "description": "Paid tier access"}'

# Operator adds a key and hands it to an authorized client out of band:
curl -X POST http://localhost:8080/apps/ecash-services/admin/api/services/allowlist/add \
  -H "Cookie: urbauth-~zod=..." -H "Content-Type: application/json" \
  -d '{"name": "vip", "key": "bus-secret-xyz"}'

# Authorized client mints credentials (no urbauth required, just the key):
curl -X POST http://localhost:8080/services/v1/vip/issue \
  -H "Content-Type: application/json" \
  -d '{"access_key": "bus-secret-xyz", "outputs": [{"B_": "02...", "amount": 0, "id": "c0..."}]}'

# Anyone holding a valid VIP token can redeem — no key needed:
curl -X POST http://localhost:8080/services/v1/vip/redeem \
  -H "Content-Type: application/json" \
  -d '{"proofs": [{"C": "02...", "secret": "...", "amount": 0, "id": "c0..."}]}'
```

### Services Error Responses

| Error | HTTP | Cause |
|-------|------|-------|
| `service-not-found` | 404 | `name` does not resolve to a service |
| `service-inactive` | 400 | Service is deactivated |
| `service-expired` | 400 | `expires` is set and in the past |
| `service-issuance-cap-reached` | 400 | `max_issuance` would be exceeded by this issue call |
| `service-access-denied` | 403 | Allowlist is non-empty and `access_key` is missing or wrong |
| `invalid-service-token` | 400 | At least one proof failed crypto verification or was signed by a different keyset |
| `service-already-exists` | 409 | Create called with a name that is already registered |
| `service-has-issued-tokens` | 400 | Delete attempted on a service that ever issued a token (use deactivate instead) |
| `deactivate-before-delete` | 400 | Delete attempted while `active=true` |

---

## Cryptography

### secp256k1

Public keys are generated using `priv-to-pub:secp256k1:secp:crypto` from zuse (jet-accelerated). BDHKE point operations use pure Hoon arithmetic in `lib/curve.hoon` — scalar multiplication runs in **Jacobian coordinates** (one field inversion per scalar-mult instead of one per point op, ~7× faster than naive affine; `npm run bench`).

### BDHKE (Blind Diffie-Hellman Key Exchange)

```
Wallet:  Y = hashToCurve(secret)
         B_ = Y + k*G                    (blinded message)
Mint:    C_ = privkey * B_               (blind signature)
Wallet:  C  = C_ - k*pubkey             (unblind)
Verify:  C  == privkey * hashToCurve(secret)
```

### DLEQ Proofs

Every blind signature includes a DLEQ proof (Fiat-Shamir sigma protocol) proving the mint used the correct private key without revealing it.

### Hash-to-Curve

Domain-separated SHA-256 with counter-based retry:
```
domain_sep = "Secp256k1_HashToCurve_Cashu_"
msg_hash = SHA256(domain_sep || secret_bytes)
for counter in 0..65535:
  h = SHA256(msg_hash || counter_le_bytes)
  try: return point_from_x(0x02 || h)
```

---

## Testing

**Prerequisites:** Node.js with `@noble/secp256k1`, `@noble/curves`, and `@noble/hashes`.

```bash
npm install @noble/secp256k1 @noble/curves @noble/hashes
```

**End-to-end tests** (sat flows):
```bash
node test-e2e.mjs          # mint / swap / checkstate / melt with change  (9)
node test-vectors.mjs      # NUT-00 hash-to-curve test vectors             (3)
node test-p2pk.mjs         # P2PK / NUT-11 coverage                        (8)
```

**Services tests** (the services layer):
```bash
node test-services.mjs     # create/issue/verify/redeem, allowlist,
                           # expiration, max-issuance, idempotent replay  (34)
```

**Credential tests** (generate a credential keyset first via the admin API):
```bash
node test-cred.mjs         # 31 tests against /cred/v1/*
```

**Lightning tests** (requires mock LNbits):
```bash
node mock-lnbits.mjs &     # Start mock on port 3338
# Configure mint: :ecash [%lnbits 'http://localhost:3338' 'test-api-key']
node test-lightning.mjs    # bolt11 integration coverage
```

**Security tests (Phase 1):**
```bash
URBAUTH_COOKIE=<ship-cookie> npm run test:security
# admin auth (401/200), legacy endpoints removed (404),
# parse robustness (400 not crash), self-method gating (disabled→400)
```

**Wallet conformance (Phase 2):** drives the real [`@cashu/cashu-ts`](https://github.com/cashubtc/cashu-ts)
library through the full standard flow (loadMint → mint → swap → receive → melt) and verifies
the mint's NUT-12 DLEQ proofs. The mint's keyset IDs match cashu-ts's `deriveKeysetId` (NUT-02)
and its DLEQ proofs pass `hasValidDleq`.
```bash
node mock-lnbits.mjs &                          # mock Lightning on :3338
URBAUTH_COOKIE=<ship-cookie> npm run test:conformance
```

**Hoon unit tests:**
```
-test /=ecash=/tests/test/hoon
```

The JS suites assert mint/swap/melt value conservation, NUT-12 DLEQ, P2PK multisig, credentials, service scoping, admin auth, and parse robustness. Run `npm run test:all` for the full set.

---

## State

The `%ecash` agent state (version 13) contains (the credential/services fields moved to the
`%ecash-services` agent; later migrations added the bolt11 melt-reconciliation state):

| Field | Type | Description |
|-------|------|-------------|
| `keysets` | `(map @t keyset)` | Value keysets (pubkeys, privkeys, unit, fee) |
| `active-keyset` | `@t` | Currently active keyset ID |
| `spent` / `spent-ys` | `(set @t)` | Spent secrets and Y-points (double-spend prevention) |
| `counter` | `@ud` | Total value tokens issued |
| `mint-quotes` / `melt-quotes` | `(map @t quote)` | Active and historical quotes |
| `ln-config` | `ln-backend` | Lightning backend (lnbits/lnd/none) |
| `pending` | `(map @ta pending-req)` | In-flight Lightning HTTP requests |
| `total-issued-sats` / `total-redeemed-sats` | `@ud` | Liability tracking |
| `mint-name` / `mint-description` | `@t` | NUT-06 mint metadata |
| `fee-reserve-pct` / `fee-reserve-min` | `@ud` | Melt fee reserve config |
| `quote-ttl-secs` | `@ud` | Quote expiry duration |
| `melt-change` | `(map @t (list json))` | NUT-08 change signatures keyed by melt quote-id |
| `self-method-enabled` | `?` | Whether the no-payment `self` mint/melt method is enabled (default off) |

State migrations are handled automatically across all versions (state-6 through state-13). The
state-10→11 migration drops the `cred-keysets` / `cred-spent` / `cred-counter` / `services`
fields, which now live in the `%ecash-services` agent (`state-0` there); later migrations add
the bolt11-melt reconciliation state (`pending`/`melt-inflight`). Historical versions before
state-6 have been dropped from the migration chain since there are no known deployments at those
versions.

## License

[PolyForm Noncommercial License 1.0.0](LICENSE.md) — source-available; free for noncommercial
use. See `LICENSE.md` for terms.

## Security

This mint handles value. It went through multiple adversarial security audits; the threat model
and operator procedures (especially Lightning melt reconciliation and stuck-payment recovery)
are documented in [`docs/operator-runbook.md`](docs/operator-runbook.md). Before running against
real value, read the runbook, start on a freshly-generated keyset, and do a small live shakedown
against your Lightning backend.

---

*Built on Urbit vere-4.3, zuse kelvin 409*
*Cashu protocol: https://cashu.space*
*secp256k1 (browser): @noble/secp256k1 v1.7.1 via esm.sh*
