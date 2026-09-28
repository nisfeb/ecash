# Operator Runbook: %ecash mint

Operating the Urbit Cashu mint: the **`%ecash`** value mint and the **`%ecash-services`**
zero-value access agent. Written against the source at `%ecash` state 15 and `%ecash-services`
state 1.

> This mint handles real value. Read §3 (melt safety) and §10 (backup) before you point it at a
> funded Lightning wallet. The most dangerous operator action is a **force-abort** of a melt
> that actually settled (§4, §15): the mint pays twice.

**Contents**

1. Architecture at a glance
2. Pre-production checklist
3. The melt safety model
4. Handling a stuck `PENDING` melt
5. Lightning backend down; LND caveats
6. Admin endpoints
7. Public API surface
8. Keyset management and rotation
9. Settings and limits
10. Backup and disaster recovery
11. Upgrade and state migration
12. Monitoring and solvency
13. Capacity, abuse and rate limiting
14. Incident response: key or pier compromise
15. Incident response: confirmed double-pay
16. Maintenance
17. Security posture and residual risk
18. Appendix: install, tests, quirks

---

## 1. Architecture at a glance

- **`%ecash`**, the value mint. Public Cashu API at `/v1/*` (keys, keysets, info, swap, mint,
  melt, checkstate, restore). A few legacy public GETs under `/apps/ecash`: `/apps/ecash`
  (status), `/apps/ecash/keysets`, `/apps/ecash/keysets/active`, `/apps/ecash/info`,
  `/apps/ecash/icon`. Admin at `/apps/ecash/admin` (dashboard) and `/apps/ecash/admin/api/*`.
- **`%ecash-services`**, zero-value credentials and access control. Public `/cred/v1/*` and
  `/services/v1/*`; admin at `/apps/ecash-services/admin` and `/apps/ecash-services/admin/api/*`.
- Shared libraries (`curve`, `bdhke`, `ecash-http`) live in `desk/lib`. `build.sh` (or
  `make sync-libs`) copies them into `desk-services/lib`, where they are gitignored. **Edit them
  in `desk/lib` only.** The mint's rules are in `desk/lib/ecash-rules.hoon`.
- Mint/melt methods: **`bolt11`** (Lightning) and **`self`** (no payment; test mints only, §2).

**Auth.** Admin routes need your ship's own login session (eyre marks a request
`authenticated` only for your ship): otherwise `401 {"detail":"unauthorized"}`. A
state-changing admin request that sends `Origin` (or else `Referer`) must name the host in
`Host`, else `403 forbidden-cross-origin` (`X-Forwarded-Host` is not trusted); one that sends neither (curl,
scripts) passes. **Behind a proxy, forward `Host`** (nginx: `proxy_set_header Host $host`) or
dashboard saves will fail. The real perimeter is the session cookie.

**Headers.** Every response carries `x-frame-options: DENY`, `x-content-type-options: nosniff`,
`cache-control: no-store` and `Access-Control-Allow-Origin: *`, and a CSP
(`default-src 'self'; frame-ancestors 'none'`; the dashboards get one that runs only their own
nonce'd script and sets `form-action 'none'`). The public routes answer CORS preflight
(`OPTIONS`), so don't add CORS headers at the proxy.

Errors are `{"detail":"<code>"}` with a 4xx/5xx status. Admin actions answer 200 with the
outcome in the JSON (for `/melt/abort`, read `result`).

---

## 2. Pre-production checklist

1. **Start on a fresh keyset.** Install generates one: 21 denominations (2^0..2^20),
   `input_fee_ppk` 0, active. Its private keys live only in agent state, so the pier is
   money-bearing. A leaked key can forge tokens under that keyset id forever (any keyset in
   state verifies), so the only remedy for exposed keys is a new pier (§14).

2. **Configure Lightning before taking bolt11 traffic.** Until then `ln-config` is `none`,
   bolt11 quotes are refused and `/v1/info` lists no bolt11. Configure
   (`POST /apps/ecash/admin/api/lightning/configure`) with LNbits for real funds (§5 on LND),
   then `POST .../lightning/test`: it calls the backend and reports `status`, `http_status` and,
   for LNbits, `balance_msat`.

3. **Leave `self_method_enabled` off.** `self` mints with no deposit and melts with a stand-in
   preimage. **Never enable it on a mint with a real Lightning backend**: tokens minted for free
   with `self` melt over bolt11 for real sats. Never turn it on to work around a down backend (§5).

4. **Set fees and TTL** (§9). `fee_reserve_pct` is basis points (default 100 = 1%). The server
   rejects non-integers and floors the TTL at 60 s, but accepts a zero reserve.

5. **Least-privilege Lightning credential.** It is stored in cleartext in agent state. Use a
   dedicated LNbits wallet holding only what the mint needs (or an LND macaroon limited to
   invoices and payments, never admin).

6. **Rate-limiting reverse proxy in front** (§13, `INSTALL.md` §3). The mint has no rate limit
   and its crypto is CPU-heavy.

7. **Record a solvency baseline:** `total_issued_sats − total_redeemed_sats` from
   `GET .../overview` against your Lightning balance (§12).

8. **Check `GET /v1/info`:** nuts 3–12 present; nuts 4 and 5 list `bolt11` only (no `self`);
   nut 4's `max_amount` is 83886080 on a current keyset (nut 5 names no maximum).

9. **Never run the JS test suites, `demo.mjs` or `npm run bench` against this mint.** They
   change settings (turning on `self`, changing fees, repointing Lightning).

---

## 3. The melt safety model

A bolt11 melt is an outbound Lightning payment. The mint often can't tell "failed" from "still
in flight", so it **never un-spends a customer's proofs on ambiguous evidence.**

On `POST /v1/melt/bolt11`, after every check passes:
- The inputs are marked **spent**, `total_redeemed_sats` goes up, the quote goes **`PENDING`**,
  and a durable `melt-inflight` record (spent secrets and Ys, input total, blank change outputs,
  overpayment) is stored, all **before** the payment is sent.
- The payment request's own answer then decides:
  - **2xx with a non-empty preimage and no error field**: settled. The quote goes `PAID`, the
    NUT-08 change is signed once, and the inflight record is dropped.
  - **LNbits refused it outright**: a 4xx other than 408/429 whose body has an error
    (`detail`/`error`) and names no payment (`payment_hash`/`checking_id`). No HTLC can exist,
    so the mint rolls back automatically: inputs spendable again, `total_redeemed_sats`
    reduced, quote `failed` (wallets see `UNPAID` and may retry).
  - **Anything else** (5xx, timeout, cancelled request, 2xx without preimage): the quote stays
    `PENDING` and the wallet gets `PENDING`. It should poll, not re-submit (`quote-pending`).
- Each poll of a `PENDING` melt (`GET /v1/melt/quote/bolt11/{id}`) answers with the stored
  state at once and asks Lightning in the background:
  - LNbits `paid: true`, or LND `status: SUCCEEDED`: **settle**.
  - LND `status: FAILED`: **roll back**.
  - Anything else (404, `paid: false`, in flight): nothing changes.
- While a melt is `PENDING`, `/v1/checkstate` reports its inputs as `PENDING`.

So: **an LNbits payment that LNbits accepted and that later fails is never rolled back
automatically.** It stays `PENDING` until you abort it (§4). This is the trade: the mint never
pays twice, at the cost of the occasional manual abort.

**Money math.** A melt needs `(inputs − input_fee) ≥ amount + fee_reserve` (else
`400 insufficient-inputs`), checked on the claimed amounts before any EC work. Change is
`(fee_reserve − routing_fee) + overpayment`, where overpayment is whatever the inputs paid
beyond `amount + fee_reserve + input_fee`. The routing fee is read **fail-closed**: sats from
`fee_sat` or `payment_route.total_fees`, else msat (rounded up) from `total_fees_msat`,
`payment_route.total_fees_msat`, `fee` or `details.fee`; LNbits' negative msat fee counts as its
magnitude. A fee the mint can't read counts as the whole reserve, so the customer gets back only
the overpayment. Check your backend's fee fields on a real small melt. Change is split into
powers of two, largest first, onto the blank outputs the wallet sent; **what doesn't fit is
kept by the mint.**

---

## 4. Handling a stuck `PENDING` melt

A `PENDING` quote means the **inputs are spent** and the Lightning outcome is unknown to the
mint. **Do not delete it** (refused: `cannot-delete-pending-melt`). Resolve it:

1. **Poll:** `GET /v1/melt/quote/bolt11/{id}`, then again a few seconds later (the check runs
   behind the first answer). If the payment settled, the quote is now `PAID` with its change.

2. **Still `PENDING`: check your Lightning node yourself** (the LNbits wallet's payments, or
   `lncli listpayments` / `lncli trackpayment`). Then abort from the dashboard (Quotes tab:
   **Abort** / **Force abort** on a PENDING bolt11 melt) or with
   `POST /apps/ecash/admin/api/melt/abort`. The mint re-checks Lightning first and answers once
   the backend replies:

   | Body | Lightning says | Outcome, `result` |
   |---|---|---|
   | `{quote_id}` | settled | settles the melt: `settled-not-aborted` |
   | `{quote_id}` | LND `FAILED` | rolls back: `aborted-confirmed-failed` |
   | `{quote_id}` | anything else | nothing changes: `in-flight-or-unconfirmed` |
   | `{quote_id, force: true}` | settled | still settles: `settled-not-aborted` |
   | `{quote_id, force: true}` | anything else | rolls back on your word: `aborted-forced` |
   | either | (the quote was rolled back and melted again while the check was out) | nothing changes: `stale-attempt` |

   Every Lightning request about a melt is tagged with the attempt it was made for, so a late
   answer about an earlier attempt of the same quote can never roll back the one in flight.

   "Settled" is LNbits `paid: true` (no preimage needed) or LND `SUCCEEDED`. A rollback makes
   the inputs spendable again, reduces `total_redeemed_sats` (never below 0) and sets the quote
   `failed`; the answer carries `unspent_secrets` and `redeemed_decremented`.

   ⚠️ **Force only after your node shows the payment FAILED**, not merely "not settled". An
   in-flight HTLC looks the same to the mint as a failed one; if it settles after a force, the
   mint has paid twice (§15). With LND, the status lookup is unverified (§5): if it can't see a
   settled payment, force rolls that back too.

3. **Backend set to `none`.** With no backend to ask, abort can only take your word: without
   `force` it changes nothing (`in-flight-or-unconfirmed`, `ln_checked: false`); with `force`
   it rolls back at once (`aborted-forced`, `ln_checked: false`). A backend removed after the
   pay went out says nothing about whether it settled, so reconnect it and abort normally
   instead whenever you can.

4. **No inflight record** (a melt older than those records): with `force: true`, name the melt's
   inputs, `{quote_id, force: true, secrets: [...], ys: [...]}`. After the Lightning check those
   exact secrets and Ys are un-spent (`redeemed_decremented: 0`: the counter can't be matched).
   Naming nothing gives `no-inflight-record` and changes nothing; the quote just stays `PENDING`
   (cleanup keeps it; it owes nothing more).

Other answers: `no-op-not-pending` (the quote stopped being `PENDING` before Lightning answered),
`400 quote-not-pending`, `404 quote-not-found`. The HTTP status is 200 for every `result`.

---

## 5. Lightning backend down; LND caveats

- **Backend `none`, or unreachable when a quote is made.** New bolt11 quotes fail:
  `400 no-lightning-backend-configured`, or a 502 (`lightning-invoice-creation-failed`,
  `lightning-decode-failed`, `lightning-request-cancelled`). A mint quote whose invoice couldn't
  be made is deleted. No value is at risk.
- **Backend down after a melt was sent.** Those quotes sit `PENDING` with inputs spent (§4).
  They are safe: `melt-inflight` survives restarts, and they reconcile on the next poll or abort
  once the backend is back. Don't delete them, don't force-abort them blind, and don't switch the
  backend to `none` and abort (§4.3).
- **Deposits during an outage.** A quote poll can't see a payment while the backend is down.
  Cleanup keeps an expired unpaid bolt11 quote for 2 days and checks it on Lightning once, in its
  first day past expiry; any wallet poll of the quote also re-checks it. If the backend was down
  across a quote's expiry, look for payments to it on your node before the 2 days are up.
- **Don't enable `self`** to keep minting during an outage: that creates unbacked tokens (§2.3).

**LND.** The code handles LND's REST conventions (int64 fields as strings, base64 `r_hash` and
preimage), but **the LND path has never been tested against a real LND node**, and its
payment-status lookup (`GET /v1/payment/{hash}`) is unverified. A melt whose payment answer
carries a preimage settles at once; one left `PENDING` may never settle by polling, and then only
`/melt/abort` resolves it (after you check the node yourself, §4). **Use LNbits for real funds.**

---

## 6. Admin endpoints

Base `/apps/ecash/admin/api`. Session cookie required; POSTs also pass the same-origin check
(§1).

| Method · path | Body | Effect / notes |
|---|---|---|
| `GET /overview` | — | `total_issued_sats`, `total_redeemed_sats`, counters, mint/melt quote tallies, `ln_backend`. `failed` quotes count as `unpaid`. |
| `GET /settings` | — | `{fee_reserve_pct, fee_reserve_min, quote_ttl_secs, self_method_enabled}` |
| `POST /settings` | any of those | Validated (§9); answers the full settings. |
| `GET /lightning` | — | `{type, configured, url, api_key_set}`; never the credential. |
| `POST /lightning/configure` | `{type:"none"}` \| `{type:"lnbits",url,api_key}` \| `{type:"lnd",url,macaroon}` | Sets the backend. |
| `POST /lightning/test` | — | Calls the backend (LNbits `GET /api/v1/wallet`, LND `GET /v1/getinfo`) → `{status:"ok"\|"error", type, url, http_status, detail?, balance_msat?}`. `400 no-ln-backend` when none. |
| `GET /keysets` · `GET /keysets/{id}` | — | List (with `key_count`, `denominations`) / one keyset with public keys. Private keys are never returned. |
| `POST /keysets/generate` | — | New **inactive** keyset, 2^0..2^20, fee 0 → `{id, active, key_count}`. |
| `POST /keysets/activate` | `{id}` | Makes it the active keyset; the previous one goes inactive. |
| `POST /keysets/deactivate` | `{id}` | Refuses the active keyset (`cannot-deactivate-active`). |
| `POST /keysets/set-fee` | `{id, input_fee_ppk}` | Forks to fresh keys under a new id (§8) → `{old_id, new_id, input_fee_ppk}`. Max 100000 (`input_fee_ppk-too-large`). |
| `GET /quotes` | — | `mint_quotes` and `melt_quotes` with `method`, `state`, `expiry`, `expired`; melts with `payment_hash`. |
| `POST /quotes/delete` | `{quote_id, type:"mint"\|"melt"}` | Refused for ISSUED or PAID mint quotes and PAID or PENDING melts (they are owed value). |
| `POST /quotes/revoke` | `{quote_id}` | ⚠️ Destructive, below. |
| `POST /melt/abort` | `{quote_id, force?, secrets?, ys?}` | §4. |
| `GET /spent` · `POST /spent/check` | `{secret}` \| `{Y}` | Spent-set sizes / one lookup (read-only). |
| `GET /info` · `POST /info/update` | `{name?, description?}` | NUT-06 info / edit name and description. |

**`/quotes/revoke`** deletes any mint quote, including ones `delete` refuses, and answers
`{revoked, quote_id, type, was_state, issued_decremented}`.
- **PAID**: a customer paid and has **not minted yet**. Revoking destroys their deposit as far
  as the mint is concerned: they can never mint it. Do it only after refunding them some other
  way, or when you know the payment is bogus.
- **ISSUED**: the amount comes off `total_issued_sats`, declaring those tokens never to be
  redeemed. If they are redeemed after all, outstanding liability goes negative.

The dashboard asks for a typed confirmation before revoking a PAID quote or force-aborting.

**`%ecash-services`** (`/apps/ecash-services/admin/api/*`, same auth): `cred/overview` (each
keyset with `service_scoped` and `service`); `cred/keysets/generate|activate|deactivate` (the
last two refuse service keysets: `keyset-is-service-scoped`); `services`, `services/{name}`;
`services/create|update|activate|deactivate|delete`; `services/allowlist/add|remove`.
`services/delete` needs the service inactive and `issued == 0` (`issued` never decreases), and
deactivates its keyset. `expires` and `max_issuance` must be `null` (clear) or a bare
non-negative integer (`invalid-expires`, `invalid-max-issuance`); on update, an absent field is
left alone. Service names are 1–64 of `a-z 0-9 _ -`, not `list`.

**`/cred/v1/*` is public**: anyone can issue on an active plain credential keyset. Access control
belongs in a service's allowlist.

---

## 7. Public API surface

Unauthenticated by protocol design.

- `GET /v1/keys`: active keyset with keys. `GET /v1/keys/{id}`: any keyset. `GET /v1/keysets`:
  all keysets, no keys.
- `GET /v1/info`: nuts 3–12. Nuts 4 and 5 list `self` only while enabled and `bolt11` only while
  a backend is configured, each with `min_amount` 1; nut 4's also carry `max_amount` (§9).
- `POST /v1/swap`: claimed amounts must balance (`(inputs − fee) == outputs`, else
  `400 amounts-do-not-balance`) before any EC work; then every output is checked
  (`invalid-msg`, `missing-B_`, `invalid-B_-point`, `duplicate-output`, `output-already-signed`,
  `unknown-keyset`, `inactive-keyset`, `unknown-denomination`); then every proof. Nothing is
  spent unless all of it passes.
- `POST /v1/mint/quote/{method}` · `GET …/{id}` · `POST /v1/mint/{method}`. Quotes over
  `max_amount` are refused (`amount-too-large`). A `PAID` quote mints even after expiry.
- `POST /v1/melt/quote/{method}` · `GET …/{id}` · `POST /v1/melt/{method}` (§3). bolt11
  requests must be letters and digits only (`invalid-request`); a decode without a payment hash
  is `502 lightning-decode-missing-hash`. A quote settles only by the method that made it
  (`method-mismatch`).
- `POST /v1/checkstate` `{Ys:[...]}` → `UNSPENT`, `PENDING` (in a melt in flight) or `SPENT`.
- `POST /v1/restore` `{outputs:[...]}` → the stored signatures for any B_ the mint signed.
- **Timing:** creating a bolt11 mint quote, a bolt11 melt quote, and `POST /v1/melt/bolt11` wait
  for the Lightning backend's answer. Quote polls (`GET`) answer at once and check Lightning
  behind the answer.

---

## 8. Keyset management and rotation

- One keyset is active. New outputs must use it (`inactive-keyset` otherwise). **Every keyset
  still in state verifies**, with its own input fee, so rotating never strands old tokens.
- Keysets made now have denominations 2^0..2^20: `max_amount` 83,886,080 sats. A mint installed
  earlier still has a 1..512 keyset, which caps each quote at 46,592 sats. **Rotate it:**

  ```bash
  B=https://mint.example.com/apps/ecash/admin/api
  C='Cookie: urbauth-~your-ship=…'
  curl -s -X POST -H "$C" $B/keysets/generate                 # → {"id":"01…","active":false,"key_count":21}
  # only if you charge an input fee (the new keyset starts at 0):
  curl -s -X POST -H "$C" -H 'content-type: application/json' \
    -d '{"id":"01…","input_fee_ppk":100}' $B/keysets/set-fee   # → use its new_id below
  curl -s -X POST -H "$C" -H 'content-type: application/json' \
    -d '{"id":"01…"}' $B/keysets/activate
  ```

  Or use the dashboard's Keysets tab. Old tokens keep redeeming. Wallets that cached the old id
  get `inactive-keyset` when minting until they refresh `/v1/keysets`.
- **`set-fee` forks.** A keyset id commits to its fee, so `set-fee` makes a **fresh keyset** (new
  keys, new id) with the new fee, and keeps the old id as an inactive alias with the old fee so
  its tokens still spend. The keys are fresh because BDHKE doesn't bind the id into a signature:
  copied keys would let anyone relabel a token to the cheaper id. If the old keyset was active
  the new one is; otherwise the new one is inactive. The same fee again is a no-op.
- There is no "deactivate the active keyset": activate a replacement.
- **`%ecash-services`:** a service's keyset is service-scoped. It is used only through
  `/services/v1/{name}/*` (never `/cred/v1`), can't be activated or deactivated through the cred
  admin, and is deactivated when its service is deleted. Its public key is still fetchable by id,
  which is harmless. Keysets from `cred/keysets/generate` are plain and publicly usable.

---

## 9. Settings and limits

| Setting | Default | Meaning |
|---|---|---|
| `self_method_enabled` | `false` | No-payment mint/melt. **Off on any real mint.** |
| `fee_reserve_pct` | `100` | Melt fee reserve, basis points: `amount × pct / 10000` (100 = 1%). |
| `fee_reserve_min` | `10` | Sats floor: `reserve = max(min, amount × pct / 10000)`. |
| `quote_ttl_secs` | `3600` | Quote lifetime and bolt11 invoice expiry. Floored at 60. |
| `mint_name` / `mint_description` | `ecash-mint` / `Cashu ecash mint on Urbit` | NUT-06 info. |
| keyset `input_fee_ppk` | `0` | Per-proof input fee, set by `set-fee`; max 100000. |

`POST /settings` changes only the fields you send. Each number must be a bare non-negative
integer and `self_method_enabled` a boolean; anything else is `400 invalid-<field>` and nothing
changes. `fee_reserve_pct: 0` with `fee_reserve_min: 0` is accepted and leaves no fee reserve:
don't.

Fixed limits: 100 inputs, outputs, Ys or restore outputs per request (`batch-too-large`); 1 MiB
request body (`body-too-large`); 2048-byte secrets (`secret-too-long`); per-mint-quote `max_amount` =
`(100 − m) × 2^m` for the active keyset's top denomination 2^m; P2PK locks of at most 10 keys
and witnesses of at most 10 signatures.

---

## 10. Backup and disaster recovery

**All money-critical secrets live only in agent state inside the pier:** keyset **private
keys** and the **Lightning credential**. There is no key export: **the pier is the backup
unit.**

- **Back up the pier** on a schedule, **encrypted**: it holds plaintext mint keys and the
  credential.
- **A stale restore reintroduces double-spend and double-pay risk.** An old snapshot reverts the
  spent sets, quotes, `melt-inflight` records and liability counters: tokens spent after the
  snapshot become spendable again, and melts that paid after it can pay again. Treat any restore
  as an incident:
  1. Before reopening, **reconcile against the Lightning node**: any payment the node made that
     the restored state shows `PENDING` or `UNPAID` must be settled, or its inputs left spent.
  2. Proofs the restored state shows unspent may already have been spent by holders; nothing can
     re-derive that. Restore the **most recent** snapshot, and if value integrity is in doubt,
     rotate to a fresh keyset and wind the old liability down deliberately.
- **Do a restore drill.** Check that the restored mint answers `/v1/info`, that `/overview` shows
  the expected counters, and that the active keyset matches (`/x/active-keyset` scry).

---

## 11. Upgrade and state migration

`on-load` migrates forward only: `%ecash` 13 → 14 (adds the NUT-09 `restore` map, empty) → 15
(adds the overpayment to each inflight melt, recorded as 0). **It loads state 13 or later.** A
mint below 13 must first upgrade through commit `eb7b56a`: build and commit that commit's desk,
let it load, then upgrade to current. `%ecash-services` migrates 0 → 1, and on every load
deactivates the keysets of deleted services. Migrations can't be reversed: older code can't
load newer state.

Procedure:
1. **Back up the pier** (§10).
2. Build and deploy with `build.sh` (it regenerates the services desk's shared libraries):
   `./build.sh -p <pier>/ecash`, and `./build.sh services -p <pier>/ecash-services` if you run it.
3. `|commit` each desk and watch the load.
4. **Verify:** `/overview` counters look right, `/v1/info` answers, the active keyset is
   unchanged. Resolve any melt that was in flight across the upgrade (§4).

Notes: loading re-arms the daily cleanup timer (at the next day boundary), so no timer is lost
across an upgrade. A melt in flight across the upgrade to 15 returns no overpayment as change.
Signatures issued before state 14 aren't in the `restore` map, so NUT-09 can't return them.

---

## 12. Monitoring and solvency

There is no metrics endpoint: the signals are `GET /overview`, `GET /quotes` and console traces.

- **`PENDING` melts:** spent value with an unknown Lightning outcome. Each is real money awaiting
  §4. Alert and work them down.
- **`PAID` but unminted mint quotes:** a customer paid and hasn't minted. Kept forever (§16);
  a growing backlog means customers can't mint.
- **Liability:** `total_issued_sats − total_redeemed_sats`. Alert when it nears your Lightning
  balance. It can go negative after revoking an ISSUED quote whose tokens were redeemed after all.
- **Disk and event log:** `du -sh <pier>/.urb/log` and `df`. The log grows fast under load and
  can fill the disk and wedge the ship (§16).
- **Bind failures:** if eyre refuses a binding, the agent prints `%ecash-bind-failed` (or
  `%ecash-services-bind-failed`) to the console and that API is offline. Probe `/v1/info`
  from outside.
- **Melt traces** worth alerting on: `%ecash-ln-pay-dispatched-pending`,
  `%ecash-ln-pay-dispatch-rejected`, `%ecash-melt-confirmed-failed`, `%ecash-melt-abort-rollback`.

**Solvency.** Check regularly, not only in an incident, that the Lightning balance covers
outstanding liability. The counters are running totals, not a ledger (and an abort's decrement
stops at 0), so cross-check against the node.

---

## 13. Capacity, abuse and rate limiting

In code: the per-request limits (§9); unbalanced swaps and melts refused on claimed amounts
before any EC work; every cheap check (shape, secret size, spent, keyset, denomination, point
decoding) run over the whole batch before any signature check.

Not in code: per-IP limits, `429`, caps on open quotes, a liability ceiling.

**CPU is the constraint.** The elliptic-curve math is pure Hoon: a 100-proof swap takes seconds
of ship CPU, and the ship handles one event at a time, so while it works every other request
waits. **The reverse proxy's rate limit is the main abuse control** (nginx example in
`INSTALL.md` §3: 20 requests/s per IP, bursts of 40, on `/v1/`). Also watch for quote spam:
each bolt11 mint quote makes an outbound Lightning call and grows the event log, and each poll of
an unpaid quote makes another.

---

## 14. Incident response: key or pier compromise

A stolen pier copy is catastrophic: every keyset's **private keys** (unlimited forgery under
those ids; rotation doesn't help, since old ids still verify) **and** the **Lightning
credential** (drain the wallet up to its scope).

1. **Rotate the Lightning credential at the backend now** (new key or macaroon; revoke the old)
   and re-`configure` the mint. Only this stops the wallet being drained.
2. **Stop taking new value** on the compromised pier.
3. **Wind down to a fresh pier** with a new keyset; move liability deliberately (let holders
   redeem) and **never reuse the exposed pier**.
4. Pier backups are part of the blast radius: a leaked backup is a leaked pier.

---

## 15. Incident response: confirmed double-pay

If a force-abort rolled back inputs and the payment later settled, or any path paid twice:
1. **Detect:** compare the node's payment history with the mint's melt quotes and
   `total_redeemed_sats`. A settled payment for a quote the mint shows `failed`/`UNPAID` is a
   double-pay.
2. **Reconcile:** the un-spent proofs may already be re-spent, and the sats left the node.
   Quantify the loss against liability.
3. **Contain:** there is no clawback. Tighten force-abort authority and, if losses are
   material, rotate to a fresh keyset and wind down.

**Prevention is the control.** Make force-abort a two-person decision that requires independent
confirmation on the node that the payment failed.

---

## 16. Maintenance

- **Event log.** Heavy traffic (and load testing) grows `<pier>/.urb/log` quickly. To reclaim:
  stop the ship and run `urbit chop <pier>`; if the bloat is in the current epoch, let the ship
  roll a new epoch first. The snapshot holds current state; chop discards only history.
- **Cleanup** runs once a day. It keeps: unexpired quotes; `PAID` mint quotes forever (a deposit
  not yet minted); unpaid bolt11 mint quotes for **2 days past expiry**, checking each on
  Lightning once in its first day past expiry when a backend is configured (so a deposit paid
  just before expiry is found);
  `PAID` melts for **30 days past expiry** (their change stays recoverable after that through
  `/v1/restore`, which keeps every signature the mint issued); `PENDING` melts forever. It drops every other expired
  quote (including `ISSUED` mint quotes and unpaid or failed melts) with its change and inflight
  records.
- **Liability:** outstanding = `total_issued_sats − total_redeemed_sats` (`/overview`).

---

## 17. Security posture and residual risk

Hardened across several adversarial audits:
- **No forgery:** DLEQ nonces bound to the full points; P2PK counts distinct x-only signers
  (verified with zuse's jetted BIP-340, stopping at the threshold); service tokens can't be issued
  through the public path.
- **No double-spend or double-pay:** melts are single-use; reconciliation never un-spends on
  ambiguous evidence; every settle requires `PENDING`, so late answers do nothing; a recorded
  B_ is never signed again (`output-already-signed`).
- **No inflation:** swaps and mints balance and are all-or-nothing; `ISSUED` quotes can't be
  re-minted; a missing proof `id` still pays the active keyset's fee; inactive keysets sign
  nothing; a bolt11 quote can't be settled by the `self` method.
- **Fail-closed money math:** refunds round against the mint; malformed input gets a clean 400.

**Residual risk, the operator's to manage:**
1. A **force-abort** of a payment that didn't really fail pays twice (§4, §15).
2. **No rate limiting** in code; CPU-heavy requests (§13).
3. **Secrets in the pier in cleartext**; backup hygiene and least-privilege credentials are
   yours (§10, §14).
4. **LND untested** against a real node (§5).
5. **`self` method** mints unbacked value if turned on (§2).
6. **Responses readable by a guessing ship.** An agent can't tell eyre's requests from a remote
   ship's subscription, so a foreign ship that guessed an in-flight request id could read that
   response.

---

## 18. Appendix: install, tests, quirks

**Install.** See [`INSTALL.md`](INSTALL.md). Always deploy with `build.sh -p` (it adds the
base-dev files and the services desk's shared libraries); don't copy `desk/` by hand. The
Lightning backend can also be set from the dojo (host only):
`:ecash [%lnbits 'https://…' 'api-key']`, `:ecash [%lnd 'https://…' 'macaroon']`,
`:ecash [%none ~]`.

**Toolchain.** The desks declare `[%zuse 408]`: upgrade a 409 ship's `%base` before installing. The JS tooling needs Node.js
(`engines` in `package.json`) and `npm install`; it is for testing only.

**Tests.** **Never run them against a mint holding real value**: they change settings. The JS
suites (`npm run test:all`) need `SHIP_URL` and `URBAUTH_COOKIE` for a ship running both agents;
the Lightning suites use a mock LNbits; suites that change settings refuse a non-loopback
`SHIP_URL` unless `ALLOW_DESTRUCTIVE=1`. The Hoon unit suites run on a separate `%ecash-test` desk
(`scripts/hoon-test-kit/hoon-test.sh <pier>`, see [`hoon-testing.md`](hoon-testing.md)).

**Quirks:**
- `/v1/info` reports version `ecash/1.0.0`; the legacy `GET /apps/ecash` reports `1.0.0`.
- A `failed` melt (rolled back) shows as `UNPAID` to wallets, which is correct for a retry;
  `/quotes` shows the same, and `/overview` counts it as unpaid.
