# Operator Runbook — %ecash mint

Practical operations for running the Urbit Cashu mint: the **`%ecash`** value
mint plus the **`%ecash-services`** zero-value access-control agent. Reflects the
current security model (verified against the source at state-13 / services
state-0). Pairs with the design specs in `docs/design/specs/`.

> This mint handles real value. Read §3 (melt safety model) and §10 (backup &
> DR) before you point it at a funded Lightning node. The single most dangerous
> operator action is a **force-abort** of a melt that later settles (§4, §15) —
> it double-pays.

**Contents**

1. Architecture at a glance
2. Pre-production checklist
3. The melt safety model
4. Handling a stuck `PENDING` melt
5. Lightning-backend-down playbook
6. Admin endpoints (full reference)
7. Public API surface (reference)
8. Keyset management & rotation
9. Settings & economic tuning
10. Backup & disaster recovery
11. Upgrade & state migration
12. Monitoring, alerting & solvency
13. Capacity, abuse & rate limiting
14. Incident response: key / pier compromise
15. Incident response: confirmed double-pay
16. Maintenance
17. Security posture & residual operator responsibility
18. Appendix: install, tests, known quirks

---

## 1. Architecture at a glance

- **`%ecash`** — the value mint. Serves the Cashu protocol at two Eyre bindings:
  the standard `/v1/*` and a legacy `/apps/ecash/*` alias. Public, unauthenticated
  by protocol design: `/v1/keys`, `/v1/keys/{id}`, `/v1/keysets`, `/v1/info`,
  `/v1/swap`, `/v1/mint/quote/{method}`, `/v1/mint/{method}`,
  `/v1/melt/quote/bolt11`, `/v1/melt/bolt11`, `/v1/checkstate`. Admin (cookie +
  CSRF gated) at `/apps/ecash/admin` and `/apps/ecash/admin/api/*`.
- **`%ecash-services`** — zero-value credentials/access control. Public `/cred/*`
  (anonymous blind-signed credentials) and `/services/{name}/*` (allowlist- and
  cap-gated service tokens). Admin at `/apps/ecash-services/admin/api/*`.
- Shared crypto (`lib/curve.hoon`, `lib/bdhke.hoon`) lives in `desk/lib` and is
  copied into `desk-services/lib` by `make sync-libs` at build time — **edit it in
  one place.** The `desk-services` copies are gitignored.
- The supported mint/melt methods are **`bolt11`** (real Lightning) and
  **`self`** (no-payment, testing only — see §2/§9).

**Auth model.** Admin = the ship's own login session only (Eyre marks
`authenticated` true exclusively for an `%ours` session; no foreign `@p` is ever
exposed to the handler, so the boolean alone proves it is your ship). A
missing-session admin request gets `401 {"detail":"unauthorized"}`.
State-changing admin POSTs additionally require a same-origin **Origin/Referer**
(CSRF): a *mismatched* Origin is rejected `403 {"detail":"forbidden-cross-origin"}`;
a *missing* Origin **and** Referer is allowed (treated as a non-browser client).
So non-browser tooling (curl/scripts) either sends `-H 'origin: https://<your-ship-host>'`
or sends neither header. **The real perimeter is the session cookie** — CSRF adds
nothing against a scripted attacker who already has it. There are no IP allowlists
or host locks; put a reverse proxy in front if you need network-layer controls
(§13).

All HTTP responses carry hardening headers: `content-security-policy: default-src
'self'; frame-ancestors 'none'`, `x-frame-options: DENY`,
`x-content-type-options: nosniff`. Errors are always `{"detail":"<msg>"}`;
success bodies are HTTP 200 with the real outcome in the JSON (including melt
`abort` results — read the `result` field, not the status code).

---

## 2. Pre-production checklist

1. **Start on a fresh keyset.** The mint auto-generates one on install (10
   power-of-2 denominations 1..512, `input_fee_ppk` 0, active). The private keys
   are derived from entropy at install time and live **only** in agent state —
   treat the pier as money-bearing. If a denomination key ever leaks, the leaked
   keyset stays usable to forge tokens *under that keyset id* (verify accepts any
   keyset a token names), so the only true remedy is to **never reuse a pier whose
   keys were exposed** (§14). Generate + activate a clean keyset before taking real
   value if there is any doubt about the install entropy.

2. **Configure the Lightning backend before taking bolt11 traffic.** A fresh
   install defaults `ln-config` to `%none`, so bolt11 mint/melt are inert and
   `/v1/info` omits the bolt11 method until you configure one. When ready, run
   `POST /apps/ecash/admin/api/lightning/configure` with a real
   `{type:"lnbits",url,api_key}` / `{type:"lnd",url,macaroon}`; or leave
   `{type:"none"}` to run credentials-only. Confirm the result with
   `GET .../lightning`.

3. **Leave `self_method_enabled` OFF.** The `self` method mints sats with **no
   Lightning deposit** and melts with a fake preimage — it is a free-money switch
   for testing only. It must stay `false` on a value mint, and must **never** be
   flipped on to "work around" a down backend (§5). `POST .../settings
   {self_method_enabled:false}`.

4. **Set sane fee / TTL.** `POST .../settings` with `fee_reserve_pct` (basis
   `pct/10000`; default `100` = 1%), `fee_reserve_min` (sats floor; default `10`),
   `quote_ttl_secs` (default `3600`). ⚠️ **The server does NOT bounds-check these**
   — a direct call can set `quote_ttl_secs:0` (every quote expires instantly) or
   `fee_reserve_pct:0`. The `>=60` floor exists only in the dashboard JS. Validate
   your own values (§9).

5. **Use a least-privilege Lightning credential.** The api-key/macaroon is stored
   in cleartext in agent state. Scope the macaroon to invoice + pay only (no
   node-admin), so a pier compromise can't drain the node beyond payments (§14).

6. **Put a rate-limiting reverse proxy in front.** There is **no** in-code
   throttle, no per-IP limit, no cap on open quotes or total liability (§13). The
   `/v1/*` surface is fully public.

7. **Record a solvency baseline.** Note `total_issued_sats − total_redeemed_sats`
   from `GET .../overview` against your Lightning balance, and decide your
   reconciliation cadence (§12).

8. Confirm `GET /v1/info` and `GET /v1/keys` return `200` and advertise the
   intended keyset + NUTs (1,2,3,4,5,6,7,8,10,11,12).

---

## 3. The melt safety model (read before operating bolt11 melts)

A bolt11 melt is an **outbound** Lightning payment. The mint cannot always tell
"failed" from "still in flight" from a backend API, so the design is
**safety-first: it never un-spends a customer's proofs on ambiguous evidence.**

On `POST /v1/melt/bolt11`:
- Inputs are marked **spent** and `total_redeemed_sats` incremented, the quote
  goes **`PENDING`**, and the reconciliation record is stored **durably**
  (`melt-inflight`, survives restart) — all **before** the pay is dispatched. The
  dispatch's HTTP response is treated as *dispatch confirmation only*.
- **Settle → `PAID`** only on positive proof: a 2xx response (incl. real LNbits
  `201`) **and** a non-empty `payment_preimage` **and** no error field. Then the
  NUT-08 change is signed **exactly once** and the inflight record cleared.
- **Anything else** — non-2xx, empty body, timeout/runtime cancel, `paid:false`,
  in-flight, `404`, or 2xx-without-preimage — leaves the quote **`PENDING`** and
  replies NUT-05 `PENDING`. The mint does **not** roll back. The client should
  **poll**, not re-submit (`POST` of a `%pending` quote is refused
  `quote-pending`).
- Polling `GET /v1/melt/quote/bolt11/{id}` re-checks Lightning and **auto-settles
  to `PAID`** once the payment confirms (paid + preimage). The auto-poll
  **auto-rolls-back only on an explicit LND `status=FAILED`**.

Two consequences to internalize:
- **LNbits has no automatic rollback path at all.** Confirmed-failure detection is
  gated on an LND `FAILED` status; an LNbits backend has no equivalent the code
  checks. A genuinely-failed LNbits payment will sit `PENDING` forever via
  polling — it waits for an operator abort (§4).
- This is the deliberate trade: **the mint never double-pays/double-spends, at the
  cost of occasionally needing a manual abort.**

Money-math notes: melt requires `(input_total − input_fee) ≥ amount +
fee_reserve` (else `400 insufficient-inputs`). Refund = `fee_reserve −
actual_routing_fee`, and `routing-fee-sats` is **fail-closed** — a fee field it
can't parse as a clean integer is treated as the full reserve, so refund rounds to
**0** rather than ever over-refunding. A backend that reports fees in an
unexpected field/encoding therefore silently overcharges the customer their whole
reserve; verify your backend's fee fields against a real small melt.

---

## 4. Handling a stuck `PENDING` melt (the core operator procedure)

A quote stuck `PENDING` means: **inputs are spent**, the Lightning outcome is
unconfirmed to the mint. **Do not delete it** (delete is refused for
pending/inflight melts — `cannot-delete-pending-melt`). Resolve it:

1. **Poll first:** `GET /v1/melt/quote/bolt11/{id}`. If the payment settled this
   flips it to `PAID` and returns the change. Done.

2. **If still `PENDING`, check your Lightning node directly** (LNbits dashboard /
   `lncli listpayments` / `lncli trackpayment`). Determine the real outcome, then:

   - **Settled on LN** → poll again, or
     `POST /apps/ecash/admin/api/melt/abort {quote_id}` — abort re-checks LN and
     **will never roll back a settled pay** (it returns
     `result:"settled-not-aborted"` and settles instead).
   - **Definitively failed, LND backend (`status=FAILED`)** →
     `POST .../melt/abort {quote_id}` (no force). The mint sees the explicit
     failure and rolls back: inputs become spendable again, `total_redeemed_sats`
     decremented (underflow-guarded), quote `→ failed`. Result:
     `aborted-confirmed-failed`.
   - **LNbits, or LND can't prove failure (404 / `paid:false` / in-flight /
     2xx-without-preimage)** → the default abort **refuses** with
     `result:"in-flight-or-unconfirmed"`, leaving the quote `PENDING`. Only after
     you have **confirmed out-of-band that the HTLC is dead/cancelled**, force it:
     `POST .../melt/abort {quote_id, force:true}`. This un-spends the inputs.
     ⚠️ **Forcing an abort on a payment that later settles double-pays you.** Even
     under force, if the LN re-check shows settled the mint settles instead of
     rolling back — but settle detection needs the preimage in the status
     response; if your backend omits it, force *will* roll back a settled HTLC.
     **Force is for confirmed-dead payments only.**

3. **Legacy / restart-orphaned quotes** (no stored `melt-inflight`, e.g. created
   before the inflight record existed or orphaned by a crash mid-flight): if abort
   reports `no-inflight-record`, recover by supplying the original input
   identifiers: `POST .../melt/abort {quote_id, force:true, secrets:[...],
   ys:[...]}` — those exact inputs are un-spent (`redeemed_decremented:0` since the
   counter linkage is gone). If you don't have them, the proofs can't be
   auto-reclaimed; the quote can be force-failed to unstick it but those inputs
   stay spent.

**Abort `result` values:** `aborted-confirmed-failed` · `aborted-forced` ·
`settled-not-aborted` · `in-flight-or-unconfirmed` · `no-op-not-pending` ·
`no-inflight-record`. The response carries `{aborted:bool, result, ...}`;
read `result`, not the (always-200) HTTP status. Note the abort runs
**asynchronously** when it can re-check LN — the decision lands on the deferred
LN response, not the initial call. There is **no dashboard button** for abort;
call it by hand.

---

## 5. Lightning-backend-down playbook

Distinguish two cases:

- **Backend `%none`, or unreachable at quote-creation time.** New bolt11
  mint/melt-quote requests fail fast (`400 no-lightning-backend-configured` for
  `%none`, or an LN-layer error). No value is at risk; the mint is effectively
  read-only for bolt11. Customers see quote-creation errors. Nothing to reconcile.
- **Backend goes down *after* a melt was dispatched.** Those quotes sit `PENDING`
  with inputs spent — exactly the §4 path. **They are safe**: the durable
  `melt-inflight` record means they will reconcile on the next poll/abort once the
  node returns. Do **not** delete them, do **not** restart-and-resubmit.

Do **NOT** enable `self_method` to "keep minting" during an outage — that creates
unbacked tokens (instant inflation, §9/§14). The correct response to a node outage
is to let bolt11 quote-creation fail, leave in-flight melts `PENDING`, and
reconcile when the node is back.

---

## 6. Admin endpoints (full reference)

All require an `%ours` session cookie. POSTs additionally require same-origin
Origin/Referer (or none). `%ecash` surface (`/apps/ecash/admin/api/...`):

| Method · Path | Body | Effect / notes |
|---|---|---|
| `GET /overview` | — | Liability + counts: `total_issued_sats`, `total_redeemed_sats`, mint/melt quote tallies, `ln_backend`. (Folds `%failed` quotes into the `unpaid` bucket; omits melt `issued`.) |
| `GET /settings` · `POST /settings` | `{fee_reserve_pct?, fee_reserve_min?, quote_ttl_secs?, self_method_enabled?}` | Read / update economic + self-method settings. ⚠️ **No server-side bounds check** (§9). |
| `GET /lightning` | — | `{type, configured, url, api_key_set}` — credential value is never exposed. |
| `POST /lightning/configure` | `{type:"none"}` \| `{type:"lnbits",url,api_key}` \| `{type:"lnd",url,macaroon}` | Set backend (stores credential in state). |
| `POST /lightning/test` | — | ⚠️ Reports config presence **only** — does **not** contact the node. A 200 here does not prove connectivity; verify with a small mint quote. |
| `GET /keysets` · `GET /keysets/{id}` | — | List / detail (public keys only; privkeys never exposed). |
| `POST /keysets/generate` | — | Create a **new inactive** keyset. Does not rotate. |
| `POST /keysets/activate` | `{id}` | Rotate: activate target, demote previous active. |
| `POST /keysets/deactivate` | `{id}` | Deactivate target; refuses the active keyset (`cannot-deactivate-active`). No dashboard button. |
| `POST /keysets/set-fee` | `{id, input_fee_ppk}` | **Forks** the keyset (§8). `409 keyset-id-collision` if the new id already exists; `400 input_fee_ppk-too-large` if `> 100000`. |
| `GET /quotes` | — | All mint + melt quotes with state/expiry. |
| `POST /quotes/delete` | `{quote_id, type:"mint"\|"melt"}` | Delete a quote. Refused for `%issued`/`%paid` mint, `%paid` melt, and `%pending`/inflight melt (owed value — use abort instead). |
| `POST /melt/abort` | `{quote_id, force?, secrets?, ys?}` | Reconcile/abort a stuck `PENDING` melt (§4). No dashboard button. |
| `GET /spent` · `POST /spent/check` | `{secret}` \| `{Y}` | Double-spend ledger sizes / point lookup (read-only despite POST). |
| `GET /info` · `POST /info/update` | `{name?, description?}` | NUT-06 info / edit name+description. |

`%ecash-services` mirrors an admin surface at `/apps/ecash-services/admin/api/*`:
`cred/overview`; `cred/keysets/generate|activate|deactivate`;
`services` · `services/{name}`; `services/create|update|activate|deactivate|delete`;
`services/allowlist/add|remove`. Same auth/CSRF model. Notable guards:
`services/delete` requires the service inactive **and** `issued==0`
(`service-has-issued-tokens` otherwise; `issued` is monotonic and never
decremented), and it does **not** remove the backing keyset.

---

## 7. Public API surface (reference)

Unauthenticated by protocol design. Knowing the surface helps with monitoring and
abuse analysis (§12–13).

- `GET /v1/keys` — active keysets + full pubkey maps. `GET /v1/keys/{id}` — one
  keyset (active or not). `GET /v1/keysets` — all keysets, metadata only.
- `GET /v1/info` — NUT-06 capabilities. Advertises `self` (min 1, max 512) always
  and `bolt11` (min 1, max 1,000,000) only when a backend is configured.
- `POST /v1/swap` — `{inputs, outputs}`. Conserves value: `(input_total − fee) ==
  output_total` or `400 amounts-do-not-balance`. Rejects spent inputs,
  duplicate-x outputs, bad signatures, unmet P2PK thresholds.
- `POST /v1/mint/quote/{method}` · `GET .../{id}` · `POST /v1/mint/{method}`.
- `POST /v1/melt/quote/bolt11` · `GET .../{id}` · `POST /v1/melt/bolt11` (§3–4).
- `POST /v1/checkstate` — `{Ys:[...]}` (capital-Y key), NUT-07 spent lookup.
- Batch cap: **100** inputs/outputs/Ys per request (`400 batch-too-large`).
- ⚠️ bolt11 quote-create / poll / melt-POST return their real body
  **asynchronously** (they dispatch an outbound LN HTTP request first); a monitor
  expecting an instant JSON body on those paths will see a delayed response.

---

## 8. Keyset management & rotation

- **Rotation:** `keysets/generate`, then `keysets/activate {id}`. New tokens use
  the new keyset; old tokens still verify under the old one (verify deliberately
  accepts inactive keysets; only **minting** is refused under an inactive keyset —
  `sign-outputs` returns `inactive-keyset`).
- **Changing a fee forks the keyset.** The keyset id commits to the fee, so
  `set-fee` derives a **new id**: it keeps the **old id as an inactive alias**
  (old fee retained, so already-issued tokens still spend correctly) and creates a
  **new active id** with the new fee, repointing `active-keyset` if the target was
  active. Wallets caching the old active id will get `inactive-keyset` on mint
  until they refresh `/v1/keysets`. Re-applying the *same* fee fork hits
  `409 keyset-id-collision` (not idempotent once forked).
- To retire the active keyset there is no one-step "deactivate active" — activate a
  replacement first (which demotes the old one).
- `%ecash-services` keysets generated via `services/create` are **service-scoped**:
  they can only be signed/verified/redeemed via the gated `/services/{name}` path,
  never the public `/cred` path. (Their public key is still fetchable by id, which
  is harmless — a pubkey can't forge a signature.) Keysets from
  `cred/keysets/generate` are *not* scoped and are publicly usable via `/cred`.

---

## 9. Settings & economic tuning

| Setting | Default | Meaning |
|---|---|---|
| `self_method_enabled` | `false` | No-payment mint/melt. **Keep off in production.** |
| `fee_reserve_pct` | `100` | Melt fee reserve, basis `amount × pct / 10000` (100 = 1%). |
| `fee_reserve_min` | `10` | Sats floor: `reserve = max(min, pct·amount)`. |
| `quote_ttl_secs` | `3600` | Quote lifetime (seconds). |
| `mint_name` / `mint_description` | `ecash-mint` / `Cashu ecash mint on Urbit` | NUT-06 info. |
| keyset `input_fee_ppk` | `0` | Per-proof input fee (ppk); cap `100000`, set via `set-fee`. |
| batch cap | `100` | Constant (not settable). Max inputs/outputs/Ys per request. |
| cleanup interval | daily (`~d1`) | Prunes expired quotes (§16). |

⚠️ **`POST /settings` performs no validation.** It applies any unsigned integer,
including `0`. `quote_ttl_secs:0` expires every new quote instantly;
`fee_reserve_pct:0` + `fee_reserve_min:0` zeroes the melt reserve. Enforce bounds
yourself before calling. (Same hazard in `%ecash-services`: a malformed
`max_issuance` or `expires` coerces to `0` — `max_issuance:0` permanently blocks
issuance, `expires:0` expires the service immediately.)

---

## 10. Backup & disaster recovery

**All money-critical secrets live only in agent state inside the pier:** keyset
**private keys** and the **Lightning credential** (LNbits api-key / LND macaroon).
There is no key export and no separate secret store — **the pier is the backup
unit.**

- **Back up the pier** on a schedule. A pier backup contains plaintext mint
  privkeys *and* the LN credential — **encrypt the backup at rest** and restrict
  access accordingly.
- **A stale restore reintroduces double-spend/double-pay risk.** Restoring an old
  pier snapshot silently reverts the spent-secret / spent-Y sets, all quotes, the
  `melt-inflight` records, and the liability counters. Tokens spent *after* the
  snapshot become spendable again; melts that paid after the snapshot can re-pay.
  Treat any restore as an incident:
  1. Before resuming public traffic, **reconcile against the Lightning node**:
     compare the node's payment ledger to the restored melt-quote / `melt-inflight`
     state; any payment the node made that the restored state shows `pending`
     /`unpaid` must be settled or the inputs left spent.
  2. Expect that proofs the restored state shows unspent may already have been
     redeemed by holders — there is no automatic way to re-derive that. Prefer
     restoring the **most recent** snapshot and, if value integrity is in doubt,
     rotate to a fresh keyset and wind down the old liability deliberately.
- **Do a restore drill** before you need one. Verify the restored mint answers
  `/v1/info`, `/overview` shows the expected counters, and the active keyset id
  matches (`/x/active-keyset` scry, host-only).

---

## 11. Upgrade & state migration

`on-load` runs a **forward-only** migration chain (currently `state-6 → … →
state-13`; services migrates `state-old → state-0`). Migrations cannot be
reversed, and a **downgraded binary cannot read newer state** — a rollback to an
older agent will fail to load.

Procedure:
1. **Take a pier backup first** (§10).
2. If you changed shared crypto, run `make sync-libs` so
   `desk-services/lib/{curve,bdhke}.hoon` are regenerated **before** committing the
   services desk.
3. `|commit` the desk(s); watch the load. Two migration steps have operational
   side effects: `11→12` **clears the volatile pending map** (in-flight iris HTTP
   requests are dropped across that upgrade — durable melt recovery relies on
   `melt-inflight`, added in `12→13`, plus the §4 poll/abort path); `12→13`
   initializes `melt-inflight` empty.
4. **Verify post-upgrade:** `/overview` counters look sane, `/v1/info` responds,
   active keyset unchanged (`/x/active-keyset`). Resolve any melts that were
   in-flight across the upgrade via §4.
5. Note: the daily cleanup timer is **not** re-armed on load (only on init and
   after each fire — intentional, to avoid leaking timers). If an upgrade lands in
   a window where the timer was already consumed, cleanup resumes on the next
   natural fire; it is not money-critical (it only prunes *expired, non-owed*
   quotes).

---

## 12. Monitoring, alerting & solvency

There is no metrics endpoint or webhook — signals are `GET /overview`,
`GET /quotes`, and console `~&` traces. Build alerting around:

- **Rising `%pending` melt count** → spent value with unresolved Lightning
  outcome. Each is real money awaiting §4. Alert and work them down.
- **`%paid`-but-unissued mint quotes** → sats received from a customer, tokens not
  yet issued. Cleanup retains these forever (owed value); they should be
  redeemable. Watch the count; a growing backlog means customers can't mint.
- **Liability ceiling** → `total_issued_sats − total_redeemed_sats`. Alert if it
  approaches your Lightning balance.
- **Disk / event log** → `du -sh <pier>/.urb/log` and `df`. The log grows fast
  under load and can fill the disk and wedge the ship (§16). Alert on a concrete
  size threshold well below capacity.
- **Silent Eyre bind failures** → if a `/v1` or legacy bind fails, the agent only
  prints `%ecash-bind-v1-failed` / `%ecash-bind-legacy-failed` to the console; the
  public API silently goes offline. Watch the trace log and probe `/v1/info`
  externally.

**Solvency / proof-of-reserves.** Run a periodic check that Lightning balance ≥
outstanding ecash liability — not just at incident time. The liability counters
are cumulative totals, not a double-entry ledger (and the abort decrement clamps
to 0 on underflow, which can understate redeemed), so cross-check against the LN
node rather than trusting the counters alone.

---

## 13. Capacity, abuse & rate limiting

**No rate limiting exists in code.** The only bounds are the `100`-item batch cap
and the `100000` `input_fee_ppk` cap. There is no per-IP throttle, no `429`, no cap
on open mint quotes, no global liability ceiling, and no min/max mint/melt amount
beyond the advertised NUT-04/05 ranges. `/v1/*` is fully public.

Compensating controls are the operator's responsibility:
- Front the ship with a **reverse proxy that rate-limits** `/v1/*` per IP.
- Watch for **quote-creation spam**: each bolt11 quote triggers an outbound LN
  HTTP call and grows the event log; a flood is both a backend-load and a
  disk-exhaustion vector (§16).
- Consider application-level limits at the proxy (max body size, request rate)
  since the mint will faithfully process anything within the batch cap.

---

## 14. Incident response: key / pier compromise

A stolen pier copy is catastrophic: it contains every keyset's **private keys**
(forge unlimited tokens under any keyset id — keyset rotation does **not** help,
since old ids still verify) **and** the **Lightning credential** (drain the node
up to the macaroon/api-key's scope).

Response:
1. **Rotate the Lightning credential at the node immediately** (new macaroon /
   api-key, revoke the old). This is independent of keyset rotation and is the only
   thing that stops node drainage. Re-`configure` the mint with the new credential.
2. **Stop taking new value** on the compromised pier.
3. **Wind down to a fresh pier**: stand up a new pier with a freshly-generated
   keyset, migrate liability deliberately (let holders redeem / re-issue), and
   **never reuse the exposed pier**. Tokens under the old keys can be forged
   forever; the old mint's liability must be drained and retired, not trusted.
4. Treat encrypted, access-controlled pier backups (§10) as part of the blast
   radius — a leaked backup is a leaked pier.

---

## 15. Incident response: confirmed double-pay

If a force-abort (§4) rolled back inputs and the HTLC later settled — or any path
double-paid:
1. **Detect** by comparing the Lightning node's payment ledger to the mint's
   melt-quote / `melt-inflight` history and the `total_redeemed_sats` counter. A
   settled HTLC for a quote the mint shows `failed`/`unpaid` is a double-pay.
2. **Reconcile the books:** the un-spent proofs may already be re-spent; the sats
   left the node. Quantify the loss against liability.
3. **Absorb / contain:** there is no protocol clawback. Tighten the force-abort
   authority (see below) and, if losses are material, rotate to a fresh keyset and
   wind down.

**Prevention is the real control.** Force-abort is the one irreversible action;
make it a two-person / pre-authorized decision and require independent LN-node
confirmation that the HTLC is dead before anyone passes `force:true`.

---

## 16. Maintenance

- **Event-log growth.** Heavy traffic (and especially load-testing) grows
  `<pier>/.urb/log` quickly — it can fill the disk and wedge the ship. Monitor
  `du -sh <pier>/.urb/log` and `df`. To reclaim: stop the ship, then truncate the
  event log with `urbit chop <pier>`; if the bloat is the *current* epoch, let the
  ship roll a new epoch first, then chop the old one. The state snapshot
  (`.urb/chk`) holds current state — chopping discards only history.
- **Cleanup.** The daily behn timer prunes *expired* quotes, but **never** deletes
  a `%paid` mint quote (sats received, awaiting issuance), a `%paid` melt quote
  (may owe NUT-08 change), or a `%pending` melt (inputs spent, outcome
  unresolved). Those are owed value and are retained indefinitely until consumed or
  reconciled — an accumulation of stuck `%pending` melts is real spent value
  awaiting §4, not garbage.
- **Liability.** Outstanding = `total_issued_sats − total_redeemed_sats`
  (`/overview`). A genuinely-failed melt that you abort decrements
  `total_redeemed_sats` (clamped at 0 on underflow).

---

## 17. Security posture & residual operator responsibility

The automatic/public surface — mint, swap, BDHKE/DLEQ, P2PK multisig, the auto
melt path, services access control — has been hardened across multiple adversarial
audits and re-verified. Key invariants:

- **No forgery:** DLEQ nonce bound to full points; P2PK counts distinct x-only
  signers; service tokens are unforgeable via the public path.
- **No double-spend / double-pay:** melt is single-use-guarded; reconciliation
  never un-spends on ambiguous evidence; every settle gates on `%pending` (stale
  responses are no-ops).
- **No inflation:** mint/swap conserve value; `%issued` quotes can't be re-minted;
  fees can't be evaded by omitting a proof id; minting under an inactive keyset is
  refused; zero-amount value outputs are rejected.
- **Fail-closed money math:** fee refunds round against the mint; underflows are
  guarded; malformed input returns clean `400`s, never a crashed event.

**Residuals that are operator responsibility, not code guarantees:**
1. A **force-abort** of a payment you wrongly believe failed will double-pay
   (§4, §15).
2. **No rate limiting / abuse controls** exist in code (§13).
3. **No bounds-checking** on economic settings (§9).
4. **Secrets live in the pier in cleartext**; backup hygiene and credential
   least-privilege are yours (§10, §14).

---

## 18. Appendix: install, tests, known quirks

**Install (per agent).** `|new-desk %ecash` → `|mount %ecash` → copy `desk/`
contents into the mount → `|commit %ecash` → `|install our %ecash`. Repeat for
`%ecash-services` from `desk-services/` — but **run `make sync-libs` first** on a
fresh clone, or the build fails (the shared `desk-services/lib/{curve,bdhke}.hoon`
are gitignored, generated from `desk/lib`). Configure Lightning via the admin API
(§2) or a host-only `%noun` poke `:ecash [%lnbits 'http://…' 'api-key']` (asserts
`src == our`).

**Toolchain.** Urbit vere 4.x, zuse kelvin `409` (`sys.kelvin`). Browser-side
crypto in tests: `@noble/secp256k1`. JS deps are test/dev only.

**Test suite (operational smoke / verification).** `npm run test:all` runs the
full suite (e2e, conformance, p2pk, cred, services, services-scope, swap-security,
vectors, melt-fee, melt-p6, admin-auth, self-method, parse-robustness,
legacy-removed, dashboards). Lightning tests need the mock on port 3338
(`make mock-lnbits`) and the mint pointed at it
(`:ecash [%lnbits 'http://localhost:3338' 'test-api-key']`).
**`test-conformance.mjs` requires `URBAUTH_COOKIE`** in the environment (it no
longer hardcodes a session cookie): `URBAUTH_COOKIE=<ship-cookie> npm run
test:conformance`. Hoon unit tests: `-test /=ecash=/tests/test/hoon`.

**Known quirks (don't be surprised):**
- **Version strings differ**: `/v1/info` reports `ecash/0.2.0` while the legacy
  `/apps/ecash` status reports `0.2.0`.
- **`/lightning/test` doesn't probe the node** — it only reports config presence.
- **`%failed` melts serialize as `UNPAID`** to wallets (correct for retry); read
  the on-state tag to tell a fresh quote from a failed-and-rolled-back one.
- **README version text may lag** the source; trust the source (`state-13`) and
  `package.json` for versions.
