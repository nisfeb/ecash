# Operator Runbook — %ecash mint

Practical operations for running the Urbit Cashu mint (`%ecash` value mint +
`%ecash-services` zero-value access agent). Reflects the current security model.
Pairs with the design specs in `docs/design/specs/`.

---

## 1. Architecture at a glance

- **`%ecash`** — the value mint. Serves the Cashu protocol at the ship's web
  root: `/v1/keys`, `/v1/info`, `/v1/swap`, `/v1/mint/quote/{method}`,
  `/v1/mint/{method}`, `/v1/melt/quote/bolt11`, `/v1/melt/bolt11`,
  `/v1/checkstate`. Admin (cookie-gated) at `/apps/ecash/admin`.
- **`%ecash-services`** — zero-value credentials/access control at `/cred/*`
  and `/services/*`. Admin at `/apps/ecash-services/admin`.
- Shared crypto (`lib/curve.hoon`, `lib/bdhke.hoon`) lives in `desk/lib` and is
  regenerated into `desk-services/lib` at deploy — **edit it in one place.**

Admin auth = the ship's own login session (Eyre `%ours`). State-changing admin
POSTs also require a same-origin **Origin/Referer** (CSRF). Non-browser tooling
(curl/scripts) must send `-H 'origin: http://<your-ship-host>'` — a *missing*
Origin is allowed (non-browser), a *mismatched* one is rejected `403`.

---

## 2. Pre-production checklist

1. **Start on a fresh keyset.** The mint generates one on init. Never expose
   private keys; if a denomination key is ever leaked, the leaked keyset stays
   usable to forge tokens *under that keyset id* (verify accepts any keyset a
   token names) — so the only true remedy is to **never reuse a pier whose keys
   were exposed**. Generate + activate a clean keyset before taking real value.
2. **Configure Lightning** (`POST /apps/ecash/admin/api/lightning/configure`
   `{type:'lnbits'|'lnd', url, api_key|macaroon}`). Leave `type:'none'` until
   ready — with `none`, bolt11 mint/melt are inert.
3. **Leave `self_method_enabled` OFF.** The `self` method mints/melts for free
   (no Lightning) — it is a testing kill-switch only. `POST .../settings
   {self_method_enabled:false}`.
4. **Set sane fee/TTL** via `.../settings`: `fee_reserve_pct`, `fee_reserve_min`,
   `quote_ttl_secs` (default 3600).
5. Confirm `GET /v1/info` and `GET /v1/keys` respond `200` and advertise the
   intended keyset + NUTs.

---

## 3. The melt safety model (read this before operating bolt11 melts)

A bolt11 melt is an **outbound** Lightning payment. The mint cannot always tell
"failed" from "still in flight" via the backend API, so the design is
**safety-first: it never un-spends a customer's proofs on ambiguous evidence.**

What happens on `POST /v1/melt/bolt11`:
- Inputs are marked **spent** and the quote goes **`PENDING`**; the pay is
  dispatched. The reconciliation data is stored durably (survives restart).
- **Settle → `PAID`** only on a positive proof: a non-empty `payment_preimage`
  and no error. Then NUT-08 change is signed once. (Accepts any 2xx incl. real
  LNbits's `201`.)
- **Anything else** (non-2xx, timeout, `%cancel`, `paid:false`, in-flight,
  `404`) → the quote **stays `PENDING`** and the response is `PENDING`. The mint
  does **not** roll back. The client should **poll**, not re-submit.
- Polling `GET /v1/melt/quote/bolt11/{id}` re-checks Lightning and **auto-settles
  to `PAID`** once the payment confirms. The auto-poll **never auto-rolls-back**
  except on an explicit LND `status=FAILED`.

Consequence to internalize: **a genuinely-failed payment does not self-heal on
LNbits** (its API can't prove failure). It waits for the operator to abort. This
is the deliberate trade — *the mint never double-pays/double-spends, at the cost
of occasionally needing a manual abort.*

---

## 4. Handling a stuck `PENDING` melt (the core operator procedure)

A quote stuck `PENDING` means: inputs are spent, the Lightning payment's outcome
is unconfirmed to the mint. **Do not delete it** (delete is refused for pending
melts). Resolve it:

1. **Poll first:** `GET /v1/melt/quote/bolt11/{id}`. If the payment settled,
   this flips it to `PAID` and returns the change. Done.
2. **If still `PENDING`, check your Lightning node directly** (lnbits dashboard /
   `lncli listpayments` / `lncli trackpayment`). Determine the real outcome:
   - **Settled on LN** → just poll again; it will settle (or
     `POST /apps/ecash/admin/api/melt/abort {quote_id}` which also settles —
     it re-checks LN and will **never** roll back a settled pay).
   - **Definitively failed** (LND `FAILED`) →
     `POST .../melt/abort {quote_id}` (no force). The mint sees the explicit
     failure and rolls back: inputs become spendable again, quote `→ failed`
     (retryable). Response `result:"aborted-confirmed-failed"`.
   - **LNbits, and the API only says `paid:false`/`404`** (can't prove failure)
     → the default abort will refuse (`result:"in-flight-or-unconfirmed"`,
     quote left `PENDING`). Only after you have **confirmed out-of-band that the
     HTLC is dead/cancelled**, force it:
     `POST .../melt/abort {quote_id, force:true}`. This un-spends the inputs.
     ⚠️ **Forcing an abort on a payment that later settles double-pays you.**
     Force is for confirmed-dead payments only. (Even under force, if LN turns
     out to show settled, the mint settles instead of rolling back.)

**Legacy / restart-orphaned quotes** (no stored reconciliation data, e.g. a
quote created before Phase 6 or orphaned by a crash mid-flight): if abort reports
`no-inflight-record`, recover by supplying the original input identifiers:
`POST .../melt/abort {quote_id, force:true, secrets:[...], ys:[...]}` — these
exact inputs are un-spent. If you don't have them, the proofs cannot be
auto-reclaimed; the quote can be force-failed to unstick it but those inputs stay
spent.

`abort` responses: `{aborted, result, ...}` where `result` ∈
`aborted-confirmed-failed` · `aborted-forced` · `settled-not-aborted` ·
`in-flight-or-unconfirmed` · `no-op-not-pending` · `no-inflight-record`.

---

## 5. Admin endpoints (state-changing — send cookie + Origin)

| Endpoint | Effect |
|---|---|
| `POST /apps/ecash/admin/api/settings` | self-method toggle, fees, TTL |
| `POST .../lightning/configure` | set LN backend (lnbits/lnd/none) |
| `POST .../keysets/generate` · `/activate` · `/deactivate` | keyset lifecycle |
| `POST .../keysets/set-fee` | change a keyset's fee (see §6) |
| `POST .../quotes/delete` | delete a quote (refused for `%paid` and `%pending`/inflight melts) |
| `POST .../melt/abort` | reconcile/abort a stuck `PENDING` melt (see §4) |
| `GET .../overview` · `/quotes` · `/keysets` · `/spent` · `/lightning` · `/info` | read-only dashboards |

`%ecash-services` mirrors an admin surface at `/apps/ecash-services/admin/api`
for services + credential keysets.

---

## 6. Keyset management

- **Rotation:** `keysets/generate` then `keysets/activate {id}`. New tokens use
  the new keyset; old tokens still verify under the old one.
- **Changing a fee forks the keyset.** `set-fee` recomputes the keyset id (the id
  commits to the fee), keeps the **old id as an inactive alias** (so
  already-issued tokens still spend at the old fee), and makes a **new active id**
  with the new fee. New tokens cannot be minted under the old (inactive) id —
  `sign-outputs` refuses inactive keysets. A repeated set-fee to a fee whose id
  already exists returns `409 keyset-id-collision`.
- Service-backing keysets (`%ecash-services`) are `service-scoped` and cannot be
  signed/redeemed/verified via the public `/cred` path — only the gated
  `/services/{name}` path (allowlist + issuance cap).

---

## 7. Maintenance

- **Event-log growth.** Heavy traffic (and especially load-testing) grows the
  ship's `.urb/log` quickly — it can fill the disk and wedge the ship. Monitor
  `du -sh <pier>/.urb/log` and `df`. To reclaim: stop the ship, then truncate the
  event log (`urbit chop <pier>`; if the bloat is the *current* epoch, let the
  ship roll a new epoch first, then chop the old one). The state snapshot
  (`.urb/chk`) holds current state — chopping discards only history.
- **Cleanup.** A daily behn timer prunes expired quotes, but **never** deletes a
  `%paid` quote (sats received, awaiting issuance/change) or a `%pending` melt
  (inputs spent, outcome unresolved) — those represent owed value and are kept
  until consumed/reconciled. Watch for an accumulation of stuck `%pending` melts
  (each is real spent value awaiting §4).
- **Liability:** outstanding = `total_issued_sats − total_redeemed_sats` (on
  `/overview`). A genuinely-failed melt that you abort decrements
  `total_redeemed_sats`.

---

## 8. Security posture (what's hardened)

Across Phases 5–8 and four adversarial audits, the automatic/public surface —
mint, swap, BDHKE/DLEQ, P2PK multisig, the auto melt path, services access
control — has been hardened and re-verified. Key invariants:

- **No forgery:** DLEQ nonce bound to full points; P2PK counts distinct x-only
  signers; service tokens unforgeable via the public path.
- **No double-spend/double-pay:** melt is single-use-guarded; the reconciliation
  never un-spends on ambiguous evidence; every settle gates on `%pending`.
- **No inflation:** mint/swap conserve value; `%issued` quotes can't be
  re-minted; fees can't be evaded by omitting a proof id.
- **Fail-closed money math:** fee refunds round against the mint; underflows are
  guarded; malformed input returns clean `400`s, never a crashed event.

The one residual that is **operator responsibility, not a code guarantee:** a
force-abort of a payment you wrongly believe failed will double-pay. Verify on
your Lightning node before forcing (§4).
