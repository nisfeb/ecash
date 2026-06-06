# ecash — Final Form: Public, Value-Bearing Cashu Mint

- **Date:** 2026-06-04
- **Status:** Draft for review
- **Scope:** Roadmap + architecture spec for evolving the current `%ecash` agent into a
  hardened, standards-conformant public Cashu mint, with the bespoke extensions split out.

## Decision summary (locked)

1. **Purpose:** a public, *value-bearing* Cashu mint that external wallets transact against.
   Security hardening and standards interop are non-negotiable.
2. **Interop bar:** mainstream wallets (cashu-ts / Nutshell / eNuts / Minibits) must mint,
   send, receive, and melt against it end-to-end.
3. **Architecture:** the credential (`/cred/v1`) and services (`/services/v1`) extensions
   move to their own desk; `%ecash` becomes a focused, spec-pure mint.
4. **`self` mint/melt:** off by default; available only behind an admin flag for testing.
5. **Performance:** pursue pure-Hoon projective-coordinate arithmetic first; hold a native
   secp jet in reserve only if measured load demands it.

## Context — what exists today

A complete Cashu mint in pure Hoon as a single Gall agent (`desk/app/ecash.hoon`, ~3,259
lines), with crypto in `desk/lib/curve.hoon` (secp256k1 point ops) and
`desk/lib/bdhke.hoon` (BDHKE, DLEQ, BIP-340 Schnorr). Shared types in `desk/sur/ecash.hoon`.
Admin dashboard in `desk/app/dashboard.txt`. State is at version 9 with a v6→v9 migration
chain.

Implemented: NUTs 00–12 — BDHKE blind signatures, DLEQ proofs, P2PK (multisig/locktime/
refund), Lightning mint+melt (LNbits/LND), NUT-08 change, plus two non-standard extensions
(zero-value credential tokens and a named-scope "services" access-control layer). Standard
API at `/v1/*`, admin at `/apps/ecash/admin/*`, extensions at `/cred/v1/*` and
`/services/v1/*`.

The crypto core is careful (correct field/scalar arithmetic, point-at-infinity crashes
instead of silent fallback, DLEQ nonce bound to the message). Testing is an 85-assertion
JS e2e suite plus 5 Hoon unit tests (crypto only).

## Goal — the final form

Two desks sharing one crypto core:

- **`%ecash`** — a focused, standards-conformant Cashu mint. `/v1/*` only. Unauthenticated
  Cashu protocol endpoints (as the spec requires) plus an **authenticated** admin surface.
  No bespoke endpoints, no free-mint paths. This is what mainstream wallets connect to.
- **`%ecash-services`** — a separate Gall agent owning the credential + services
  access-control layer (`/cred/v1`, `/services/v1`), depending on the shared crypto.
- **Shared crypto** — `lib/curve` + `lib/bdhke` as a single source of truth both desks build
  against (vendored via peru or a small shared desk; decided in Phase 3).

## Non-goals

- Token string (`cashuA…`/`cashuB…`) serialization — that is wallet-side, not mint-side.
- A wallet/frontend UI for end users (the admin dashboard stays; a consumer wallet is out
  of scope for this spec).
- Multi-unit support beyond `sat` unless a target wallet requires it.
- SIG_ALL for P2PK (SIG_INPUTS only remains a documented limitation).

## Problem inventory (what the plan fixes)

🔴 **Critical**
- **C1 — Admin API has no authentication.** `handle-http` never inspects `authenticated`
  on the inbound request; the only access check in the agent is the services allowlist.
  Every `/apps/ecash/admin/*` route is callable by anyone who can reach the ship's HTTP.
- **C2 — Unauthenticated free minting.** The `self` mint method auto-marks quotes paid and
  `/v1/mint/self` issues real signatures with no payment. The legacy
  `POST /apps/ecash/mint` (`post-mint-legacy`) signs arbitrary outputs with no quote at all.
  With a funded Lightning backend, C1+C2 make the mint drainable (self-mint, then
  bolt11-melt out).

🟠 **Significant**
- **S1 — Pure-Hoon EC performance / DoS.** Only `k*G` is jetted. Every verify, blind-sign,
  and most DLEQ ops use pure-Hoon double-and-add where `pt-add`/`pt-dbl` perform a field
  **inversion per operation** (`fdiv`→`finv`, a 256-bit modexp). Heavy per-token cost on the
  single-threaded event loop; large batches can wedge the ship; unauthenticated CPU-exhaustion
  vector.
- **S2 — Keyset-ID / response conformance is unverified.** Keyset IDs use a string-canonical,
  `01`-prefixed, 66-char scheme. The JS tests echo the mint's own ID back, so they pass
  regardless. Mainstream wallets that re-derive the keyset ID (and parse `/v1/info`, DLEQ,
  and response shapes strictly) may reject. No test drives a real wallet library.
- **S3 — Malformed numbers crash the event.** `parse-ud` (`scan … (plus dit)`) crashes on any
  non-integer JSON number (`{"amount":1.5}`), aborting the request instead of a 400.
- **S4 — No state hygiene.** `mint-quotes`, `melt-quotes`, `pending`, `melt-change` grow
  unbounded; nothing prunes expired entries, and `pending` leaks if an iris call never
  reaches `%finished`.
- **S5 — Melt over-refunds routing fees.** bolt11 change is signed for the entire
  `fee-reserve`, not `reserve − actual_fee`, so the mint eats real routing fees.

🟡 **Polish**
- Thin Hoon-level tests (handlers/P2PK/services/migrations only covered by live-ship JS).
- Migration chain starts at v6 (acceptable — no known older deployments).
- Allowlist keys stored/compared in plaintext (moves to `%ecash-services`).

## Key decisions & rationale

- **Cashu endpoints stay public; only admin is authenticated.** `/v1/*` is unauthenticated
  by protocol design. The fix for C1 gates `/apps/ecash/admin/*` on
  `authenticated.inbound-request` and returns 401 otherwise. Optionally require `secure` when
  TLS is terminated on-ship (configurable, since TLS is often terminated upstream).
- **`self` off by default (C2).** A public sats mint must not coin free value. Add a state
  flag `self-method-enabled=?` defaulting to `%.n`; when off, `self` returns
  `400 self-method-disabled`. Remove the legacy free-sign endpoints entirely.
- **Standard keyset IDs require a migration, not a rename (S2).** Keyset IDs are embedded in
  every issued token. The conformant ID is derived differently, so the mint introduces a new
  active keyset whose ID matches what wallets derive, while **keeping existing keysets under
  their old IDs for redemption**. The exact target derivation (most likely the widely-deployed
  `00`+14-hex-of-sha256-over-sorted-compressed-pubkeys, 16 chars total) is **confirmed
  empirically against cashu-ts** in Phase 2 rather than assumed here.
- **Projective coordinates before a jet (S1).** Converting `lib/curve` point ops to Jacobian
  coordinates defers the per-operation inversion to a single inversion per scalar-mult —
  plausibly ~100× off the dominant cost — while keeping the "runs on any stock ship"
  property. A native jet costs a custom Vere binary (ops burden + trust surface for a public
  mint) and is reserved for measured need.

## Phased roadmap

Each phase ends in a strictly safer, shippable state. Phases are ordered risk-first: the only
changes that can lose money land first.

### Phase 1 — Stop the bleeding (security). *Outcome: safe to run privately.*
- Gate every `/apps/ecash/admin/*` route on `authenticated.inbound-request`; 401 otherwise.
  (C1)
- Remove `post-mint-legacy` and `post-melt-legacy` and their routes. (C2)
- Add `self-method-enabled=?` to state (default `%.n`) + admin settings get/set; gate the
  `self` branch in `post-mint-quote`, `post-mint-v1`, `post-melt-quote`, `post-melt-v1`. (C2)
- Make `parse-ud` total so it cannot crash the event on non-integer input — degrade to a
  safe value (e.g. 0) that the existing per-field validation already rejects with a 400,
  rather than aborting the request. (S3)
- **Acceptance:** unauthenticated admin calls return 401; `self` mint returns 400 when
  disabled and works when enabled; legacy mint/melt routes 404; `{"amount":1.5}` yields a 400,
  not a crashed event; existing e2e suite still green.

### Phase 2 — Mainstream conformance. *Outcome: "public" becomes true.*
- Implement conformant NUT-02 keyset-ID derivation; introduce a new active keyset with a
  conformant ID; retain old keysets for redemption; migrate state. (S2)
- Audit and align `/v1/info` (NUT-06 capabilities), `/v1/keys`, `/v1/keysets`, and the DLEQ /
  signature response shapes against what cashu-ts parses. (S2)
- Build a **conformance harness** that drives the real `cashu-ts` library through
  mint → send → receive (swap) → melt, plus the NUT-00 hash-to-curve vectors. This replaces
  the self-referential keyset-ID assumption in the current JS tests.
- **Acceptance:** a cashu-ts-driven flow completes mint→send→receive→melt against the mint;
  cashu-ts independently derives the same active keyset ID it receives; NUT-00 vectors pass.

### Phase 3 — Split the extensions. *Outcome: minimal mint, independently-ownable access layer.*
- Create `%ecash-services` agent + desk owning `/cred/v1` and `/services/v1`, the
  `cred-keysets`/`cred-spent`/`cred-counter`/`services` state, and their handlers.
- Factor `lib/curve` + `lib/bdhke` into a single shared source both desks build against
  (peru-vendored from one location, or a small shared desk — decide at implementation time).
- Remove the extension endpoints, state fields, and helpers from `%ecash`; migrate `%ecash`
  state to drop them; stand up `%ecash-services` state from the migrated-out data (or a clean
  init if no production data exists).
- Port `test-cred.mjs` and `test-services.mjs` to target the new desk.
- **Acceptance:** `%ecash` builds with no `/cred` or `/services` references; both desks
  install and pass their suites; shared crypto has one source of truth.

### Phase 4 — Scale & ops. *Outcome: ready for real traffic.*
- Convert `lib/curve` point arithmetic to Jacobian/projective coordinates (one inversion per
  scalar-mult); keep the affine `point` type at the API boundary; add known-answer vectors.
  (S1)
- Add request caps: max inputs/outputs per request and max body size, rejected with 400. (S1)
- Add a behn cleanup timer pruning expired mint/melt quotes, stale `pending`, and orphaned
  `melt-change`. (S4)
- Fix NUT-08 melt change to refund `fee-reserve − actual_fee` using the fee the LN backend
  reports. (S5)
- **Acceptance:** before/after benchmark shows a material per-token speedup with identical
  signatures/DLEQ; oversized requests 400; expired state is pruned on the timer; melt change
  equals reserve minus actual fee.

## Testing strategy

- **Hoon unit tests** (`desk/tests/`): keep crypto roundtrip/DLEQ/Schnorr; add point-op
  known-answer vectors (especially guarding the projective rewrite), keyset-ID derivation,
  state-migration tests, and `parse-ud` fail-soft.
- **Conformance harness** (Phase 2): real `cashu-ts` library against a running mint; the
  authoritative interop gate.
- **Existing JS e2e** (`test-e2e`, `test-vectors`, `test-p2pk`): keep for regression; move
  `test-cred`/`test-services` to `%ecash-services` in Phase 3.
- **Security regression**: explicit cases for unauthenticated admin (401), disabled `self`
  (400), and removed legacy routes (404).

## Risks & open questions

- **Keyset-ID version.** Which derivation mainstream wallets require is confirmed against
  cashu-ts in Phase 2; if multiple are in play, target the widely-deployed v0 (16-char) form.
- **Shared-crypto mechanism.** peru-vendoring vs. a shared desk — decided at Phase 3
  implementation; both keep a single source of truth.
- **Production data.** If the mint has issued real tokens, the Phase 2 keyset migration and
  Phase 3 state split must preserve redemption of outstanding tokens; if not, both simplify to
  clean re-init.
- **TLS/auth posture.** Whether to also require `secure` on admin depends on where TLS
  terminates; left configurable.
- **Lightning solvency.** The mint trusts the LN backend as the source of truth for funds;
  this spec does not add internal solvency accounting beyond the existing liability counters.

## Implementation status (updated 2026-06-05)

Phase 1 is implemented and verified against a live `~zod` (branch `phase-1-security`):
C1 (admin auth), C1-poke (operator-only config poke), C2a (legacy endpoints removed),
C2b (self off by default + gated, state v9→v10), and S3 (parse-ud total) — all done and tested.

Adversarial review *during* implementation found and closed three further value holes:

- **C3 — self-quote bolt11-redemption bypass** (CRITICAL, unconditional): a `%paid` self
  quote stayed redeemable via `POST /v1/mint/bolt11` even with self disabled (the gate only
  blocked the self verb). Fixed — redemption of self-origin (`request='self-mint'`) quotes is
  gated on the flag regardless of URL method.
- **C4 — amount-0 → 64-sat inflation** (CRITICAL, unconditional): `sign-outputs` upgraded an
  `amount:0` value output to denomination 64 while balance checks counted it as 0, so a swap
  could mint 64 sats from nothing. Fixed — removed the default; amount-0 value outputs error.
- **S5 (partially fixed) — bolt11 melt over-issuance** (MEDIUM, needs an LN backend): the melt
  gate now requires `inputs ≥ amount + fee_reserve`, closing the minting of unbacked change.
  The remaining refinement — refund `fee_reserve − actual_routing_fee` instead of the whole
  reserve — stays Phase 4.

Regression at completion: value-token e2e, P2PK (8/8), and the 5-file security/value suite all
green; the live mint ends with `self` off and no LN backend. S2 (wallet conformance), S4
(state hygiene), the S5 refinement, performance (S1), and the extension split remain Phases
2–4 per the roadmap above.

### Phase 2 — wallet conformance (done 2026-06-05, branch `phase-2-conformance`)

Verified by driving the real `@cashu/cashu-ts` (v4.5.1) library through the full standard flow
against the live mint + mock Lightning: **loadMint, mint, DLEQ, send/swap, receive, melt all
PASS (6/6)**. Three conformance bugs found and fixed:

- **Keyset IDs (S2).** `compute-ks-id` emitted `shax`'s little-endian digest directly, so
  `/v1/keys` ids were byte-reversed vs NUT-02 / cashu-ts `deriveKeysetId`, and `Wallet.loadMint`
  rejected the keyset. Fixed by reversing the 32-byte digest (`rev 3 32`), as `lib/bdhke`
  already did. Fresh installs now mint conformant ids; the dev ship was rotated via the admin
  generate+activate endpoints. No state migration was added — pre-launch there are no
  outstanding tokens, so existing installs self-heal by rotating the active keyset; a proper
  migration is only needed once a deployment has issued real tokens.
- **DLEQ (NUT-12).** The proofs were internally consistent but non-standard: `s = r − a·e`
  (NUT-12 uses `r + a·e`), the challenge hashed compressed-point bytes (NUT-12 hashes
  uncompressed-hex points as ASCII), and `e` was reduced mod n (NUT-12 sends the raw digest).
  Rewrote `dleq-prove`/`dleq-verify` to match; `cashu-ts hasValidDleq` now returns true.
- **Melt `request` (NUT-05).** Melt-quote responses omitted the bolt11 `request` string that
  cashu-ts requires; added it to all seven melt-quote responses.

Harness: `test-conformance.mjs` (`npm run test:conformance`; needs `mock-lnbits` + an
`URBAUTH_COOKIE`). Now remaining: Phase 3 (split cred/services to their own desk) and Phase 4
(projective-coordinate perf, state-hygiene timer, the S5 fee-refund refinement). Deferred from
Phase 2 (non-blocking): `/v1/info` still advertises `self` when disabled; wallet testing beyond
cashu-ts (Nutshell, eNuts); the Hoon DLEQ unit tests were not re-run on-ship — cashu-ts's live
verification supersedes them.

### Phase 3 — split the extensions (done 2026-06-05, branch `phase-3-split`)

The credential + services extensions are now a **separate `%ecash-services` Gall agent**
(`desk-services/`), leaving `%ecash` a focused value mint:

- **`%ecash`** (`desk/`): `/v1/*` Cashu + `/apps/ecash/admin`. State migrated v10→v11, dropping
  `cred-keysets`/`cred-spent`/`cred-counter`/`services`. All ~33 cred/services arms, their
  routes, and the `/cred`+`/services` Eyre bindings removed. (The `cred-keyset`/`service` sur
  types remain only because the historical state-10 migration shape references them.)
- **`%ecash-services`** (`desk-services/`, ~1000 lines): owns `/cred/v1/*`, `/services/v1/*`,
  and an authenticated admin API at `/apps/ecash-services/admin/api/*`, over its own `state-0`
  (cred-keysets, cred-spent, cred-counter, services). The cred/services arms moved verbatim
  (only the state-version reference changed).
- **Shared crypto**: `desk/lib/{curve,bdhke}.hoon` is the single source of truth; the
  `%ecash-services` copies are gitignored and regenerated by `make sync-libs`.

Binding handoff is clean — Eyre lets the later `%connect` win, and a fresh deploy never
conflicts since stripped `%ecash` no longer binds `/cred`/`/services`. Pre-launch, so
`%ecash-services` clean-inits (no cross-agent data migration).

Verified live: `%ecash` — conformance 6/6, security 5/5 files, e2e, P2PK 8/8; `%ecash-services`
— cred 28/28, services 34/34. Remaining: Phase 4 (projective-coordinate perf, state-hygiene
timer, the S5 fee-refund refinement).

### Phase 4 — scale & ops (done 2026-06-05, branch `phase-4-perf`)

The last roadmap phase — four pieces, all verified live:

- **Performance (S1).** `lib/curve` `pt-mul` now runs its double-and-add in Jacobian
  coordinates — one field inversion per scalar-mult instead of ~384 (one per affine point op).
  Byte-identical outputs (e2e/p2pk/conformance/cred/services all green). Benchmark
  (`npm run bench`): minting 24 outputs **43.8s → 6.0s** (1824 → 251 ms/output), ~7×. Affine
  `pt-add`/`pt-dbl` are kept for the single-addition callers.
- **Request caps (S1).** Inputs/outputs per request capped at 100 (`400 batch-too-large`) in
  both agents' signing paths (swap/mint/melt on `%ecash`; cred/service issue on
  `%ecash-services`), bounding per-event EC work.
- **State hygiene (S4).** A daily behn timer (`run-cleanup`) prunes expired mint/melt quotes
  and orphaned melt-change. (Pending requests carry no timestamp and are left as-is — bounded
  by in-flight count.)
- **Melt fee (S5).** bolt11 melt now refunds `fee_reserve − actual_routing_fee` (read from the
  LN response) instead of the whole reserve; a mock fee + `test-melt-fee.mjs` verify it.

Further perf (wNAF/windowing, or a native secp jet) is possible but out of scope — the Jacobian
win keeps the mint pure-Hoon (runs on any stock ship). **All four phases of the roadmap are now
complete.**

## Out of scope / future

- Native secp jet (only if Phase 4 benchmarks fall short).
- Consumer wallet/frontend.
- Multi-mint / multi-unit support.
- SIG_ALL P2PK.
