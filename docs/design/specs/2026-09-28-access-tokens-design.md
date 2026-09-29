# Access tokens: design (P0)

A desk that issues blind-signed **access tokens** instead of money: passes,
credits, tickets and invites that ships and web clients present to reach a
resource. It replaces `%ecash-services`. The value mint (`%ecash`) stays as
it is; the two share the blind-signature core.

Working name `%tessera` (a Roman token of admission). Renaming is a
search-and-replace until the first release.

## Decisions (2026-09-28)

| Question | Decision |
|---|---|
| First use cases | Gating our own apps, and credits (rate/quota) |
| Relation to `%ecash-services` | A new desk replaces it |
| Token shape | Wallet-compatible: amount 1, NUT-22 blind-auth tokens |
| Who verifies | Other ships (the main case), apps on the same ship, and web services |
| Transfer | Bearer |
| Paid issuance | Not needed |

## The token

A token is a Cashu proof of **amount 1 in unit `auth`** (NUT-22's blind auth
token, a "BAT"): `{id, secret, C}`, with a DLEQ proof at issuance (NUT-12).

- Serialized as `authA` + base64url(JSON `{id, secret, C}`), the form cashu-ts's
  `AuthManager` writes, and sent in a `Blind-auth` header over HTTP or as that
  string in a poke over Ames.
- **Each service is its own NUT-22 auth mint:** its own keyset, its own spent
  set, its own base URL. A cashu-ts client points `AuthManager` at the service's
  URL and works unmodified.
- **Credits are a count of tokens.** Spending one token is one use. There are
  no denominations and no swap.
- **Tiers are separate services** (`chat-member`, `chat-mod`). cashu-ts
  assumes one active auth keyset per mint, so tiers stay compatible this
  way, and each tier gets its own quota and expiry for free.

Old amount-0 credentials are not carried over (see Migration).

## Kinds, all built from the same token

| Kind | Examples | How |
|---|---|---|
| Pass (single use) | invite, ticket, one post, one vote | issue 1, redeem burns it |
| Credits | API calls, messages, downloads | issue N; each use burns one |
| Time-boxed | day pass, monthly access | the keyset is tied to a window; tokens die with it (P4) |
| Rate limit | fair use, anti-spam | a per-identity quota per window on issuance (P3/P4) |

Redeem modes per service: **burn** (default); **check** (verify without
burning, for "is a member" gates, at the cost of linking uses of one token);
and the existing idempotent retry (`fresh`/`replay`, where only `fresh`
grants access).

## Who talks to whom

Every ship that uses tokens runs the same desk. It is an **issuer** for the
services it owns, and a **holder** (a token wallet) for tokens it got from
other ships.

### Ship to ship (the main case)

```
holder ~A                      issuer ~I                 resource
  |  %request svc n outputs  ->  |  policy: src.bowl        |
  |  <- %issued sigs (DLEQ)      |  (allowlist, quota,      |
  |  unblind, store              |   ship class)            |
  |                              |                          |
  |  %present svc token act  ->  |  verify + burn           |
  |                              |  then poke act ------->  | local agent on ~I
  |  <- %presented ok/why        |                          |
```

- **Issuance:** ~A's desk makes n blinded outputs and pokes ~I. ~I checks the
  policy against `src.bowl`, which Ames authenticates: that is the "ship
  authenticating with the mint". Then ~I signs and pokes the signatures back
  to ~A's desk under a request id. ~A unblinds, checks the DLEQ proofs and
  stores the proofs under `[~I svc]`.
- **Presentation to the issuer** (the common case): ~A pokes ~I with a token
  and an **action**, the poke that ~I should deliver to a local agent if the
  token is good, as `[agent mark noun]`. ~I burns the token and forwards the
  action with a header naming the service and the presenting ship. Resource
  agents trust `%tessera`'s forwards (`src.bowl` = `our`, from the tessera
  desk). They don't handle tokens at all: gating an app is one line in its
  poke handler.
- **A third ship ~R as the resource:** ~A pokes ~R with the token; ~R's desk
  asks ~I to verify or burn it. ~R must be on the service's **verifier list**
  of ships. That is one extra Ames round trip.
- **Transfer (bearer):** ~A can hand tokens to ~B (a poke). ~B should
  **refresh** them at ~I straight away (burn the old tokens, get the same
  number of new ones, with no policy check since nothing is created). Until
  ~B refreshes, ~A could spend them too.

Honest privacy note: over Ames the issuer sees who asks and who presents, so
for ship-to-ship use the tokens are **capabilities and quota accounting**,
not anonymity. Unlinkability still holds wherever the presenter isn't
identified: anonymous HTTP, or tokens that changed hands.

### Apps on the same ship

- A local agent asks `%tessera` to verify or burn a token that one of its own
  clients sent it, by poke with a request id, and gets the answer as a fact.
- Or it lets `%tessera` gate its pokes by the forward pattern above.
- A scry answers "valid, unspent?" without burning.

### Web services

Per service, under `https://<issuer>/tessera/<svc>`:

| Route | |
|---|---|
| `GET /v1/info` | NUT-06, with `nuts.22 {bat_max_mint, protected_endpoints}` |
| `GET /v1/auth/blind/keys`, `/keysets` | the service's keyset |
| `POST /v1/auth/blind/mint` | issue; the policy decides |
| `POST /redeem`, `/check` | for resource servers, authenticated with a verifier key |
| `POST /refresh` | burn n tokens, issue n new ones |

HTTP issuance policies: open, or a service key sent as `Clear-auth` (NUT-21's
header, but not OIDC). Whether cashu-ts can carry a static `Clear-auth` value
without an OIDC provider is to be checked in P2; if it can't, key-gated web
issuance uses the plain API.

## Issuance policy (per service)

- **open**, with a per-identity quota to bound it;
- **ships**: an allowlist, or any ship of a given class (planet and up keeps
  free comets out), with a quota per ship per window;
- **key**: allowlisted API keys (exists in `%ecash-services` today);
- **admin**: issue a batch and export it as `authA…` strings (for tickets
  and invites handed out off-ship).

Caps stay (total issued per service). There is no paid issuance.

## State

- `services`: name → kind, keyset(s), policy, quota, window, verifier ships
  and keys, caps, counters, expiry.
- `keysets`: id → keys; the old keyset stays verifiable until its window
  closes.
- `spent`: per keyset. **When a keyset's window closes, its spent set is
  dropped whole.** Unlike the value mint, state stays bounded.
- `quota`: `[svc identity window]` → count, pruned with the window. Identity
  is a ship, or a hash of the key.
- `wallet` (holder side): `[issuer svc]` → proofs, plus pending requests.

## Reuse

- `curve`, `bdhke` and `ecash-http` as they are.
- **Extract the blind-signature core** from `desk/lib/ecash-rules.hoon`
  (keyset generation and ids, `sign-one` with DLEQ, proof checks, output
  checks, restore records) into a lib that `%ecash` and `%tessera` both
  import, the way `make sync-libs` shares the others. The unit-specific
  rules (fees, melt, Lightning) stay in `ecash-rules`.
- `desk-services/lib/ecash-services-rules.hoon` has the service and policy
  rules to start from: name validation, resolve, caps, allowlist.

## Phases

| Phase | Deliverable | Done when |
|---|---|---|
| P1 Core lib | the blind-signature core extracted and generalized to any unit | the kit suites and a mutation pass are green; `%ecash`'s JS suites are unchanged and green |
| P2 Issuer over HTTP | `%tessera` with services, the NUT-22 routes, open/key/admin issuance, redeem/check/refresh | a cashu-ts `AuthManager` tops up and spends against a service; JS route suite |
| P3 Ship to ship | issue, present with forward, third-party verifier ships, refresh and transfer, per-ship quota, the holder wallet | two-ship test on fake ships (issuer, holder, third party); one real app gated |
| P4 Windows | keysets tied to windows, rotation on a timer with overlap, spent and quota pruning | rotation and pruning pass across a restart |
| P5 Ship it | dashboard (from the services one), docs and runbook, an integration guide for app authors, the retirement of `%ecash-services` | deployed to ~lyd, then ricsul via `/mcp` |

Testing follows the repo's policy throughout: decisions in pure libs with
hoon-test-kit suites and mutation passes; an HTTP route suite on the
`run-tests.mjs` harness; the test-audit gate for every new test.

## P2 as built (2026-09-28)

`desk-tessera/` installs as `%tessera`. The decisions are in
`lib/tessera-rules.hoon` (24 kit tests); the agent holds state and routes.

- **One keyset per service** for now, kept in the service record. P4 turns
  it into a list with windows.
- **Routes** under `/tessera/<name>`: `GET /v1/info`, `/v1/auth/blind/keys`,
  `/v1/auth/blind/keysets`; `POST /v1/auth/blind/mint`, `/redeem`, `/check`,
  `/refresh`. Admin: `GET /apps/tessera/api/services`, and `POST
  /apps/tessera/api/services/{create,update,activate,deactivate,delete,batch}`
  with `{name, ...}`.
- **Mint** is all or nothing (a wallet pairs signatures with outputs by
  position): every output must be amount 1 under the service's keyset id.
  `bat_max_mint` is 10: signing costs about 90 ms per output, so one event
  stays under a second.
- **Policy over HTTP:** `open`, and/or `keys` sent as `Clear-auth`. cashu-ts
  sends a static key with `AuthManager.setCAT(key)`, no OIDC needed. A wrong
  key is refused even on an open service. NUT-21 is advertised only where no
  one can mint without a key. A new service is closed: only the owner
  issues until it is opened or given keys. The owner's session (from its own
  origin) skips the policy, the quota and the verifier key.
- **Quota** counts per identity per window: each key apart, and all open
  clients together as one bucket (eyre gives no client identity worth
  trusting behind a proxy).
- **Redeem and check** take `{token, key}` in the body, `key` being a
  verifier key. Redeem answers `fresh` or `replay`, and only `fresh` grants
  access. In check mode, redeem never burns, so a token is `fresh` every time
  until it is refreshed away. `/check` answers `{spent}` and burns nothing.
- **Refresh** is open to any holder, with no policy, quota or cap, because
  nothing new is issued.
- **Batch** (admin) mints n ≤ 100 tokens directly (C = k·Y for random
  secrets) and returns them as `authA` strings. They count toward the cap,
  not the quota.
- Spent sets keep `sha256(secret)` per keyset id, so state stays the same
  size per token whatever the secret's length.
- Tokens are parsed padded (as cashu-ts writes them) or unpadded, and are
  capped at 4096 bytes before decoding.

Verified with `test-tessera.mjs`: a real `AuthManager` tops up (it checks the
keyset id and each DLEQ proof), and every route, refusal and admin action is
covered.

## P3–P5 as built (2026-09-28)

- **Ships.** One poke mark, `%tessera-action`. Issuer-side actions (`%request`,
  `%present`, `%refresh`, `%verify`) take tokens as `authA` strings and
  outputs as B_ hex, and reuse the HTTP checks. Answers go back as
  `%answer rid` pokes, accepted only from the ship the request went to.
  Holder actions (`%get`, `%use`, `%ask`, `%give`) come from this ship only.
  They are answered with a `%tessera-answer` poke to the asking agent (found
  by `sap.bowl`), or to the admin HTTP request, which waits for the other
  ship.
- **Policy over Ames:** `open`, `ships`, or `rank` (galaxy … comet, "at
  least"). Quota per ship. The owner's own requests count against no quota.
- **Forward:** a present with `to=[agent data]` burns the token, then pokes
  the agent `%tessera-granted [svc who data]`. The answer waits for the ack,
  and a nack un-burns the token and the holder gets it back.
- **Hand-over:** `%give` sends tokens, and they wait at the receiver as an
  offer: 100 at most, each up to 10 tokens. The owner accepts it, which
  refreshes the tokens at the issuer, or declines it. A review found that
  refreshing straight away let any ship spend the receiver's CPU and grow
  its state. `take` (admin) pops one token out as an `authA` string, for a
  web client or anyone.
- **Forward agents:** each service lists the agents a present may be
  delivered to. The issuer checks that the agent is running (`%gu`) and
  that `data` is at most 16 KiB before touching the token. Gall would
  otherwise hold a poke to a stopped agent for good.
- **Windows (P4):** lazy rotation, with no timer. When a windowed service is
  used after its window turned (or after its window setting changed), it
  gets a new keyset whose id commits to `final_expiry`. The old keyset's
  spent set goes with it. Only one keyset per service is live at a time, so
  a holder drops the tokens it holds under any other kid when new ones
  arrive. An hourly timer (one at a time: each prune cancels the last)
  drops quota counts of past windows and spent sets of closed keysets.
  Rotation, pruning and the timer survive a restart.
- **P5:** a dashboard at `/apps/tessera` and a Landscape tile; the guide in
  `docs/tessera.md`; `%ecash-services` retired from the repo (desk, suites,
  build). The gated app is `%tessera-demo`, a guestbook shipped on the desk
  but not started on install. It is the pattern to copy into a real app.

## Migration

`%tessera` starts fresh: amount-0 credentials don't fit the new token, and
the services' policies change shape. If a live ship depends on
`%ecash-services`, import its service definitions (not its tokens) with a
one-time poke, and keep `%ecash-services` running redeem-only until its
tokens expire. Otherwise, uninstall it.

## Risks

- **CPU:** issuing or checking a token is pure-Hoon EC, about 0.1 s each.
  Credits multiply that. Keep `bat_max_mint` small, rely on quotas, and
  rate-limit HTTP at the proxy.
- **The issuer must be up** for every presentation, since verification is
  online. That's inherent to the scheme, so a resource that needs to work
  when the issuer is offline has to run its own issuer.
- **Check mode links uses** of one token.
- **Holders need the desk** for ship-to-ship use. Web clients need only
  cashu-ts.
- **Forwarded pokes:** resource agents must trust only forwards from the
  tessera desk on their own ship, never a remote `src`.

## Open

- The desk name (`%tessera` so far).
- Which real app to gate first: `%tessera-demo` shows the pattern.
- Deploying `%tessera` to ~ricsul-bilwyt, and removing `%ecash-services`
  from any ship that runs it, wait on the owner's go-ahead.
