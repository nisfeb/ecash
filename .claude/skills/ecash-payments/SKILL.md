---
name: ecash-payments
description: Guide for integrating Cashu ecash payments into Urbit Gall agents. Use when building payment-gated services, requiring ecash tokens for access, implementing subscription/whitelist patterns, or calling Cashu mint APIs from Hoon.
user-invocable: true
---

# Integrating Ecash Payments into Urbit Apps

This guide explains how to gate an Urbit Gall agent's services behind Cashu ecash payments. The user pays ecash tokens to your app, your app verifies them with the mint, and the user gets whitelisted for a period of time.

This works with any Cashu-compliant mint. The examples assume the mint runs on the same ship at `localhost:8080`, but the pattern works with any mint URL.

---

## Concepts

### What is Cashu ecash?

Cashu is a protocol for **blind signature-based ecash**. A mint issues cryptographically signed tokens that are:

- **Bearer instruments** — whoever holds the token can spend it
- **Unlinkable** — the mint cannot connect issuance to redemption (blind signatures)
- **Divisible** — tokens come in fixed denominations (1, 2, 4, 8, 16... sats)
- **Double-spend protected** — the mint tracks spent secrets

### Token structure

A Cashu token (called a "proof") has four fields:

```json
{
  "C": "02abc...",      // unblinded signature (compressed point, 33 bytes hex)
  "secret": "unique-random-string",
  "amount": 4,          // denomination in sats
  "id": "01abc..."      // keyset ID (identifies which mint key signed it)
}
```

### How verification works

To verify and redeem tokens, your app **swaps** them at the mint. A swap atomically:

1. Verifies each input token's signature is valid
2. Checks none of the tokens have been spent before
3. Marks the input tokens as spent (they can never be used again)
4. Signs new output tokens of equal total value

This is the key insight: **you don't just "check" tokens — you swap them for fresh ones**. This guarantees atomic double-spend prevention. If the swap succeeds, the payment is real and final.

If your app only needs to verify payment (not hold a balance), you can discard the output tokens. If your app wants to accumulate a balance (to pay others later), keep the outputs.

---

## Architecture

### Payment flow

```
┌──────┐                    ┌──────────┐                    ┌──────┐
│ User │                    │ Your App │                    │ Mint │
└──┬───┘                    └────┬─────┘                    └──┬───┘
   │                             │                             │
   │  1. Request access          │                             │
   ├────────────────────────────>│                             │
   │                             │                             │
   │  2. "Pay X sats"           │                             │
   │<────────────────────────────┤                             │
   │                             │                             │
   │  3. Send ecash tokens      │                             │
   ├────────────────────────────>│                             │
   │                             │                             │
   │                             │  4. POST /v1/swap           │
   │                             ├────────────────────────────>│
   │                             │                             │
   │                             │  5. {signatures: [...]}     │
   │                             │<────────────────────────────┤
   │                             │                             │
   │  6. "Access granted        │                             │
   │      until <expiry>"       │                             │
   │<────────────────────────────┤                             │
```

### What your app needs

1. **A poke handler** that accepts ecash tokens from users
2. **An iris HTTP call** to swap the tokens at the mint (verification)
3. **A whitelist** in state tracking who paid and when they expire
4. **Access checks** on gated operations

---

## Implementation

### Step 1: Define state

Add payment tracking to your agent's state:

```hoon
+$  payment-record
  $:  who=@p               ::  who paid
      amount=@ud            ::  sats paid
      expiry=@da            ::  when access expires
  ==

+$  state-0
  $:  %0
      whitelist=(map @p payment-record)
      ::  ... your other state fields
  ==
```

### Step 2: Define the payment poke mark

Create a mark file at `mar/ecash-payment.hoon` or use `%json`. The simplest approach is accepting JSON via `%handle-http-request` or a custom mark.

The token format your app receives from users:

```json
{
  "action": "pay",
  "proofs": [
    {"C": "02...", "secret": "...", "amount": 4, "id": "01..."},
    {"C": "02...", "secret": "...", "amount": 1, "id": "01..."}
  ]
}
```

### Step 3: Verify tokens by swapping at the mint

When your app receives tokens, it must swap them at the mint to verify they're real and unspent. This is an HTTP POST to the mint's `/v1/swap` endpoint via iris.

**Building the swap request:**

Your app needs to provide `inputs` (the user's tokens) and `outputs` (blinded messages for new tokens). The output total must equal the input total minus any fees.

For a **verify-and-discard** pattern (you just want to confirm payment, not hold tokens), you still need valid outputs. The simplest approach: generate a random secret, compute `B_ = hashToCurve(secret)` (no blinding factor needed if you're discarding), and request a single output for the full amount.

However, since BDHKE requires proper blinding, the practical approach is:

**Option A: Use `make-output` from the BDHKE library**

The simplest verification is to swap the user's tokens for a token you control. Import the BDHKE library (which includes wallet-side helpers):

```hoon
/+  *bdhke
```

The library provides:
- `make-output` — generates a random secret, blinds it, returns `[B_hex secret blinding-factor]`
- `split-amount` — splits a sat total into power-of-2 denominations (e.g., 5 -> ~[1 4])
- `blind-message` — low-level: blinds a secret with a given r, returns `[B_ r-mod]`
- `unblind-signature` — low-level: unblinds `C_ - r*K` to get the final token `C`

Build a swap request using `make-output`:

```hoon
++  build-swap-request
  |=  [proofs=(list json) total=@ud keyset-id=@t]
  ^-  json
  ::  Split total into denominations and generate blinded outputs
  =/  denoms=(list @ud)  (split-amount total)
  =/  outputs=(list json)
    =/  idx=@ud  0
    =/  acc=(list json)  ~
    |-
    ?~  denoms  (flop acc)
    =/  eny-i  (shax (add eny.bowl idx))
    =/  [b-hex=@t secret=@t r=@]  (make-output i.denoms keyset-id eny-i)
    %=  $
      denoms  t.denoms
      idx     +(idx)
      acc     :_  acc
              %-  pairs:enjs:format
              :~  ['B_' s+b-hex]
                  ['amount' (numb:enjs:format i.denoms)]
                  ['id' s+keyset-id]
              ==
    ==
  %-  pairs:enjs:format
  :~  ['inputs' [%a proofs]]
      ['outputs' [%a outputs]]
  ==
```

**Option B: Single output (simpler, less spec-correct)**

If you don't care about receiving usable tokens back (verify-and-discard), use a single output for the full amount. This is simpler but only works if the total matches a denomination the mint supports:

```hoon
=/  [b-hex=@t secret=@t r=@]  (make-output total keyset-id eny.bowl)
```

The standard approach is Option A with `split-amount` — it works for any total.

### Step 4: Make the iris HTTP request

Send the swap request to the mint:

```hoon
++  verify-payment
  |=  [proofs=(list json) total=@ud eyre-id=@ta who=@p]
  ^-  (list card)
  =/  swap-body=json  (build-swap-request proofs total)
  =/  body-octs=octs  (as-octs:mimes:html (en:json:html swap-body))
  =/  mint-url=@t  'http://localhost:8080/v1/swap'
  =/  wire-id=@ta  (scot %uv (sham (add eny.bowl now.bowl)))
  =/  =request:http
    :*  method=%'POST'
        url=mint-url
        header-list=['content-type' 'application/json']~
        body=`body-octs
    ==
  :~  [%pass /payment/[wire-id] %arvo %i %request request *outbound-config:iris]
  ==
```

Store the pending verification in state so you can match the response:

```hoon
+$  pending-payment
  $:  who=@p
      amount=@ud
      eyre-id=@ta           ::  if you need to respond to the user
  ==
```

### Step 5: Handle the iris response

In your `on-arvo` arm, handle the mint's response:

```hoon
++  on-arvo
  |=  [=wire =sign-arvo]
  ^-  (quip card _this)
  ?+  wire  (on-arvo:def wire sign-arvo)
      [%payment @ta ~]
    ?>  ?=(%iris -.sign-arvo)
    ?>  ?=(%http-response +<.sign-arvo)
    =/  wire-id=@ta  i.t.wire
    ::  Look up pending payment by wire-id
    =/  pend  (~(get by pending-payments.state) wire-id)
    ?~  pend
      ~&  >>>  [%unknown-payment-response wire-id]
      `this
    ::  Parse response
    =/  resp  client-response.sign-arvo
    ?.  ?=(%finished -.resp)
      `this
    =/  status  status-code.response-header.resp
    ?.  =(200 status)
      ::  Swap failed — tokens are invalid, already spent, or amounts don't balance
      ~&  >>>  [%payment-rejected who.u.pend status]
      =.  pending-payments.state  (~(del by pending-payments.state) wire-id)
      ::  Notify user of failure here
      `this
    ::  Swap succeeded — payment is verified!
    ~&  >  [%payment-accepted who.u.pend amount.u.pend]
    =/  expiry=@da  (add now.bowl (mul ~d30 1))  ::  30-day access
    =/  record=payment-record
      [who=who.u.pend amount=amount.u.pend expiry=expiry]
    =.  whitelist.state  (~(put by whitelist.state) who.u.pend record)
    =.  pending-payments.state  (~(del by pending-payments.state) wire-id)
    ::  Notify user of success here
    `this
  ==
```

### Step 6: Check whitelist on gated operations

```hoon
++  is-whitelisted
  |=  who=@p
  ^-  ?
  =/  record  (~(get by whitelist.state) who)
  ?~  record  %.n
  (gth expiry.u.record now.bowl)
```

Use it to gate pokes, scries, or subscriptions:

```hoon
++  on-poke
  |=  [=mark =vase]
  ^-  (quip card _this)
  ?+  mark  (on-poke:def mark vase)
      %some-gated-action
    ?.  (is-whitelisted src.bowl)
      ~|  %payment-required
      !!
    ::  ... handle the action
  ==
```

---

## Complete poke handler example

Here's a full payment poke handler that receives tokens via JSON:

```hoon
++  handle-payment-poke
  |=  [jon=json who=@p]
  ^-  (quip card _this)
  ?.  ?=([%o *] jon)
    `this
  =/  maybe-proofs  (~(get by p.jon) 'proofs')
  ?~  maybe-proofs
    ~&  >>>  %missing-proofs
    `this
  ?.  ?=([%a *] u.maybe-proofs)
    `this
  =/  proofs=(list json)  p.u.maybe-proofs
  ::  Sum up the token amounts
  =/  total=@ud
    %+  roll  proofs
    |=  [tok=json acc=@ud]
    ?.  ?=([%o *] tok)  acc
    =/  amt-val  (~(get by p.tok) 'amount')
    ?~  amt-val  acc
    ?+  -.u.amt-val  acc
      %n  (add acc (rash p.u.amt-val dem:ag))
    ==
  ::  Require minimum payment
  ?.  (gte total 100)                      ::  100 sats minimum
    ~&  >>>  [%insufficient-payment total]
    `this
  ::  Build swap request and send to mint
  =/  swap-body=json  (build-swap-request proofs total)
  =/  body-octs=octs  (as-octs:mimes:html (en:json:html swap-body))
  =/  wire-id=@ta  (scot %uv (sham (add eny.bowl now.bowl)))
  =.  pending-payments.state
    (~(put by pending-payments.state) wire-id [who total])
  :_  this
  :~  :*  %pass
          /payment/[wire-id]
          %arvo  %i  %request
          :*  method=%'POST'
              url='http://localhost:8080/v1/swap'
              header-list=['content-type' 'application/json']~
              body=`body-octs
          ==
          *outbound-config:iris
      ==
  ==
```

---

## Mint API reference

These are the mint endpoints your app will use. All are unauthenticated HTTP JSON APIs.

### POST /v1/swap — Verify and redeem tokens

This is the primary endpoint your app uses. It atomically verifies input tokens and issues new output tokens.

**Request:**
```json
{
  "inputs": [
    {"C": "02...", "secret": "...", "amount": 4, "id": "01..."},
    {"C": "02...", "secret": "...", "amount": 1, "id": "01..."}
  ],
  "outputs": [
    {"B_": "02...", "amount": 5}
  ]
}
```

**Rules:**
- `sum(input amounts) - fee == sum(output amounts)`
- Fee is computed from `input_fee_ppk` of each input's keyset: `ceil(sum(ppk) / 1000)`
- Every input must have a valid signature and unspent secret
- Every output must reference a valid, active keyset and denomination

**Success (200):**
```json
{
  "signatures": [
    {"C_": "02...", "amount": 5, "id": "01...", "dleq": {"e": "...", "s": "..."}}
  ]
}
```

**Failure (400):**
```json
{"detail": "token-already-spent"}
```

Possible errors: `token-already-spent`, `invalid-token-signature`, `unknown-keyset`, `unknown-denomination`, `amounts-do-not-balance`, `missing-inputs`, `missing-outputs`.

### GET /v1/keys — Get mint's active public keys

Needed to construct blinded output messages.

**Response:**
```json
{
  "keysets": [{
    "id": "01abc...",
    "unit": "sat",
    "active": true,
    "input_fee_ppk": 0,
    "keys": {
      "1": "02...", "2": "02...", "4": "02...", "8": "02...",
      "16": "02...", "32": "02...", "64": "02...", "128": "02...",
      "256": "02...", "512": "02..."
    }
  }]
}
```

### POST /v1/checkstate — Check if tokens are spent

Read-only check. Does NOT mark as spent. Useful for checking token validity without consuming them, but **does not prevent double-spend** — another party could spend the token between your check and your swap.

**Request:**
```json
{"Ys": ["02...", "02..."]}
```

Where each Y is `hashToCurve(secret)` as a compressed hex point.

**Response:**
```json
{
  "states": [
    {"Y": "02...", "state": "UNSPENT"},
    {"Y": "02...", "state": "SPENT"}
  ]
}
```

### GET /v1/info — Mint capabilities

```json
{
  "name": "~zod ecash",
  "version": "ecash/0.2.0",
  "nuts": {
    "1": {"methods": [{"method": "bolt11", "unit": "sat"}, {"method": "self", "unit": "sat"}]},
    "4": {"methods": [...]},
    "5": {"methods": [...]},
    ...
  }
}
```

---

## Patterns

### Subscription tiers

Different payment amounts grant different access durations or levels:

```hoon
++  access-duration
  |=  amount=@ud
  ^-  @dr
  ?:  (gte amount 1.000)  ~d365    ::  1000+ sats = 1 year
  ?:  (gte amount 500)    ~d180    ::  500+ sats = 6 months
  ?:  (gte amount 100)    ~d30     ::  100+ sats = 30 days
  ~d7                               ::  any amount = 7 days
```

### Extending existing access

When a user pays again while already whitelisted, extend from their current expiry rather than from now:

```hoon
=/  current-expiry=@da
  =/  existing  (~(get by whitelist.state) who)
  ?~  existing  now.bowl
  (max now.bowl expiry.u.existing)
=/  new-expiry=@da
  (add current-expiry (access-duration amount))
```

### Periodic whitelist cleanup

Use a timer to prune expired entries:

```hoon
::  In on-init or on-load, set a daily timer:
[%pass /cleanup %arvo %b %wait (add now.bowl ~d1)]

::  In on-arvo, handle the timer:
    [%cleanup ~]
  ?>  ?=(%behn -.sign-arvo)
  =.  whitelist.state
    %-  ~(rep by whitelist.state)
    |=  [[who=@p rec=payment-record] acc=(map @p payment-record)]
    ?:  (gth expiry.rec now.bowl)
      (~(put by acc) who rec)
    acc
  :_  this
  :~  [%pass /cleanup %arvo %b %wait (add now.bowl ~d1)]
  ==
```

### Multi-mint support

Accept tokens from multiple mints by trying each:

```hoon
+$  mint-config  [url=@t name=@t]

++  known-mints
  ^-  (list mint-config)
  :~  ['http://localhost:8080' 'local']
      ['https://mint.example.com' 'remote']
  ==
```

The keyset ID in each token tells you which mint issued it. Maintain a mapping of keyset ID to mint URL, populated by fetching `/v1/keysets` from each mint at startup.

### Without BDHKE (simplified verify-and-burn)

If your app doesn't need to hold tokens and you don't want to import the BDHKE library, you can use a workaround: swap the user's tokens for tokens locked to a random P2PK key that nobody holds. This effectively burns them while satisfying the swap balance requirement.

```hoon
::  Generate throwaway output — no one can spend it
=/  rand-secret=@t
  (crip (weld "burn-" (trip (scot %uv (sham eny.bowl)))))
```

You still need to compute `B_` (a blinded message), which requires `hash-to-curve` and point multiplication. So in practice, importing `bdhke` is the cleanest path.

### Accepting tokens via HTTP

If your app has an HTTP endpoint (bound via Eyre), you can accept payments as JSON POST bodies. This is convenient for web frontends:

```
POST /apps/your-app/pay
Content-Type: application/json
Cookie: urbauth-~zod=...

{
  "proofs": [
    {"C": "02...", "secret": "...", "amount": 4, "id": "01..."}
  ]
}
```

### Accepting tokens via poke

For ship-to-ship payments, define a mark and accept pokes:

```hoon
::  mar/ecash-payment.hoon
|_  payment=[proofs=(list json)]
++  grab
  |%
  ++  noun  ecash-payment
  ++  json
    |=  jon=^json
    ?.  ?=([%o *] jon)  *ecash-payment
    =/  proofs  (~(get by p.jon) 'proofs')
    ?~  proofs  *ecash-payment
    ?.  ?=([%a *] u.proofs)  *ecash-payment
    [p.u.proofs]
  --
++  grow
  |%
  ++  noun  payment
  --
++  grad  %noun
--
```

---

## Checklist

When integrating ecash payments into your Gall agent:

- [ ] Add `whitelist=(map @p payment-record)` to state
- [ ] Add `pending-payments=(map @ta pending-payment)` to state
- [ ] Import `/+  *bdhke` for `hash-to-curve` and point operations
- [ ] Add a poke handler that accepts tokens (via JSON or custom mark)
- [ ] Sum input token amounts and enforce a minimum
- [ ] Build a swap request with proper blinded outputs
- [ ] Send the swap via iris to the mint's `/v1/swap`
- [ ] Handle the iris response in `on-arvo` — 200 = valid, else rejected
- [ ] On success, add the payer to the whitelist with an expiry
- [ ] Gate protected operations with a whitelist check
- [ ] Set up periodic cleanup of expired whitelist entries
- [ ] Handle the case where a user pays again (extend, don't overwrite)
