---
name: ecash-payments
description: Guide for integrating Cashu ecash payments into Urbit Gall agents. Use when building payment-gated services, requiring ecash tokens for access, implementing subscription/whitelist patterns, or calling Cashu mint APIs from Hoon.
user-invocable: true
---

# Integrating Ecash Payments into Urbit Apps

How to gate a Gall agent's features behind Cashu ecash payments: a user sends your app ecash
tokens, your app swaps them at the mint (which proves they were real and unspent), and the user
is whitelisted for a while.

This works with any Cashu mint. The examples assume the `%ecash` mint on the same ship at
`http://localhost:8080`.

---

## Concepts

### Cashu ecash

A mint issues blind-signed tokens that are:

- **Bearer**: whoever holds a token can spend it.
- **Unlinkable**: the mint can't connect issuance to redemption.
- **Fixed denominations**: powers of two (1, 2, 4, 8 … sats), up to the keyset's largest key.
- **Single-use**: the mint records every spent secret.

### A token ("proof")

```json
{
  "amount": 4,            // denomination in sats
  "id": "01abc…",         // keyset id: which mint key signed it
  "secret": "…",          // at most 2048 bytes at the %ecash mint
  "C": "02abc…"           // unblinded signature, compressed point (66 hex chars)
}
```

### Verify by swapping

To accept tokens, your app **swaps** them at the mint (`POST /v1/swap`). A swap, all at once:

1. checks each input's signature,
2. checks none was spent,
3. marks them spent,
4. signs new outputs worth the inputs minus the input fee.

If the swap succeeds, the payment is real and final. Checking without swapping
(`/v1/checkstate`) proves nothing: the payer can spend the token elsewhere a moment later.

The **input fee** is `ceil(sum of each input's keyset input_fee_ppk / 1000)` sats. The outputs
must total exactly `inputs − fee`, or the mint answers `400 amounts-do-not-balance`. Credit the
payer with the net amount.

---

## Architecture

```
User                         Your app                          Mint
 │  1. ask for access           │                                │
 ├─────────────────────────────>│                                │
 │  2. "pay N sats"             │                                │
 │<─────────────────────────────┤                                │
 │  3. ecash tokens (a poke)    │                                │
 ├─────────────────────────────>│  4. POST /v1/swap (iris)       │
 │                              ├───────────────────────────────>│
 │                              │  5. 200 {signatures: [...]}    │
 │                              │<───────────────────────────────┤
 │  6. access until <expiry>    │                                │
 │<─────────────────────────────┤                                │
```

### What your desk needs

Copy **both** `lib/curve.hoon` and `lib/bdhke.hoon` from the ecash repo's `desk/lib/` into your
desk: `bdhke` imports `curve`. Import them with `/+  *curve, *bdhke`.

The arms you will use:

| Arm | Sample → product | Does |
|---|---|---|
| `make-output` (bdhke) | `[amount=@ud keyset-id=@t eny=@]` → `[b-hex=@t secret=@t blinding-factor=@]` | A random secret, blinded. Only `eny` affects the result. |
| `split-amount` (bdhke) | `total=@ud` → `(list @ud)` | Powers of two, largest first: `(split-amount 5)` is `~[4 1]`. No cap on size. |
| `blind-message` (bdhke) | `[secret=@t r=@]` → `[b-prime=point blinding-factor=@]` | `B_ = Y + r·G` |
| `unblind-signature` (bdhke) | `[c-=point r=@ mint-key=point]` → `point` | `C = C_ − r·K` |
| `dleq-verify` (bdhke) | `[b-=point c-=point a-pub=point e=@ s=@]` → `?` | Checks the mint's NUT-12 proof |
| `hash-to-curve` (bdhke) | `msg=@` → `point` | `Y` for a secret (for `/v1/checkstate`) |
| `hex-to-pt` (curve) | `hex=@t` → `(unit point)` | Parse a compressed point |
| `pt-to-hex` (curve) | `p=point` → `@t` | Compressed hex |
| `hex-decode` (curve) | `hex=@t` → `@` | Hex to atom (for DLEQ `e`, `s`) |

---

## Implementation: a complete paywall agent

One file, `app/paywall.hoon`. The helper core `pay` holds the logic and sees `bowl` and state.

```hoon
::  app/paywall.hoon: access for ecash paid to a Cashu mint
::
/+  default-agent, dbug, *curve, *bdhke
|%
+$  payment-record  [amount=@ud expiry=@da]
+$  pending-payment  [who=@p amount=@ud]
+$  state-0
  $:  %0
      whitelist=(map @p payment-record)
      pending-payments=(map @ta pending-payment)
      mint-url=@t          ::  e.g. 'http://localhost:8080', no trailing slash
      keyset-id=@t         ::  the mint's active keyset (GET /v1/keys)
      top-denom=@ud        ::  that keyset's largest denomination
      fees=(map @t @ud)    ::  input_fee_ppk by keyset id (GET /v1/keysets)
  ==
+$  card  card:agent:gall
--
%-  agent:dbug
^-  agent:gall
=<
=|  state-0
=*  state  -
|_  =bowl:gall
+*  this  .
    def   ~(. (default-agent this %.n) bowl)
    hc    ~(. pay [bowl state])
++  on-init  ^-  (quip card _this)  `this
++  on-save  ^-  vase  !>(state)
++  on-load
  |=  old=vase
  ^-  (quip card _this)
  `this(state !<(state-0 old))
++  on-poke
  |=  [=mark =vase]
  ^-  (quip card _this)
  ?+  mark  (on-poke:def mark vase)
  ::  a payment: the payer's proofs
      %ecash-payment
    =^  cards  state  (take-payment:hc !<((list json) vase))
    [cards this]
  ::  the host sets the mint: url, active keyset, largest denomination, fees
      %noun
    ?>  =(src.bowl our.bowl)
    =+  !<([url=@t kid=@t top=@ud fee=(map @t @ud)] vase)
    `this(mint-url.state url, keyset-id.state kid, top-denom.state top, fees.state fee)
  ::  anything you gate
      %some-gated-action
    ?>  (is-whitelisted:hc src.bowl)
    `this
  ==
++  on-watch  on-watch:def
++  on-leave  on-leave:def
++  on-peek   on-peek:def
++  on-agent  on-agent:def
++  on-arvo
  |=  [=wire =sign-arvo]
  ^-  (quip card _this)
  ?+  wire  (on-arvo:def wire sign-arvo)
      [%payment @ta ~]
    ?>  ?=([%iris %http-response *] sign-arvo)
    =^  cards  state  (take-swap:hc i.t.wire client-response.sign-arvo)
    [cards this]
  ==
++  on-fail  on-fail:def
--
|%
++  pay
  |_  [=bowl:gall st=state-0]
  ::
  ::  take-payment: swap the payer's proofs at the mint; the payer is
  ::  credited when the mint answers (take-swap)
  ++  take-payment
    |=  proofs=(list json)
    ^-  (quip card state-0)
    =/  total=@ud  (proofs-total proofs)
    =/  fee=@ud  (input-fee proofs)
    ::  the mint takes at most 100 proofs; ask for at least 100 sats net
    ?:  |((gth (lent proofs) 100) (lth total (add fee 100)))
      ~&  >>>  [%payment-refused total fee]
      `st
    =/  amount=@ud  (sub total fee)
    =/  wire-id=@ta  (scot %uv (sham eny.bowl))
    =.  pending-payments.st  (~(put by pending-payments.st) wire-id [src.bowl amount])
    =/  req=request:http  (swap-request proofs amount)
    :_  st
    [%pass /payment/[wire-id] %arvo %i %request req *outbound-config:iris]~
  ::
  ::  proofs-total: the sum of the proofs' amounts
  ++  proofs-total
    |=  proofs=(list json)
    ^-  @ud
    %+  roll  proofs
    |=  [j=json acc=@ud]
    ?.  ?=([%o *] j)  acc
    =/  a  (~(get by p.j) 'amount')
    ?.  ?=([~ %n *] a)  acc
    (add acc (fall (rush p.u.a (bass 10 (plus dit))) 0))
  ::
  ::  input-fee: ceil(sum of each proof's keyset input_fee_ppk / 1000)
  ++  input-fee
    |=  proofs=(list json)
    ^-  @ud
    =/  ppk=@ud
      %+  roll  proofs
      |=  [j=json acc=@ud]
      ?.  ?=([%o *] j)  acc
      =/  id  (~(get by p.j) 'id')
      ?.  ?=([~ %s *] id)  acc
      (add acc (~(gut by fees.st) p.u.id 0))
    (div (add ppk 999) 1.000)
  ::
  ::  split-to: an amount as powers of two, none above top-denom
  ++  split-to
    |=  amount=@ud
    ^-  (list @ud)
    %+  weld  (reap (div amount top-denom.st) top-denom.st)
    (split-amount (mod amount top-denom.st))
  ::
  ::  swap-request: POST /v1/swap trading the proofs for new outputs worth
  ::  amount. The outputs' secrets and blinding factors are dropped, so
  ::  this burns the value (see "Keeping the tokens" to hold it).
  ++  swap-request
    |=  [proofs=(list json) amount=@ud]
    ^-  request:http
    =/  outputs=(list json)
      =/  denoms=(list @ud)  (split-to amount)
      =|  idx=@ud
      =|  acc=(list json)
      |-  ^-  (list json)
      ?~  denoms  (flop acc)
      =/  out  (make-output i.denoms keyset-id.st (shax (add eny.bowl idx)))
      =/  o=json
        %-  pairs:enjs:format
        :~  ['amount' (numb:enjs:format i.denoms)]
            ['id' s+keyset-id.st]
            ['B_' s+b-hex.out]
        ==
      $(denoms t.denoms, idx +(idx), acc [o acc])
    =/  body=json
      (pairs:enjs:format ~[['inputs' a+proofs] ['outputs' a+outputs]])
    :*  %'POST'
        (cat 3 mint-url.st '/v1/swap')
        ['content-type' 'application/json']~
        `(as-octs:mimes:html (en:json:html body))
    ==
  ::
  ::  take-swap: the mint's answer. 200 means it took the proofs.
  ++  take-swap
    |=  [wire-id=@ta res=client-response:iris]
    ^-  (quip card state-0)
    =/  pend  (~(get by pending-payments.st) wire-id)
    ?~  pend  `st
    ::  more of the answer is coming
    ?:  ?=(%progress -.res)  `st
    =.  pending-payments.st  (~(del by pending-payments.st) wire-id)
    ::  cancelled: the swap may or may not have happened (see below)
    ?.  ?=(%finished -.res)
      ~&  >>>  [%payment-unknown who.u.pend]
      `st
    =/  status=@ud  status-code.response-header.res
    ?.  =(200 status)
      ~&  >>>  [%payment-rejected who.u.pend status]
      `st
    ::  extend from the current expiry, not from now
    =/  old  (~(get by whitelist.st) who.u.pend)
    =/  from=@da  ?~(old now.bowl (max now.bowl expiry.u.old))
    =/  until=@da  (add from (access-duration amount.u.pend))
    =.  whitelist.st  (~(put by whitelist.st) who.u.pend [amount.u.pend until])
    `st
  ::
  ::  access-duration: what an amount buys
  ++  access-duration
    |=  amount=@ud
    ^-  @dr
    ?:  (gte amount 1.000)  ~d365
    ?:  (gte amount 500)  ~d180
    ~d30
  ::
  ++  is-whitelisted
    |=  who=@p
    ^-  ?
    =/  rec  (~(get by whitelist.st) who)
    ?~  rec  %.n
    (gth expiry.u.rec now.bowl)
  --
--
```

Set the mint from the dojo (values from `GET /v1/keys` and `GET /v1/keysets`):

```
:paywall ['http://localhost:8080' '01ab…' 1.048.576 (my ~[['01ab…' 0]])]
```

When the mint rotates keys, swaps fail with `inactive-keyset` or `unknown-keyset`: fetch the
keysets again and re-set. A proof from a keyset missing from `fees` is counted at fee 0; if that
keyset charges a fee, the swap fails with `amounts-do-not-balance`.

**A lost answer.** If iris gives `%cancel`, or the ship restarts before the answer, the mint may
have swapped the proofs anyway. Check one of them: `POST /v1/checkstate` with
`Y = (pt-to-hex (hash-to-curve secret))`; `SPENT` means the swap went through.

### The poke mark

`mar/ecash-payment.hoon`: a list of proofs, from a noun or from JSON `{"proofs": [...]}`.

```hoon
::  mar/ecash-payment.hoon
|_  proofs=(list json)
++  grab
  |%
  ++  noun  (list ^json)
  ++  json
    |=  jon=^json
    ^-  (list ^json)
    ?.  ?=([%o *] jon)  ~
    =/  v  (~(get by p.jon) 'proofs')
    ?.  ?=([~ %a *] v)  ~
    p.u.v
  --
++  grow
  |%
  ++  noun  proofs
  --
++  grad  %noun
--
```

Inside `grab`, `json` is the arm, so the type is written `^json`.

### Keeping the tokens

To hold the value instead of burning it, keep each output's whole `make-output` result, then
unblind the mint's signature:

```hoon
::  keep all of out: [b-hex=@t secret=@t blinding-factor=@]
=/  out  (make-output 64 keyset-id.st (shax eny.bowl))
::
::  the mint returned {C_, amount, id, dleq: {e, s}} for it; k-hex is
::  the mint's public key for 64 in that keyset (GET /v1/keys)
=/  c-  (need (hex-to-pt c-hex))
=/  k   (need (hex-to-pt k-hex))
?>  (dleq-verify (need (hex-to-pt b-hex.out)) c- k (hex-decode e-hex) (hex-decode s-hex))
=/  c=@t  (pt-to-hex (unblind-signature c- blinding-factor.out k))
::  the new proof: {"amount": 64, "id": <id>, "secret": secret.out, "C": c}
```

The outputs and signatures come back in the same order.

---

## Mint API reference

All public JSON over HTTP. Errors are `{"detail": "<code>"}` with a 4xx/5xx status.

### POST /v1/swap

**Request:**
```json
{
  "inputs": [
    {"amount": 4, "id": "01…", "secret": "…", "C": "02…"},
    {"amount": 1, "id": "01…", "secret": "…", "C": "02…"}
  ],
  "outputs": [
    {"amount": 4, "id": "01…", "B_": "02…"},
    {"amount": 1, "id": "01…", "B_": "03…"}
  ]
}
```

**Rules:**
- `sum(inputs) − fee == sum(outputs)`, fee as above.
- Every output amount is a denomination of the active keyset, and names that keyset.
- At most 100 inputs and 100 outputs.
- All or nothing: if any output can't be signed or any input fails, nothing is spent.

**200:**
```json
{"signatures": [{"C_": "02…", "amount": 4, "id": "01…", "dleq": {"e": "…", "s": "…"}}, …]}
```

**400 codes:** `amounts-do-not-balance`, `fee-exceeds-inputs`, `token-already-spent`,
`invalid-token-signature`, `invalid-C-point`, `secret-too-long`, `unknown-keyset`,
`inactive-keyset`, `unknown-denomination`, `duplicate-output`, `output-already-signed`,
`invalid-B_-point`, `missing-B_`, `batch-too-large`, `missing-inputs`, `missing-outputs`, and
for P2PK-locked inputs `missing-witness-signatures`, `insufficient-p2pk-signatures`,
`unsupported-spending-condition`.

### GET /v1/keys

The active keyset. Take `id` for your outputs and the largest key as `top-denom`.

```json
{"keysets": [{
  "id": "01…", "unit": "sat", "active": true, "input_fee_ppk": 0,
  "keys": {"1": "02…", "2": "03…", "4": "02…", "…": "…", "1048576": "02…"}
}]}
```

A keyset made on an older `%ecash` mint stops at `"512"`.

### GET /v1/keysets

Every keyset, active or not, without keys: fill `fees` from it.

```json
{"keysets": [{"id": "01…", "unit": "sat", "active": true, "input_fee_ppk": 0}, …]}
```

### POST /v1/checkstate

Read-only; it does **not** reserve anything.

```json
{"Ys": ["02…", "03…"]}
→ {"states": [{"Y": "02…", "state": "UNSPENT", "witness": null},
              {"Y": "03…", "state": "SPENT", "witness": null}]}
```

`PENDING` means the proof is in a Lightning payment still in flight; it may come back.

### GET /v1/info

```json
{
  "name": "ecash-mint",
  "version": "ecash/1.0.0",
  "description": "Cashu ecash mint on Urbit",
  "nuts": {
    "4": {"methods": [{"method": "bolt11", "unit": "sat", "min_amount": 1, "max_amount": 83886080}],
          "disabled": false},
    "5": {"methods": [{"method": "bolt11", "unit": "sat", "min_amount": 1}],
          "disabled": false},
    "7": {"supported": true},
    "…": "nuts 3 to 12"
  }
}
```

`max_amount` is the most one mint quote can be; melts name no maximum.

### Limits at the %ecash mint

- 100 inputs, outputs or `Ys` per request; request bodies up to 1 MiB.
- Secrets up to 2048 bytes (`make-output` makes 64).
- P2PK: only `SIG_INPUTS`. A lock whose `data` key plus `pubkeys` number more than 10 can never
  be spent by those keys (the same for more than 10 `refund` keys), and a witness with more than
  10 signatures is refused.

---

## Patterns

### Multiple mints

Keep a mint URL per keyset id, filled from each mint's `GET /v1/keysets`, and send each payment's
swap to the mint that issued its keyset. Proofs from different mints can't share one swap.

### Accepting tokens over HTTP

Bind a path with eyre and read the same `{"proofs": [...]}` body. A public caller has no ship
identity you can trust, so key the whitelist on something the caller proves (a session or
account you issue), not on `src.bowl`.

### Access tokens instead of sats (`%ecash-services`)

If you gate access with zero-value service tokens rather than payments, redeem them with
`POST /services/v1/{name}/redeem`. **Grant access only when a token's `status` is `"fresh"`.**
The endpoint answers 200 with `"replay"` for a token that was already redeemed, possibly by
someone else.

---

## Checklist

- [ ] Copy `lib/curve.hoon` and `lib/bdhke.hoon`; import `/+  *curve, *bdhke`
- [ ] State: `whitelist`, `pending-payments`, and the mint's url, keyset id, top denomination and fees
- [ ] A poke (mark `%ecash-payment`) that takes proofs
- [ ] Sum the proofs, subtract the input fee, enforce a minimum
- [ ] Outputs: powers of two no larger than the top denomination, worth exactly `total − fee`
- [ ] Send the swap with iris; on 200 credit the payer, otherwise don't
- [ ] On `%cancel`, check `/v1/checkstate` before telling the payer it failed
- [ ] Extend an existing whitelist entry from its current expiry
- [ ] Gate protected pokes with `is-whitelisted`
- [ ] Re-fetch keysets when swaps fail `inactive-keyset` or `unknown-keyset`
