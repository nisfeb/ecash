::  /lib/ecash-rules: the mint's rules as pure arms. The agent keeps state
::  and I/O; everything that decides lives here, where tests reach it:
::  keysets, fees, proof and output checks, signing, P2PK, what a
::  Lightning answer means, and how long a quote lives.
::
/-  *ecash
/+  *bdhke, *ecash-http, *blind
|%
::
::  -- keysets --
::
::  default-denoms: 2^0..2^20 sats. max-amount of such a keyset is
::  (max-batch - 20) * 2^20, about 84M sats.
++  default-denoms  ^-  (list @ud)  (turn (gulf 0 20) |=(i=@ud `@ud`(bex i)))
::
::  gen-ks-keys: a keyset's keys for the default denominations
++  gen-ks-keys  |=(ent=@ (gen-keys ent default-denoms))
::
::  max-amount: the largest amount a keyset can always pay in max-batch
::  outputs. With power-of-two denominations up to top = 2^m, an amount a
::  takes (a / top) + popcount(a mod top) outputs, and the popcount is at
::  most m. A quote larger than this could be paid and never minted.
++  max-amount
  |=  keys=(map @ud @t)
  ^-  @ud
  =/  top=@ud  (roll ~(tap in ~(key by keys)) max)
  ?:  =(0 top)  0
  =/  m=@ud  (dec (xeb top))
  ?:  (lte max-batch m)  0
  (mul (sub max-batch m) top)
::
::  -- amounts and fees --
::
::  amount-total: the sum of the claimed amounts in proofs or outputs
++  amount-total
  |=  msgs=(list json)
  ^-  @ud
  %+  roll  msgs
  |=  [m=json acc=@ud]
  ?.  ?=([%o *] m)  acc
  (add acc (get-num p.m 'amount'))
::
::  compute-fee: NUT-02 input fee, summed per proof, ceil-divided by 1000
++  compute-fee
  |=  [proofs=(list json) keysets=(map @t keyset) active=@t]
  ^-  @ud
  =/  ppk=@ud
    %+  roll  proofs
    |=  [proof=json acc=@ud]
    ?.  ?=([%o *] proof)  acc
    =/  kid  (get-str p.proof 'id')
    ::  an empty id is verified against the active keyset, so it pays that
    ::  keyset's fee (else dropping 'id' dodges the fee)
    =?  kid  =('' kid)  active
    =/  ks  (~(get by keysets) kid)
    ?~  ks  acc
    (add acc input-fee-ppk.u.ks)
  (div (add ppk 999) 1.000)
::
::  melt-fee-reserve: the Lightning fee reserve for a melt, in basis points
::  of the amount with a floor
++  melt-fee-reserve
  |=  [amount=@ud bps=@ud floor=@ud]
  ^-  @ud
  (max floor (div (mul amount bps) 10.000))
::
::  melt-change: NUT-08 change for a settled bolt11 melt, the unused fee
::  reserve plus whatever the inputs paid beyond amount + reserve
++  melt-change
  |=  [reserve=@ud fee=@ud excess=@ud]
  ^-  @ud
  (add (sub reserve (min fee reserve)) excess)
::
::  -- proofs --
::
::  max P2PK witness sigs / pubkeys per proof. Honest n-of-m multisig is
::  far below it; it bounds the sigs * keys verifies one proof can cost.
++  max-p2pk-keys  ^-  @ud  10
::
::  verify-proofs: check a batch of input proofs, answering the total and
::  the spent sets with the batch added. Every cheap check runs over the
::  whole batch before any EC work, so a bad proof anywhere costs little.
++  verify-proofs
  |=  $:  inputs=(list json)
          spent=(set @t)
          spent-ys=(set @t)
          keysets=(map @t keyset)
          active=@t
          now=@da
      ==
  ^-  (each [total=@ud spent=(set @t) spent-ys=(set @t)] @t)
  ::  pass 1: shape, secret size, spent, keyset, denomination, C on curve
  =/  cheap=(unit @t)
    =|  seen=(set @t)
    =/  todo  inputs
    |-  ^-  (unit @t)
    ?~  todo  ~
    =/  tok  i.todo
    ?.  ?=([%o *] tok)  `'invalid-proof'
    =/  secret  (get-str p.tok 'secret')
    ?:  (gth (met 3 secret) max-secret-bytes)  `'secret-too-long'
    ?:  |((~(has in spent) secret) (~(has in seen) secret))
      `'token-already-spent'
    =/  kid  (get-str p.tok 'id')
    =?  kid  =('' kid)  active
    =/  ks  (~(get by keysets) kid)
    ?~  ks  `'unknown-keyset'
    ?.  (~(has by privkeys.u.ks) (get-num p.tok 'amount'))
      `'unknown-denomination'
    ?:  =(~ (hex-to-pt (get-str p.tok 'C')))  `'invalid-C-point'
    $(todo t.todo, seen (~(put in seen) secret))
  ?^  cheap  [%| u.cheap]
  ::  pass 2: the signature, any spending condition, and the Y it spends
  =|  total=@ud
  |-  ^-  (each [total=@ud spent=(set @t) spent-ys=(set @t)] @t)
  ?~  inputs  [%& total spent spent-ys]
  =/  tok  i.inputs
  ?.  ?=([%o *] tok)  [%| 'invalid-proof']
  =/  secret  (get-str p.tok 'secret')
  =/  amt  (get-num p.tok 'amount')
  =/  kid  (get-str p.tok 'id')
  =?  kid  =('' kid)  active
  =/  ks  (~(got by keysets) kid)
  =/  c  (hex-to-pt (get-str p.tok 'C'))
  ?~  c  [%| 'invalid-C-point']
  =/  y  (hash-to-curve secret)
  ?.  =(u.c (pt-mul (~(got by privkeys.ks) amt) y))
    [%| 'invalid-token-signature']
  ::  NUT-10: a well-known secret binds a spending condition. P2PK is
  ::  enforced; any other kind (HTLC, ...) is refused, never bearer-spent.
  =/  wk  (parse-wk-secret secret)
  ?^  wk
    ?.  =('P2PK' kind.u.wk)  [%| 'unsupported-spending-condition']
    =/  err  (check-p2pk tok secret u.wk now)
    ?^  err  [%| u.err]
    =/  y-hex  (pt-to-hex y)
    $(inputs t.inputs, total (add total amt), spent (~(put in spent) secret), spent-ys (~(put in spent-ys) y-hex))
  =/  y-hex  (pt-to-hex y)
  $(inputs t.inputs, total (add total amt), spent (~(put in spent) secret), spent-ys (~(put in spent-ys) y-hex))
::
::  -- NUT-10 / NUT-11 spending conditions --
::
::  parse-wk-secret: a well-known secret ["kind", {nonce, data, tags}]
++  parse-wk-secret
  |=  secret=@t
  ^-  (unit [kind=@t data=@t tags=(list (list @t))])
  =/  jon  (de:json:html secret)
  ?.  ?=([~ %a ^] jon)  ~
  =/  kind-j  i.p.u.jon
  ?.  ?=([%s *] kind-j)  ~
  =/  rest  t.p.u.jon
  ?.  ?=([^ ~] rest)  ~
  =/  payload-j  i.rest
  ?.  ?=([%o *] payload-j)  ~
  =/  kind=@t  p.kind-j
  =/  payload=(map @t json)  p.payload-j
  =/  data  (~(get by payload) 'data')
  ?.  ?=([~ %s *] data)  ~
  =/  tags=(list (list @t))
    %+  turn  (get-array payload 'tags')
    |=  tag=json
    ?.  ?=([%a *] tag)  ~
    (turn p.tag |=(v=json ?.(?=([%s *] v) '' p.v)))
  `[kind p.u.data tags]
::
::  get-tag: the values after a tag's key
++  get-tag
  |=  [tags=(list (list @t)) key=@t]
  ^-  (list @t)
  |-
  ?~  tags  ~
  ?~  i.tags  $(tags t.tags)
  ?:  =(i.i.tags key)  t.i.tags
  $(tags t.tags)
::
::  get-witness-sigs: the signatures in a proof's witness JSON string
++  get-witness-sigs
  |=  tok=json
  ^-  (list @t)
  ?.  ?=([%o *] tok)  ~
  =/  wit  (get-str p.tok 'witness')
  ?:  =('' wit)  ~
  =/  wj  (de:json:html wit)
  ?.  ?=([~ %o *] wj)  ~
  (turn (get-array p.u.wj 'signatures') |=(s=json ?.(?=([%s *] s) '' p.s)))
::
::  canon-x: one spelling per x-only signer. schnorr-verify reads only x
::  (lifted to even y) and hex case-insensitively, so 02<x>, 03<x> and
::  02<X> are the same signer and must fill one slot of a threshold.
::  Anything but 66 characters passes through and fails verification.
++  canon-x
  |=  pk=@t
  ^-  @t
  =/  chars  (trip pk)
  ?.  =(66 (lent chars))  pk
  (crip (weld "02" (cass (slag 2 chars))))
::
::  count-valid-sigs: how many DISTINCT signers some signature satisfies,
::  counting up to need. One keyholder can't fill an n-of-m threshold with
::  several signatures. Oversized lists count 0, so the spend fails.
++  count-valid-sigs
  |=  [sigs=(list @t) pks=(list @t) msg=@ need=@ud]
  ^-  @ud
  ?:  |((gth (lent sigs) max-p2pk-keys) (gth (lent pks) max-p2pk-keys))
    0
  =/  real-sigs=(list @t)  (skip sigs |=(s=@t =('' s)))
  =/  uniq=(list @t)  ~(tap in (silt (turn pks canon-x)))
  =|  acc=@ud
  |-  ^-  @ud
  ?~  uniq  acc
  ?:  (gte acc need)  acc
  =?  acc  (lien real-sigs |=(s=@t (schnorr-verify i.uniq msg s)))  +(acc)
  $(uniq t.uniq)
::
::  check-p2pk: ~ if the witness meets the P2PK lock, else why not
++  check-p2pk
  |=  [tok=json secret=@t wk=[kind=@t data=@t tags=(list (list @t))] now=@da]
  ^-  (unit @t)
  =/  sigs  (get-witness-sigs tok)
  ::  only SIG_INPUTS is supported
  =/  sf  (get-tag tags.wk 'sigflag')
  ?.  =('SIG_INPUTS' ?~(sf 'SIG_INPUTS' i.sf))  `'unsupported-sigflag'
  ::  a present but unparseable locktime or threshold is refused
  =/  lt  (get-tag tags.wk 'locktime')
  =/  locktime=(unit @ud)  ?~(lt `0 (parse-ud-strict i.lt))
  ?~  locktime  `'invalid-locktime'
  =/  ns  (get-tag tags.wk 'n_sigs')
  =/  n-sigs=(unit @ud)  ?~(ns `1 (parse-ud-strict i.ns))
  ?~  n-sigs  `'invalid-n-sigs'
  =/  msg  (shax secret)
  ?:  &((gth u.locktime 0) (gth (da-to-unix now) u.locktime))
    ::  locktime passed: the refund keys can spend, and with none named,
    ::  anyone can
    =/  refund  (get-tag tags.wk 'refund')
    ?~  refund  ~
    =/  nr  (get-tag tags.wk 'n_sigs_refund')
    =/  n-refund=(unit @ud)  ?~(nr `1 (parse-ud-strict i.nr))
    ?~  n-refund  `'invalid-n-sigs-refund'
    ?~  sigs  `'missing-witness-signatures'
    =/  need  (max 1 u.n-refund)
    ?:  (gte (count-valid-sigs sigs refund msg need) need)  ~
    `'invalid-refund-signature'
  ?~  sigs  `'missing-witness-signatures'
  =/  need  (max 1 u.n-sigs)
  ?:  (gte (count-valid-sigs sigs [data.wk (get-tag tags.wk 'pubkeys')] msg need) need)
    ~
  `'insufficient-p2pk-signatures'
::
::  -- outputs --
::
::  output-error: the first reason a batch of blinded outputs can't be
::  signed, found before anything is spent: a swap or mint either signs
::  every output or changes nothing. blank: NUT-08 change outputs, whose
::  amounts and keyset the mint picks at settle time.
++  output-error
  |=  $:  outputs=(list json)
          keysets=(map @t keyset)
          active=@t
          signed=(map @t restored-sig)
          blank=?
      ==
  ^-  (unit @t)
  =|  seen=(set @)
  |-  ^-  (unit @t)
  ?~  outputs  ~
  =/  msg  i.outputs
  ?.  ?=([%o *] msg)  `'invalid-msg'
  =/  b-hex  (canon-hex (get-str p.msg 'B_'))
  ?:  =('' b-hex)  `'missing-B_'
  =/  b  (hex-to-pt b-hex)
  ?~  b  `'invalid-B_-point'
  ::  two B_ with one x is the B_/-B_ DLEQ nonce-reuse shape
  ?:  (~(has in seen) x.u.b)  `'duplicate-output'
  ::  NUT-13 wallets recover their counter from this refusal; signing a
  ::  B_ twice hands back a token that may already be spent
  ?:  (~(has by signed) b-hex)  `'output-already-signed'
  =.  seen  (~(put in seen) x.u.b)
  ?:  blank  $(outputs t.outputs)
  =/  kid  (get-str p.msg 'id')
  =?  kid  =('' kid)  active
  =/  ks  (~(get by keysets) kid)
  ?~  ks  `'unknown-keyset'
  ::  an inactive keyset (a retired one, or the alias set-fee leaves)
  ::  still verifies old tokens but signs no new ones
  ?.  active.u.ks  `'inactive-keyset'
  ?.  (~(has by privkeys.u.ks) (get-num p.msg 'amount'))
    `'unknown-denomination'
  $(outputs t.outputs)
::
::  sign-one: C_ = a*B_ for one output under the keyset's key for amt,
::  with a DLEQ proof. An unsignable output gets an error object; callers
::  run output-error first, so that is only a last defense.
++  sign-one
  |=  [msg=json amt=@ud ks=keyset ent=@]
  ^-  json
  ?.  ?=([%o *] msg)  (pairs:enjs:format ['error' s+'invalid-msg']~)
  =/  b-hex  (get-str p.msg 'B_')
  =/  b  (hex-to-pt b-hex)
  ?~  b  (pairs:enjs:format ['error' s+'invalid-B_-point']~)
  =/  priv  (~(get by privkeys.ks) amt)
  ?~  priv  (pairs:enjs:format ['error' s+'unknown-denomination']~)
  =/  pub  (biff (~(get by keys.ks) amt) hex-to-pt)
  ?~  pub  (pairs:enjs:format ['error' s+'unknown-denomination']~)
  (sign-blinded b-hex u.b amt ks-id.ks u.priv u.pub ent)
::
::  sign-outputs: sign a swap's or mint's outputs, each under its own keyset
++  sign-outputs
  |=  [outputs=(list json) keysets=(map @t keyset) active=@t ent=@]
  ^-  (list json)
  %+  turn  outputs
  |=  msg=json
  ^-  json
  ?.  ?=([%o *] msg)  (pairs:enjs:format ['error' s+'invalid-msg']~)
  =/  kid  (get-str p.msg 'id')
  =?  kid  =('' kid)  active
  =/  ks  (~(get by keysets) kid)
  ?~  ks  (pairs:enjs:format ['error' s+'unknown-keyset']~)
  ?.  active.u.ks  (pairs:enjs:format ['error' s+'inactive-keyset']~)
  (sign-one msg (get-num p.msg 'amount') u.ks ent)
::
::  sign-change-outputs: NUT-08 change. Splits overpaid into powers of two
::  and signs them onto the blank outputs in order, under the active
::  keyset. Positions are kept: an unsignable output gets an error object,
::  since the wallet and restore-entries pair outputs and signatures by
::  index.
++  sign-change-outputs
  |=  [outputs=(list json) overpaid=@ud keysets=(map @t keyset) active=@t ent=@]
  ^-  (list json)
  =/  ks  (~(get by keysets) active)
  =/  amounts  (split-amount overpaid)
  =|  idx=@ud
  =|  acc=(list json)
  |-  ^-  (list json)
  ?~  amounts  (flop acc)
  ?~  outputs  (flop acc)
  =/  sig=json
    ?~  ks  (pairs:enjs:format ['error' s+'unknown-keyset']~)
    (sign-one i.outputs i.amounts u.ks (add ent idx))
  $(amounts t.amounts, outputs t.outputs, idx +(idx), acc [sig acc])
::
::  restore-entries: NUT-09 records (B_ -> signature) for a batch, pairing
::  outputs and signatures by index. Error results are skipped.
++  restore-entries
  |=  [msgs=(list json) sigs=(list json)]
  ^-  (map @t restored-sig)
  =|  out=(map @t restored-sig)
  |-  ^-  (map @t restored-sig)
  ?~  msgs  out
  ?~  sigs  out
  =/  msg  i.msgs
  =/  sig  i.sigs
  ?.  &(?=([%o *] msg) ?=([%o *] sig))  $(msgs t.msgs, sigs t.sigs)
  =/  b-hex  (canon-hex (get-str p.msg 'B_'))
  =/  c-hex  (get-str p.sig 'C_')
  ?:  |(=('' b-hex) =('' c-hex))  $(msgs t.msgs, sigs t.sigs)
  =/  dleq  (get-obj p.sig 'dleq')
  =/  rs=restored-sig
    [(get-num p.sig 'amount') (get-str p.sig 'id') c-hex (get-str dleq 'e') (get-str dleq 's')]
  $(msgs t.msgs, sigs t.sigs, out (~(put by out) b-hex rs))
::
::  -- Lightning --
::
::  valid-bolt11: plausible bolt11 text. It lands in a backend URL path
::  (LND decodes with GET /v1/payreq/<bolt11>), so only bech32's letters
::  and digits pass, never / ? # . or %.
++  valid-bolt11
  |=  t=@t
  ^-  ?
  =/  n  (met 3 t)
  ?&  (gth n 0)
      (lte n 4.096)
      %+  levy  (trip t)
      |=  c=@
      ?|  &((gte c 'a') (lte c 'z'))
          &((gte c 'A') (lte c 'Z'))
          &((gte c '0') (lte c '9'))
      ==
  ==
::
::  get-int: a count sent as a number or, as LND's REST API sends every
::  int64, as a string of digits; else 0
++  get-int
  |=  [o=(map @t json) k=@t]
  ^-  @ud
  =/  v  (~(get by o) k)
  ?:  ?=([~ %n *] v)  (parse-ud p.u.v)
  ?:  ?=([~ %s *] v)  (parse-ud p.u.v)
  0
::
::  b64-hex: LND's REST API sends bytes fields (r_hash, SendResponse's
::  payment_preimage) as base64 but string fields (a Payment's
::  payment_preimage) as hex; wallets and LND's lookups want hex. 64 hex
::  digits are already hex (32 bytes of base64 is 44 characters), and text
::  that isn't base64 comes back as it was.
++  b64-hex
  |=  t=@t
  ^-  @t
  ?:  &(=(64 (met 3 t)) (is-hex t))  t
  =/  o  (de:base64:mimes:html t)
  ?~  o  t
  (pad-hex (rev 3 p.u.o q.u.o) (mul 2 p.u.o))
::
::  ln-settled-sats: the settled amount in an LN status answer, in sats.
::  LNbits: details.amount, amount_msat or amount (all msat). LND:
::  amt_paid_sat or value (sats). 0 when none is present.
++  ln-settled-sats
  |=  o=(map @t json)
  ^-  @ud
  =/  det-msat=@ud  (get-int (get-obj o 'details') 'amount')
  ?:  (gth det-msat 0)  (div det-msat 1.000)
  =/  top-msat=@ud  (get-int o 'amount_msat')
  ?:  (gth top-msat 0)  (div top-msat 1.000)
  =/  amt-msat=@ud  (get-int o 'amount')
  ?:  (gth amt-msat 0)  (div amt-msat 1.000)
  =/  lnd-sat=@ud  (get-int o 'amt_paid_sat')
  ?:  (gth lnd-sat 0)  lnd-sat
  (get-int o 'value')
::
::  invoice-paid: does a status answer show the mint's own invoice paid?
::  bolt11 is all-or-nothing, so LNbits' paid:true with no usable amount
::  is trusted; only an explicitly short amount is refused.
++  invoice-paid
  |=  [ln=ln-backend jon=(unit json) amount=@ud]
  ^-  ?
  ?.  ?=([~ %o *] jon)  %.n
  ?-  -.ln
      %none  %.n
  ::
      %lnbits
    ?.  (get-bool p.u.jon 'paid')  %.n
    =/  settled  (ln-settled-sats p.u.jon)
    |(=(0 settled) (gte settled amount))
  ::
      %lnd
    ?.  =('SETTLED' (get-str p.u.jon 'state'))  %.n
    (gte (ln-settled-sats p.u.jon) amount)
  ==
::
::  pay-status: what a status answer says about an outgoing payment. Only
::  a settled pay and LND's explicit FAILED are definite. A 404,
::  IN_FLIGHT, paid:false or an error body can't be told apart from a pay
::  still in flight, and rolling back on those double-pays a live payment.
++  pay-status
  |=  [ln=ln-backend status=@ud jon=(unit json)]
  ^-  ?(%settled %failed %unknown)
  ?:  =(404 status)  %unknown
  ?.  ?=([~ %o *] jon)  %unknown
  ?-  -.ln
      %none    %unknown
      %lnbits  ?:((get-bool p.u.jon 'paid') %settled %unknown)
      %lnd
    =/  s  (get-str p.u.jon 'status')
    ?:  =('SUCCEEDED' s)  %settled
    ?:  =('FAILED' s)  %failed
    %unknown
  ==
::
::  pay-settled: does the pay dispatch answer itself prove settlement?
::  Only a 2xx carrying a preimage and no error.
++  pay-settled
  |=  [status=@ud jon=(unit json)]
  ^-  ?
  ?&  (gte status 200)
      (lth status 300)
      ?=([~ %o *] jon)
      !=('' (extract-str u.jon 'payment_preimage' 'preimage'))
      =('' (extract-str u.jon 'payment_error' 'error'))
  ==
::
::  pay-rejected: did the pay fail before any HTLC existed? Only an LNbits
::  4xx (not 408 or 429, which mean try again) whose body is a
::  recognizable error and names no payment. A 5xx, an empty or opaque
::  body, or a named payment stays ambiguous.
++  pay-rejected
  |=  [ln=ln-backend status=@ud jon=(unit json)]
  ^-  ?
  ?&  ?=(%lnbits -.ln)
      (gte status 400)
      (lth status 500)
      !=(408 status)
      !=(429 status)
      ?=([~ %o *] jon)
      =('' (extract-str u.jon 'payment_hash' 'checking_id'))
      !=('' (extract-str u.jon 'detail' 'error'))
  ==
::
::  routing-fee-sats: a settled pay's routing fee in sats, read FAIL-CLOSED:
::  a fee that can't be read counts as the whole cap (the fee reserve), so
::  the refund is 0 and the mint never over-refunds. LNbits reports an
::  outgoing fee as negative msat; the magnitude is the fee.
::
::    First field that parses wins (a present 0 is a real 0-sat fee):
::      sats as-is:  fee_sat, payment_route.total_fees
::      msat, ceil /1000:  total_fees_msat, payment_route.total_fees_msat,
::                         fee, details.fee
::    LND REST string-encodes int64, so each is read as string or number.
++  routing-fee-sats
  |=  [jon=json cap=@ud]
  ^-  @ud
  ?.  ?=([%o *] jon)  cap
  =/  pick
    |=  [o=(map @t json) k=@t]
    ^-  (unit @ud)
    =/  v  (~(get by o) k)
    ?:  ?=([~ %s *] v)  (parse-abs p.u.v)
    ?:  ?=([~ %n *] v)  (parse-abs p.u.v)
    ~
  =/  route  (get-obj p.jon 'payment_route')
  =/  sat-u=(unit @ud)
    =/  fs  (pick p.jon 'fee_sat')
    ?^  fs  fs
    (pick route 'total_fees')
  ?^  sat-u  (min u.sat-u cap)
  =/  msat-u=(unit @ud)
    =/  tfm  (pick p.jon 'total_fees_msat')
    ?^  tfm  tfm
    =/  ptfm  (pick route 'total_fees_msat')
    ?^  ptfm  ptfm
    =/  fm  (pick p.jon 'fee')
    ?^  fm  fm
    (pick (get-obj p.jon 'details') 'fee')
  ?~  msat-u  cap
  (min (div (add u.msat-u 999) 1.000) cap)
::
::  -- quotes --
::
++  quote-state-text
  |=  qs=quote-state
  ^-  @t
  ?-  qs
    %unpaid   'UNPAID'
    %pending  'PENDING'
    %paid     'PAID'
    %issued   'ISSUED'
    %failed   'UNPAID'
  ==
::
++  mint-quote-method
  |=  q=mint-quote
  ^-  @t
  ?:(=('self-mint' request.q) 'self' 'bolt11')
::
++  melt-quote-method
  |=  q=melt-quote
  ^-  @t
  ?:(=('' payment-hash.q) 'self' 'bolt11')
::
::  quote-grace: how long an expired, unpaid bolt11 mint quote is kept.
::  Its invoice can't be paid after expiry, but one paid just before is
::  only noticed by a check, so the daily cleanup checks it once
::  (recheck-mint-quote) and keeps it long enough for the answer.
++  quote-grace  ~d2
::
::  keep-mint-quote: does the daily cleanup keep this mint quote? A %paid
::  quote is a deposit not yet minted, kept whatever its age.
++  keep-mint-quote
  |=  [q=mint-quote now=@da]
  ^-  ?
  ?|  (gth expiry.q now)
      =(%paid state.q)
      ?&  =(%unpaid state.q)
          !=('' checking-id.q)
          (gth (add expiry.q quote-grace) now)
      ==
  ==
::
::  recheck-mint-quote: an unpaid bolt11 quote that expired within the
::  last day gets one last Lightning check from the daily cleanup
++  recheck-mint-quote
  |=  [q=mint-quote now=@da]
  ^-  ?
  ?&  =(%unpaid state.q)
      !=('' checking-id.q)
      (lte expiry.q now)
      (gth (add expiry.q ~d1) now)
  ==
::
::  paid-melt-life: how long a %paid melt quote outlives its expiry. Its
::  NUT-08 change stays recoverable after that through /v1/restore, which
::  keeps every signature the mint issued, so the quote needn't live on.
++  paid-melt-life  ~d30
::
::  keep-melt-quote: a %pending melt owes a settle-or-rollback decision, so
::  it stays whatever its age; a %paid one stays paid-melt-life past expiry
++  keep-melt-quote
  |=  [q=melt-quote now=@da]
  ^-  ?
  ?|  (gth expiry.q now)
      =(%pending state.q)
      &(=(%paid state.q) (gth (add expiry.q paid-melt-life) now))
  ==
--
