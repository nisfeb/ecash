::  ecash: Cashu NUT-00..NUT-12 mint agent with Lightning backend
::
::    secp256k1 + BDHKE + DLEQ proofs + P2PK Schnorr verification.
::    Shared types live in /sur/ecash, the mint's rules in /lib/ecash-rules
::    and the HTTP plumbing in /lib/ecash-http; this agent keeps the state
::    and does the I/O. Migration-only shapes are below.
::
/-  *ecash
/+  default-agent, dbug, *bdhke, *ecash-http, *ecash-rules
/*  dashboard-lines  %txt  /app/dashboard/txt
/*  icon-svg         %txt  /app/icon-svg/txt
|%
::  melt-inflight-entry-0: the state-13/14 inflight record, before .excess
+$  melt-inflight-entry-0
  $:  secrets=(set @t)
      ys=(set @t)
      input-total=@ud
      change=(list json)
  ==
::  state-13: the oldest state this agent loads. Every public release has
::  been at 13 or later; an older ship must upgrade through commit eb7b56a.
+$  state-13
  $:  %13
      keysets=(map @t keyset)
      active-keyset=@t
      spent=(set @t)
      spent-ys=(set @t)
      counter=@ud
      mint-quotes=(map @t mint-quote)
      melt-quotes=(map @t melt-quote)
      ln-config=ln-backend
      pending=(map @ta pending-req-v2)
      total-issued-sats=@ud
      total-redeemed-sats=@ud
      mint-name=@t
      mint-description=@t
      fee-reserve-pct=@ud
      fee-reserve-min=@ud
      quote-ttl-secs=@ud
      melt-change=(map @t (list json))
      self-method-enabled=?
      melt-inflight=(map @t melt-inflight-entry-0)
  ==
::  state-14: state-13 plus `restore`, each issued signature by its B_
::  (NUT-09)
+$  state-14
  $:  %14
      keysets=(map @t keyset)
      active-keyset=@t
      spent=(set @t)
      spent-ys=(set @t)
      counter=@ud
      mint-quotes=(map @t mint-quote)
      melt-quotes=(map @t melt-quote)
      ln-config=ln-backend
      pending=(map @ta pending-req-v2)
      total-issued-sats=@ud
      total-redeemed-sats=@ud
      mint-name=@t
      mint-description=@t
      fee-reserve-pct=@ud
      fee-reserve-min=@ud
      quote-ttl-secs=@ud
      melt-change=(map @t (list json))
      self-method-enabled=?
      melt-inflight=(map @t melt-inflight-entry-0)
      restore=(map @t restored-sig)
  ==
::  state-15: state-14 with .excess on each inflight melt, so a settled
::  melt returns the inputs' overpayment as change too
+$  state-15
  $:  %15
      keysets=(map @t keyset)
      active-keyset=@t
      spent=(set @t)
      spent-ys=(set @t)
      counter=@ud
      mint-quotes=(map @t mint-quote)
      melt-quotes=(map @t melt-quote)
      ln-config=ln-backend
      pending=(map @ta pending-req-v2)
      total-issued-sats=@ud
      total-redeemed-sats=@ud
      mint-name=@t
      mint-description=@t
      fee-reserve-pct=@ud
      fee-reserve-min=@ud
      quote-ttl-secs=@ud
      melt-change=(map @t (list json))
      self-method-enabled=?
      melt-inflight=(map @t melt-inflight-entry)
      restore=(map @t restored-sig)
  ==
+$  versioned-state  $%(state-13 state-14 state-15)
+$  card  card:agent:gall
--
%-  agent:dbug
^-  agent:gall
=<
=|  state-15
=*  state  -
|_  =bowl:gall
+*  this  .
    def   ~(. (default-agent this %.n) bowl)
    hc    ~(. ec [bowl state])
++  on-save   ^-  vase  !>(state)
++  on-load
  |=  old=vase
  |^  ^-  (quip card _this)
      =/  prev=versioned-state  !<(versioned-state old)
      =?  prev  ?=(%13 -.prev)  (state-13-to-14 prev)
      =?  prev  ?=(%14 -.prev)  (state-14-to-15 prev)
      ?>  ?=(%15 -.prev)
      ::  Re-arm /cleanup idempotently. The timer fires at a CANONICAL time (the
      ::  next ~d1 boundary), so %rest+%wait at that exact time cancels any
      ::  existing timer and re-arms exactly one, and it self-heals if a prior
      ::  cleanup wake was ever lost.
      =/  next=@da  (add ~d1 (mul ~d1 (div now.bowl ~d1)))
      :_  this(state prev)
      :~  [%pass /cleanup %arvo %b %rest next]
          [%pass /cleanup %arvo %b %wait next]
      ==
  ::
  ::  state-13 -> state-14: add the restore map, empty
  ++  state-13-to-14
    |=  p=state-13
    ^-  state-14
    :*  %14
        keysets.p
        active-keyset.p
        spent.p
        spent-ys.p
        counter.p
        mint-quotes.p
        melt-quotes.p
        ln-config.p
        pending.p
        total-issued-sats.p
        total-redeemed-sats.p
        mint-name.p
        mint-description.p
        fee-reserve-pct.p
        fee-reserve-min.p
        quote-ttl-secs.p
        melt-change.p
        self-method-enabled.p
        melt-inflight.p
        ~
    ==
  ::  state-14 -> state-15: inflight melts carry no overpayment record, so
  ::  their change stays what it was (excess 0), and their attempt starts
  ::  now. Restore keys are lowercased, as lookups now are.
  ++  state-14-to-15
    |=  p=state-14
    ^-  state-15
    =/  inflight=(map @t melt-inflight-entry)
      %-  ~(run by melt-inflight.p)
      |=  e=melt-inflight-entry-0
      ^-  melt-inflight-entry
      [secrets.e ys.e input-total.e change.e 0 now.bowl]
    =/  restore=(map @t restored-sig)
      (malt (turn ~(tap by restore.p) |=([k=@t v=restored-sig] [(canon-hex k) v])))
    :*  %15
        keysets.p
        active-keyset.p
        spent.p
        spent-ys.p
        counter.p
        mint-quotes.p
        melt-quotes.p
        ln-config.p
        pending.p
        total-issued-sats.p
        total-redeemed-sats.p
        mint-name.p
        mint-description.p
        fee-reserve-pct.p
        fee-reserve-min.p
        quote-ttl-secs.p
        melt-change.p
        self-method-enabled.p
        inflight
        restore
    ==
  --
++  on-init
  ^-  (quip card _this)
  =^  cards  state  init:hc
  [cards this]
++  on-poke
  |=  [=mark =vase]
  ^-  (quip card _this)
  ?+  mark  (on-poke:def mark vase)
      %handle-http-request
    =+  !<([eyre-id=@ta req=inbound-request:eyre] vase)
    =^  cards  state  (handle-http:hc eyre-id req)
    [cards this]
  ::
      %noun
    ?>  =(src.bowl our.bowl)
    `this(ln-config.state !<(ln-backend vase))
  ==
++  on-watch
  |=  =path
  ^-  (quip card _this)
  ?+  path  (on-watch:def path)
      ::  no source check: eyre subscribes as the request's identity (a
      ::  guest @p for a public caller), and gall gives that the same
      ::  provenance as a remote ship's, so nothing here tells them apart
      [%http-response *]
    `this
  ==
++  on-leave  on-leave:def
++  on-peek
  |=  =path
  ^-  (unit (unit cage))
  ?+  path  [~ ~]
    [%x %counter ~]        ``noun+!>(counter.state)
    [%x %active-keyset ~]  ``noun+!>(active-keyset.state)
  ==
++  on-agent  on-agent:def
++  on-arvo
  |=  [=wire =sign-arvo]
  ^-  (quip card _this)
  ?+  wire  (on-arvo:def wire sign-arvo)
      [%eyre ?(%connect %connect-v1) ~]
    ?.  ?=([%eyre %bound *] sign-arvo)  (on-arvo:def wire sign-arvo)
    ~?  >>>  !accepted.sign-arvo  [%ecash-bind-failed wire]
    `this
  ::
      [%ln @ta *]
    ?>  ?=([%iris %http-response *] sign-arvo)
    ::  /ln/<id>/<attempt>: the melt attempt a request was made for
    =/  att=(unit @da)  ?.(?=([%ln @ta @ta ~] wire) ~ (slaw %da i.t.t.wire))
    =^  cards  state  (handle-ln-response:hc i.t.wire att client-response.sign-arvo)
    [cards this]
  ::
      [%cleanup ~]
    ?>  ?=(%behn -.sign-arvo)
    =^  cards  state  run-cleanup:hc
    :_  this
    :-  [%pass /cleanup %arvo %b %wait (add ~d1 (mul ~d1 (div now.bowl ~d1)))]
    cards
  ==
++  on-fail   on-fail:def
--
::  -- Helper core --
|%
++  ec
  |_  [=bowl:gall st=state-15]
  ::
  ::  -- small helpers --
  ::
  ::  ent: entropy for this event's DLEQ nonces
  ++  ent  ^-  @  (add eny.bowl now.bowl)
  ::  new-wire: the wire id of this event's one Lightning request
  ++  new-wire  ^-  @ta  (scot %uv (sham eny.bowl))
  ::  gen-quote-id: this event's one quote id
  ++  gen-quote-id  ^-  @t  (pad-hex (shax (add eny.bowl now.bowl)) 64)
  ++  quote-expiry  ^-  @da  (add now.bowl (mul ~s1 quote-ttl-secs.st))
  ::  mint-max: the largest amount the active keyset can mint in one
  ::  request; a larger quote could be paid and never minted
  ++  mint-max
    ^-  @ud
    =/  ks  (~(get by keysets.st) active-keyset.st)
    ?~(ks 0 (max-amount keys.u.ks))
  ::
  ++  ln-card
    |=  [wid=@ta req=request:http]
    ^-  card
    [%pass /ln/[wid] %arvo %i %request req *outbound-config:iris]
  ::  ln-card-at: a request about a melt, tagged with the melt's attempt
  ++  ln-card-at
    |=  [wid=@ta att=(unit @da) req=request:http]
    ^-  card
    ?~  att  (ln-card wid req)
    [%pass [%ln wid (scot %da u.att) ~] %arvo %i %request req *outbound-config:iris]
  ::  attempt-of: the attempt now in flight for a melt quote, if any
  ++  attempt-of
    |=  qid=@t
    ^-  (unit @da)
    (bind (~(get by melt-inflight.st) qid) |=(e=melt-inflight-entry started.e))
  ::  this-attempt: was an answer asked for the attempt now in flight? A
  ::  quote can fail, roll back and be melted again while an older check is
  ::  still out, and that check's FAILED must not roll back the new attempt.
  ::  An answer from before attempts were tagged (att ~) counts as current.
  ++  this-attempt
    |=  [att=(unit @da) qid=@t]
    ^-  ?
    ?~  att  &
    =(att (attempt-of qid))
  ::
  ::  fresh-keyset: new keys under their NUT-02 id
  ++  fresh-keyset
    |=  [unt=@t fee=@ud active=?]
    ^-  keyset
    =/  keys  (gen-ks-keys (shax eny.bowl))
    [(compute-ks-id pubkeys.keys unt fee 0) active unt fee pubkeys.keys privkeys.keys now.bowl]
  ::
  ++  ln-summary
    ^-  [type=@t url=@t configured=?]
    ?-  -.ln-config.st
      %lnbits  ['lnbits' url.ln-config.st %.y]
      %lnd     ['lnd' url.ln-config.st %.y]
      %none    ['none' '' %.n]
    ==
  ::
  ::  -- JSON --
  ::
  ++  keyset-json
    |=  [ks=keyset with-keys=?]
    ^-  json
    %-  pairs:enjs:format
    %+  weld
      ^-  (list [@t json])
      :~  ['id' s+ks-id.ks]
          ['unit' s+unt.ks]
          ['active' b+active.ks]
          ['input_fee_ppk' (numb:enjs:format input-fee-ppk.ks)]
      ==
    ?.  with-keys  ~
    :~  :-  'keys'
        %-  pairs:enjs:format
        %+  turn  (sort ~(tap by keys.ks) |=([a=[@ud @t] b=[@ud @t]] (lth -.a -.b)))
        |=([amt=@ud pub=@t] [(dec-cord amt) s+pub])
    ==
  ::
  ++  mint-quote-json
    |=  mq=mint-quote
    ^-  json
    %-  pairs:enjs:format
    :~  ['quote' s+quote-id.mq]
        ['request' s+request.mq]
        ['unit' s+unt.mq]
        ['amount' (numb:enjs:format amount.mq)]
        ['state' s+(quote-state-text state.mq)]
        ['expiry' (numb:enjs:format (da-to-unix expiry.mq))]
    ==
  ::  melt-quote-json: a melt quote as NUT-05 sends it, with its NUT-08 change
  ++  melt-quote-json
    |=  [mq=melt-quote change=(list json)]
    ^-  json
    %-  pairs:enjs:format
    :~  ['quote' s+quote-id.mq]
        ['amount' (numb:enjs:format amount.mq)]
        ['fee_reserve' (numb:enjs:format fee-reserve.mq)]
        ['unit' s+unt.mq]
        ['request' s+request.mq]
        ['state' s+(quote-state-text state.mq)]
        ['paid' b+=(%paid state.mq)]
        ['payment_preimage' s+payment-preimage.mq]
        ['expiry' (numb:enjs:format (da-to-unix expiry.mq))]
        ['change' a+change]
    ==
  ++  stored-change
    |=  qid=@t
    ^-  (list json)
    (fall (~(get by melt-change.st) qid) ~)
  ::
  ::  -- initialization and cleanup --
  ::
  ++  init
    ^-  (quip card state-15)
    =/  ks  (fresh-keyset 'sat' 0 &)
    =.  keysets.st           (~(put by keysets.st) ks-id.ks ks)
    =.  active-keyset.st     ks-id.ks
    ::  defaults: bunts would leave quote-ttl-secs=0
    =.  mint-name.st         'ecash-mint'
    =.  mint-description.st  'Cashu ecash mint on Urbit'
    =.  fee-reserve-pct.st   100
    =.  fee-reserve-min.st   10
    =.  quote-ttl-secs.st    3.600
    =.  self-method-enabled.st  %.n
    ::  the bunt of ln-backend is its head variant (%lnbits with an empty
    ::  url), which would report a phantom backend on a fresh mint
    =.  ln-config.st         [%none ~]
    :_  st
    :~  [%pass /eyre/connect %arvo %e %connect [`/apps/ecash dap.bowl]]
        [%pass /eyre/connect-v1 %arvo %e %connect [`/v1 dap.bowl]]
        [%pass /cleanup %arvo %b %wait (add ~d1 (mul ~d1 (div now.bowl ~d1)))]
    ==
  ::
  ::  run-cleanup: drop quotes past their life (keep-mint-quote,
  ::  keep-melt-quote) with the change and inflight records of dropped
  ::  melts, and give each unpaid bolt11 quote that expired in the last day
  ::  one Lightning check in the background.
  ++  run-cleanup
    ^-  (quip card state-15)
    =/  live-mint=(map @t mint-quote)
      (malt (skim ~(tap by mint-quotes.st) |=([@t q=mint-quote] (keep-mint-quote q now.bowl))))
    =/  live-melt=(map @t melt-quote)
      (malt (skim ~(tap by melt-quotes.st) |=([@t q=melt-quote] (keep-melt-quote q now.bowl))))
    =.  mint-quotes.st  live-mint
    =.  melt-quotes.st  live-melt
    =.  melt-change.st
      (malt (skim ~(tap by melt-change.st) |=([k=@t *] (~(has by live-melt) k))))
    =.  melt-inflight.st
      (malt (skim ~(tap by melt-inflight.st) |=([k=@t *] (~(has by live-melt) k))))
    ?:  ?=(%none -.ln-config.st)  [~ st]
    =/  due=(list mint-quote)
      (skim ~(val by live-mint) |=(q=mint-quote (recheck-mint-quote q now.bowl)))
    =|  cards=(list card)
    |-  ^-  (quip card state-15)
    ?~  due  [cards st]
    =/  wid=@ta  (scot %uv (sham [eny.bowl quote-id.i.due]))
    =.  pending.st  (~(put by pending.st) wid [%mint-quote-check '' quote-id.i.due])
    $(due t.due, cards [(ln-card wid (ln-check-invoice checking-id.i.due)) cards])
  ::
  ::  -- routing --
  ::
  ++  handle-http
    |=  [eyre-id=@ta req=inbound-request:eyre]
    ^-  (quip card state-15)
    =/  body  body.request.req
    =/  segs=(list @t)  (parse-request-path url.request.req)
    =/  admin=?  ?=([%apps %ecash %admin *] segs)
    ::  The admin surface needs our ship's session; Cashu /v1 is public by
    ::  design. Eyre sets authenticated only for our own identity.
    ?:  &(admin !authenticated.req)  [(give-err eyre-id 401 'unauthorized') st]
    ::  a state-changing admin request must be same-origin
    ?:  &(admin !(csrf-ok req))  [(give-err eyre-id 403 'forbidden-cross-origin') st]
    ::  CORS preflight for the public routes; the admin surface answers none,
    ::  so a browser never sends it a cross-origin JSON POST
    ?:  &(=(%'OPTIONS' method.request.req) !admin)  [(give-preflight eyre-id) st]
    =/  route=(list @t)  [method.request.req segs]
    ?+  route  [(give-err eyre-id 404 'not-found') st]
    ::  NUT-01/02: keys and keysets
        [%'GET' %v1 %keys ~]           [(get-keys-all eyre-id) st]
        [%'GET' %v1 %keys @ ~]         [(get-keys-by-id eyre-id i.t.t.t.route) st]
        [%'GET' %v1 %keysets ~]        [(get-keysets-v1 eyre-id) st]
    ::  NUT-03: swap
        [%'POST' %v1 %swap ~]          (post-swap eyre-id body)
    ::  NUT-04: mint
        [%'POST' %v1 %mint %quote @ ~]     (post-mint-quote eyre-id i.t.t.t.t.route body)
        [%'GET' %v1 %mint %quote @ @ ~]    (get-mint-quote eyre-id i.t.t.t.t.route i.t.t.t.t.t.route)
        [%'POST' %v1 %mint @ ~]            (post-mint-v1 eyre-id i.t.t.t.route body)
    ::  NUT-05: melt
        [%'POST' %v1 %melt %quote @ ~]     (post-melt-quote eyre-id i.t.t.t.t.route body)
        [%'GET' %v1 %melt %quote @ @ ~]    (get-melt-quote eyre-id i.t.t.t.t.route i.t.t.t.t.t.route)
        [%'POST' %v1 %melt @ ~]            (post-melt-v1 eyre-id i.t.t.t.route body)
    ::  NUT-06, 07, 09
        [%'GET' %v1 %info ~]           [(get-info eyre-id) st]
        [%'POST' %v1 %checkstate ~]    (post-checkstate eyre-id body)
        [%'POST' %v1 %restore ~]       (post-restore eyre-id body)
    ::  legacy public endpoints (kept for backwards-compat)
        [%'GET' %apps %ecash ~]
      :_  st
      %-  give-json  :_  eyre-id
      %-  pairs:enjs:format
      :~  ['name' s+mint-name.st]
          ['version' s+'1.0.0']
          ['active_keyset' s+active-keyset.st]
          ['tokens_issued' (numb:enjs:format counter.st)]
          ['crypto' s+'secp256k1-bdhke-pure-hoon']
      ==
        [%'GET' %apps %ecash %keysets ~]           [(get-keys-all eyre-id) st]
        [%'GET' %apps %ecash %keysets %active ~]   [(get-keys-all eyre-id) st]
        [%'GET' %apps %ecash %info ~]              [(get-info eyre-id) st]
    ::  Landscape tile icon (public: the docket image)
        [%'GET' %apps %ecash %icon ~]
      :_  st
      %:  give-http  eyre-id  200  ['content-type' 'image/svg+xml']~
        `(as-octs:mimes:html (rap 3 (join `@t`10 `wain`icon-svg)))
      ==
    ::  admin dashboard and API
        [%'GET' %apps %ecash %admin ~]   [(give-dashboard eyre-id dashboard-lines eny.bowl) st]
        [%'GET' %apps %ecash %admin %api %overview ~]   [(admin-overview eyre-id) st]
        [%'GET' %apps %ecash %admin %api %keysets ~]    [(admin-keysets eyre-id) st]
        [%'GET' %apps %ecash %admin %api %keysets @ ~]  [(admin-keyset-detail eyre-id i.t.t.t.t.t.t.route) st]
        [%'POST' %apps %ecash %admin %api %keysets %generate ~]    (admin-keyset-generate eyre-id)
        [%'POST' %apps %ecash %admin %api %keysets %activate ~]    (admin-keyset-activate eyre-id body)
        [%'POST' %apps %ecash %admin %api %keysets %deactivate ~]  (admin-keyset-deactivate eyre-id body)
        [%'POST' %apps %ecash %admin %api %keysets %set-fee ~]     (admin-keyset-set-fee eyre-id body)
        [%'GET' %apps %ecash %admin %api %quotes ~]              [(admin-quotes eyre-id) st]
        [%'POST' %apps %ecash %admin %api %quotes %delete ~]     (admin-quote-delete eyre-id body)
        [%'POST' %apps %ecash %admin %api %quotes %revoke ~]     (admin-quote-revoke eyre-id body)
        [%'POST' %apps %ecash %admin %api %melt %abort ~]        (admin-melt-abort eyre-id body)
        [%'GET' %apps %ecash %admin %api %spent ~]               [(admin-spent eyre-id) st]
        [%'POST' %apps %ecash %admin %api %spent %check ~]       [(admin-spent-check eyre-id body) st]
        [%'GET' %apps %ecash %admin %api %lightning ~]           [(admin-lightning eyre-id) st]
        [%'POST' %apps %ecash %admin %api %lightning %configure ~]  (admin-ln-configure eyre-id body)
        [%'POST' %apps %ecash %admin %api %lightning %test ~]       (admin-ln-test eyre-id)
        [%'GET' %apps %ecash %admin %api %info ~]                [(get-info eyre-id) st]
        [%'POST' %apps %ecash %admin %api %info %update ~]       (admin-info-update eyre-id body)
        [%'GET' %apps %ecash %admin %api %settings ~]            [(admin-get-settings eyre-id) st]
        [%'POST' %apps %ecash %admin %api %settings ~]           (admin-update-settings eyre-id body)
    ==
  ::
  ::  -- NUT-01/02: keys --
  ::
  ::  every ACTIVE keyset with its keys
  ++  get-keys-all
    |=  eyre-id=@ta
    ^-  (list card)
    =/  ks-list=(list json)
      (murn ~(val by keysets.st) |=(ks=keyset ?.(active.ks ~ `(keyset-json ks &))))
    (give-json (pairs:enjs:format ['keysets' a+ks-list]~) eyre-id)
  ::  one keyset, active or not, with its keys
  ++  get-keys-by-id
    |=  [eyre-id=@ta kid=@t]
    ^-  (list card)
    =/  ks  (~(get by keysets.st) kid)
    ?~  ks  (give-err eyre-id 404 'keyset-not-found')
    (give-json (pairs:enjs:format ['keysets' a+~[(keyset-json u.ks &)]]~) eyre-id)
  ::  every keyset's metadata, no keys
  ++  get-keysets-v1
    |=  eyre-id=@ta
    ^-  (list card)
    =/  ks-list=(list json)  (turn ~(val by keysets.st) |=(ks=keyset (keyset-json ks |)))
    (give-json (pairs:enjs:format ['keysets' a+ks-list]~) eyre-id)
  ::
  ::  -- NUT-03: swap --
  ::
  ++  post-swap
    |=  [eyre-id=@ta body=(unit octs)]
    ^-  (quip card state-15)
    =/  parsed  (parse-object-body body)
    ?:  ?=(%| -.parsed)  [(give-err eyre-id 400 p.parsed) st]
    ?>  ?=([%o *] p.parsed)
    =/  jon  p.p.parsed
    ?.  (has-key jon 'inputs')   [(give-err eyre-id 400 'missing-inputs') st]
    ?.  (has-key jon 'outputs')  [(give-err eyre-id 400 'missing-outputs') st]
    =/  inputs   (get-array jon 'inputs')
    =/  outputs  (get-array jon 'outputs')
    ?:  |((gth (lent inputs) max-batch) (gth (lent outputs) max-batch))
      [(give-err eyre-id 400 'batch-too-large') st]
    ::  balance the claimed amounts before any EC work: an unbalanced swap
    ::  is refused for the price of a sum
    =/  fee  (compute-fee inputs keysets.st active-keyset.st)
    =/  claimed  (amount-total inputs)
    =/  output-total  (amount-total outputs)
    ?:  (gth fee claimed)  [(give-err eyre-id 400 'fee-exceeds-inputs') st]
    ?.  =((sub claimed fee) output-total)
      [(give-err eyre-id 400 'amounts-do-not-balance') st]
    ::  every output signable, or nothing is spent
    =/  bad  (output-error outputs keysets.st active-keyset.st restore.st |)
    ?^  bad  [(give-err eyre-id 400 u.bad) st]
    =/  vres  (verify-proofs inputs spent.st spent-ys.st keysets.st active-keyset.st now.bowl)
    ?:  ?=(%| -.vres)  [(give-err eyre-id 400 p.vres) st]
    =/  sigs  (sign-outputs outputs keysets.st active-keyset.st ent)
    ?.  (all-signed sigs)  [(give-err eyre-id 500 'signing-failed') st]
    =.  restore.st              (~(uni by restore.st) (restore-entries outputs sigs))
    =.  spent.st                spent.p.vres
    =.  spent-ys.st             spent-ys.p.vres
    =.  counter.st              (add counter.st (lent sigs))
    =.  total-issued-sats.st    (add total-issued-sats.st output-total)
    =.  total-redeemed-sats.st  (add total-redeemed-sats.st total.p.vres)
    [(give-json (pairs:enjs:format ['signatures' a+sigs]~) eyre-id) st]
  ::
  ::  -- NUT-04: mint --
  ::
  ++  post-mint-quote
    |=  [eyre-id=@ta method=@t body=(unit octs)]
    ^-  (quip card state-15)
    ?.  |(=('self' method) =('bolt11' method))
      [(give-err eyre-id 400 'unsupported-method') st]
    ?:  &(=('self' method) !self-method-enabled.st)
      [(give-err eyre-id 400 'self-method-disabled') st]
    =/  parsed  (parse-object-body body)
    ?:  ?=(%| -.parsed)  [(give-err eyre-id 400 p.parsed) st]
    ?>  ?=([%o *] p.parsed)
    =/  amount=@ud  (get-num p.p.parsed 'amount')
    ?:  =(0 amount)  [(give-err eyre-id 400 'invalid-amount') st]
    ?:  (gth amount mint-max)  [(give-err eyre-id 400 'amount-too-large') st]
    ?:  =('self' method)
      ::  self: paid on creation
      =/  mq=mint-quote  [gen-quote-id amount 'sat' 'self-mint' '' %paid quote-expiry now.bowl]
      =.  mint-quotes.st  (~(put by mint-quotes.st) quote-id.mq mq)
      [(give-json (mint-quote-json mq) eyre-id) st]
    ?:  ?=(%none -.ln-config.st)
      [(give-err eyre-id 400 'no-lightning-backend-configured') st]
    =/  mq=mint-quote  [gen-quote-id amount 'sat' '' '' %unpaid quote-expiry now.bowl]
    =.  mint-quotes.st  (~(put by mint-quotes.st) quote-id.mq mq)
    =/  wid  new-wire
    =.  pending.st  (~(put by pending.st) wid [%mint-quote-create eyre-id quote-id.mq amount])
    [~[(ln-card wid (ln-create-invoice amount 'ecash mint deposit'))] st]
  ::
  ::  get-mint-quote: answers at once. An unpaid bolt11 quote is checked on
  ::  Lightning behind the answer, so a later poll sees it paid: holding
  ::  the poll open until Lightning answered made mobile wallets time out
  ::  and stop polling.
  ++  get-mint-quote
    |=  [eyre-id=@ta method=@t qid=@t]
    ^-  (quip card state-15)
    ?.  |(=('self' method) =('bolt11' method))
      [(give-err eyre-id 400 'unsupported-method') st]
    =/  mq  (~(get by mint-quotes.st) qid)
    ?~  mq  [(give-err eyre-id 404 'quote-not-found') st]
    =/  resp  (give-json (mint-quote-json u.mq) eyre-id)
    ?.  ?&  =(%unpaid state.u.mq)
            !=('' checking-id.u.mq)
            !?=(%none -.ln-config.st)
        ==
      [resp st]
    =/  wid  new-wire
    =.  pending.st  (~(put by pending.st) wid [%mint-quote-check '' qid])
    [[(ln-card wid (ln-check-invoice checking-id.u.mq)) resp] st]
  ::
  ++  post-mint-v1
    |=  [eyre-id=@ta method=@t body=(unit octs)]
    ^-  (quip card state-15)
    ?.  |(=('self' method) =('bolt11' method))
      [(give-err eyre-id 400 'unsupported-method') st]
    ?:  &(=('self' method) !self-method-enabled.st)
      [(give-err eyre-id 400 'self-method-disabled') st]
    =/  parsed  (parse-object-body body)
    ?:  ?=(%| -.parsed)  [(give-err eyre-id 400 p.parsed) st]
    ?>  ?=([%o *] p.parsed)
    =/  jon  p.p.parsed
    =/  qid=@t  (get-str jon 'quote')
    ?:  =('' qid)  [(give-err eyre-id 400 'missing-quote') st]
    =/  mq  (~(get by mint-quotes.st) qid)
    ?~  mq  [(give-err eyre-id 404 'quote-not-found') st]
    ::  a self quote was paid by nobody: it mints only while self is on,
    ::  whatever method the URL names
    ?:  &(=('self-mint' request.u.mq) !self-method-enabled.st)
      [(give-err eyre-id 400 'self-method-disabled') st]
    ::  a %paid quote's sats are in the mint, so it mints even past its TTL
    ?.  =(%paid state.u.mq)  [(give-err eyre-id 400 'quote-not-paid') st]
    ?.  (has-key jon 'outputs')  [(give-err eyre-id 400 'missing-outputs') st]
    =/  outputs  (get-array jon 'outputs')
    ?:  (gth (lent outputs) max-batch)  [(give-err eyre-id 400 'batch-too-large') st]
    ?.  =((amount-total outputs) amount.u.mq)
      [(give-err eyre-id 400 'output-amount-mismatch') st]
    =/  bad  (output-error outputs keysets.st active-keyset.st restore.st |)
    ?^  bad  [(give-err eyre-id 400 u.bad) st]
    =/  sigs  (sign-outputs outputs keysets.st active-keyset.st ent)
    ?.  (all-signed sigs)  [(give-err eyre-id 500 'signing-failed') st]
    =.  restore.st            (~(uni by restore.st) (restore-entries outputs sigs))
    =.  mint-quotes.st        (~(put by mint-quotes.st) qid u.mq(state %issued))
    =.  counter.st            (add counter.st (lent sigs))
    =.  total-issued-sats.st  (add total-issued-sats.st amount.u.mq)
    [(give-json (pairs:enjs:format ['signatures' a+sigs]~) eyre-id) st]
  ::
  ::  -- NUT-05: melt --
  ::
  ++  post-melt-quote
    |=  [eyre-id=@ta method=@t body=(unit octs)]
    ^-  (quip card state-15)
    ?.  |(=('self' method) =('bolt11' method))
      [(give-err eyre-id 400 'unsupported-method') st]
    ?:  &(=('self' method) !self-method-enabled.st)
      [(give-err eyre-id 400 'self-method-disabled') st]
    =/  parsed  (parse-object-body body)
    ?:  ?=(%| -.parsed)  [(give-err eyre-id 400 p.parsed) st]
    ?>  ?=([%o *] p.parsed)
    =/  jon  p.p.parsed
    ?:  =('self' method)
      =/  amount=@ud  (get-num jon 'amount')
      ?:  =(0 amount)  [(give-err eyre-id 400 'missing-amount') st]
      ::  a self quote names no invoice, and never keeps the caller's
      ::  `request`: that could be a real invoice the quote isn't bound to
      =/  mq=melt-quote
        [gen-quote-id amount 0 'sat' 'self-melt' %unpaid '' '' quote-expiry now.bowl]
      =.  melt-quotes.st  (~(put by melt-quotes.st) quote-id.mq mq)
      [(give-json (melt-quote-json mq ~) eyre-id) st]
    ?:  ?=(%none -.ln-config.st)
      [(give-err eyre-id 400 'no-lightning-backend-configured') st]
    =/  bolt11=@t  (get-str jon 'request')
    ?:  =('' bolt11)  [(give-err eyre-id 400 'missing-request-bolt11') st]
    ?.  (valid-bolt11 bolt11)  [(give-err eyre-id 400 'invalid-request') st]
    =/  wid  new-wire
    =.  pending.st  (~(put by pending.st) wid [%melt-quote-create eyre-id gen-quote-id bolt11])
    [~[(ln-card wid (ln-decode-invoice bolt11))] st]
  ::
  ::  get-melt-quote: answers at once; a %pending bolt11 melt is checked on
  ::  Lightning behind the answer (see get-mint-quote)
  ++  get-melt-quote
    |=  [eyre-id=@ta method=@t qid=@t]
    ^-  (quip card state-15)
    ?.  |(=('self' method) =('bolt11' method))
      [(give-err eyre-id 400 'unsupported-method') st]
    =/  mq  (~(get by melt-quotes.st) qid)
    ?~  mq  [(give-err eyre-id 404 'quote-not-found') st]
    =/  resp  (give-json (melt-quote-json u.mq (stored-change qid)) eyre-id)
    ?.  ?&  =(%pending state.u.mq)
            !=('' payment-hash.u.mq)
            !?=(%none -.ln-config.st)
        ==
      [resp st]
    =/  wid  new-wire
    =.  pending.st  (~(put by pending.st) wid [%melt-check '' qid])
    [[(ln-card-at wid (attempt-of qid) (ln-check-payment payment-hash.u.mq)) resp] st]
  ::
  ++  post-melt-v1
    |=  [eyre-id=@ta method=@t body=(unit octs)]
    ^-  (quip card state-15)
    ?.  |(=('self' method) =('bolt11' method))
      [(give-err eyre-id 400 'unsupported-method') st]
    ?:  &(=('self' method) !self-method-enabled.st)
      [(give-err eyre-id 400 'self-method-disabled') st]
    =/  parsed  (parse-object-body body)
    ?:  ?=(%| -.parsed)  [(give-err eyre-id 400 p.parsed) st]
    ?>  ?=([%o *] p.parsed)
    =/  jon  p.p.parsed
    =/  qid=@t  (get-str jon 'quote')
    ?:  =('' qid)  [(give-err eyre-id 400 'missing-quote') st]
    =/  mq  (~(get by melt-quotes.st) qid)
    ?~  mq  [(give-err eyre-id 404 'quote-not-found') st]
    ::  a quote settles only by the method that made it: a self quote names
    ::  no invoice to pay, and a bolt11 quote must not be marked paid for free
    ?.  =(method (melt-quote-method u.mq))  [(give-err eyre-id 400 'method-mismatch') st]
    ?:  (gth now.bowl expiry.u.mq)  [(give-err eyre-id 400 'quote-expired') st]
    ::  NUT-05 single use: an in-flight (%pending) or settled (%paid) quote is
    ::  refused; %unpaid and %failed (a pay that definitely failed) may go
    ?:  =(%pending state.u.mq)  [(give-err eyre-id 400 'quote-pending') st]
    ?:  =(%paid state.u.mq)  [(give-err eyre-id 400 'quote-already-paid') st]
    ?.  (has-key jon 'inputs')  [(give-err eyre-id 400 'missing-inputs') st]
    =/  inputs=(list json)  (get-array jon 'inputs')
    ::  NUT-08: optional blank outputs for change
    =/  blanks=(list json)  (get-array jon 'outputs')
    ?:  |((gth (lent inputs) max-batch) (gth (lent blanks) max-batch))
      [(give-err eyre-id 400 'batch-too-large') st]
    ::  inputs must cover amount + fee reserve after the input fee, else a
    ::  melt would take change it never paid for; checked on the claimed
    ::  amounts before any EC work
    =/  fee  (compute-fee inputs keysets.st active-keyset.st)
    =/  claimed  (amount-total inputs)
    =/  need  (add amount.u.mq fee-reserve.u.mq)
    ?:  (gth fee claimed)  [(give-err eyre-id 400 'fee-exceeds-inputs') st]
    ?:  (lth (sub claimed fee) need)  [(give-err eyre-id 400 'insufficient-inputs') st]
    =/  bad  (output-error blanks keysets.st active-keyset.st restore.st &)
    ?^  bad  [(give-err eyre-id 400 u.bad) st]
    =/  vres  (verify-proofs inputs spent.st spent-ys.st keysets.st active-keyset.st now.bowl)
    ?:  ?=(%| -.vres)  [(give-err eyre-id 400 p.vres) st]
    =/  input-total=@ud  total.p.vres
    ::  what the inputs paid beyond amount + reserve: returned as change
    =/  excess=@ud  (sub (sub input-total fee) need)
    ::  exactly what this melt spends, so a failed pay un-spends precisely
    =/  added-secrets  (~(dif in spent.p.vres) spent.st)
    =/  added-ys  (~(dif in spent-ys.p.vres) spent-ys.st)
    =.  spent.st  spent.p.vres
    =.  spent-ys.st  spent-ys.p.vres
    =.  total-redeemed-sats.st  (add total-redeemed-sats.st input-total)
    ?:  =('self' method)
      ::  self: no payment; a stand-in preimage, and change at once
      =/  paid  u.mq(state %paid, payment-preimage (pad-hex (shax (add eny.bowl input-total)) 64))
      =/  change  (sign-change-outputs blanks excess keysets.st active-keyset.st ent)
      =.  melt-quotes.st  (~(put by melt-quotes.st) qid paid)
      =.  restore.st  (~(uni by restore.st) (restore-entries blanks change))
      =?  melt-change.st  !=(~ change)  (~(put by melt-change.st) qid change)
      [(give-json (melt-quote-json paid change) eyre-id) st]
    ::  bolt11: the inputs are spent and the quote goes %pending before the
    ::  pay goes out, so a re-submit is refused. melt-inflight keeps what a
    ::  settle or a rollback needs, durably across restarts. The pay's own
    ::  answer is only a dispatch receipt (see ln-melt-paid).
    =.  melt-quotes.st  (~(put by melt-quotes.st) qid u.mq(state %pending))
    =.  melt-inflight.st
      (~(put by melt-inflight.st) qid [added-secrets added-ys input-total blanks excess now.bowl])
    =/  wid  new-wire
    =.  pending.st
      (~(put by pending.st) wid [%melt-pay eyre-id qid blanks added-secrets added-ys input-total])
    [~[(ln-card-at wid `now.bowl (ln-pay-invoice request.u.mq fee-reserve.u.mq))] st]
  ::
  ::  settle-melt: a pay Lightning showed settled. Lock the quote %paid,
  ::  sign NUT-08 change (the unused reserve plus the excess) onto its blank
  ::  outputs, and drop the inflight record. Callers settle only a %pending
  ::  quote, so a late or repeated answer can't settle twice.
  ++  settle-melt
    |=  [qid=@t mq=melt-quote jon=(unit json) preimage=@t]
    ^-  [change=(list json) st=state-15]
    =/  inflight  (~(get by melt-inflight.st) qid)
    ::  fail closed: an unreadable routing fee counts as the whole reserve
    =/  fee=@ud  ?~(jon fee-reserve.mq (routing-fee-sats u.jon fee-reserve.mq))
    =/  blanks=(list json)  ?~(inflight ~ change.u.inflight)
    =/  over=@ud  (melt-change fee-reserve.mq fee ?~(inflight 0 excess.u.inflight))
    =/  change  (sign-change-outputs blanks over keysets.st active-keyset.st ent)
    =.  restore.st  (~(uni by restore.st) (restore-entries blanks change))
    =?  melt-change.st  !=(~ change)  (~(put by melt-change.st) qid change)
    =.  melt-quotes.st  (~(put by melt-quotes.st) qid mq(state %paid, payment-preimage preimage))
    =.  melt-inflight.st  (~(del by melt-inflight.st) qid)
    [change st]
  ::
  ::  rollback-melt: un-spend exactly what a melt spent, take it off the
  ::  redeemed total, and make the quote %failed (retryable). Only for a pay
  ::  known to have failed, or an operator's forced abort.
  ++  rollback-melt
    |=  [qid=@t mq=melt-quote secrets=(set @t) ys=(set @t) input-total=@ud]
    ^-  state-15
    =.  spent.st  (~(dif in spent.st) secrets)
    =.  spent-ys.st  (~(dif in spent-ys.st) ys)
    =.  total-redeemed-sats.st
      (sub total-redeemed-sats.st (min input-total total-redeemed-sats.st))
    =.  melt-quotes.st  (~(put by melt-quotes.st) qid mq(state %failed))
    =.  melt-inflight.st  (~(del by melt-inflight.st) qid)
    st
  ::
  ::  -- NUT-06: mint info --
  ::
  ++  get-info
    |=  eyre-id=@ta
    ^-  (list card)
    =/  top=@ud  mint-max
    ::  a mint quote is capped at what one request can mint; a melt is only
    ::  bounded by the inputs a wallet can send, so it names no maximum
    =/  method-json
      |=  [m=@t cap=?]
      ^-  json
      %-  pairs:enjs:format
      %+  weld
        ^-  (list [@t json])
        ~[['method' s+m] ['unit' s+'sat'] ['min_amount' (numb:enjs:format 1)]]
      ?.(cap ~ ['max_amount' (numb:enjs:format top)]~)
    ::  only methods that work right now
    =/  live=(list @t)
      %+  weld
        ?.(self-method-enabled.st ~ ~['self'])
      ?:(?=(%none -.ln-config.st) ~ ~['bolt11'])
    =/  ways
      |=  cap=?
      =/  ms=(list json)  (turn live |=(m=@t (method-json m cap)))
      (pairs:enjs:format ~[['methods' a+ms] ['disabled' b+=(~ ms)]])
    =/  yes  (pairs:enjs:format ['supported' b+&]~)
    %-  give-json  :_  eyre-id
    %-  pairs:enjs:format
    :~  ['name' s+mint-name.st]
        ['version' s+'ecash/1.0.0']
        ['description' s+mint-description.st]
        :-  'nuts'
        %-  pairs:enjs:format
        :~  ['3' yes]
            ['4' (ways &)]
            ['5' (ways |)]
            ['6' yes]
            ['7' yes]
            ['8' yes]
            ['9' yes]
            ['10' yes]
            ['11' yes]
            ['12' yes]
        ==
    ==
  ::
  ::  -- NUT-09: restore --
  ::
  ::  For each blinded message a wallet re-derived from its seed, the
  ::  signature the mint issued for it, if any. Unknown B_ are left out; the
  ::  wallet then asks /v1/checkstate which recovered tokens are unspent.
  ++  post-restore
    |=  [eyre-id=@ta body=(unit octs)]
    ^-  (quip card state-15)
    =/  parsed  (parse-object-body body)
    ?:  ?=(%| -.parsed)  [(give-err eyre-id 400 p.parsed) st]
    ?>  ?=([%o *] p.parsed)
    =/  outs-j  (~(get by p.p.parsed) 'outputs')
    ?.  ?=([~ %a *] outs-j)  [(give-err eyre-id 400 'missing-outputs') st]
    =/  outs=(list json)  p.u.outs-j
    ?:  (gth (lent outs) max-batch)  [(give-err eyre-id 400 'batch-too-large') st]
    =|  os=(list json)
    =|  ss=(list json)
    |-  ^-  (quip card state-15)
    ?~  outs
      :_  st
      (give-json (pairs:enjs:format ~[['outputs' a+(flop os)] ['signatures' a+(flop ss)]]) eyre-id)
    =/  msg=json  i.outs
    ?.  ?=([%o *] msg)  $(outs t.outs)
    =/  b-hex  (canon-hex (get-str p.msg 'B_'))
    =/  found  (~(get by restore.st) b-hex)
    ?~  found  $(outs t.outs)
    =/  rs  u.found
    =/  out-j=json
      (pairs:enjs:format ~[['amount' (numb:enjs:format amount.rs)] ['B_' s+b-hex] ['id' s+id.rs]])
    =/  sig-j=json
      %-  pairs:enjs:format
      :~  ['amount' (numb:enjs:format amount.rs)]
          ['id' s+id.rs]
          ['C_' s+c-hex.rs]
          ['dleq' (pairs:enjs:format ~[['e' s+e.rs] ['s' s+s.rs]])]
      ==
    $(outs t.outs, os [out-j os], ss [sig-j ss])
  ::
  ::  -- NUT-07: token state --
  ::
  ::  A Y spent by a melt whose pay is still in flight is PENDING: its
  ::  proofs come back if the pay fails, so a wallet must keep them.
  ++  post-checkstate
    |=  [eyre-id=@ta body=(unit octs)]
    ^-  (quip card state-15)
    =/  parsed  (parse-object-body body)
    ?:  ?=(%| -.parsed)  [(give-err eyre-id 400 p.parsed) st]
    ?>  ?=([%o *] p.parsed)
    ?.  (has-key p.p.parsed 'Ys')  [(give-err eyre-id 400 'missing-Ys') st]
    =/  ys  (get-array p.p.parsed 'Ys')
    ?:  (gth (lent ys) max-batch)  [(give-err eyre-id 400 'batch-too-large') st]
    =/  in-flight=(set @t)
      %-  ~(rep by melt-inflight.st)
      |=([[@t e=melt-inflight-entry] acc=(set @t)] (~(uni in acc) ys.e))
    =/  states=(list json)
      %+  turn  ys
      |=  y=json
      ^-  json
      =/  y-hex=@t  ?.(?=([%s *] y) '' (canon-hex p.y))
      =/  state=@t
        ?:  (~(has in in-flight) y-hex)  'PENDING'
        ?:  (~(has in spent-ys.st) y-hex)  'SPENT'
        'UNSPENT'
      (pairs:enjs:format ~[['Y' s+y-hex] ['state' s+state] ['witness' ~]])
    [(give-json (pairs:enjs:format ['states' a+states]~) eyre-id) st]
  ::
  ::  -- admin: read --
  ::
  ++  admin-overview
    |=  eyre-id=@ta
    ^-  (list card)
    =/  mq  (turn ~(val by mint-quotes.st) |=(q=mint-quote state.q))
    =/  lq  (turn ~(val by melt-quotes.st) |=(q=melt-quote state.q))
    =/  count
      |=  [l=(list quote-state) s=(list quote-state)]
      ^-  json
      (numb:enjs:format (lent (skim l |=(q=quote-state !=(~ (find ~[q] s))))))
    =/  ln  ln-summary
    %-  give-json  :_  eyre-id
    %-  pairs:enjs:format
    :~  ['active_keyset' s+active-keyset.st]
        ['tokens_issued' (numb:enjs:format counter.st)]
        ['spent_count' (numb:enjs:format ~(wyt in spent.st))]
        ['spent_ys_count' (numb:enjs:format ~(wyt in spent-ys.st))]
        ['keyset_count' (numb:enjs:format ~(wyt by keysets.st))]
        ['pending_requests' (numb:enjs:format ~(wyt by pending.st))]
        ['total_issued_sats' (numb:enjs:format total-issued-sats.st)]
        ['total_redeemed_sats' (numb:enjs:format total-redeemed-sats.st)]
        ['mint_name' s+mint-name.st]
        ['mint_description' s+mint-description.st]
        :-  'mint_quotes'
        %-  pairs:enjs:format
        :~  ['unpaid' (count mq ~[%unpaid %failed])]
            ['paid' (count mq ~[%paid])]
            ['issued' (count mq ~[%issued])]
            ['pending' (count mq ~[%pending])]
        ==
        :-  'melt_quotes'
        %-  pairs:enjs:format
        :~  ['unpaid' (count lq ~[%unpaid %failed])]
            ['paid' (count lq ~[%paid])]
            ['pending' (count lq ~[%pending])]
        ==
        :-  'ln_backend'
        (pairs:enjs:format ~[['type' s+type.ln] ['url' s+url.ln] ['configured' b+configured.ln]])
    ==
  ::
  ++  admin-keysets
    |=  eyre-id=@ta
    ^-  (list card)
    =/  ks-list=(list json)
      %+  turn  ~(val by keysets.st)
      |=  ks=keyset
      ^-  json
      %-  pairs:enjs:format
      :~  ['id' s+ks-id.ks]
          ['unit' s+unt.ks]
          ['active' b+active.ks]
          ['input_fee_ppk' (numb:enjs:format input-fee-ppk.ks)]
          ['key_count' (numb:enjs:format ~(wyt by keys.ks))]
          ['created' (numb:enjs:format (da-to-unix created.ks))]
          :-  'denominations'
          a+(turn (sort ~(tap in ~(key by keys.ks)) lth) numb:enjs:format)
      ==
    (give-json (pairs:enjs:format ['keysets' a+ks-list]~) eyre-id)
  ::
  ++  admin-keyset-detail
    |=  [eyre-id=@ta kid=@t]
    ^-  (list card)
    =/  ks  (~(get by keysets.st) kid)
    ?~  ks  (give-err eyre-id 404 'keyset-not-found')
    =/  jon  (keyset-json u.ks &)
    ?>  ?=([%o *] jon)
    (give-json o+(~(put by p.jon) 'created' (numb:enjs:format (da-to-unix created.u.ks))) eyre-id)
  ::
  ++  admin-quotes
    |=  eyre-id=@ta
    ^-  (list card)
    =/  mq-list=(list json)
      %+  turn  (sort ~(val by mint-quotes.st) |=([a=mint-quote b=mint-quote] (gth created.a created.b)))
      |=  q=mint-quote
      ^-  json
      %-  pairs:enjs:format
      :~  ['quote_id' s+quote-id.q]
          ['method' s+(mint-quote-method q)]
          ['amount' (numb:enjs:format amount.q)]
          ['unit' s+unt.q]
          ['request' s+request.q]
          ['checking_id' s+checking-id.q]
          ['state' s+(quote-state-text state.q)]
          ['expiry' (numb:enjs:format (da-to-unix expiry.q))]
          ['created' (numb:enjs:format (da-to-unix created.q))]
          ['expired' b+(gth now.bowl expiry.q)]
      ==
    =/  lq-list=(list json)
      %+  turn  (sort ~(val by melt-quotes.st) |=([a=melt-quote b=melt-quote] (gth created.a created.b)))
      |=  q=melt-quote
      ^-  json
      %-  pairs:enjs:format
      :~  ['quote_id' s+quote-id.q]
          ['method' s+(melt-quote-method q)]
          ['amount' (numb:enjs:format amount.q)]
          ['fee_reserve' (numb:enjs:format fee-reserve.q)]
          ['unit' s+unt.q]
          ['request' s+request.q]
          ['state' s+(quote-state-text state.q)]
          ['payment_preimage' s+payment-preimage.q]
          ['payment_hash' s+payment-hash.q]
          ['expiry' (numb:enjs:format (da-to-unix expiry.q))]
          ['created' (numb:enjs:format (da-to-unix created.q))]
          ['expired' b+(gth now.bowl expiry.q)]
      ==
    (give-json (pairs:enjs:format ~[['mint_quotes' a+mq-list] ['melt_quotes' a+lq-list]]) eyre-id)
  ::
  ++  admin-spent
    |=  eyre-id=@ta
    ^-  (list card)
    %-  give-json  :_  eyre-id
    %-  pairs:enjs:format
    :~  ['spent_count' (numb:enjs:format ~(wyt in spent.st))]
        ['spent_ys_count' (numb:enjs:format ~(wyt in spent-ys.st))]
    ==
  ::
  ++  admin-spent-check
    |=  [eyre-id=@ta body=(unit octs)]
    ^-  (list card)
    =/  parsed  (parse-object-body body)
    ?:  ?=(%| -.parsed)  (give-err eyre-id 400 p.parsed)
    ?>  ?=([%o *] p.parsed)
    =/  jon  p.p.parsed
    ?:  (has-key jon 'secret')
      =/  secret=@t  (get-str jon 'secret')
      (give-json (pairs:enjs:format ~[['secret' s+secret] ['spent' b+(~(has in spent.st) secret)]]) eyre-id)
    ?.  (has-key jon 'Y')  (give-err eyre-id 400 'missing-secret-or-Y')
    =/  y-hex=@t  (canon-hex (get-str jon 'Y'))
    (give-json (pairs:enjs:format ~[['Y' s+y-hex] ['spent' b+(~(has in spent-ys.st) y-hex)]]) eyre-id)
  ::
  ++  admin-lightning
    |=  eyre-id=@ta
    ^-  (list card)
    =/  ln  ln-summary
    =/  key-set=?
      ?-  -.ln-config.st
        %lnbits  !=('' api-key.ln-config.st)
        %lnd     !=('' macaroon.ln-config.st)
        %none    %.n
      ==
    %-  give-json  :_  eyre-id
    %-  pairs:enjs:format
    :~  ['type' s+type.ln]
        ['configured' b+configured.ln]
        ['url' s+url.ln]
        ['api_key_set' b+key-set]
    ==
  ::
  ++  admin-get-settings
    |=  eyre-id=@ta
    ^-  (list card)
    %-  give-json  :_  eyre-id
    %-  pairs:enjs:format
    :~  ['fee_reserve_pct' (numb:enjs:format fee-reserve-pct.st)]
        ['fee_reserve_min' (numb:enjs:format fee-reserve-min.st)]
        ['quote_ttl_secs' (numb:enjs:format quote-ttl-secs.st)]
        ['self_method_enabled' b+self-method-enabled.st]
    ==
  ::
  ::  -- admin: keysets --
  ::
  ++  admin-keyset-generate
    |=  eyre-id=@ta
    ^-  (quip card state-15)
    =/  ks  (fresh-keyset 'sat' 0 |)
    =.  keysets.st  (~(put by keysets.st) ks-id.ks ks)
    :_  st
    %-  give-json  :_  eyre-id
    %-  pairs:enjs:format
    :~  ['id' s+ks-id.ks]
        ['active' b+%.n]
        ['key_count' (numb:enjs:format ~(wyt by keys.ks))]
    ==
  ::
  ::  admin-keyset-id: the keyset named by the body's `id`, or an error
  ++  admin-keyset-id
    |=  body=(unit octs)
    ^-  (each [kid=@t ks=keyset jon=(map @t json)] [@ud @t])
    =/  parsed  (parse-object-body body)
    ?:  ?=(%| -.parsed)  [%| 400 p.parsed]
    ?>  ?=([%o *] p.parsed)
    =/  kid=@t  (get-str p.p.parsed 'id')
    ?:  =('' kid)  [%| 400 'missing-id']
    =/  ks  (~(get by keysets.st) kid)
    ?~  ks  [%| 404 'keyset-not-found']
    [%& kid u.ks p.p.parsed]
  ::
  ++  admin-keyset-activate
    |=  [eyre-id=@ta body=(unit octs)]
    ^-  (quip card state-15)
    =/  got  (admin-keyset-id body)
    ?:  ?=(%| -.got)  [(give-err eyre-id p.got) st]
    =/  old  (~(get by keysets.st) active-keyset.st)
    =?  keysets.st  ?=(^ old)  (~(put by keysets.st) active-keyset.st u.old(active %.n))
    =.  keysets.st  (~(put by keysets.st) kid.p.got ks.p.got(active %.y))
    =.  active-keyset.st  kid.p.got
    [(give-json (pairs:enjs:format ~[['id' s+kid.p.got] ['active' b+&]]) eyre-id) st]
  ::
  ++  admin-keyset-deactivate
    |=  [eyre-id=@ta body=(unit octs)]
    ^-  (quip card state-15)
    =/  got  (admin-keyset-id body)
    ?:  ?=(%| -.got)  [(give-err eyre-id p.got) st]
    ?:  =(kid.p.got active-keyset.st)  [(give-err eyre-id 400 'cannot-deactivate-active') st]
    =.  keysets.st  (~(put by keysets.st) kid.p.got ks.p.got(active %.n))
    [(give-json (pairs:enjs:format ~[['id' s+kid.p.got] ['active' b+|]]) eyre-id) st]
  ::
  ::  admin-keyset-set-fee: a fee change ROTATES to a fresh keyset (new keys,
  ::  new id) and keeps the old id as an INACTIVE alias, so tokens that carry
  ::  it still verify. The keys are fresh, not copied: BDHKE doesn't bind the
  ::  keyset id into a signature, so a copied-key twin would let a token be
  ::  relabelled to the lower-fee id to dodge the input fee.
  ++  admin-keyset-set-fee
    |=  [eyre-id=@ta body=(unit octs)]
    ^-  (quip card state-15)
    =/  got  (admin-keyset-id body)
    ?:  ?=(%| -.got)  [(give-err eyre-id p.got) st]
    ?.  (has-key jon.p.got 'input_fee_ppk')
      [(give-err eyre-id 400 'missing-input_fee_ppk') st]
    =/  fee  (get-ud jon.p.got 'input_fee_ppk')
    ?~  fee  [(give-err eyre-id 400 'invalid-input_fee_ppk') st]
    ?:  (gth u.fee max-input-fee-ppk)  [(give-err eyre-id 400 'input_fee_ppk-too-large') st]
    =/  old  ks.p.got
    =/  reply
      |=  new-id=@t
      %-  give-json  :_  eyre-id
      %-  pairs:enjs:format
      :~  ['old_id' s+kid.p.got]
          ['new_id' s+new-id]
          ['input_fee_ppk' (numb:enjs:format u.fee)]
      ==
    ?:  =(u.fee input-fee-ppk.old)  [(reply kid.p.got) st]
    =/  was-active=?  =(kid.p.got active-keyset.st)
    =/  new  (fresh-keyset unt.old u.fee was-active)
    ?:  (~(has by keysets.st) ks-id.new)  [(give-err eyre-id 409 'keyset-id-collision') st]
    =.  keysets.st  (~(put by keysets.st) kid.p.got old(active %.n))
    =.  keysets.st  (~(put by keysets.st) ks-id.new new)
    =?  active-keyset.st  was-active  ks-id.new
    [(reply ks-id.new) st]
  ::  max admin-settable per-proof input fee (ppk): bounds the fee sums
  ++  max-input-fee-ppk  ^-  @ud  100.000
  ::
  ::  -- admin: Lightning --
  ::
  ++  admin-ln-configure
    |=  [eyre-id=@ta body=(unit octs)]
    ^-  (quip card state-15)
    =/  parsed  (parse-object-body body)
    ?:  ?=(%| -.parsed)  [(give-err eyre-id 400 p.parsed) st]
    ?>  ?=([%o *] p.parsed)
    =/  jon  p.p.parsed
    =/  ln-type=@t  (get-str jon 'type')
    ?:  =('' ln-type)  [(give-err eyre-id 400 'missing-type') st]
    ?:  =('none' ln-type)
      =.  ln-config.st  [%none ~]
      [(give-json (pairs:enjs:format ~[['type' s+'none'] ['configured' b+|]]) eyre-id) st]
    =/  url=@t  (get-str jon 'url')
    ?:  =('' url)  [(give-err eyre-id 400 'missing-url') st]
    =/  reply  (give-json (pairs:enjs:format ~[['type' s+ln-type] ['url' s+url] ['configured' b+&]]) eyre-id)
    ?:  =('lnbits' ln-type)
      =/  key=@t  (get-str jon 'api_key')
      ?:  =('' key)  [(give-err eyre-id 400 'missing-api_key') st]
      [reply st(ln-config [%lnbits url key])]
    ?:  =('lnd' ln-type)
      =/  mac=@t  (get-str jon 'macaroon')
      ?:  =('' mac)  [(give-err eyre-id 400 'missing-macaroon') st]
      [reply st(ln-config [%lnd url mac])]
    [(give-err eyre-id 400 'unknown-type') st]
  ::
  ::  admin-ln-test: ask the backend for its wallet (LNbits) or node info
  ::  (LND); ln-tested reports what came back
  ++  admin-ln-test
    |=  eyre-id=@ta
    ^-  (quip card state-15)
    ?:  ?=(%none -.ln-config.st)  [(give-err eyre-id 400 'no-ln-backend') st]
    =/  wid  new-wire
    =.  pending.st  (~(put by pending.st) wid [%ln-test eyre-id ~])
    [~[(ln-card wid ln-wallet-info)] st]
  ::
  ::  -- admin: quotes --
  ::
  ++  admin-quote-delete
    |=  [eyre-id=@ta body=(unit octs)]
    ^-  (quip card state-15)
    =/  parsed  (parse-object-body body)
    ?:  ?=(%| -.parsed)  [(give-err eyre-id 400 p.parsed) st]
    ?>  ?=([%o *] p.parsed)
    =/  qid=@t    (get-str p.p.parsed 'quote_id')
    =/  qtype=@t  (get-str p.p.parsed 'type')
    ?:  =('' qid)    [(give-err eyre-id 400 'missing-quote_id') st]
    ?:  =('' qtype)  [(give-err eyre-id 400 'missing-type') st]
    =/  reply  (give-json (pairs:enjs:format ~[['deleted' b+&] ['quote_id' s+qid] ['type' s+qtype]]) eyre-id)
    ?:  =('mint' qtype)
      =/  q  (~(get by mint-quotes.st) qid)
      ?~  q  [(give-err eyre-id 404 'quote-not-found') st]
      ?:  =(%issued state.u.q)  [(give-err eyre-id 400 'cannot-delete-issued') st]
      ::  a %paid mint quote is a deposit not yet minted
      ?:  =(%paid state.u.q)  [(give-err eyre-id 400 'cannot-delete-paid-mint') st]
      [reply st(mint-quotes (~(del by mint-quotes.st) qid))]
    ?:  =('melt' qtype)
      =/  q  (~(get by melt-quotes.st) qid)
      ?~  q  [(give-err eyre-id 404 'quote-not-found') st]
      ?:  =(%paid state.u.q)  [(give-err eyre-id 400 'cannot-delete-paid-melt') st]
      ::  a %pending melt has spent inputs and a live pay: /melt/abort
      ?:  |(=(%pending state.u.q) (~(has by melt-inflight.st) qid))
        [(give-err eyre-id 400 'cannot-delete-pending-melt') st]
      [reply st(melt-quotes (~(del by melt-quotes.st) qid))]
    [(give-err eyre-id 400 'invalid-type') st]
  ::
  ::  admin-quote-revoke: write off a mint quote. The deliberate override of
  ::  delete, which refuses %paid/%issued: it deletes the quote, and for an
  ::  %issued one takes its amount off total-issued-sats, declaring those
  ::  tokens never to be redeemed. A %paid quote is a deposit not yet minted.
  ++  admin-quote-revoke
    |=  [eyre-id=@ta body=(unit octs)]
    ^-  (quip card state-15)
    =/  parsed  (parse-object-body body)
    ?:  ?=(%| -.parsed)  [(give-err eyre-id 400 p.parsed) st]
    ?>  ?=([%o *] p.parsed)
    =/  qid=@t  (get-str p.p.parsed 'quote_id')
    ?:  =('' qid)  [(give-err eyre-id 400 'missing-quote_id') st]
    =/  q  (~(get by mint-quotes.st) qid)
    ?~  q  [(give-err eyre-id 404 'quote-not-found') st]
    =/  dec=@ud  ?:(=(%issued state.u.q) amount.u.q 0)
    =.  total-issued-sats.st  (sub total-issued-sats.st (min dec total-issued-sats.st))
    =.  mint-quotes.st  (~(del by mint-quotes.st) qid)
    :_  st
    %-  give-json  :_  eyre-id
    %-  pairs:enjs:format
    :~  ['revoked' b+&]
        ['quote_id' s+qid]
        ['type' s+'mint']
        ['was_state' s+(quote-state-text state.u.q)]
        ['issued_decremented' (numb:enjs:format dec)]
    ==
  ::
  ::  admin-melt-abort: the operator's backstop for a stuck %pending bolt11
  ::  melt. It never rolls back blind: with a backend to ask, it checks the
  ::  payment first and ln-melt-abort decides (settled: settle; FAILED or
  ::  forced: roll back; else leave it). Without one it can only take the
  ::  operator's word, so it rolls back only when forced: a backend removed
  ::  after the pay went out says nothing about whether it settled.
  ::
  ::    Body {quote_id, force?, secrets?, ys?}. secrets/ys name what to
  ::    un-spend for a melt stuck from before inflight records existed.
  ++  admin-melt-abort
    |=  [eyre-id=@ta body=(unit octs)]
    ^-  (quip card state-15)
    =/  parsed  (parse-object-body body)
    ?:  ?=(%| -.parsed)  [(give-err eyre-id 400 p.parsed) st]
    ?>  ?=([%o *] p.parsed)
    =/  jon  p.p.parsed
    =/  qid=@t  (get-str jon 'quote_id')
    ?:  =('' qid)  [(give-err eyre-id 400 'missing-quote_id') st]
    =/  mq  (~(get by melt-quotes.st) qid)
    ?~  mq  [(give-err eyre-id 404 'quote-not-found') st]
    ?.  =(%pending state.u.mq)  [(give-err eyre-id 400 'quote-not-pending') st]
    =/  force=?  (get-bool jon 'force')
    =/  strs
      |=  k=@t
      ^-  (set @t)
      (silt (murn (get-array jon k) |=(j=json ?.(?=([%s *] j) ~ `p.j))))
    =/  inflight  (~(get by melt-inflight.st) qid)
    ::  what a rollback would un-spend: the inflight record, or for a melt
    ::  from before those existed, what the operator names
    =/  what=[secrets=(set @t) ys=(set @t) total=@ud]
      ?^  inflight  [secrets.u.inflight ys.u.inflight input-total.u.inflight]
      [(strs 'secrets') (strs 'ys') 0]
    ?:  &(!?=(%none -.ln-config.st) !=('' payment-hash.u.mq))
      =/  wid  new-wire
      =.  pending.st
        %+  ~(put by pending.st)  wid
        ?.  force  [%melt-abort eyre-id qid]
        ?^  inflight  [%melt-abort-force eyre-id qid]
        [%melt-abort-named eyre-id qid secrets.what ys.what]
      [~[(ln-card-at wid (attempt-of qid) (ln-check-payment payment-hash.u.mq))] st]
    ::  nothing to ask: roll back only on the operator's word
    ?.  force
      ~&  >>>  [%ecash-melt-abort-unverifiable qid]
      :_  st
      %-  give-json  :_  eyre-id
      %-  pairs:enjs:format
      :~  ['aborted' b+|]
          ['result' s+'in-flight-or-unconfirmed']
          ['ln_checked' b+|]
          ['quote_id' s+qid]
      ==
    =.  st  (rollback-melt qid u.mq secrets.what ys.what total.what)
    :_  st
    %-  give-json  :_  eyre-id
    %-  pairs:enjs:format
    :~  ['aborted' b+&]
        ['result' s+'aborted-forced']
        ['ln_checked' b+|]
        ['quote_id' s+qid]
        ['unspent_secrets' (numb:enjs:format ~(wyt in secrets.what))]
        ['redeemed_decremented' (numb:enjs:format total.what)]
    ==
  ::
  ::  -- admin: info and settings --
  ::
  ++  admin-info-update
    |=  [eyre-id=@ta body=(unit octs)]
    ^-  (quip card state-15)
    =/  parsed  (parse-object-body body)
    ?:  ?=(%| -.parsed)  [(give-err eyre-id 400 p.parsed) st]
    ?>  ?=([%o *] p.parsed)
    =/  jon  p.p.parsed
    =?  mint-name.st  (has-key jon 'name')  (get-str jon 'name')
    =?  mint-description.st  (has-key jon 'description')  (get-str jon 'description')
    :_  st
    %-  give-json  :_  eyre-id
    (pairs:enjs:format ~[['name' s+mint-name.st] ['description' s+mint-description.st]])
  ::
  ::  admin-update-settings: each present field must be a bare non-negative
  ::  integer (or a boolean for self_method_enabled), else 400 and nothing
  ::  changes
  ++  admin-update-settings
    |=  [eyre-id=@ta body=(unit octs)]
    ^-  (quip card state-15)
    =/  parsed  (parse-object-body body)
    ?:  ?=(%| -.parsed)  [(give-err eyre-id 400 p.parsed) st]
    ?>  ?=([%o *] p.parsed)
    =/  jon  p.p.parsed
    =/  num
      |=  k=@t
      ^-  (each (unit @ud) @t)
      ?.  (has-key jon k)  [%& ~]
      =/  v  (get-ud jon k)
      ?~  v  [%| (cat 3 'invalid-' k)]
      [%& v]
    =/  pct  (num 'fee_reserve_pct')
    ?:  ?=(%| -.pct)  [(give-err eyre-id 400 p.pct) st]
    =/  floor  (num 'fee_reserve_min')
    ?:  ?=(%| -.floor)  [(give-err eyre-id 400 p.floor) st]
    =/  ttl  (num 'quote_ttl_secs')
    ?:  ?=(%| -.ttl)  [(give-err eyre-id 400 p.ttl) st]
    =/  self  (~(get by jon) 'self_method_enabled')
    ?:  &(?=(^ self) !?=([~ %b *] self))  [(give-err eyre-id 400 'invalid-self_method_enabled') st]
    =?  fee-reserve-pct.st  ?=(^ p.pct)  u.p.pct
    =?  fee-reserve-min.st  ?=(^ p.floor)  u.p.floor
    ::  floor the TTL at 60s: it is also the bolt11 invoice expiry, so a tiny
    ::  one would mint invoices that expire before anyone can pay them
    =?  quote-ttl-secs.st  ?=(^ p.ttl)  (max 60 u.p.ttl)
    =?  self-method-enabled.st  ?=([~ %b *] self)  p.u.self
    [(admin-get-settings eyre-id) st]
  ::
  ::  -- Lightning requests --
  ::
  ++  ln-auth
    ^-  header-list:http
    ?-  -.ln-config.st
      %lnbits  ~[['X-Api-Key' api-key.ln-config.st]]
      %lnd     ~[['Grpc-Metadata-macaroon' macaroon.ln-config.st]]
      %none    ~
    ==
  ::  ln-get / ln-post: a request to the backend at this path. Callers check
  ::  first that one is configured.
  ++  ln-get
    |=  pax=tape
    ^-  request:http
    ?<  ?=(%none -.ln-config.st)
    [%'GET' (crip (weld (trip url.ln-config.st) pax)) ln-auth ~]
  ++  ln-post
    |=  [pax=tape jon=json]
    ^-  request:http
    ?<  ?=(%none -.ln-config.st)
    =/  body=@t  (en:json:html jon)
    :*  %'POST'
        (crip (weld (trip url.ln-config.st) pax))
        [['Content-Type' 'application/json'] ln-auth]
        `(as-octs:mimes:html body)
    ==
  ::  ln-create-invoice: the invoice expires with the quote, so it can't be
  ::  paid after run-cleanup may have dropped the quote
  ++  ln-create-invoice
    |=  [amount=@ud memo=@t]
    ^-  request:http
    ?:  ?=(%lnd -.ln-config.st)
      %+  ln-post  "/v1/invoices"
      %-  pairs:enjs:format
      :~  ['value' (numb:enjs:format amount)]
          ['memo' s+memo]
          ['expiry' (numb:enjs:format quote-ttl-secs.st)]
      ==
    %+  ln-post  "/api/v1/payments"
    %-  pairs:enjs:format
    :~  ['out' b+|]
        ['amount' (numb:enjs:format amount)]
        ['memo' s+memo]
        ['expiry' (numb:enjs:format quote-ttl-secs.st)]
    ==
  ++  ln-check-invoice
    |=  checking-id=@t
    ^-  request:http
    ?:  ?=(%lnd -.ln-config.st)  (ln-get (weld "/v1/invoice/" (trip checking-id)))
    (ln-get (weld "/api/v1/payments/" (trip checking-id)))
  ::  ln-decode-invoice: bolt11 reaches here only through valid-bolt11
  ++  ln-decode-invoice
    |=  bolt11=@t
    ^-  request:http
    ?:  ?=(%lnd -.ln-config.st)  (ln-get (weld "/v1/payreq/" (trip bolt11)))
    (ln-post "/api/v1/payments/decode" (pairs:enjs:format ['data' s+bolt11]~))
  ++  ln-pay-invoice
    |=  [bolt11=@t fee-limit=@ud]
    ^-  request:http
    ?:  ?=(%lnd -.ln-config.st)
      %+  ln-post  "/v1/channels/transactions"
      %-  pairs:enjs:format
      :~  ['payment_request' s+bolt11]
          ['fee_limit' (pairs:enjs:format ['fixed_msat' (numb:enjs:format (mul fee-limit 1.000))]~)]
      ==
    %+  ln-post  "/api/v1/payments"
    %-  pairs:enjs:format
    :~  ['out' b+&]
        ['bolt11' s+bolt11]
        ['fee_limit_msat' (numb:enjs:format (mul fee-limit 1.000))]
    ==
  ++  ln-check-payment
    |=  payment-hash=@t
    ^-  request:http
    ?:  ?=(%lnd -.ln-config.st)  (ln-get (weld "/v1/payment/" (trip payment-hash)))
    (ln-get (weld "/api/v1/payments/" (trip payment-hash)))
  ++  ln-wallet-info
    ^-  request:http
    ?:  ?=(%lnd -.ln-config.st)  (ln-get "/v1/getinfo")
    (ln-get "/api/v1/wallet")
  ::
  ::  -- Lightning answers --
  ::
  ++  handle-ln-response
    |=  [wid=@ta att=(unit @da) res=client-response:iris]
    ^-  (quip card state-15)
    ::  a chunked answer arrives as %progress reports before %finished:
    ::  keep waiting for the whole of it
    ?:  ?=(%progress -.res)  [~ st]
    =/  pend  (~(get by pending.st) wid)
    ?~  pend
      ~&  >>>  [%ecash-ln-response-no-pending wid]
      [~ st]
    =.  pending.st  (~(del by pending.st) wid)
    ?.  ?=(%finished -.res)
      ::  %cancel (a runtime restart, a cancelled request). For an outbound
      ::  pay that is AMBIGUOUS: the HTLC may be in flight or settled, so the
      ::  quote stays %pending with its proofs spent, and only a status check
      ::  or an operator abort decides. Nothing else spent anything: 502.
      ~&  >>>  [%ecash-ln-response-not-finished -.res wid]
      ?.  ?=(%melt-pay -.u.pend)
        [(give-err eyre-id.u.pend 502 'lightning-request-cancelled') st]
      =/  mq  (~(get by melt-quotes.st) quote-id.u.pend)
      ?~  mq  [(give-err eyre-id.u.pend 500 'quote-lost') st]
      [(give-json (melt-quote-json u.mq ~) eyre-id.u.pend) st]
    =/  status=@ud  status-code.response-header.res
    =/  jon=(unit json)
      ?~  full-file.res  ~
      (de:json:html q.data.u.full-file.res)
    ?-  -.u.pend
      %mint-quote-create  (ln-mint-created eyre-id.u.pend quote-id.u.pend status jon)
      %mint-quote-check   (ln-mint-checked eyre-id.u.pend quote-id.u.pend jon)
      %melt-quote-create  (ln-melt-quoted eyre-id.u.pend quote-id.u.pend bolt11.u.pend status jon)
      %melt-pay           (ln-melt-paid eyre-id.u.pend quote-id.u.pend att status jon)
      %melt-check         (ln-melt-checked eyre-id.u.pend quote-id.u.pend att status jon)
      %melt-abort         (ln-melt-abort eyre-id.u.pend quote-id.u.pend att | ~ ~ status jon)
      %melt-abort-force   (ln-melt-abort eyre-id.u.pend quote-id.u.pend att & ~ ~ status jon)
      %ln-test            (ln-tested eyre-id.u.pend status jon)
    ::
        %melt-abort-named
      (ln-melt-abort eyre-id.u.pend quote-id.u.pend att & secrets.u.pend ys.u.pend status jon)
    ==
  ::
  ::  ln-mint-created: the backend made (or didn't make) a deposit invoice
  ++  ln-mint-created
    |=  [eid=@ta qid=@t status=@ud jon=(unit json)]
    ^-  (quip card state-15)
    =/  mq  (~(get by mint-quotes.st) qid)
    ?~  mq  [(give-err eid 500 'quote-lost') st]
    =/  bolt11=@t  ?~(jon '' (extract-str u.jon 'payment_request' 'bolt11'))
    =/  chk=@t  ?~(jon '' (extract-str u.jon 'checking_id' 'r_hash'))
    =?  chk  ?=(%lnd -.ln-config.st)  (b64-hex chk)
    ?:  |((lth status 200) (gth status 299) =('' bolt11) =('' chk))
      ~&  >>>  [%ecash-ln-create-invoice-failed status]
      ::  no invoice, so nothing can ever pay this quote: drop it
      =.  mint-quotes.st  (~(del by mint-quotes.st) qid)
      [(give-err eid 502 'lightning-invoice-creation-failed') st]
    =/  new=mint-quote  u.mq(request bolt11, checking-id chk)
    =.  mint-quotes.st  (~(put by mint-quotes.st) qid new)
    [(give-json (mint-quote-json new) eid) st]
  ::
  ::  ln-mint-checked: promote only a still-%unpaid quote. A late or repeated
  ::  check landing after the mint (%issued) must not make it %paid again,
  ::  and so mintable twice.
  ++  ln-mint-checked
    |=  [eid=@ta qid=@t jon=(unit json)]
    ^-  (quip card state-15)
    =/  mq  (~(get by mint-quotes.st) qid)
    ?~  mq  [(give-err eid 404 'quote-not-found') st]
    ?.  &(=(%unpaid state.u.mq) (invoice-paid ln-config.st jon amount.u.mq))
      [(give-json (mint-quote-json u.mq) eid) st]
    =/  paid=mint-quote  u.mq(state %paid)
    =.  mint-quotes.st  (~(put by mint-quotes.st) qid paid)
    [(give-json (mint-quote-json paid) eid) st]
  ::
  ::  ln-melt-quoted: the backend decoded the invoice a melt quote pays
  ++  ln-melt-quoted
    |=  [eid=@ta qid=@t bolt11=@t status=@ud jon=(unit json)]
    ^-  (quip card state-15)
    ?.  &((gte status 200) (lth status 300) ?=([~ %o *] jon))
      ~&  >>>  [%ecash-ln-decode-failed status]
      [(give-err eid 502 'lightning-decode-failed') st]
    =/  o  p.u.jon
    ::  an invoice for a fraction of a sat costs the whole sat
    =/  amount=@ud
      =/  msat=@ud
        ?.  ?=(%lnd -.ln-config.st)  (get-int o 'amount_msat')
        =/  m  (get-int o 'num_msat')
        ?.(=(0 m) m (mul 1.000 (get-int o 'num_satoshis')))
      (div (add msat 999) 1.000)
    ?:  =(0 amount)  [(give-err eid 400 'could-not-decode-invoice-amount') st]
    ::  the hash is how a %pending melt is checked later, and what marks the
    ::  quote bolt11 (melt-quote-method)
    =/  hash=@t  (extract-str u.jon 'payment_hash' 'r_hash')
    ?:  =('' hash)  [(give-err eid 502 'lightning-decode-missing-hash') st]
    =/  mq=melt-quote
      :*  qid
          amount
          (melt-fee-reserve amount fee-reserve-pct.st fee-reserve-min.st)
          'sat'
          bolt11
          %unpaid
          ''
          hash
          quote-expiry
          now.bowl
      ==
    =.  melt-quotes.st  (~(put by melt-quotes.st) qid mq)
    [(give-json (melt-quote-json mq ~) eid) st]
  ::
  ::  ln-melt-paid: the pay's own answer. A DISPATCH receipt: it settles only
  ::  on proof, rolls back only on a refusal made before any HTLC existed,
  ::  and otherwise leaves the quote %pending for the wallet to poll.
  ++  ln-melt-paid
    |=  [eid=@ta qid=@t att=(unit @da) status=@ud jon=(unit json)]
    ^-  (quip card state-15)
    =/  mq  (~(get by melt-quotes.st) qid)
    ?~  mq  [(give-err eid 500 'quote-lost') st]
    =/  inflight  (~(get by melt-inflight.st) qid)
    ?:  ?&  (pay-rejected ln-config.st status jon)
            =(%pending state.u.mq)
            (this-attempt att qid)
            ?=(^ inflight)
        ==
      ~&  >>>  [%ecash-ln-pay-dispatch-rejected qid status]
      =.  st  (rollback-melt qid u.mq secrets.u.inflight ys.u.inflight input-total.u.inflight)
      [(give-json (melt-quote-json u.mq(state %failed) ~) eid) st]
    ?.  &((pay-settled status jon) =(%pending state.u.mq))
      ~&  >>>  [%ecash-ln-pay-dispatched-pending qid status]
      [(give-json (melt-quote-json u.mq (stored-change qid)) eid) st]
    =/  pre=@t  ?~(jon '' (extract-str u.jon 'payment_preimage' 'preimage'))
    =?  pre  ?=(%lnd -.ln-config.st)  (b64-hex pre)
    =^  change  st  (settle-melt qid u.mq jon pre)
    [(give-json (melt-quote-json (~(got by melt-quotes.st) qid) change) eid) st]
  ::
  ::  ln-melt-checked: a status check of a %pending melt. It settles on a
  ::  settled pay and rolls back only on LND's explicit FAILED (pay-status);
  ::  everything else leaves the quote as it is.
  ++  ln-melt-checked
    |=  [eid=@ta qid=@t att=(unit @da) status=@ud jon=(unit json)]
    ^-  (quip card state-15)
    =/  mq  (~(get by melt-quotes.st) qid)
    ?~  mq  [(give-err eid 404 'quote-not-found') st]
    ?.  =(%pending state.u.mq)
      [(give-json (melt-quote-json u.mq (stored-change qid)) eid) st]
    =/  outcome  (pay-status ln-config.st status jon)
    ?:  =(%settled outcome)
      =^  change  st  (settle-melt qid u.mq jon (preimage-of jon))
      [(give-json (melt-quote-json (~(got by melt-quotes.st) qid) change) eid) st]
    =/  inflight  (~(get by melt-inflight.st) qid)
    ?.  &(=(%failed outcome) (this-attempt att qid) ?=(^ inflight))
      [(give-json (melt-quote-json u.mq ~) eid) st]
    ~&  >>>  [%ecash-melt-confirmed-failed qid status]
    =.  st  (rollback-melt qid u.mq secrets.u.inflight ys.u.inflight input-total.u.inflight)
    [(give-json (melt-quote-json u.mq(state %failed) ~) eid) st]
  ::
  ++  preimage-of
    |=  jon=(unit json)
    ^-  @t
    =/  pre  ?~(jon '' (extract-str u.jon 'preimage' 'payment_preimage'))
    ?.(?=(%lnd -.ln-config.st) pre (b64-hex pre))
  ::
  ::  ln-melt-abort: an operator abort, after re-checking the payment. A
  ::  settled pay is settled, never rolled back, even when forced. A
  ::  rollback needs LND's explicit FAILED, or force (the operator asserting
  ::  the pay failed). named: for a melt with no inflight record, what the
  ::  operator named to un-spend.
  ++  ln-melt-abort
    |=  [eid=@ta qid=@t att=(unit @da) force=? named=(set @t) named-ys=(set @t) status=@ud jon=(unit json)]
    ^-  (quip card state-15)
    =/  mq  (~(get by melt-quotes.st) qid)
    ?~  mq  [(give-err eid 404 'quote-not-found') st]
    =/  reply
      |=  [aborted=? result=@t more=(list [@t json])]
      ^-  (list card)
      %-  give-json  :_  eid
      %-  pairs:enjs:format
      %+  weld
        ^-  (list [@t json])
        :~  ['aborted' b+aborted]
            ['result' s+result]
            ['ln_checked' b+&]
            ['quote_id' s+qid]
        ==
      more
    ?.  =(%pending state.u.mq)
      [(reply | 'no-op-not-pending' ['state' s+(quote-state-text state.u.mq)]~) st]
    =/  outcome  (pay-status ln-config.st status jon)
    ?:  =(%settled outcome)
      =/  pre  (preimage-of jon)
      =^  change  st  (settle-melt qid u.mq jon pre)
      [(reply | 'settled-not-aborted' ~[['state' s+'PAID'] ['payment_preimage' s+pre]]) st]
    ?.  |(force =(%failed outcome))
      ~&  >>>  [%ecash-melt-abort-ambiguous qid status]
      [(reply | 'in-flight-or-unconfirmed' ['state' s+'PENDING']~) st]
    ::  the quote was rolled back and melted again since this check left
    ?.  (this-attempt att qid)
      [(reply | 'stale-attempt' ['state' s+'PENDING']~) st]
    =/  inflight  (~(get by melt-inflight.st) qid)
    =/  what=[secrets=(set @t) ys=(set @t) total=@ud]
      ?^  inflight  [secrets.u.inflight ys.u.inflight input-total.u.inflight]
      [named named-ys 0]
    ?:  &(?=(~ inflight) =(~ named) =(~ named-ys))
      ~&  >>>  [%ecash-melt-abort-no-inflight qid status]
      [(reply | 'no-inflight-record' ['state' s+'PENDING']~) st]
    ~&  >>>  [%ecash-melt-abort-rollback qid status force]
    =.  st  (rollback-melt qid u.mq secrets.what ys.what total.what)
    :_  st
    %^  reply  &
      ?:(=(%failed outcome) 'aborted-confirmed-failed' 'aborted-forced')
    :~  ['unspent_secrets' (numb:enjs:format ~(wyt in secrets.what))]
        ['redeemed_decremented' (numb:enjs:format total.what)]
    ==
  ::
  ::  ln-tested: what the backend said to admin-ln-test
  ++  ln-tested
    |=  [eid=@ta status=@ud jon=(unit json)]
    ^-  (quip card state-15)
    =/  ok=?  &((gte status 200) (lth status 300) ?=([~ %o *] jon))
    =/  ln  ln-summary
    =/  more=(list [@t json])
      ?.  ok  ['detail' s+?~(jon '' (extract-str u.jon 'detail' 'error'))]~
      ?.  ?=([~ %o *] jon)  ~
      ?.  (has-key p.u.jon 'balance')  ~
      ['balance_msat' (numb:enjs:format (get-num p.u.jon 'balance'))]~
    :_  st
    %-  give-json  :_  eid
    %-  pairs:enjs:format
    %+  weld
      ^-  (list [@t json])
      :~  ['status' s+?:(ok 'ok' 'error')]
          ['type' s+type.ln]
          ['url' s+url.ln]
          ['http_status' (numb:enjs:format status)]
      ==
    more
  --
--
