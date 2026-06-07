::  ecash: Cashu NUT-00..NUT-12 mint agent with Lightning backend
::
::    secp256k1 + BDHKE + DLEQ proofs + P2PK Schnorr verification.
::    Shared types live in /sur/ecash; migration-only shapes below.
::
/-  *ecash
/+  default-agent, dbug, *bdhke
/*  dashboard-lines  %txt  /app/dashboard/txt
|%
+$  state-6
  $:  %6
      keysets=(map @t keyset)
      active-keyset=@t
      spent=(set @t)
      spent-ys=(set @t)
      counter=@ud
      mint-quotes=(map @t mint-quote)
      melt-quotes=(map @t melt-quote)
      ln-config=ln-backend
      pending=(map @ta pending-req)
      total-issued-sats=@ud
      total-redeemed-sats=@ud
      mint-name=@t
      mint-description=@t
      fee-reserve-pct=@ud
      fee-reserve-min=@ud
      quote-ttl-secs=@ud
      ::  credential extension
      cred-keysets=(map @t cred-keyset)
      cred-spent=(set @t)
      cred-counter=@ud
  ==
+$  state-7
  $:  %7
      keysets=(map @t keyset)
      active-keyset=@t
      spent=(set @t)
      spent-ys=(set @t)
      counter=@ud
      mint-quotes=(map @t mint-quote)
      melt-quotes=(map @t melt-quote)
      ln-config=ln-backend
      pending=(map @ta pending-req)
      total-issued-sats=@ud
      total-redeemed-sats=@ud
      mint-name=@t
      mint-description=@t
      fee-reserve-pct=@ud
      fee-reserve-min=@ud
      quote-ttl-secs=@ud
      ::  credential extension
      cred-keysets=(map @t cred-keyset)
      cred-spent=(set @t)
      cred-counter=@ud
      ::  NUT-08: stored change signatures keyed by melt quote-id
      melt-change=(map @t (list json))
  ==
::  service-v0: the state-8 service shape, before the allowlist field was
::  added. Kept only for migration; new code uses the sur-defined `service`.
::
+$  service-v0
  $:  name=@t
      title=@t
      description=@t
      kind=service-kind
      ks-id=@t
      active=?
      expires=(unit @da)
      max-issuance=(unit @ud)
      issued=@ud
      redeemed=@ud
      created=@da
  ==
+$  state-8
  $:  %8
      keysets=(map @t keyset)
      active-keyset=@t
      spent=(set @t)
      spent-ys=(set @t)
      counter=@ud
      mint-quotes=(map @t mint-quote)
      melt-quotes=(map @t melt-quote)
      ln-config=ln-backend
      pending=(map @ta pending-req)
      total-issued-sats=@ud
      total-redeemed-sats=@ud
      mint-name=@t
      mint-description=@t
      fee-reserve-pct=@ud
      fee-reserve-min=@ud
      quote-ttl-secs=@ud
      cred-keysets=(map @t cred-keyset)
      cred-spent=(set @t)
      cred-counter=@ud
      melt-change=(map @t (list json))
      services=(map @t service-v0)
  ==
+$  state-9
  $:  %9
      keysets=(map @t keyset)
      active-keyset=@t
      spent=(set @t)
      spent-ys=(set @t)
      counter=@ud
      mint-quotes=(map @t mint-quote)
      melt-quotes=(map @t melt-quote)
      ln-config=ln-backend
      pending=(map @ta pending-req)
      total-issued-sats=@ud
      total-redeemed-sats=@ud
      mint-name=@t
      mint-description=@t
      fee-reserve-pct=@ud
      fee-reserve-min=@ud
      quote-ttl-secs=@ud
      cred-keysets=(map @t cred-keyset)
      cred-spent=(set @t)
      cred-counter=@ud
      melt-change=(map @t (list json))
      services=(map @t service)
  ==
+$  state-10
  $:  %10
      keysets=(map @t keyset)
      active-keyset=@t
      spent=(set @t)
      spent-ys=(set @t)
      counter=@ud
      mint-quotes=(map @t mint-quote)
      melt-quotes=(map @t melt-quote)
      ln-config=ln-backend
      pending=(map @ta pending-req)
      total-issued-sats=@ud
      total-redeemed-sats=@ud
      mint-name=@t
      mint-description=@t
      fee-reserve-pct=@ud
      fee-reserve-min=@ud
      quote-ttl-secs=@ud
      cred-keysets=(map @t cred-keyset)
      cred-spent=(set @t)
      cred-counter=@ud
      melt-change=(map @t (list json))
      services=(map @t service)
      self-method-enabled=?
  ==
+$  state-11
  $:  %11
      keysets=(map @t keyset)
      active-keyset=@t
      spent=(set @t)
      spent-ys=(set @t)
      counter=@ud
      mint-quotes=(map @t mint-quote)
      melt-quotes=(map @t melt-quote)
      ln-config=ln-backend
      pending=(map @ta pending-req)
      total-issued-sats=@ud
      total-redeemed-sats=@ud
      mint-name=@t
      mint-description=@t
      fee-reserve-pct=@ud
      fee-reserve-min=@ud
      quote-ttl-secs=@ud
      melt-change=(map @t (list json))
      self-method-enabled=?
  ==
::  state-12: identical to state-11 except pending uses pending-req-v2 (the
::  %melt-pay variant now carries rollback data). The shape change is why this
::  is a new version; the 11->12 migration clears any stale in-flight pending.
+$  state-12
  $:  %12
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
  ==
::  state-13: identical to state-12 plus melt-inflight — durable per-quote
::  reconciliation data (secrets/ys/input-total/change) for an in-flight bolt11
::  melt, so the %pending recheck path and admin abort can settle or roll back
::  even after a restart/migration. The 12->13 migration inits it to ~.
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
      melt-inflight=(map @t melt-inflight-entry)
  ==
+$  versioned-state  $%(state-6 state-7 state-8 state-9 state-10 state-11 state-12 state-13)
+$  card  card:agent:gall
--
%-  agent:dbug
^-  agent:gall
=<
=|  state-13
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
      =?  prev  ?=(%6 -.prev)  (state-6-to-7 prev)
      =?  prev  ?=(%7 -.prev)  (state-7-to-8 prev)
      =?  prev  ?=(%8 -.prev)  (state-8-to-9 prev)
      =?  prev  ?=(%9 -.prev)  (state-9-to-10 prev)
      =?  prev  ?=(%10 -.prev)  (state-10-to-11 prev)
      =?  prev  ?=(%11 -.prev)  (state-11-to-12 prev)
      =?  prev  ?=(%12 -.prev)  (state-12-to-13 prev)
      ?>  ?=(%13 -.prev)
      ::  Do NOT arm /cleanup here: on-init arms it once and on-arvo re-arms
      ::  after each fire, so arming on every upgrade leaks timers (LOW-6).
      [~ this(state prev)]
  ::
  ++  state-6-to-7
    |=  prev=state-6
    ^-  state-7
    :*  %7
        keysets.prev
        active-keyset.prev
        spent.prev
        spent-ys.prev
        counter.prev
        mint-quotes.prev
        melt-quotes.prev
        ln-config.prev
        pending.prev
        total-issued-sats.prev
        total-redeemed-sats.prev
        mint-name.prev
        mint-description.prev
        fee-reserve-pct.prev
        fee-reserve-min.prev
        quote-ttl-secs.prev
        cred-keysets.prev
        cred-spent.prev
        cred-counter.prev
        *(map @t (list json))
    ==
  ::
  ++  state-7-to-8
    |=  prev=state-7
    ^-  state-8
    :*  %8
        keysets.prev
        active-keyset.prev
        spent.prev
        spent-ys.prev
        counter.prev
        mint-quotes.prev
        melt-quotes.prev
        ln-config.prev
        pending.prev
        total-issued-sats.prev
        total-redeemed-sats.prev
        mint-name.prev
        mint-description.prev
        fee-reserve-pct.prev
        fee-reserve-min.prev
        quote-ttl-secs.prev
        cred-keysets.prev
        cred-spent.prev
        cred-counter.prev
        melt-change.prev
        *(map @t service-v0)
    ==
  ::
  ::  state-8 → state-9: widen each service to include an empty allowlist.
  ::
  ++  state-8-to-9
    |=  prev=state-8
    ^-  state-9
    =/  upgraded=(map @t service)
      %-  ~(run by services.prev)
      |=  svc=service-v0
      ^-  service
      :*  name.svc
          title.svc
          description.svc
          kind.svc
          ks-id.svc
          active.svc
          expires.svc
          max-issuance.svc
          issued.svc
          redeemed.svc
          created.svc
          *(set @t)
      ==
    :*  %9
        keysets.prev
        active-keyset.prev
        spent.prev
        spent-ys.prev
        counter.prev
        mint-quotes.prev
        melt-quotes.prev
        ln-config.prev
        pending.prev
        total-issued-sats.prev
        total-redeemed-sats.prev
        mint-name.prev
        mint-description.prev
        fee-reserve-pct.prev
        fee-reserve-min.prev
        quote-ttl-secs.prev
        cred-keysets.prev
        cred-spent.prev
        cred-counter.prev
        melt-change.prev
        upgraded
    ==
  ::
  ::  state-9 → state-10: add self-method-enabled, default off (public mint).
  ::
  ++  state-9-to-10
    |=  prev=state-9
    ^-  state-10
    :*  %10
        keysets.prev
        active-keyset.prev
        spent.prev
        spent-ys.prev
        counter.prev
        mint-quotes.prev
        melt-quotes.prev
        ln-config.prev
        pending.prev
        total-issued-sats.prev
        total-redeemed-sats.prev
        mint-name.prev
        mint-description.prev
        fee-reserve-pct.prev
        fee-reserve-min.prev
        quote-ttl-secs.prev
        cred-keysets.prev
        cred-spent.prev
        cred-counter.prev
        melt-change.prev
        services.prev
        %.n
    ==
  ::
  ::  state-10 → state-11: drop the cred/services fields (moved to %ecash-services).
  ::
  ++  state-10-to-11
    |=  prev=state-10
    ^-  state-11
    :*  %11
        keysets.prev
        active-keyset.prev
        spent.prev
        spent-ys.prev
        counter.prev
        mint-quotes.prev
        melt-quotes.prev
        ln-config.prev
        pending.prev
        total-issued-sats.prev
        total-redeemed-sats.prev
        mint-name.prev
        mint-description.prev
        fee-reserve-pct.prev
        fee-reserve-min.prev
        quote-ttl-secs.prev
        melt-change.prev
        self-method-enabled.prev
    ==
  ::
  ::  state-11 → state-12: pending-req gained rollback fields on %melt-pay, so
  ::  the pending map shape changed. Any in-flight iris request is already lost
  ::  across an upgrade, so clear pending; everything else is copied verbatim.
  ::
  ++  state-11-to-12
    |=  prev=state-11
    ^-  state-12
    :*  %12
        keysets.prev
        active-keyset.prev
        spent.prev
        spent-ys.prev
        counter.prev
        mint-quotes.prev
        melt-quotes.prev
        ln-config.prev
        *(map @ta pending-req-v2)
        total-issued-sats.prev
        total-redeemed-sats.prev
        mint-name.prev
        mint-description.prev
        fee-reserve-pct.prev
        fee-reserve-min.prev
        quote-ttl-secs.prev
        melt-change.prev
        self-method-enabled.prev
    ==
  ::
  ::  state-12 -> state-13: add melt-inflight (durable melt reconciliation),
  ::  initialised empty. Everything else copied verbatim.
  ::
  ++  state-12-to-13
    |=  prev=state-12
    ^-  state-13
    :*  %13
        keysets.prev
        active-keyset.prev
        spent.prev
        spent-ys.prev
        counter.prev
        mint-quotes.prev
        melt-quotes.prev
        ln-config.prev
        pending.prev
        total-issued-sats.prev
        total-redeemed-sats.prev
        mint-name.prev
        mint-description.prev
        fee-reserve-pct.prev
        fee-reserve-min.prev
        quote-ttl-secs.prev
        melt-change.prev
        self-method-enabled.prev
        *(map @t melt-inflight-entry)
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
    =/  cmd  !<(ln-backend vase)
    `this(ln-config.state cmd)
  ==
++  on-watch
  |=  =path
  ^-  (quip card _this)
  ?+  path  (on-watch:def path)
      [%http-response *]
    `this
  ==
++  on-leave  on-leave:def
++  on-peek
  |=  =path
  ^-  (unit (unit cage))
  ?+  path
    [~ ~]
      [%x %counter ~]
    ``noun+!>(counter.state)
      [%x %active-keyset ~]
    ``noun+!>(active-keyset.state)
  ==
++  on-agent  on-agent:def
++  on-arvo
  |=  [=wire =sign-arvo]
  ^-  (quip card _this)
  ?+  wire
    (on-arvo:def wire sign-arvo)
      [%eyre %connect ~]
    ?.  ?=([%eyre %bound *] sign-arvo)
      (on-arvo:def wire sign-arvo)
    ?:  accepted.sign-arvo  `this
    ~&  >>>  %ecash-bind-legacy-failed
    `this
  ::
      [%eyre %connect-v1 ~]
    ?.  ?=([%eyre %bound *] sign-arvo)
      (on-arvo:def wire sign-arvo)
    ?:  accepted.sign-arvo  `this
    ~&  >>>  %ecash-bind-v1-failed
    `this
  ::
      [%ln @ta ~]
    ?>  ?=(%iris -.sign-arvo)
    ?>  ?=(%http-response +<.sign-arvo)
    =/  wire-id=@ta  i.t.wire
    =^  cards  state  (handle-ln-response:hc wire-id client-response.sign-arvo)
    [cards this]
  ::
      [%cleanup ~]
    ?>  ?=(%behn -.sign-arvo)
    :_  this(state run-cleanup:hc)
    :~  [%pass /cleanup %arvo %b %wait (add now.bowl ~d1)]
    ==
  ==
++  on-fail   on-fail:def
--
::  -- Helper core --
|%
++  ec
  |_  [=bowl:gall st=state-13]
  ::
  ::  -- JSON number parsing (bare digits, no Hoon dot separators) --
  ++  parse-ud
    |=  t=@t  ^-  @ud
    =/  res  (rust (trip t) (bass 10 (plus dit)))
    ?~(res 0 u.res)
  ::
  ::  strict variant: ~ when the cord is not a bare run of digits.
  ::  (parse-ud coerces garbage to 0, which is unsafe for thresholds.)
  ++  parse-ud-strict
    |=  t=@t  ^-  (unit @ud)
    ?:  =('' t)  ~
    (rust (trip t) (bass 10 (plus dit)))
  ::
  ::  max inputs or outputs accepted per request (bounds per-event EC work)
  ++  max-batch  ^-  @ud  100
  ::
  ::  max admin-settable per-proof input fee (ppk); guards swap/melt sub
  ++  max-input-fee-ppk  ^-  @ud  100.000
  ::
  ::  host-of-url: extract the host[:port] authority from an Origin/Referer
  ::  url cord (strips scheme://, drops any /path and trailing fragment).
  ++  host-of-url
    |=  url=@t
    ^-  @t
    =/  txt=tape  (trip url)
    =/  spos=(unit @ud)  (find "://" txt)
    =?  txt  ?=(^ spos)  (slag (add 3 u.spos) txt)
    =/  ppos=(unit @ud)  (find "/" txt)
    =?  txt  ?=(^ ppos)  (scag u.ppos txt)
    (crip txt)
  ::
  ::  csrf-ok: CSRF guard for state-changing admin requests.
  ::
  ::    Safe (non-mutating) methods are always allowed. A mutating method that
  ::    carries an Origin (or Referer) header must be same-origin: its host
  ::    authority must equal the request Host. A request with no Origin/Referer
  ::    is a non-browser client (curl/scripts) and carries no CSRF risk, so it
  ::    is allowed; browsers always attach Origin on a cross-site POST, so the
  ::    cross-site forced-POST attack is still rejected.
  ++  csrf-ok
    |=  req=inbound-request:eyre
    ^-  ?
    =/  meth  method.request.req
    ?:  ?|  =(%'GET' meth)  =(%'HEAD' meth)  =(%'OPTIONS' meth)  ==
      &
    =/  hdrs  header-list.request.req
    =/  origin  (get-header:http 'origin' hdrs)
    =/  src=(unit @t)
      ?^  origin  origin
      (get-header:http 'referer' hdrs)
    ?~  src  &
    =/  host  (get-header:http 'host' hdrs)
    ?~  host  |
    =((host-of-url u.src) u.host)
  ::
  ::  run-cleanup: drop expired mint/melt quotes and orphaned melt-change.
  ::
  ::    A %paid quote is sats-already-received (mint: awaiting issuance) or a
  ::    payment that still owes the client NUT-08 change (melt). Deleting either
  ::    on TTL destroys owed value, so %paid quotes are retained regardless of
  ::    expiry until they reach a true terminal transition (mint->%issued, or
  ::    the client redeems the melt change). Because live-change keeps only
  ::    entries whose quote survives in live-melt, retaining %paid melt quotes
  ::    here also preserves their unredeemed change automatically.
  ++  run-cleanup
    ^-  state-13
    =/  live-mint
      %-  ~(gas by *(map @t mint-quote))
      %+  skim  ~(tap by mint-quotes.st)
      |=([@t q=mint-quote] |((gth expiry.q now.bowl) =(%paid state.q)))
    ::  retain a %pending melt (and its inflight data) regardless of expiry:
    ::  a stuck pay still owes a settle-or-rollback decision via recheck/abort.
    =/  live-melt
      %-  ~(gas by *(map @t melt-quote))
      %+  skim  ~(tap by melt-quotes.st)
      |=([@t q=melt-quote] ?|((gth expiry.q now.bowl) =(%paid state.q) =(%pending state.q)))
    =/  live-change
      %-  ~(gas by *(map @t (list json)))
      %+  skim  ~(tap by melt-change.st)
      |=([k=@t *] (~(has by live-melt) k))
    =/  live-inflight
      %-  ~(gas by *(map @t melt-inflight-entry))
      %+  skim  ~(tap by melt-inflight.st)
      |=([k=@t *] (~(has by live-melt) k))
    %=  st
      mint-quotes    live-mint
      melt-quotes    live-melt
      melt-change    live-change
      melt-inflight  live-inflight
    ==
  ::
  ::  Compute NUT-02 v2 keyset id: '01' || sha256(canonical-string)
  ::
  ::    canonical = "<amt>:<pk>,...,<amt>:<pk>|unit:<unt>[|input_fee_ppk:<n>][|final_expiry:<n>]"
  ::
  ++  compute-ks-id
    |=  [keys=(map @ud @t) unt=@t input-fee-ppk=@ud final-expiry=@ud]
    ^-  @t
    =/  sorted=(list [@ud @t])
      %+  sort  ~(tap by keys)
      |=([a=[@ud @t] b=[@ud @t]] (lth -.a -.b))
    =/  pair-cords=(list @t)
      %+  turn  sorted
      |=([amt=@ud pub=@t] (rap 3 ~[(scot %ud amt) ':' pub]))
    =|  pieces=(list @t)
    =.  pieces  (snoc pieces (rap 3 (join ',' pair-cords)))
    =.  pieces  (weld pieces `(list @t)`~['|unit:' unt])
    =?  pieces  (gth input-fee-ppk 0)
      (weld pieces `(list @t)`~['|input_fee_ppk:' (scot %ud input-fee-ppk)])
    =?  pieces  (gth final-expiry 0)
      (weld pieces `(list @t)`~['|final_expiry:' (scot %ud final-expiry)])
    ::  shax yields the digest as a little-endian atom; reverse to standard
    ::  big-endian byte order so the hex matches NUT-02 / cashu-ts deriveKeysetId.
    =/  hash  (rev 3 32 (shax (rap 3 pieces)))
    (rap 3 ~['01' (pad-hex hash 64)])
  ::
  ::  parse-object-body: decode a POST body as a JSON object.
  ::
  ::    Returns %& with the whole %o json on success (callers still access
  ::    `p.jon` to get the map), or %| with an error cord suitable for a
  ::    400 detail payload.
  ::
  ++  parse-object-body
    |=  body=(unit octs)
    ^-  (each json @t)
    ?~  body  [%| 'no-body']
    =/  parsed=(unit json)  (de:json:html (crip (trip q.u.body)))
    ?~  parsed               [%| 'invalid-json']
    ?.  ?=([%o *] u.parsed)  [%| 'expected-object']
    [%& u.parsed]
  ::
  ::  JSON field extractors — each returns a default on missing / wrong type.
  ::
  ::    Callers that need to distinguish absent-vs-default check `has` first.
  ::
  ++  has-key  |=([o=(map @t json) k=@t] ?=(^ (~(get by o) k)))
  ::
  ++  get-str
    |=  [o=(map @t json) k=@t]
    ^-  @t
    =/  v  (~(get by o) k)
    ?~  v  ''
    ?+(-.u.v '' %s p.u.v)
  ::
  ++  get-num
    |=  [o=(map @t json) k=@t]
    ^-  @ud
    =/  v  (~(get by o) k)
    ?~  v  0
    ?+(-.u.v 0 %n (parse-ud p.u.v))
  ::
  ++  get-bool
    |=  [o=(map @t json) k=@t]
    ^-  ?
    =/  v  (~(get by o) k)
    ?~  v  %.n
    ?+(-.u.v %.n %b p.u.v)
  ::
  ++  get-array
    |=  [o=(map @t json) k=@t]
    ^-  (list json)
    =/  v  (~(get by o) k)
    ?~  v  ~
    ?.  ?=([%a *] u.v)  ~
    p.u.v
  ::
  ++  get-obj
    |=  [o=(map @t json) k=@t]
    ^-  (map @t json)
    =/  v  (~(get by o) k)
    ?~  v  ~
    ?.  ?=([%o *] u.v)  ~
    p.u.v
  ::
  ::  ln-settled-sats: settled amount (sats) from an LN status response.
  ::  LNbits: details.amount or top-level amount_msat / amount (all msat).
  ::  LND:    amt_paid_sat or value (already sats).
  ::  Returns 0 if no amount field is present (fail-closed for paid checks).
  ::
  ++  ln-settled-sats
    |=  o=(map @t json)
    ^-  @ud
    =/  det=(map @t json)  (get-obj o 'details')
    =/  det-msat=@ud  (get-num det 'amount')
    ?:  (gth det-msat 0)  (div det-msat 1.000)
    =/  top-msat=@ud  (get-num o 'amount_msat')
    ?:  (gth top-msat 0)  (div top-msat 1.000)
    =/  amt-msat=@ud  (get-num o 'amount')
    ?:  (gth amt-msat 0)  (div amt-msat 1.000)
    =/  lnd-sat=@ud  (get-num o 'amt_paid_sat')
    ?:  (gth lnd-sat 0)  lnd-sat
    (get-num o 'value')
  ::
  ::  routing-fee-sats: NUT-08 actual routing fee in SATS, read FAIL-CLOSED.
  ::    A fee that is NOT a clean non-negative integer (absent / non-numeric)
  ::    is treated as the FULL `cap` (= fee_reserve), so the refund becomes 0
  ::    and the mint can never over-refund.
  ::
  ::    Field priority (first that parses wins; a present 0 = genuine 0-sat fee):
  ::      SATS (as-is):  fee_sat, payment_route.total_fees
  ::      MSAT (ceil /1000):  total_fees_msat, payment_route.total_fees_msat,
  ::                          fee, details.fee
  ::    LND REST string-encodes int64 fees, so each field is read string-OR-number
  ::    (parse-ud-strict, like num_satoshis). Result capped at `cap`.
  ::
  ++  routing-fee-sats
    |=  [jon=json cap=@ud]
    ^-  @ud
    ?.  ?=([%o *] jon)  cap
    ::  pick: strict (unit @ud) for a key, accepting %s (string int) or %n.
    =/  pick
      |=  [o=(map @t json) k=@t]
      ^-  (unit @ud)
      =/  v  (~(get by o) k)
      ?~  v  ~
      ?+  -.u.v  ~
        %s  (parse-ud-strict p.u.v)
        %n  (parse-ud-strict p.u.v)
      ==
    =/  route  (get-obj p.jon 'details')
    =/  proute  (get-obj p.jon 'payment_route')
    ::  SATS fields: explicit sat fee, used as-is.
    =/  sat-u=(unit @ud)
      =/  fs  (pick p.jon 'fee_sat')
      ?^  fs  fs
      (pick proute 'total_fees')
    ?^  sat-u  (min u.sat-u cap)
    ::  MSAT fields: ceil-divide to the next whole sat.
    =/  msat-u=(unit @ud)
      =/  tfm  (pick p.jon 'total_fees_msat')
      ?^  tfm  tfm
      =/  ptfm  (pick proute 'total_fees_msat')
      ?^  ptfm  ptfm
      =/  fm  (pick p.jon 'fee')
      ?^  fm  fm
      (pick route 'fee')
    ?~  msat-u  cap
    =/  fee-msat=@ud  u.msat-u
    ?:  =(0 fee-msat)  0
    =/  fee-sat=@ud  (div (add fee-msat 999) 1.000)
    (min fee-sat cap)
  ::
  ::  ln-summary: lightning backend status as type/url/configured triple
  ::
  ++  ln-summary
    ^-  [type=@t url=@t configured=?]
    ?-  -.ln-config.st
      %lnbits  ['lnbits' url.ln-config.st %.y]
      %lnd     ['lnd' url.ln-config.st %.y]
      %none    ['none' '' %.n]
    ==
  ::
  ::  default-denoms: the 10 power-of-2 denominations 1..512
  ::
  ++  default-denoms  `(list @ud)`~[1 2 4 8 16 32 64 128 256 512]
  ::
  ::  gen-ks-keys: deterministic privkey/pubkey map for default denominations.
  ::
  ::    Used by both the initial on-init keyset and admin-triggered new keysets.
  ::    Returns [privkeys pubkeys] keyed by denomination amount.
  ::
  ++  gen-ks-keys
    |=  ent=@
    ^-  [privkeys=(map @ud @) pubkeys=(map @ud @t)]
    =|  privs=(map @ud @)
    =|  pubs=(map @ud @t)
    =.  privs
      %+  roll  default-denoms
      |=  [d=@ud acc=(map @ud @)]
      =/  k   (mod (shax (add (mul ent (bex 64)) d)) secp-n)
      =/  k2  ?:(=(0 k) 1 k)
      (~(put by acc) d k2)
    =.  pubs
      %+  roll  ~(tap by privs)
      |=  [[d=@ud k=@] acc=(map @ud @t)]
      (~(put by acc) d (pt-to-hex (pubkey k)))
    [privs pubs]
  ::
  ::  Quote expiry from configurable TTL
  ::
  ++  quote-expiry
    ^-  @da
    (add now.bowl (mul ~s1 quote-ttl-secs.st))
  ::
  ::  -- Melt fee reserve from configurable percent + min --
  ::
  ++  melt-fee-reserve
    |=  amount=@ud
    ^-  @ud
    =/  pct-fee=@ud  (div (mul amount fee-reserve-pct.st) 10.000)
    (max fee-reserve-min.st pct-fee)
  ::
  ::  compute-fee: NUT-02 input fee, summed per-proof and ceil-divided by 1k
  ::
  ++  compute-fee
    |=  proofs=(list json)
    ^-  @ud
    =/  fee-sum=@ud
      %+  roll  proofs
      |=  [proof=json acc=@ud]
      ?.  ?=([%o *] proof)  acc
      =/  ks-id=@t  (get-str p.proof 'id')
      ::  Match verify-proofs: an empty id is validated against the active
      ::  keyset, so its fee must be computed against that keyset too (else
      ::  dropping 'id' evades the input fee).
      =?  ks-id  =('' ks-id)  active-keyset.st
      =/  maybe-ks  (~(get by keysets.st) ks-id)
      ?~  maybe-ks  acc
      (add acc input-fee-ppk.u.maybe-ks)
    ?:  =(0 fee-sum)  0
    (div (add fee-sum 999) 1.000)
  ::
  ::  -- Random quote ID generation --
  ::
  ++  gen-quote-id
    ^-  @t
    (pad-hex (shax (add eny.bowl now.bowl)) 64)
  ::
  ::  -- Initialization --
  ::
  ++  init
    ^-  (quip card state-13)
    =/  keys      (gen-ks-keys (shax eny.bowl))
    =/  ks-id=@t  (compute-ks-id pubkeys.keys 'sat' 0 0)
    =/  ks=keyset
      :*  ks-id=ks-id
          active=%.y
          unt='sat'
          input-fee-ppk=0
          keys=pubkeys.keys
          privkeys=privkeys.keys
          created=now.bowl
      ==
    =.  keysets.st           (~(put by keysets.st) ks-id ks)
    =.  active-keyset.st     ks-id
    ::  defaults for config fields — bunts would leave quote-ttl-secs=0
    =.  mint-name.st         'ecash-mint'
    =.  mint-description.st  'Cashu ecash mint on Urbit'
    =.  fee-reserve-pct.st   100
    =.  fee-reserve-min.st   10
    =.  quote-ttl-secs.st    3.600
    =.  self-method-enabled.st  %.n
    ::  default Lightning backend to %none — the bunt of ln-backend is its head
    ::  variant (%lnbits with empty url), which would report a phantom configured
    ::  backend on a fresh mint, so set it explicitly.
    =.  ln-config.st         [%none ~]
    :_  st
    :~  [%pass /eyre/connect %arvo %e %connect [`/apps/ecash dap.bowl]]
        [%pass /eyre/connect-v1 %arvo %e %connect [`/v1 dap.bowl]]
        [%pass /cleanup %arvo %b %wait (add now.bowl ~d1)]
    ==
  ::  parse-request-path: url cord -> list of path segments (query stripped)
  ::
  ++  parse-request-path
    |=  url=@t
    ^-  (list @t)
    =/  tail=tape  (trip url)
    =/  qpos=(unit @ud)  (find "?" tail)
    =?  tail  ?=(^ qpos)  (scag u.qpos tail)
    =/  tail-len=@ud  (lent tail)
    =?  tail  &((gth tail-len 0) =('/' (snag (dec tail-len) tail)))
      (scag (dec tail-len) tail)
    %+  turn
      (skip (split-tape tail '/') |=(s=tape =(~ s)))
    crip
  ::
  ::  handle-http: route an inbound HTTP request to its handler.
  ::
  ::    Dispatch is a single ?+ on `[method path-segments]`. The 404 default
  ::    is in the `?+` header; each arm produces a `(quip card state-11)`.
  ::
  ++  handle-http
    |=  [eyre-id=@ta req=inbound-request:eyre]
    ^-  (quip card state-13)
    =/  req-body            body.request.req
    =/  segs=(list @t)      (parse-request-path url.request.req)
    =/  route=(list @t)     [method.request.req segs]
    ::  Admin surface requires a valid ship session; Cashu /v1 stays public
    ::  by protocol design. Eyre sets authenticated=%.y only for a %ours
    ::  session, so this boolean already guarantees the session ship is
    ::  our.bowl (no foreign session @p is exposed on the http request to
    ::  compare; cf. the %noun poke's =(src.bowl our.bowl) assertion).
    ?:  ?&  ?=([%apps %ecash %admin *] segs)
            !authenticated.req
        ==
      :_  st  (give-err eyre-id 401 'unauthorized')
    ::  CSRF: a state-changing admin request must be same-origin; a cross-site
    ::  POST riding on the operator session cookie is rejected (csrf-ok allows
    ::  safe methods and non-browser clients that send no Origin/Referer).
    ?:  ?&  ?=([%apps %ecash %admin *] segs)
            !(csrf-ok req)
        ==
      :_  st  (give-err eyre-id 403 'forbidden-cross-origin')
    ?+  route  :_  st  (give-err eyre-id 404 'not-found')
    ::
    ::  NUT-01: public keys
    ::
        [%'GET' %v1 %keys ~]
      :_  st  (get-keys-all eyre-id)
    ::
        [%'GET' %v1 %keys @ ~]
      :_  st  (get-keys-by-id eyre-id i.t.t.t.route)
    ::
    ::  NUT-02: keyset metadata
    ::
        [%'GET' %v1 %keysets ~]
      :_  st  (get-keysets-v1 eyre-id)
    ::
    ::  NUT-03: swap
    ::
        [%'POST' %v1 %swap ~]
      (post-swap eyre-id req-body)
    ::
    ::  NUT-04: mint
    ::
        [%'POST' %v1 %mint %quote @ ~]
      (post-mint-quote eyre-id i.t.t.t.t.route req-body)
    ::
        [%'GET' %v1 %mint %quote @ @ ~]
      (get-mint-quote eyre-id i.t.t.t.t.route i.t.t.t.t.t.route)
    ::
        [%'POST' %v1 %mint @ ~]
      (post-mint-v1 eyre-id i.t.t.t.route req-body)
    ::
    ::  NUT-05: melt
    ::
        [%'POST' %v1 %melt %quote @ ~]
      (post-melt-quote eyre-id i.t.t.t.t.route req-body)
    ::
        [%'GET' %v1 %melt %quote @ @ ~]
      (get-melt-quote eyre-id i.t.t.t.t.route i.t.t.t.t.t.route)
    ::
        [%'POST' %v1 %melt @ ~]
      (post-melt-v1 eyre-id i.t.t.t.route req-body)
    ::
    ::  NUT-06: mint info
    ::
        [%'GET' %v1 %info ~]
      :_  st  (get-info eyre-id)
    ::
    ::  NUT-07: token state
    ::
        [%'POST' %v1 %checkstate ~]
      (post-checkstate eyre-id req-body)
    ::
    ::  Legacy public endpoints (kept for backwards-compat)
    ::
        [%'GET' %apps %ecash ~]
      :_  st
      %-  give-json  :_  eyre-id
      %-  pairs:enjs:format
      :~  ['name' s+'ecash-mint']
          ['version' s+'0.2.0']
          ['active_keyset' s+active-keyset.st]
          ['tokens_issued' (numb:enjs:format counter.st)]
          ['crypto' s+'secp256k1-bdhke-pure-hoon']
      ==
    ::
        [%'GET' %apps %ecash %keysets ~]
      :_  st  (get-keys-all eyre-id)
        [%'GET' %apps %ecash %keysets %active ~]
      :_  st  (get-keys-all eyre-id)
        [%'GET' %apps %ecash %info ~]
      :_  st  (get-info eyre-id)
    ::
    ::  Admin HTML dashboard
    ::
        [%'GET' %apps %ecash %admin ~]
      :_  st
      (give-http eyre-id 200 [['content-type' 'text/html'] ~] `(as-octs:mimes:html (rap 3 (join `@t`10 `wain`dashboard-lines))))
    ::
    ::  Admin API: keyset management
    ::
        [%'GET' %apps %ecash %admin %api %overview ~]
      :_  st  (admin-overview eyre-id)
        [%'GET' %apps %ecash %admin %api %keysets ~]
      :_  st  (admin-keysets eyre-id)
        [%'GET' %apps %ecash %admin %api %keysets @ ~]
      :_  st  (admin-keyset-detail eyre-id i.t.t.t.t.t.t.route)
        [%'POST' %apps %ecash %admin %api %keysets %generate ~]
      (admin-keyset-generate eyre-id)
        [%'POST' %apps %ecash %admin %api %keysets %activate ~]
      (admin-keyset-activate eyre-id req-body)
        [%'POST' %apps %ecash %admin %api %keysets %deactivate ~]
      (admin-keyset-deactivate eyre-id req-body)
        [%'POST' %apps %ecash %admin %api %keysets %set-fee ~]
      (admin-keyset-set-fee eyre-id req-body)
    ::
    ::  Admin API: quotes
    ::
        [%'GET' %apps %ecash %admin %api %quotes ~]
      :_  st  (admin-quotes eyre-id)
        [%'POST' %apps %ecash %admin %api %quotes %delete ~]
      (admin-quote-delete eyre-id req-body)
    ::
    ::  Admin API: melt abort (operator-confirmed-failed backstop)
    ::
        [%'POST' %apps %ecash %admin %api %melt %abort ~]
      (admin-melt-abort eyre-id req-body)
    ::
    ::  Admin API: spent tokens
    ::
        [%'GET' %apps %ecash %admin %api %spent ~]
      :_  st  (admin-spent eyre-id)
        [%'POST' %apps %ecash %admin %api %spent %check ~]
      :_  st  (admin-spent-check eyre-id req-body)
    ::
    ::  Admin API: lightning
    ::
        [%'GET' %apps %ecash %admin %api %lightning ~]
      :_  st  (admin-lightning eyre-id)
        [%'POST' %apps %ecash %admin %api %lightning %configure ~]
      (admin-ln-configure eyre-id req-body)
        [%'POST' %apps %ecash %admin %api %lightning %test ~]
      (admin-ln-test eyre-id)
    ::
    ::  Admin API: mint info
    ::
        [%'GET' %apps %ecash %admin %api %info ~]
      :_  st  (get-info eyre-id)
        [%'POST' %apps %ecash %admin %api %info %update ~]
      (admin-info-update eyre-id req-body)
    ::
    ::  Admin API: mint settings
    ::
        [%'GET' %apps %ecash %admin %api %settings ~]
      :_  st  (admin-get-settings eyre-id)
        [%'POST' %apps %ecash %admin %api %settings ~]
      (admin-update-settings eyre-id req-body)
    ==
  ::
  ::  ============================================================
  ::  NUT-01: GET /v1/keys -all active keysets with full key maps
  ::  ============================================================
  ::
  ++  get-keys-all
    |=  eyre-id=@ta
    ^-  (list card)
    =/  ks-list
      ^-  (list json)
      %+  murn  ~(tap by keysets.st)
      |=  [id=@t ks=keyset]
      ?.  active.ks  ~
      %-  some
      %-  pairs:enjs:format
      :~  ['id' s+ks-id.ks]
          ['unit' s+unt.ks]
          ['active' b+active.ks]
          ['input_fee_ppk' (numb:enjs:format input-fee-ppk.ks)]
          :-  'keys'
          %-  pairs:enjs:format
          %+  turn  ~(tap by keys.ks)
          |=  [amt=@ud pub=@t]
          [(scot %ud amt) s+pub]
      ==
    (give-json (pairs:enjs:format ['keysets' [%a ks-list]]~) eyre-id)
  ::
  ::  ============================================================
  ::  NUT-02: GET /v1/keys/{keyset_id} -keys for specific keyset
  ::  ============================================================
  ::
  ++  get-keys-by-id
    |=  [eyre-id=@ta kid=@t]
    ^-  (list card)
    =/  maybe-ks  (~(get by keysets.st) kid)
    ?~  maybe-ks
      (give-err eyre-id 404 'keyset-not-found')
    =/  ks  u.maybe-ks
    =/  resp
      %-  pairs:enjs:format
      :~  :-  'keysets'
          :-  %a
          :~  %-  pairs:enjs:format
              :~  ['id' s+ks-id.ks]
                  ['unit' s+unt.ks]
                  ['active' b+active.ks]
                  ['input_fee_ppk' (numb:enjs:format input-fee-ppk.ks)]
                  :-  'keys'
                  %-  pairs:enjs:format
                  %+  turn  ~(tap by keys.ks)
                  |=  [amt=@ud pub=@t]
                  [(scot %ud amt) s+pub]
              ==
          ==
      ==
    (give-json resp eyre-id)
  ::
  ::  ============================================================
  ::  NUT-02: GET /v1/keysets -all keyset metadata (no keys)
  ::  ============================================================
  ::
  ++  get-keysets-v1
    |=  eyre-id=@ta
    ^-  (list card)
    =/  ks-list
      ^-  (list json)
      %+  turn  ~(tap by keysets.st)
      |=  [id=@t ks=keyset]
      %-  pairs:enjs:format
      :~  ['id' s+ks-id.ks]
          ['unit' s+unt.ks]
          ['active' b+active.ks]
          ['input_fee_ppk' (numb:enjs:format input-fee-ppk.ks)]
      ==
    (give-json (pairs:enjs:format ['keysets' [%a ks-list]]~) eyre-id)
  ::
  ::  ============================================================
  ::  NUT-03: POST /v1/swap -swap proofs for new blind signatures
  ::  ============================================================
  ::
  ++  post-swap
    |=  [eyre-id=@ta req-body=(unit octs)]
    ^-  (quip card state-13)
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_  st  (give-err eyre-id 400 p.parsed)
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    ?.  (has-key p.jon 'inputs')   :_  st  (give-err eyre-id 400 'missing-inputs')
    ?.  (has-key p.jon 'outputs')  :_  st  (give-err eyre-id 400 'missing-outputs')
    =/  inputs   (get-array p.jon 'inputs')
    =/  outputs  (get-array p.jon 'outputs')
    ?:  |((gth (lent inputs) max-batch) (gth (lent outputs) max-batch))
      :_  st  (give-err eyre-id 400 'batch-too-large')
    =/  vres  (verify-proofs inputs)
    ?:  ?=(%| -.vres)  :_  st  (give-err eyre-id 400 p.vres)
    =/  input-total=@ud         -.p.vres
    =/  updated-spent=(set @t)  +<.p.vres
    =/  updated-spent-ys        +>.p.vres
    =/  fee=@ud  (compute-fee inputs)
    ?:  (gth fee input-total)
      :_  st  (give-err eyre-id 400 'fee-exceeds-inputs')
    =/  output-total=@ud
      %+  roll  outputs
      |=  [msg=json acc=@ud]
      ?.  ?=([%o *] msg)  acc
      (add acc (get-num p.msg 'amount'))
    ?.  =((sub input-total fee) output-total)
      :_  st  (give-err eyre-id 400 'amounts-do-not-balance')
    ?:  (has-dup-x outputs)
      :_  st  (give-err eyre-id 400 'duplicate-output')
    =/  sigs  (sign-outputs outputs)
    =.  spent.st                updated-spent
    =.  spent-ys.st             updated-spent-ys
    =.  counter.st              (add counter.st (lent sigs))
    =.  total-issued-sats.st    (add total-issued-sats.st output-total)
    =.  total-redeemed-sats.st  (add total-redeemed-sats.st input-total)
    :_  st
    (give-json (pairs:enjs:format ['signatures' [%a sigs]]~) eyre-id)
  ::
  ::  ============================================================
  ::  NUT-04: Mint quote endpoints
  ::  ============================================================
  ::
  ++  post-mint-quote
    |=  [eyre-id=@ta method=@t req-body=(unit octs)]
    ^-  (quip card state-13)
    ?.  |(=('self' method) =('bolt11' method))
      :_  st  (give-err eyre-id 400 'unsupported-method')
    ?:  &(=('self' method) !self-method-enabled.st)
      :_  st  (give-err eyre-id 400 'self-method-disabled')
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_  st  (give-err eyre-id 400 p.parsed)
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    =/  amount=@ud  (get-num p.jon 'amount')
    ?:  =(0 amount)  :_  st  (give-err eyre-id 400 'invalid-amount')
    =/  qid=@t  gen-quote-id
    =/  expiry=@da  quote-expiry
    ?:  =('self' method)
      ::  Self method: auto-approve immediately
      =/  mq=mint-quote
        :*  quote-id=qid
            amount=amount
            unt='sat'
            request='self-mint'
            checking-id=''
            state=%paid
            expiry=expiry
            created=now.bowl
        ==
      =.  mint-quotes.st  (~(put by mint-quotes.st) qid mq)
      :_  st
      %-  give-json  :_  eyre-id
      %-  pairs:enjs:format
      :~  ['quote' s+qid]
          ['request' s+'self-mint']
          ['unit' s+'sat']
          ['amount' (numb:enjs:format amount)]
          ['state' s+'PAID']
          ['expiry' (numb:enjs:format (da-to-unix expiry))]
      ==
    ::  bolt11 method: create Lightning invoice
    ?:  ?=([%none ~] ln-config.st)
      :_  st  (give-err eyre-id 400 'no-lightning-backend-configured')
    =/  desc=@t  'ecash mint deposit'
    =/  mq=mint-quote
      :*  quote-id=qid
          amount=amount
          unt='sat'
          request=''
          checking-id=''
          state=%unpaid
          expiry=expiry
          created=now.bowl
      ==
    =.  mint-quotes.st  (~(put by mint-quotes.st) qid mq)
    =/  wire-id=@ta  (scot %uv (sham eny.bowl))
    =.  pending.st  (~(put by pending.st) wire-id [%mint-quote-create eyre-id qid amount])
    =/  req=request:http  (ln-create-invoice amount desc)
    :_  st
    :~  [%pass /ln/[wire-id] %arvo %i %request req *outbound-config:iris]
    ==
  ::
  ++  get-mint-quote
    |=  [eyre-id=@ta method=@t quote-id=@t]
    ^-  (quip card state-13)
    ?.  |(=('self' method) =('bolt11' method))
      :_  st  (give-err eyre-id 400 'unsupported-method')
    =/  maybe-mq  (~(get by mint-quotes.st) quote-id)
    ?~  maybe-mq
      :_  st  (give-err eyre-id 404 'quote-not-found')
    =/  mq  u.maybe-mq
    ::  For bolt11 unpaid quotes, check Lightning status
    ?:  &(=('bolt11' method) =(%unpaid state.mq) !=('' checking-id.mq))
      =/  wire-id=@ta  (scot %uv (sham eny.bowl))
      =.  pending.st  (~(put by pending.st) wire-id [%mint-quote-check eyre-id quote-id])
      =/  req=request:http  (ln-check-invoice checking-id.mq)
      :_  st
      :~  [%pass /ln/[wire-id] %arvo %i %request req *outbound-config:iris]
      ==
    ::  Otherwise return current state
    =/  st-text=@t  (quote-state-text state.mq)
    :_  st
    %-  give-json  :_  eyre-id
    %-  pairs:enjs:format
    :~  ['quote' s+quote-id.mq]
        ['request' s+request.mq]
        ['unit' s+unt.mq]
        ['amount' (numb:enjs:format amount.mq)]
        ['state' s+st-text]
        ['expiry' (numb:enjs:format (da-to-unix expiry.mq))]
    ==
  ::
  ++  post-mint-v1
    |=  [eyre-id=@ta method=@t req-body=(unit octs)]
    ^-  (quip card state-13)
    ?.  |(=('self' method) =('bolt11' method))
      :_  st  (give-err eyre-id 400 'unsupported-method')
    ?:  &(=('self' method) !self-method-enabled.st)
      :_  st  (give-err eyre-id 400 'self-method-disabled')
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_  st  (give-err eyre-id 400 p.parsed)
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    =/  qid=@t  (get-str p.jon 'quote')
    ?:  =('' qid)
      :_  st  (give-err eyre-id 400 'missing-quote')
    =/  maybe-mq  (~(get by mint-quotes.st) qid)
    ?~  maybe-mq
      :_  st  (give-err eyre-id 404 'quote-not-found')
    =/  mq  u.maybe-mq
    ::  A self-origin quote (request='self-mint') is minted with no payment, so
    ::  it must not be redeemable while the self method is disabled — regardless
    ::  of the URL method. Without this, a stale %paid self quote stays redeemable
    ::  via POST /v1/mint/bolt11 even with the flag off (free value).
    ?:  &(=('self-mint' request.mq) !self-method-enabled.st)
      :_  st  (give-err eyre-id 400 'self-method-disabled')
    ?.  =(%paid state.mq)
      :_  st  (give-err eyre-id 400 'quote-not-paid')
    ::  Once a quote is %paid the sats are already in the mint, so it stays
    ::  redeemable even past the original TTL — run-cleanup now retains %paid
    ::  mint quotes for exactly this reason. (Non-%paid quotes were already
    ::  rejected by the guard above, so an expiry check here could only ever
    ::  reject a deposit whose value was received: pure harm. Removed.)
    ?.  (has-key p.jon 'outputs')
      :_  st  (give-err eyre-id 400 'missing-outputs')
    =/  outputs  (get-array p.jon 'outputs')
    ?:  (gth (lent outputs) max-batch)
      :_  st  (give-err eyre-id 400 'batch-too-large')
    =/  output-total=@ud
      %+  roll  outputs
      |=  [msg=json acc=@ud]
      ?.  ?=([%o *] msg)  acc
      (add acc (get-num p.msg 'amount'))
    ?.  =(output-total amount.mq)
      :_  st  (give-err eyre-id 400 'output-amount-mismatch')
    ?:  (has-dup-x outputs)
      :_  st  (give-err eyre-id 400 'duplicate-output')
    =/  sigs  (sign-outputs outputs)
    =.  mint-quotes.st          (~(put by mint-quotes.st) qid mq(state %issued))
    =.  counter.st              (add counter.st (lent sigs))
    =.  total-issued-sats.st    (add total-issued-sats.st output-total)
    :_  st
    (give-json (pairs:enjs:format ['signatures' [%a sigs]]~) eyre-id)
  ::
  ::  ============================================================
  ::  NUT-05: Melt quote endpoints
  ::  ============================================================
  ::
  ++  post-melt-quote
    |=  [eyre-id=@ta method=@t req-body=(unit octs)]
    ^-  (quip card state-13)
    ?.  |(=('self' method) =('bolt11' method))
      :_  st  (give-err eyre-id 400 'unsupported-method')
    ?:  &(=('self' method) !self-method-enabled.st)
      :_  st  (give-err eyre-id 400 'self-method-disabled')
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_  st  (give-err eyre-id 400 p.parsed)
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    =/  bolt11=@t  (get-str p.jon 'request')
    ?:  =('self' method)
      =/  amount=@ud  (get-num p.jon 'amount')
      ?:  =(0 amount)
        :_  st  (give-err eyre-id 400 'missing-amount')
      =/  qid=@t  gen-quote-id
      =/  expiry=@da  quote-expiry
      =/  mq=melt-quote
        :*  quote-id=qid
            amount=amount
            fee-reserve=0
            unt='sat'
            request=(crip ?~(bolt11 "self-melt" (trip bolt11)))
            state=%unpaid
            payment-preimage=''
            payment-hash=''
            expiry=expiry
            created=now.bowl
        ==
      =.  melt-quotes.st  (~(put by melt-quotes.st) qid mq)
      :_  st
      %-  give-json  :_  eyre-id
      %-  pairs:enjs:format
      :~  ['quote' s+qid]
          ['amount' (numb:enjs:format amount)]
          ['request' s+request.mq]
          ['fee_reserve' n+'0']
          ['unit' s+'sat']
          ['state' s+'UNPAID']
          ['expiry' (numb:enjs:format (da-to-unix expiry))]
      ==
    ::  bolt11 method: decode the invoice via Lightning backend
    ?:  ?=([%none ~] ln-config.st)
      :_  st  (give-err eyre-id 400 'no-lightning-backend-configured')
    ?:  =('' bolt11)
      :_  st  (give-err eyre-id 400 'missing-request-bolt11')
    =/  qid=@t  gen-quote-id
    =/  wire-id=@ta  (scot %uv (sham eny.bowl))
    =.  pending.st  (~(put by pending.st) wire-id [%melt-quote-create eyre-id qid bolt11])
    =/  req=request:http  (ln-decode-invoice bolt11)
    :_  st
    :~  [%pass /ln/[wire-id] %arvo %i %request req *outbound-config:iris]
    ==
  ::
  ++  get-melt-quote
    |=  [eyre-id=@ta method=@t quote-id=@t]
    ^-  (quip card state-13)
    ?.  |(=('self' method) =('bolt11' method))
      :_  st  (give-err eyre-id 400 'unsupported-method')
    =/  maybe-mq  (~(get by melt-quotes.st) quote-id)
    ?~  maybe-mq
      :_  st  (give-err eyre-id 404 'quote-not-found')
    =/  mq  u.maybe-mq
    ::  For bolt11 pending payments, check status
    ?:  &(=('bolt11' method) =(%pending state.mq) !=('' payment-hash.mq))
      =/  wire-id=@ta  (scot %uv (sham eny.bowl))
      =.  pending.st  (~(put by pending.st) wire-id [%melt-check eyre-id quote-id])
      =/  req=request:http  (ln-check-payment payment-hash.mq)
      :_  st
      :~  [%pass /ln/[wire-id] %arvo %i %request req *outbound-config:iris]
      ==
    =/  st-text=@t  (quote-state-text state.mq)
    =/  stored-change=(list json)
      =/  mc  (~(get by melt-change.st) quote-id)
      ?~  mc  ~
      u.mc
    :_  st
    %-  give-json  :_  eyre-id
    %-  pairs:enjs:format
    :~  ['quote' s+quote-id.mq]
        ['amount' (numb:enjs:format amount.mq)]
        ['fee_reserve' (numb:enjs:format fee-reserve.mq)]
        ['unit' s+unt.mq]
        ['state' s+st-text]
        ['expiry' (numb:enjs:format (da-to-unix expiry.mq))]
        ['request' s+request.mq]
        ['payment_preimage' s+payment-preimage.mq]
        ['change' [%a stored-change]]
    ==
  ::
  ++  post-melt-v1
    |=  [eyre-id=@ta method=@t req-body=(unit octs)]
    ^-  (quip card state-13)
    ?.  |(=('self' method) =('bolt11' method))
      :_  st  (give-err eyre-id 400 'unsupported-method')
    ?:  &(=('self' method) !self-method-enabled.st)
      :_  st  (give-err eyre-id 400 'self-method-disabled')
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_  st  (give-err eyre-id 400 p.parsed)
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    =/  qid=@t  (get-str p.jon 'quote')
    ?:  =('' qid)
      :_  st  (give-err eyre-id 400 'missing-quote')
    =/  maybe-mq  (~(get by melt-quotes.st) qid)
    ?~  maybe-mq
      :_  st  (give-err eyre-id 404 'quote-not-found')
    =/  mq  u.maybe-mq
    ?:  (gth now.bowl expiry.mq)
      :_  st  (give-err eyre-id 400 'quote-expired')
    ::  NUT-05 single-use guard: reject a quote that is already in-flight
    ::  (%pending) or already settled (%paid). %unpaid and %failed fall through
    ::  so a quote whose pay definitively FAILED can be retried.
    ?:  =(%pending state.mq)
      :_  st  (give-err eyre-id 400 'quote-pending')
    ?:  =(%paid state.mq)
      :_  st  (give-err eyre-id 400 'quote-already-paid')
    ?.  (has-key p.jon 'inputs')
      :_  st  (give-err eyre-id 400 'missing-inputs')
    =/  inputs=(list json)  (get-array p.jon 'inputs')
    ?:  (gth (lent inputs) max-batch)
      :_  st  (give-err eyre-id 400 'batch-too-large')
    =/  vres  (verify-proofs inputs)
    ?:  ?=(%| -.vres)  :_  st  (give-err eyre-id 400 p.vres)
    =/  input-total=@ud         -.p.vres
    =/  updated-spent=(set @t)  +<.p.vres
    =/  updated-spent-ys        +>.p.vres
    ::  exact members added by this melt (full set minus prior state), captured
    ::  before mutation so a failed bolt11 pay can un-spend precisely.
    =/  added-secrets=(set @t)  (~(dif in updated-spent) spent.st)
    =/  added-ys=(set @t)       (~(dif in updated-spent-ys) spent-ys.st)
    =/  fee=@ud  (compute-fee inputs)
    ?:  (gth fee input-total)
      :_  st  (give-err eyre-id 400 'fee-exceeds-inputs')
    ::  inputs must cover the amount AND the fee reserve; otherwise a bolt11
    ::  melt mints up to fee_reserve in change that was never deposited.
    ::  (self melts set fee-reserve=0, so this is unchanged for them.)
    ?.  (gte (sub input-total fee) (add amount.mq fee-reserve.mq))
      :_  st  (give-err eyre-id 400 'insufficient-inputs')
    ::  NUT-08: optional blank outputs for change
    =/  change-outputs=(list json)  (get-array p.jon 'outputs')
    ?:  (gth (lent change-outputs) max-batch)
      :_  st  (give-err eyre-id 400 'batch-too-large')
    =.  spent.st                updated-spent
    =.  spent-ys.st             updated-spent-ys
    =.  total-redeemed-sats.st  (add total-redeemed-sats.st input-total)
    ?:  =('self' method)
      ::  Self method: fake preimage, immediate response
      =/  preimage=@t  (pad-hex (shax (add eny.bowl input-total)) 64)
      =.  melt-quotes.st
        (~(put by melt-quotes.st) qid mq(state %paid, payment-preimage preimage))
      ::  NUT-08: compute overpaid and sign change outputs
      =/  overpaid=@ud  (sub input-total (add fee amount.mq))
      =/  change-sigs=(list json)  (sign-change-outputs change-outputs overpaid)
      =?  melt-change.st  !=(~ change-sigs)
        (~(put by melt-change.st) qid change-sigs)
      :_  st
      %-  give-json  :_  eyre-id
      %-  pairs:enjs:format
      :~  ['quote' s+quote-id.mq]
          ['amount' (numb:enjs:format amount.mq)]
          ['request' s+request.mq]
          ['fee_reserve' (numb:enjs:format fee-reserve.mq)]
          ['unit' s+unt.mq]
          ['state' s+'PAID']
          ['paid' b+%.y]
          ['payment_preimage' s+preimage]
          ['expiry' (numb:enjs:format (da-to-unix expiry.mq))]
          ['change' [%a change-sigs]]
      ==
    ::  bolt11 method: pay via Lightning backend. Inputs are already marked
    ::  spent (above) and the quote moves to the in-flight %pending state so a
    ::  re-submit is rejected by the guard. Reconciliation data (exact members
    ::  spent, input total, change outputs) is persisted DURABLY in melt-inflight
    ::  keyed by quote-id, so the recheck path and admin abort can settle or roll
    ::  back even across a restart/migration. The pay response is treated as a
    ::  DISPATCH only; it can never roll back (see handle-ln-response %melt-pay).
    =.  melt-quotes.st
      (~(put by melt-quotes.st) qid mq(state %pending))
    =.  melt-inflight.st
      %+  ~(put by melt-inflight.st)  qid
      [added-secrets added-ys input-total change-outputs]
    =/  wire-id=@ta  (scot %uv (sham eny.bowl))
    =.  pending.st
      %+  ~(put by pending.st)  wire-id
      [%melt-pay eyre-id qid change-outputs added-secrets added-ys input-total]
    =/  req=request:http  (ln-pay-invoice request.mq fee-reserve.mq)
    :_  st
    :~  [%pass /ln/[wire-id] %arvo %i %request req *outbound-config:iris]
    ==
  ::
  ::  ============================================================
  ::  NUT-06: GET /v1/info -mint information
  ::  ============================================================
  ::
  ++  get-info
    |=  eyre-id=@ta
    ^-  (list card)
    =/  maybe-ks  (~(get by keysets.st) active-keyset.st)
    =/  mint-pub=@t
      ?~  maybe-ks  '02unknown'
      =/  key-list  ~(tap by keys.u.maybe-ks)
      ?~  key-list  '02unknown'
      q.i.key-list
    %-  give-json  :_  eyre-id
    %-  pairs:enjs:format
    :~  ['name' s+mint-name.st]
        ['pubkey' s+mint-pub]
        ['version' s+'ecash/0.2.0']
        ['description' s+mint-description.st]
        :-  'nuts'
        %-  pairs:enjs:format
        :~  :-  '1'
            %-  pairs:enjs:format
            :~  :-  'methods'
                :-  %a
                :~  %-  pairs:enjs:format
                    :~  ['method' s+'self']  ['unit' s+'sat']
                    ==
                ==
                ['disabled' b+%.n]
            ==
            :-  '2'
            %-  pairs:enjs:format
            :~  :-  'methods'
                :-  %a
                :~  %-  pairs:enjs:format
                    :~  ['method' s+'self']  ['unit' s+'sat']
                    ==
                ==
                ['disabled' b+%.n]
            ==
            :-  '3'
            (pairs:enjs:format ['supported' b+%.y]~)
            :-  '4'
            =/  methods=(list json)
              :~  %-  pairs:enjs:format
                  :~  ['method' s+'self']
                      ['unit' s+'sat']
                      ['min_amount' n+'1']
                      ['max_amount' n+'512']
                  ==
              ==
            =/  methods=_methods
              ?.  ?=([%none ~] ln-config.st)
                :_  methods
                %-  pairs:enjs:format
                :~  ['method' s+'bolt11']
                    ['unit' s+'sat']
                    ['min_amount' n+'1']
                    ['max_amount' n+'1000000']
                ==
              methods
            %-  pairs:enjs:format
            :~  ['methods' [%a methods]]
                ['disabled' b+%.n]
            ==
            :-  '5'
            =/  methods=(list json)
              :~  %-  pairs:enjs:format
                  :~  ['method' s+'self']
                      ['unit' s+'sat']
                      ['min_amount' n+'1']
                      ['max_amount' n+'512']
                  ==
              ==
            =/  methods=_methods
              ?.  ?=([%none ~] ln-config.st)
                :_  methods
                %-  pairs:enjs:format
                :~  ['method' s+'bolt11']
                    ['unit' s+'sat']
                    ['min_amount' n+'1']
                    ['max_amount' n+'1000000']
                ==
              methods
            %-  pairs:enjs:format
            :~  ['methods' [%a methods]]
                ['disabled' b+%.n]
            ==
            :-  '6'
            (pairs:enjs:format ['supported' b+%.y]~)
            :-  '7'
            (pairs:enjs:format ['supported' b+%.y]~)
            :-  '8'
            (pairs:enjs:format ['supported' b+%.y]~)
            :-  '10'
            (pairs:enjs:format ['supported' b+%.y]~)
            :-  '11'
            %-  pairs:enjs:format
            :~  ['supported' b+%.y]
                ['disabled' b+%.n]
            ==
            :-  '12'
            (pairs:enjs:format ['supported' b+%.y]~)
        ==
    ==
  ::
  ::  ============================================================
  ::  NUT-07: POST /v1/checkstate -check token spent status
  ::  ============================================================
  ::
  ++  post-checkstate
    |=  [eyre-id=@ta req-body=(unit octs)]
    ^-  (quip card state-13)
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_  st  (give-err eyre-id 400 p.parsed)
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    ?.  (has-key p.jon 'Ys')
      :_  st  (give-err eyre-id 400 'missing-Ys')
    =/  ys  (get-array p.jon 'Ys')
    ?:  (gth (lent ys) max-batch)
      :_  st  (give-err eyre-id 400 'batch-too-large')
    =/  states=(list json)
      %+  turn  ys
      |=  y-json=json
      ^-  json
      ?.  ?=([%s *] y-json)
        (pairs:enjs:format ~[['Y' s+''] ['state' s+'UNSPENT']])
      =/  y-hex=@t  p.y-json
      =/  st-text=@t
        ?:  (~(has in spent-ys.st) y-hex)  'SPENT'
        'UNSPENT'
      %-  pairs:enjs:format
      :~  ['Y' s+y-hex]
          ['state' s+st-text]
          ['witness' ~]
      ==
    :_  st
    (give-json (pairs:enjs:format ['states' [%a states]]~) eyre-id)
  ::
  ::  ============================================================
  ::  Shared helpers
  ::  ============================================================
  ::
  ::  Verify a list of input proofs, returning total and updated spent/spent-ys sets
  ++  verify-proofs
    |=  inputs=(list json)
    ^-  (each [@ud (set @t) (set @t)] @t)
    =/  total=@ud  0
    =/  spnt=(set @t)  spent.st
    =/  spnt-ys=(set @t)  spent-ys.st
    |-
    ?~  inputs
      [%& [total spnt spnt-ys]]
    =/  tok  i.inputs
    ?.  ?=([%o *] tok)  [%| 'invalid-proof']
    =/  c-hex=@t   (get-str p.tok 'C')
    =/  amt=@ud    (get-num p.tok 'amount')
    =/  secret=@t  (get-str p.tok 'secret')
    =/  kid=@t     (get-str p.tok 'id')
    =?  kid  =('' kid)  active-keyset.st
    ?:  (~(has in spnt) secret)
      [%| 'token-already-spent']
    =/  maybe-ks  (~(get by keysets.st) kid)
    ?~  maybe-ks
      [%| 'unknown-keyset']
    =/  ks  u.maybe-ks
    =/  maybe-priv  (~(get by privkeys.ks) amt)
    ?~  maybe-priv
      [%| 'unknown-denomination']
    =/  priv=@  u.maybe-priv
    =/  maybe-c-pt  (hex-to-pt c-hex)
    ?~  maybe-c-pt
      [%| 'invalid-C-point']
    =/  c-pt=point  u.maybe-c-pt
    =/  h-pt=point  (hash-to-curve (crip (trip secret)))
    =/  expected=point  (pt-mul priv h-pt)
    ?.  =(c-pt expected)
      [%| 'invalid-token-signature']
    ::  NUT-10/11: Check spending conditions
    =/  maybe-wk  (parse-wk-secret secret)
    ?^  maybe-wk
      =/  wk  u.maybe-wk
      ?:  =(kind.wk 'P2PK')
        =/  p2pk-err  (check-p2pk tok secret wk)
        ?^  p2pk-err
          [%| u.p2pk-err]
        =/  y-hex=@t  (pt-to-hex h-pt)
        %=  $
          inputs   t.inputs
          total    (add total amt)
          spnt     (~(put in spnt) secret)
          spnt-ys  (~(put in spnt-ys) y-hex)
        ==
      ::  Well-known NUT-10 secret with a kind we do not enforce (e.g. a
      ::  future HTLC kind). Refuse rather than bearer-spend it.
      [%| 'unsupported-spending-condition']
    ::  Regular (non-well-known) secret
    =/  y-hex=@t  (pt-to-hex h-pt)
    %=  $
      inputs   t.inputs
      total    (add total amt)
      spnt     (~(put in spnt) secret)
      spnt-ys  (~(put in spnt-ys) y-hex)
    ==
  ::
  ::  NUT-10: Parse well-known secret format ["kind", {nonce, data, tags}]
  ++  parse-wk-secret
    |=  secret=@t
    ^-  (unit [kind=@t data=@t tags=(list (list @t))])
    =/  maybe-json  (de:json:html secret)
    ?~  maybe-json  ~
    =/  jon  u.maybe-json
    ?.  ?=([%a *] jon)  ~
    ?.  =(2 (lent p.jon))  ~
    =/  kind-json  (snag 0 p.jon)
    =/  payload-json  (snag 1 p.jon)
    ?.  ?=([%s *] kind-json)  ~
    ?.  ?=([%o *] payload-json)  ~
    =/  data-val  (~(get by p.payload-json) 'data')
    ?~  data-val  ~
    ?.  ?=([%s *] u.data-val)  ~
    =/  tags-val  (~(get by p.payload-json) 'tags')
    =/  tags=(list (list @t))
      ?~  tags-val  ~
      ?.  ?=([%a *] u.tags-val)  ~
      %+  turn  p.u.tags-val
      |=  tag=json
      ?.  ?=([%a *] tag)  ~
      %+  turn  p.tag
      |=  v=json
      ?+  -.v  ''  %s  p.v  ==
    `[p.kind-json p.u.data-val tags]
  ::
  ::  NUT-10: Get values for a tag key from tags list
  ++  get-tag
    |=  [tags=(list (list @t)) key=@t]
    ^-  (list @t)
    |-
    ?~  tags  ~
    =/  tag  i.tags
    ?~  tag  $(tags t.tags)
    ?:  =(i.tag key)  t.tag
    $(tags t.tags)
  ::
  ::  NUT-11: Extract witness signatures from proof JSON
  ++  get-witness-sigs
    |=  tok=json
    ^-  (list @t)
    ?.  ?=([%o *] tok)  ~
    =/  wit-val  (~(get by p.tok) 'witness')
    ?~  wit-val  ~
    ?.  ?=([%s *] u.wit-val)  ~
    =/  maybe-wj  (de:json:html p.u.wit-val)
    ?~  maybe-wj  ~
    ?.  ?=([%o *] u.maybe-wj)  ~
    =/  sigs-val  (~(get by p.u.maybe-wj) 'signatures')
    ?~  sigs-val  ~
    ?.  ?=([%a *] u.sigs-val)  ~
    %+  turn  p.u.sigs-val
    |=  s=json
    ?+  -.s  ''  %s  p.s  ==
  ::
  ::  NUT-11: Count DISTINCT pubkeys that are satisfied by some signature.
  ::
  ::    Dedups pubkeys (silt) and ignores signature multiplicity, so one
  ::    keyholder cannot satisfy an n-of-m threshold by submitting several
  ::    (randomized) sigs or a duplicated sig. Mirrors cashu-ts:
  ::    Array.from(new Set(pubkeys)).filter(pk => sigs.some(verify)).length
  ::  NUT-11: canonical x-only key. schnorr-verify is x-only (lifts to
  ::  even-y), so a compressed key's parity prefix (02/03) is irrelevant to
  ::  verification. Map any 66-hex compressed key to a single representative
  ::  ('02' || x) so parity twins collapse to one signer under (silt ...).
  ::  Non-66-length cords pass through (they fail hex-to-pt downstream).
  ++  canon-x
    |=  pk=@t
    ^-  @t
    =/  chars  (trip pk)
    ?.  =(66 (lent chars))  pk
    ::  P2PK-1: schnorr-verify decodes hex case-insensitively, so 02<x> and
    ::  02<X> are the SAME signer. Lowercase the x-part (not just the parity
    ::  prefix) so a mixed-case parity twin collapses to one slot under (silt).
    (crip (weld "02" (cass (slag 2 chars))))
  ::
  ++  count-valid-sigs
    |=  [sigs=(list @t) pks=(list @t) msg=@]
    ^-  @ud
    =/  real-sigs=(list @t)  (skip sigs |=(s=@t =('' s)))
    ::  dedup on the canonical x-only key, not the full compressed cord, so a
    ::  02<x>/03<x> parity twin cannot satisfy two slots of an n-of-m threshold
    ::  with a single signature.
    =/  uniq-pks=(list @t)   ~(tap in (silt (turn pks canon-x)))
    %+  roll  uniq-pks
    |=  [pk=@t acc=@ud]
    =/  found
      %+  lien  real-sigs
      |=(s=@t (schnorr-verify pk msg s))
    ?:  found  +(acc)  acc
  ::
  ::  NUT-11: Check P2PK spending conditions
  ++  check-p2pk
    |=  [tok=json secret=@t wk=[kind=@t data=@t tags=(list (list @t))]]
    ^-  (unit @t)
    =/  sigs  (get-witness-sigs tok)
    ::  Check sigflag - only support SIG_INPUTS
    =/  sigflag-vals  (get-tag tags.wk 'sigflag')
    =/  sigflag=@t
      ?~  sigflag-vals  'SIG_INPUTS'
      i.sigflag-vals
    ?.  =(sigflag 'SIG_INPUTS')
      `'unsupported-sigflag'
    ::  Check locktime (reject a present-but-unparseable value)
    =/  locktime-vals  (get-tag tags.wk 'locktime')
    =/  maybe-locktime=(unit @ud)
      ?~  locktime-vals  `0
      (parse-ud-strict i.locktime-vals)
    ?~  maybe-locktime  `'invalid-locktime'
    =/  locktime=@ud  u.maybe-locktime
    ::  Collect valid pubkeys: data field + extra pubkeys tag
    =/  extra-pks  (get-tag tags.wk 'pubkeys')
    =/  all-pks=(list @t)  [data.wk extra-pks]
    ::  n_sigs threshold (reject a present-but-unparseable value; floor at 1)
    =/  nsigs-vals  (get-tag tags.wk 'n_sigs')
    =/  maybe-nsigs=(unit @ud)
      ?~  nsigs-vals  `1
      (parse-ud-strict i.nsigs-vals)
    ?~  maybe-nsigs  `'invalid-n-sigs'
    =/  n-sigs=@ud  (max 1 u.maybe-nsigs)
    ::  Check locktime & refund
    ?:  &((gth locktime 0) (gth (da-to-unix now.bowl) locktime))
      ::  Locktime expired - check refund keys
      =/  refund-pks  (get-tag tags.wk 'refund')
      ::  NUT-11: expired locktime + no refund keys = anyone-can-spend.
      ?~  refund-pks  ~
      ::  NUT-11 n_sigs_refund threshold (reject garbage; floor at 1)
      =/  nsr-vals  (get-tag tags.wk 'n_sigs_refund')
      =/  maybe-nsr=(unit @ud)
        ?~  nsr-vals  `1
        (parse-ud-strict i.nsr-vals)
      ?~  maybe-nsr  `'invalid-n-sigs-refund'
      =/  n-refund=@ud  (max 1 u.maybe-nsr)
      ?~  sigs  `'missing-witness-signatures'
      =/  msg  (shax secret)
      =/  valid  (count-valid-sigs sigs refund-pks msg)
      ?:  (gte valid n-refund)  ~
      `'invalid-refund-signature'
    ::  Normal case: verify n_sigs distinct signers from all_pks
    ?~  sigs  `'missing-witness-signatures'
    =/  msg  (shax secret)
    =/  valid  (count-valid-sigs sigs all-pks msg)
    ?:  (gte valid n-sigs)  ~
    `'insufficient-p2pk-signatures'
  ::
  ::  has-dup-x: does the output batch contain two B_ points sharing an
  ::    x-coordinate?  This is the B_/-B_ DLEQ nonce-reuse attack shape
  ::    (same x, negated y).  Malformed / missing B_ are skipped here; they
  ::    fail individually in sign-outputs.  Defense in depth on top of the
  ::    bdhke-level full-point nonce binding.
  ::
  ++  has-dup-x
    |=  outputs=(list json)
    ^-  ?
    =|  seen=(set @)
    |-  ^-  ?
    ?~  outputs  %.n
    =*  msg  i.outputs
    ?.  ?=([%o *] msg)  $(outputs t.outputs)
    =/  b-hex=@t  (get-str p.msg 'B_')
    ?:  =('' b-hex)  $(outputs t.outputs)
    =/  mb  (hex-to-pt b-hex)
    ?~  mb  $(outputs t.outputs)
    =/  xx=@  x.u.mb
    ?:  (~(has in seen) xx)  %.y
    $(outputs t.outputs, seen (~(put in seen) xx))
  ::
  ::  sign-outputs: sign each blinded output message in the list
  ::
  ::    Malformed messages produce per-element `{"error": ...}` JSON objects
  ::    rather than crashing the whole batch.
  ::
  ++  sign-outputs
    |=  outputs=(list json)
    ^-  (list json)
    %+  turn  outputs
    |=  msg=json
    ^-  json
    ?.  ?=([%o *] msg)
      (pairs:enjs:format ['error' s+'invalid-msg']~)
    =/  amt=@ud  (get-num p.msg 'amount')
    =/  b-hex=@t  (get-str p.msg 'B_')
    ?:  =('' b-hex)
      (pairs:enjs:format ['error' s+'missing-B_']~)
    =/  maybe-b-pt  (hex-to-pt b-hex)
    ?~  maybe-b-pt
      (pairs:enjs:format ['error' s+'invalid-B_-point']~)
    =/  b-=point  u.maybe-b-pt
    =/  kid=@t    (get-str p.msg 'id')
    =?  kid  =('' kid)  active-keyset.st
    =/  maybe-ks  (~(get by keysets.st) kid)
    ?~  maybe-ks
      (pairs:enjs:format ['error' s+'unknown-keyset']~)
    =/  ks  u.maybe-ks
    ::  setfee-1: refuse to MINT new outputs under an INACTIVE keyset (e.g. the
    ::  alias retained after admin-keyset-set-fee). Old tokens still VERIFY under
    ::  the alias (verify-proofs/compute-fee deliberately omit this check), but a
    ::  wallet must not keep issuing fresh tokens at the superseded fee.
    ?.  active.ks
      (pairs:enjs:format ['error' s+'inactive-keyset']~)
    =/  maybe-priv  (~(get by privkeys.ks) amt)
    ?~  maybe-priv
      (pairs:enjs:format ['error' s+'unknown-denomination']~)
    =/  priv=@  u.maybe-priv
    =/  c-=point  (blind-sign b- priv)
    =/  c-hex=@t  (pt-to-hex c-)
    ::  Mix the full B_ hex (02/03 prefix differs for B_ vs -B_) into rng so
    ::  same-amount outputs in one Gall event get distinct entropy.
    =/  rng=@  (shax (cat 3 b-hex (add eny.bowl (add now.bowl amt))))
    =/  dleq-es  (dleq-prove b- c- priv rng)
    =/  dleq-map=(map @t json)
      %-  my
      :~  ['e' s+(scalar-to-hex e.dleq-es)]
          ['s' s+(scalar-to-hex s.dleq-es)]
      ==
    %-  pairs:enjs:format
    :~  ['C_' s+c-hex]
        ['amount' (numb:enjs:format amt)]
        ['id' s+kid]
        ['dleq' [%o dleq-map]]
    ==
  ::
  ::  NUT-08: Sign blank change outputs with power-of-2 decomposition
  ++  sign-change-outputs
    |=  [outputs=(list json) overpaid=@ud]
    ^-  (list json)
    ?:  |(=(0 overpaid) =(~ outputs))  ~
    =/  amounts=(list @ud)  (split-amount overpaid)
    =/  n=@ud  (min (lent amounts) (lent outputs))
    =/  idx=@ud  0
    =/  acc=(list json)  ~
    |-
    ?:  =(idx n)  (flop acc)
    =/  amt=@ud  (snag idx amounts)
    =/  msg=json  (snag idx outputs)
    ?.  ?=([%o *] msg)  $(idx +(idx))
    =/  b-hex=@t  (get-str p.msg 'B_')
    ?:  =('' b-hex)  $(idx +(idx))
    =/  maybe-b-pt  (hex-to-pt b-hex)
    ?~  maybe-b-pt
      $(idx +(idx))
    =/  b-=point  u.maybe-b-pt
    =/  kid=@t  active-keyset.st
    =/  maybe-ks  (~(get by keysets.st) kid)
    ?~  maybe-ks
      $(idx +(idx))
    =/  ks  u.maybe-ks
    =/  maybe-priv  (~(get by privkeys.ks) amt)
    ?~  maybe-priv
      $(idx +(idx))
    =/  priv=@  u.maybe-priv
    =/  c-=point  (blind-sign b- priv)
    =/  c-hex=@t  (pt-to-hex c-)
    ::  Mix the full B_ hex (02/03 prefix differs for B_ vs -B_) into rng so
    ::  each blank-change output gets distinct entropy.
    =/  rng=@  (shax (cat 3 b-hex (add eny.bowl (add now.bowl (add amt idx)))))
    =/  dleq-es  (dleq-prove b- c- priv rng)
    =/  dleq-map=(map @t json)
      %-  my
      :~  ['e' s+(scalar-to-hex e.dleq-es)]
          ['s' s+(scalar-to-hex s.dleq-es)]
      ==
    =/  sig=json
      %-  pairs:enjs:format
      :~  ['C_' s+c-hex]
          ['amount' (numb:enjs:format amt)]
          ['id' s+kid]
          ['dleq' [%o dleq-map]]
      ==
    $(idx +(idx), acc [sig acc])
  ::
  ::  Convert @da to unix timestamp @ud
  ++  da-to-unix
    |=  da=@da
    ^-  @ud
    (div (sub da ~1970.1.1) ~s1)
  ::
  ::  Convert quote-state to JSON text
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
  ::  Split a tape on a character
  ++  split-tape
    |=  [t=tape c=@]
    ^-  (list tape)
    =|  acc=(list tape)
    =|  cur=tape
    |-
    ?~  t
      (flop [cur acc])
    ?:  =(i.t c)
      $(t t.t, acc [cur acc], cur ~)
    $(t t.t, cur (snoc cur i.t))
  ::
  ::  ============================================================
  ::  Admin API handlers (read-only, Phase 1)
  ::  ============================================================
  ::
  ++  admin-overview
    |=  eyre-id=@ta
    ^-  (list card)
    ::  Count quotes by state
    =/  mq-counts=[unpaid=@ud paid=@ud issued=@ud pending=@ud]
      %+  roll  ~(val by mint-quotes.st)
      |=  [mq=mint-quote acc=[unpaid=@ud paid=@ud issued=@ud pending=@ud]]
      ?-  state.mq
        %unpaid   acc(unpaid +(unpaid.acc))
        %paid     acc(paid +(paid.acc))
        %issued   acc(issued +(issued.acc))
        %pending  acc(pending +(pending.acc))
        %failed   acc(unpaid +(unpaid.acc))
      ==
    =/  lq-counts=[unpaid=@ud paid=@ud pending=@ud issued=@ud]
      %+  roll  ~(val by melt-quotes.st)
      |=  [mq=melt-quote acc=[unpaid=@ud paid=@ud pending=@ud issued=@ud]]
      ?-  state.mq
        %unpaid   acc(unpaid +(unpaid.acc))
        %paid     acc(paid +(paid.acc))
        %pending  acc(pending +(pending.acc))
        %issued   acc(issued +(issued.acc))
        %failed   acc(unpaid +(unpaid.acc))
      ==
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
        :~  ['unpaid' (numb:enjs:format unpaid.mq-counts)]
            ['paid' (numb:enjs:format paid.mq-counts)]
            ['issued' (numb:enjs:format issued.mq-counts)]
            ['pending' (numb:enjs:format pending.mq-counts)]
        ==
        :-  'melt_quotes'
        %-  pairs:enjs:format
        :~  ['unpaid' (numb:enjs:format unpaid.lq-counts)]
            ['paid' (numb:enjs:format paid.lq-counts)]
            ['pending' (numb:enjs:format pending.lq-counts)]
        ==
        :-  'ln_backend'
        %-  pairs:enjs:format
        :~  ['type' s+type.ln]
            ['url' s+url.ln]
            ['configured' b+configured.ln]
        ==
    ==
  ::
  ++  admin-keysets
    |=  eyre-id=@ta
    ^-  (list card)
    =/  ks-list=(list json)
      %+  turn  ~(tap by keysets.st)
      |=  [id=@t ks=keyset]
      ^-  json
      %-  pairs:enjs:format
      :~  ['id' s+id]
          ['unit' s+unt.ks]
          ['active' b+active.ks]
          ['input_fee_ppk' (numb:enjs:format input-fee-ppk.ks)]
          ['key_count' (numb:enjs:format ~(wyt by keys.ks))]
          ['created' (numb:enjs:format (da-to-unix created.ks))]
          :-  'denominations'
          :-  %a
          %+  turn
            %+  sort  ~(tap by keys.ks)
            |=  [a=[@ud @t] b=[@ud @t]]
            (lth -.a -.b)
          |=  [d=@ud pub=@t]
          (numb:enjs:format d)
      ==
    %-  give-json  :_  eyre-id
    (pairs:enjs:format ['keysets' [%a ks-list]]~)
  ::
  ++  admin-keyset-detail
    |=  [eyre-id=@ta ks-id=@t]
    ^-  (list card)
    =/  maybe-ks  (~(get by keysets.st) ks-id)
    ?~  maybe-ks
      (give-err eyre-id 404 'keyset-not-found')
    =/  ks  u.maybe-ks
    =/  sorted-keys=(list [@ud @t])
      %+  sort  ~(tap by keys.ks)
      |=  [a=[@ud @t] b=[@ud @t]]
      (lth -.a -.b)
    %-  give-json  :_  eyre-id
    %-  pairs:enjs:format
    :~  ['id' s+ks-id]
        ['unit' s+unt.ks]
        ['active' b+active.ks]
        ['input_fee_ppk' (numb:enjs:format input-fee-ppk.ks)]
        ['created' (numb:enjs:format (da-to-unix created.ks))]
        :-  'keys'
        %-  pairs:enjs:format
        %+  turn  sorted-keys
        |=  [d=@ud pub=@t]
        [(crip (trip (scot %ud d))) s+pub]
    ==
  ::
  ++  admin-quotes
    |=  eyre-id=@ta
    ^-  (list card)
    ::  Mint quotes sorted by created desc
    =/  mq-list=(list json)
      =/  sorted=(list mint-quote)
        %+  sort  ~(val by mint-quotes.st)
        |=  [a=mint-quote b=mint-quote]
        (gth created.a created.b)
      %+  turn  sorted
      |=  mq=mint-quote
      ^-  json
      %-  pairs:enjs:format
      :~  ['quote_id' s+quote-id.mq]
          ['amount' (numb:enjs:format amount.mq)]
          ['unit' s+unt.mq]
          ['request' s+request.mq]
          ['checking_id' s+checking-id.mq]
          ['state' s+(quote-state-text state.mq)]
          ['expiry' (numb:enjs:format (da-to-unix expiry.mq))]
          ['created' (numb:enjs:format (da-to-unix created.mq))]
          ['expired' b+(gth now.bowl expiry.mq)]
      ==
    ::  Melt quotes sorted by created desc
    =/  lq-list=(list json)
      =/  sorted=(list melt-quote)
        %+  sort  ~(val by melt-quotes.st)
        |=  [a=melt-quote b=melt-quote]
        (gth created.a created.b)
      %+  turn  sorted
      |=  mq=melt-quote
      ^-  json
      %-  pairs:enjs:format
      :~  ['quote_id' s+quote-id.mq]
          ['amount' (numb:enjs:format amount.mq)]
          ['fee_reserve' (numb:enjs:format fee-reserve.mq)]
          ['unit' s+unt.mq]
          ['request' s+request.mq]
          ['state' s+(quote-state-text state.mq)]
          ['payment_preimage' s+payment-preimage.mq]
          ['payment_hash' s+payment-hash.mq]
          ['expiry' (numb:enjs:format (da-to-unix expiry.mq))]
          ['created' (numb:enjs:format (da-to-unix created.mq))]
          ['expired' b+(gth now.bowl expiry.mq)]
      ==
    %-  give-json  :_  eyre-id
    %-  pairs:enjs:format
    :~  ['mint_quotes' [%a mq-list]]
        ['melt_quotes' [%a lq-list]]
    ==
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
    |=  [eyre-id=@ta req-body=(unit octs)]
    ^-  (list card)
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  (give-err eyre-id 400 p.parsed)
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    ?:  (has-key p.jon 'secret')
      =/  secret=@t  (get-str p.jon 'secret')
      %-  give-json  :_  eyre-id
      %-  pairs:enjs:format
      :~  ['secret' s+secret]
          ['spent' b+(~(has in spent.st) secret)]
      ==
    ?.  (has-key p.jon 'Y')
      (give-err eyre-id 400 'missing-secret-or-Y')
    =/  y-hex=@t  (get-str p.jon 'Y')
    %-  give-json  :_  eyre-id
    %-  pairs:enjs:format
    :~  ['Y' s+y-hex]
        ['spent' b+(~(has in spent-ys.st) y-hex)]
    ==
  ::
  ++  admin-lightning
    |=  eyre-id=@ta
    ^-  (list card)
    =/  ln  ln-summary
    =/  aks=?
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
        ['api_key_set' b+aks]
    ==
  ::
  ::  ============================================================
  ::  Admin API handlers (write, Phase 2: keyset management)
  ::  ============================================================
  ::
  ++  admin-keyset-generate
    |=  eyre-id=@ta
    ^-  (quip card state-13)
    =/  keys      (gen-ks-keys (shax eny.bowl))
    =/  ks-id=@t  (compute-ks-id pubkeys.keys 'sat' 0 0)
    =/  ks=keyset
      :*  ks-id=ks-id
          active=%.n
          unt='sat'
          input-fee-ppk=0
          keys=pubkeys.keys
          privkeys=privkeys.keys
          created=now.bowl
      ==
    =.  keysets.st  (~(put by keysets.st) ks-id ks)
    :_  st
    %-  give-json  :_  eyre-id
    %-  pairs:enjs:format
    :~  ['id' s+ks-id]
        ['active' b+%.n]
        ['key_count' (numb:enjs:format ~(wyt by pubkeys.keys))]
    ==
  ::
  ++  admin-keyset-activate
    |=  [eyre-id=@ta req-body=(unit octs)]
    ^-  (quip card state-13)
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_(st (give-err eyre-id 400 p.parsed))
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    =/  target-id=@t  (get-str p.jon 'id')
    ?:  =('' target-id)  :_(st (give-err eyre-id 400 'missing-id'))
    =/  maybe-ks  (~(get by keysets.st) target-id)
    ?~  maybe-ks  :_(st (give-err eyre-id 404 'keyset-not-found'))
    =/  old-ks  (~(get by keysets.st) active-keyset.st)
    =?  keysets.st  ?=(^ old-ks)
      (~(put by keysets.st) active-keyset.st u.old-ks(active %.n))
    =.  keysets.st        (~(put by keysets.st) target-id u.maybe-ks(active %.y))
    =.  active-keyset.st  target-id
    :_  st
    %-  give-json  :_  eyre-id
    (pairs:enjs:format ['id' s+target-id] ['active' b+%.y] ~)
  ::
  ++  admin-keyset-deactivate
    |=  [eyre-id=@ta req-body=(unit octs)]
    ^-  (quip card state-13)
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_(st (give-err eyre-id 400 p.parsed))
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    =/  target-id=@t  (get-str p.jon 'id')
    ?:  =('' target-id)  :_(st (give-err eyre-id 400 'missing-id'))
    =/  maybe-ks  (~(get by keysets.st) target-id)
    ?~  maybe-ks  :_(st (give-err eyre-id 404 'keyset-not-found'))
    ?:  =(target-id active-keyset.st)
      :_(st (give-err eyre-id 400 'cannot-deactivate-active'))
    =.  keysets.st  (~(put by keysets.st) target-id u.maybe-ks(active %.n))
    :_  st
    %-  give-json  :_  eyre-id
    (pairs:enjs:format ['id' s+target-id] ['active' b+%.n] ~)
  ::
  ++  admin-keyset-set-fee
    |=  [eyre-id=@ta req-body=(unit octs)]
    ^-  (quip card state-13)
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_(st (give-err eyre-id 400 p.parsed))
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    =/  target-id=@t  (get-str p.jon 'id')
    ?:  =('' target-id)  :_(st (give-err eyre-id 400 'missing-id'))
    ?.  (has-key p.jon 'input_fee_ppk')
      :_(st (give-err eyre-id 400 'missing-input_fee_ppk'))
    =/  new-fee=@ud  (get-num p.jon 'input_fee_ppk')
    ?:  (gth new-fee max-input-fee-ppk)
      :_(st (give-err eyre-id 400 'input_fee_ppk-too-large'))
    =/  maybe-ks  (~(get by keysets.st) target-id)
    ?~  maybe-ks  :_(st (give-err eyre-id 404 'keyset-not-found'))
    =/  new-ks-id=@t  (compute-ks-id keys.u.maybe-ks unt.u.maybe-ks new-fee 0)
    =/  was-active=?  =(target-id active-keyset.st)
    ::  No-op: fee unchanged (the id commits to the fee) so the id is identical.
    ?:  =(new-ks-id target-id)
      =.  keysets.st
        (~(put by keysets.st) target-id u.maybe-ks(input-fee-ppk new-fee))
      :_  st
      %-  give-json  :_  eyre-id
      %-  pairs:enjs:format
      :~  ['old_id' s+target-id]
          ['new_id' s+new-ks-id]
          ['input_fee_ppk' (numb:enjs:format new-fee)]
      ==
    ::  Refuse to clobber an unrelated keyset that already owns new-ks-id.
    ?:  (~(has by keysets.st) new-ks-id)
      :_(st (give-err eyre-id 409 'keyset-id-collision'))
    ::  RETAIN the old id as an INACTIVE alias (keeping its OLD fee/id) so
    ::  already-issued tokens that carry it still resolve in verify-proofs /
    ::  compute-fee. Add the new-id entry with the new fee, active iff the
    ::  target was active. Changing the fee forks the keyset; it never bricks
    ::  outstanding tokens.
    =/  new-ks=keyset
      u.maybe-ks(input-fee-ppk new-fee, ks-id new-ks-id, active was-active)
    =.  keysets.st  (~(put by keysets.st) target-id u.maybe-ks(active %.n))
    =.  keysets.st  (~(put by keysets.st) new-ks-id new-ks)
    =?  active-keyset.st  was-active  new-ks-id
    :_  st
    %-  give-json  :_  eyre-id
    %-  pairs:enjs:format
    :~  ['old_id' s+target-id]
        ['new_id' s+new-ks-id]
        ['input_fee_ppk' (numb:enjs:format new-fee)]
    ==
  ::
  ::  ============================================================
  ::  Admin API handlers (write, Phase 3: Lightning config)
  ::  ============================================================
  ::
  ++  admin-ln-configure
    |=  [eyre-id=@ta req-body=(unit octs)]
    ^-  (quip card state-13)
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_(st (give-err eyre-id 400 p.parsed))
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    =/  ln-type=@t  (get-str p.jon 'type')
    ?:  =('' ln-type)  :_(st (give-err eyre-id 400 'missing-type'))
    ?:  =(ln-type 'none')
      =.  ln-config.st  [%none ~]
      :_  st
      %-  give-json  :_  eyre-id
      (pairs:enjs:format ['type' s+'none'] ['configured' b+%.n]~)
    =/  ln-url=@t  (get-str p.jon 'url')
    ?:  =('' ln-url)  :_(st (give-err eyre-id 400 'missing-url'))
    ?:  =(ln-type 'lnbits')
      =/  api-key=@t  (get-str p.jon 'api_key')
      ?:  =('' api-key)  :_(st (give-err eyre-id 400 'missing-api_key'))
      =.  ln-config.st  [%lnbits ln-url api-key]
      :_  st
      %-  give-json  :_  eyre-id
      (pairs:enjs:format ['type' s+'lnbits'] ['url' s+ln-url] ['configured' b+%.y]~)
    ?:  =(ln-type 'lnd')
      =/  macaroon=@t  (get-str p.jon 'macaroon')
      ?:  =('' macaroon)  :_(st (give-err eyre-id 400 'missing-macaroon'))
      =.  ln-config.st  [%lnd ln-url macaroon]
      :_  st
      %-  give-json  :_  eyre-id
      (pairs:enjs:format ['type' s+'lnd'] ['url' s+ln-url] ['configured' b+%.y]~)
    :_(st (give-err eyre-id 400 'unknown-type'))
  ::
  ++  admin-ln-test
    |=  eyre-id=@ta
    ^-  (quip card state-13)
    ?:  ?=([%none ~] ln-config.st)
      :_(st (give-err eyre-id 400 'no-ln-backend'))
    =/  ln  ln-summary
    :_  st
    %-  give-json  :_  eyre-id
    %-  pairs:enjs:format
    :~  ['status' s+'configured']
        ['type' s+type.ln]
        ['url' s+url.ln]
        ['message' s+'Backend configured. Create a small mint quote to verify connectivity.']
    ==
  ::
  ::  ============================================================
  ::  Admin API handlers (write, Phase 4: quote management)
  ::  ============================================================
  ::
  ++  admin-quote-delete
    |=  [eyre-id=@ta req-body=(unit octs)]
    ^-  (quip card state-13)
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_(st (give-err eyre-id 400 p.parsed))
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    =/  qid=@t    (get-str p.jon 'quote_id')
    =/  qtype=@t  (get-str p.jon 'type')
    ?:  =('' qid)    :_(st (give-err eyre-id 400 'missing-quote_id'))
    ?:  =('' qtype)  :_(st (give-err eyre-id 400 'missing-type'))
    ?:  =(qtype 'mint')
      =/  maybe-q  (~(get by mint-quotes.st) qid)
      ?~  maybe-q  :_(st (give-err eyre-id 404 'quote-not-found'))
      ?:  =(state.u.maybe-q %issued)
        :_(st (give-err eyre-id 400 'cannot-delete-issued'))
      ::  A %paid mint quote means sats were received but not yet issued —
      ::  deleting it destroys an owed deposit, mirroring cannot-delete-paid-melt.
      ?:  =(state.u.maybe-q %paid)
        :_(st (give-err eyre-id 400 'cannot-delete-paid-mint'))
      =.  mint-quotes.st  (~(del by mint-quotes.st) qid)
      :_  st
      %-  give-json  :_  eyre-id
      (pairs:enjs:format ['deleted' b+%.y] ['quote_id' s+qid] ['type' s+'mint']~)
    ?:  =(qtype 'melt')
      =/  maybe-q  (~(get by melt-quotes.st) qid)
      ?~  maybe-q  :_(st (give-err eyre-id 404 'quote-not-found'))
      ?:  =(state.u.maybe-q %paid)
        :_(st (give-err eyre-id 400 'cannot-delete-paid-melt'))
      ::  MIG-2: a %pending melt has its inputs already spent with a live LN
      ::  dispatch and a durable melt-inflight record; deleting it strands the
      ::  spent proofs and orphans inflight. Refuse; route operator to /melt/abort.
      ?:  |(=(state.u.maybe-q %pending) (~(has by melt-inflight.st) qid))
        :_(st (give-err eyre-id 400 'cannot-delete-pending-melt'))
      =.  melt-quotes.st  (~(del by melt-quotes.st) qid)
      :_  st
      %-  give-json  :_  eyre-id
      (pairs:enjs:format ['deleted' b+%.y] ['quote_id' s+qid] ['type' s+'melt']~)
    :_(st (give-err eyre-id 400 'invalid-type'))
  ::  admin-melt-abort: operator-confirmed-failed backstop for a stuck %pending
  ::  bolt11 melt. When the operator has independently verified the Lightning
  ::  payment did NOT and will not settle, this un-spends EXACTLY the persisted
  ::  members, decrements the redeemed counter (underflow-guarded), sets the
  ::  quote %failed (retryable), and clears the inflight record. Also recovers
  ::  quotes stranded %pending across a restart. Body: {"quote_id": "..."}.
  ::
  ::  admin-melt-abort: operator backstop for a stuck %pending bolt11 melt.
  ::    MELT-2: never roll back blind. Default path is ASYNC -- dispatch
  ::    ln-check-payment under a %melt-abort pending entry and defer the
  ::    settle-or-rollback decision to handle-ln-response (settle if LN shows
  ::    settled, else operator-authorized un-spend; the only 404->rollback path).
  ::    Synchronous fallbacks cover cases with no possible LN re-check: ln-config
  ::    %none, empty payment-hash, or (MIG-1) a legacy stuck quote with no inflight.
  ++  admin-melt-abort
    |=  [eyre-id=@ta req-body=(unit octs)]
    ^-  (quip card state-13)
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_(st (give-err eyre-id 400 p.parsed))
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    =/  qid=@t  (get-str p.jon 'quote_id')
    ?:  =('' qid)  :_(st (give-err eyre-id 400 'missing-quote_id'))
    =/  maybe-mq  (~(get by melt-quotes.st) qid)
    ?~  maybe-mq  :_(st (give-err eyre-id 404 'quote-not-found'))
    =/  mq  u.maybe-mq
    ?.  =(%pending state.mq)
      :_(st (give-err eyre-id 400 'quote-not-pending'))
    =/  maybe-inflight  (~(get by melt-inflight.st) qid)
    ::  Operator FORCE flag (body "force":true). Absent/non-bool -> %.n (the
    ::  conservative default): an ambiguous LN signal leaves the quote %pending.
    =/  force=?  (get-bool p.jon 'force')
    ::  Can we LN-re-check? Need a backend AND a payment-hash to query.
    =/  can-ln-check=?
      ?&  !?=([%none ~] ln-config.st)
          !=('' payment-hash.mq)
      ==
    ?:  can-ln-check
      ::  ASYNC: verify on Lightning before touching any spend state. The
      ::  settle-or-rollback happens in handle-ln-response under the dispatched
      ::  tag; here we mutate ONLY the pending map. Force selects the variant
      ::  whose handler authorizes a rollback on any non-settled outcome.
      =/  wire-id=@ta  (scot %uv (sham eny.bowl))
      =/  pend-tag=pending-req-v2
        ?:  force  [%melt-abort-force eyre-id qid]
        [%melt-abort eyre-id qid]
      =.  pending.st  (~(put by pending.st) wire-id pend-tag)
      =/  req=request:http  (ln-check-payment payment-hash.mq)
      :_  st
      :~  [%pass /ln/[wire-id] %arvo %i %request req *outbound-config:iris]
      ==
    ::  Ambiguous & not authorized: a backend IS configured (so failure is in
    ::  principle verifiable, we just lack the hash) and force is off. Treat like
    ::  the async paid:false/404 case -- do NOT roll back, leave the quote
    ::  %pending. Sync-rollback is allowed only for %none (no LN to ever query)
    ::  or an explicit operator force.
    ?:  &(!?=([%none ~] ln-config.st) !force)
      ~&  >>>  [%ecash-melt-abort-unverifiable qid]
      :_  st
      %-  give-json  :_  eyre-id
      %-  pairs:enjs:format
      :~  ['aborted' b+%.n]
          ['result' s+'in-flight-or-unconfirmed']
          ['ln_checked' b+%.n]
          ['quote_id' s+qid]
      ==
    ::  SYNCHRONOUS rollback authorized: ln-config %none (no LN to ever check),
    ::  OR the operator forced it. The operator is asserting failure.
    ?^  maybe-inflight
      =/  inflight  u.maybe-inflight
      =.  spent.st     (~(dif in spent.st) secrets.inflight)
      =.  spent-ys.st  (~(dif in spent-ys.st) ys.inflight)
      =.  total-redeemed-sats.st
        ?:  (gte total-redeemed-sats.st input-total.inflight)
          (sub total-redeemed-sats.st input-total.inflight)
        0
      =.  melt-quotes.st  (~(put by melt-quotes.st) qid mq(state %failed))
      =.  melt-inflight.st  (~(del by melt-inflight.st) qid)
      :_  st
      %-  give-json  :_  eyre-id
      %-  pairs:enjs:format
      :~  ['aborted' b+%.y]
          ['ln_checked' b+%.n]
          ['quote_id' s+qid]
          ['unspent_secrets' (numb:enjs:format ~(wyt in secrets.inflight))]
          ['redeemed_decremented' (numb:enjs:format input-total.inflight)]
      ==
    ::  MIG-1: legacy stuck %pending with NO inflight (pre-Phase-6). Accept
    ::  OPTIONAL operator-supplied secrets/ys to un-spend best-effort; else just
    ::  set %failed so the quote unsticks (those proofs are NOT reclaimed).
    =/  sup-secrets=(set @t)
      %-  ~(gas in *(set @t))
      %+  murn  (get-array p.jon 'secrets')
      |=(j=json ?:(?=([%s *] j) (some p.j) ~))
    =/  sup-ys=(set @t)
      %-  ~(gas in *(set @t))
      %+  murn  (get-array p.jon 'ys')
      |=(j=json ?:(?=([%s *] j) (some p.j) ~))
    =.  spent.st     (~(dif in spent.st) sup-secrets)
    =.  spent-ys.st  (~(dif in spent-ys.st) sup-ys)
    =.  melt-quotes.st  (~(put by melt-quotes.st) qid mq(state %failed))
    :_  st
    %-  give-json  :_  eyre-id
    %-  pairs:enjs:format
    :~  ['aborted' b+%.y]
        ['ln_checked' b+%.n]
        ['legacy_recovery' b+%.y]
        ['quote_id' s+qid]
        ['unspent_secrets' (numb:enjs:format ~(wyt in sup-secrets))]
        ['redeemed_decremented' (numb:enjs:format 0)]
    ==
  ::
  ::  ============================================================
  ::  Admin API handlers (write, Phase 5: mint info)
  ::  ============================================================
  ::
  ++  admin-info-update
    |=  [eyre-id=@ta req-body=(unit octs)]
    ^-  (quip card state-13)
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_(st (give-err eyre-id 400 p.parsed))
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    =?  mint-name.st         (has-key p.jon 'name')         (get-str p.jon 'name')
    =?  mint-description.st  (has-key p.jon 'description')  (get-str p.jon 'description')
    :_  st
    %-  give-json  :_  eyre-id
    %-  pairs:enjs:format
    :~  ['name' s+mint-name.st]
        ['description' s+mint-description.st]
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
  ++  admin-update-settings
    |=  [eyre-id=@ta req-body=(unit octs)]
    ^-  (quip card state-13)
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_(st (give-err eyre-id 400 p.parsed))
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    =?  fee-reserve-pct.st  (has-key p.jon 'fee_reserve_pct')  (get-num p.jon 'fee_reserve_pct')
    =?  fee-reserve-min.st  (has-key p.jon 'fee_reserve_min')  (get-num p.jon 'fee_reserve_min')
    =?  quote-ttl-secs.st   (has-key p.jon 'quote_ttl_secs')   (get-num p.jon 'quote_ttl_secs')
    =?  self-method-enabled.st  (has-key p.jon 'self_method_enabled')
      (get-bool p.jon 'self_method_enabled')
    :_  st
    %-  give-json  :_  eyre-id
    %-  pairs:enjs:format
    :~  ['fee_reserve_pct' (numb:enjs:format fee-reserve-pct.st)]
        ['fee_reserve_min' (numb:enjs:format fee-reserve-min.st)]
        ['quote_ttl_secs' (numb:enjs:format quote-ttl-secs.st)]
        ['self_method_enabled' b+self-method-enabled.st]
    ==
  ::
  ::  ============================================================
  ::  Lightning backend helpers
  ::  ============================================================
  ::
  ::  Build request to create a Lightning invoice
  ++  ln-create-invoice
    |=  [amount=@ud memo=@t]
    ^-  request:http
    ?-    -.ln-config.st
        %lnbits
      =/  body=@t
        %-  en:json:html
        %-  pairs:enjs:format
        :~  ['out' b+%.n]
            ['amount' (numb:enjs:format amount)]
            ['memo' s+memo]
        ==
      :*  %'POST'
          (crip (weld (trip url.ln-config.st) "/api/v1/payments"))
          :~  ['Content-Type' 'application/json']
              ['X-Api-Key' api-key.ln-config.st]
          ==
          `[(met 3 body) body]
      ==
    ::
        %lnd
      =/  body=@t
        %-  en:json:html
        %-  pairs:enjs:format
        :~  ['value' (numb:enjs:format amount)]
            ['memo' s+memo]
        ==
      :*  %'POST'
          (crip (weld (trip url.ln-config.st) "/v1/invoices"))
          :~  ['Content-Type' 'application/json']
              ['Grpc-Metadata-macaroon' macaroon.ln-config.st]
          ==
          `[(met 3 body) body]
      ==
    ::
        %none
      !!
    ==
  ::
  ::  Build request to check invoice payment status
  ++  ln-check-invoice
    |=  checking-id=@t
    ^-  request:http
    ?-    -.ln-config.st
        %lnbits
      :*  %'GET'
          (crip :(weld (trip url.ln-config.st) "/api/v1/payments/" (trip checking-id)))
          :~  ['X-Api-Key' api-key.ln-config.st]
          ==
          ~
      ==
    ::
        %lnd
      :*  %'GET'
          (crip :(weld (trip url.ln-config.st) "/v1/invoice/" (trip checking-id)))
          :~  ['Grpc-Metadata-macaroon' macaroon.ln-config.st]
          ==
          ~
      ==
    ::
        %none
      !!
    ==
  ::
  ::  Build request to decode a bolt11 invoice
  ++  ln-decode-invoice
    |=  bolt11=@t
    ^-  request:http
    ?-    -.ln-config.st
        %lnbits
      =/  body=@t
        %-  en:json:html
        (pairs:enjs:format ['data' s+bolt11]~)
      :*  %'POST'
          (crip (weld (trip url.ln-config.st) "/api/v1/payments/decode"))
          :~  ['Content-Type' 'application/json']
              ['X-Api-Key' api-key.ln-config.st]
          ==
          `[(met 3 body) body]
      ==
    ::
        %lnd
      :*  %'GET'
          (crip :(weld (trip url.ln-config.st) "/v1/payreq/" (trip bolt11)))
          :~  ['Grpc-Metadata-macaroon' macaroon.ln-config.st]
          ==
          ~
      ==
    ::
        %none
      !!
    ==
  ::
  ::  Build request to pay a bolt11 invoice
  ++  ln-pay-invoice
    |=  [bolt11=@t fee-limit=@ud]
    ^-  request:http
    ?-    -.ln-config.st
        %lnbits
      =/  body=@t
        %-  en:json:html
        %-  pairs:enjs:format
        :~  ['out' b+%.y]
            ['bolt11' s+bolt11]
            ['fee_limit_msat' (numb:enjs:format (mul fee-limit 1.000))]
        ==
      :*  %'POST'
          (crip (weld (trip url.ln-config.st) "/api/v1/payments"))
          :~  ['Content-Type' 'application/json']
              ['X-Api-Key' api-key.ln-config.st]
          ==
          `[(met 3 body) body]
      ==
    ::
        %lnd
      =/  body=@t
        %-  en:json:html
        %-  pairs:enjs:format
        :~  ['payment_request' s+bolt11]
            :-  'fee_limit'
            %-  pairs:enjs:format
            ['fixed_msat' (numb:enjs:format (mul fee-limit 1.000))]~
        ==
      :*  %'POST'
          (crip (weld (trip url.ln-config.st) "/v1/channels/transactions"))
          :~  ['Content-Type' 'application/json']
              ['Grpc-Metadata-macaroon' macaroon.ln-config.st]
          ==
          `[(met 3 body) body]
      ==
    ::
        %none
      !!
    ==
  ::
  ::  Build request to check outgoing payment status
  ++  ln-check-payment
    |=  payment-hash=@t
    ^-  request:http
    ?-    -.ln-config.st
        %lnbits
      :*  %'GET'
          (crip :(weld (trip url.ln-config.st) "/api/v1/payments/" (trip payment-hash)))
          :~  ['X-Api-Key' api-key.ln-config.st]
          ==
          ~
      ==
    ::
        %lnd
      :*  %'GET'
          (crip :(weld (trip url.ln-config.st) "/v1/payment/" (trip payment-hash)))
          :~  ['Grpc-Metadata-macaroon' macaroon.ln-config.st]
          ==
          ~
      ==
    ::
        %none
      !!
    ==
  ::
  ::  ============================================================
  ::  Lightning response handler
  ::  ============================================================
  ::
  ++  handle-ln-response
    |=  [wire-id=@ta res=client-response:iris]
    ^-  (quip card state-13)
    =/  maybe-pend  (~(get by pending.st) wire-id)
    ?~  maybe-pend
      ~&  >>>  [%ecash-ln-response-no-pending wire-id]
      `st
    =/  pend  u.maybe-pend
    ?.  ?=(%finished -.res)
      ::  Non-settled outcome (%cancel on runtime cancel/restart/timeout). For an
      ::  OUTBOUND pay this is AMBIGUOUS: the HTLC may already be in flight or
      ::  settled. We must NOT un-spend or fail here -- doing so let a re-submit
      ::  double-pay. Keep the quote %pending (proofs stay spent) and reply
      ::  NUT-05 PENDING; settlement is decided later only by a status check
      ::  (get-melt-quote -> %melt-check) or an operator abort. For a non-pay
      ::  request (decode/invoice-create/checks) nothing is spent, so 502 it.
      ~&  >>>  [%ecash-ln-response-not-finished -.res wire-id]
      =.  pending.st  (~(del by pending.st) wire-id)
      ?.  ?=(%melt-pay -.pend)
        :_  st  (give-err eyre-id.pend 502 'lightning-request-cancelled')
      =/  maybe-mq  (~(get by melt-quotes.st) quote-id.pend)
      ?~  maybe-mq
        :_  st  (give-err eyre-id.pend 500 'quote-lost')
      =/  mq  u.maybe-mq
      :_  st
      %-  give-json  :_  eyre-id.pend
      %-  pairs:enjs:format
      :~  ['quote' s+quote-id.pend]
          ['amount' (numb:enjs:format amount.mq)]
          ['request' s+request.mq]
          ['fee_reserve' (numb:enjs:format fee-reserve.mq)]
          ['unit' s+unt.mq]
          ['state' s+'PENDING']
          ['payment_preimage' s+'']
          ['expiry' (numb:enjs:format (da-to-unix expiry.mq))]
          ['change' [%a ~]]
      ==
    =.  pending.st  (~(del by pending.st) wire-id)
    =/  status  status-code.response-header.res
    =/  body=@t
      ?~  full-file.res  ''
      q.data.u.full-file.res
    =/  maybe-json=(unit json)
      ?:  =('' body)  ~
      (de:json:html body)
    ?-    -.pend
    ::
    ::  -- mint-quote-create: LN invoice created --
        %mint-quote-create
      ?:  |(!=(200 status) ?=(~ maybe-json))
        ~&  >>>  [%ecash-ln-create-invoice-failed status]
        :_  st
        (give-err eyre-id.pend 502 'lightning-invoice-creation-failed')
      =/  jon  u.maybe-json
      ?.  ?=([%o *] jon)
        :_  st  (give-err eyre-id.pend 502 'lightning-bad-response')
      ::  Extract bolt11 and checking_id from response
      =/  bolt11=@t  (extract-str jon 'payment_request' 'bolt11')
      =/  chk-id=@t  (extract-str jon 'checking_id' 'r_hash')
      =/  maybe-mq  (~(get by mint-quotes.st) quote-id.pend)
      ?~  maybe-mq
        :_  st  (give-err eyre-id.pend 500 'quote-lost')
      =/  mq  u.maybe-mq
      =.  mint-quotes.st
        (~(put by mint-quotes.st) quote-id.pend mq(request bolt11, checking-id chk-id))
      :_  st
      %-  give-json  :_  eyre-id.pend
      %-  pairs:enjs:format
      :~  ['quote' s+quote-id.pend]
          ['request' s+bolt11]
          ['unit' s+'sat']
          ['amount' (numb:enjs:format amount.pend)]
          ['state' s+'UNPAID']
          ['expiry' (numb:enjs:format (da-to-unix expiry.mq))]
      ==
    ::
    ::  -- mint-quote-check: check if LN invoice is paid --
        %mint-quote-check
      =/  maybe-mq  (~(get by mint-quotes.st) quote-id.pend)
      ?~  maybe-mq
        :_  st  (give-err eyre-id.pend 404 'quote-not-found')
      =/  mq  u.maybe-mq
      =/  is-paid=?
        ?~  maybe-json  %.n
        ?.  ?=([%o *] u.maybe-json)  %.n
        ?-  -.ln-config.st
            %lnbits
          ?.  (get-bool p.u.maybe-json 'paid')  %.n
          ::  cross-check settled amount >= quoted amount (NUT robustness):
          ::  never flip to PAID on an underpaid/zero invoice.
          (gte (ln-settled-sats p.u.maybe-json) amount.mq)
        ::
            %lnd
          ?.  =('SETTLED' (get-str p.u.maybe-json 'state'))  %.n
          (gte (ln-settled-sats p.u.maybe-json) amount.mq)
        ::
          %none    %.n
        ==
      ::  Only ever promote a still-%unpaid quote to %paid. A late or repeat
      ::  check can land AFTER the deposit was minted (state %issued); without
      ::  this guard is-paid would clobber %issued -> %paid, re-passing the
      ::  /v1/mint/bolt11 'quote-not-paid' check and double-issuing (inflation).
      =/  promote=?  &(is-paid =(%unpaid state.mq))
      =?  mint-quotes.st  promote
        (~(put by mint-quotes.st) quote-id.pend mq(state %paid))
      =/  st-text=@t  (quote-state-text ?:(promote %paid state.mq))
      :_  st
      %-  give-json  :_  eyre-id.pend
      %-  pairs:enjs:format
      :~  ['quote' s+quote-id.pend]
          ['request' s+request.mq]
          ['unit' s+unt.mq]
          ['amount' (numb:enjs:format amount.mq)]
          ['state' s+st-text]
          ['expiry' (numb:enjs:format (da-to-unix expiry.mq))]
      ==
    ::
    ::  -- melt-quote-create: bolt11 decoded, create quote --
        %melt-quote-create
      ?:  |(!=(200 status) ?=(~ maybe-json))
        ~&  >>>  [%ecash-ln-decode-failed status]
        :_  st
        (give-err eyre-id.pend 502 'lightning-decode-failed')
      =/  jon  u.maybe-json
      ?.  ?=([%o *] jon)
        :_  st  (give-err eyre-id.pend 502 'lightning-bad-response')
      ::  Extract amount from decoded invoice
      =/  amount=@ud
        ?-  -.ln-config.st
          %lnbits  (div (get-num p.jon 'amount_msat') 1.000)
          %lnd     ?:  (has-key p.jon 'num_satoshis')
                     =/  ns  (get-str p.jon 'num_satoshis')
                     ?:  =('' ns)  (get-num p.jon 'num_satoshis')
                     (parse-ud ns)
                   0
          %none    0
        ==
      ?:  =(0 amount)
        :_  st  (give-err eyre-id.pend 400 'could-not-decode-invoice-amount')
      ::  Fee reserve from configurable percent + minimum
      =/  fee-reserve=@ud  (melt-fee-reserve amount)
      =/  expiry=@da  quote-expiry
      ::  Capture payment_hash at quote CREATION (LNbits decode returns it; LND
      ::  exposes r_hash) so a later %pending recheck via get-melt-quote can fire
      ::  ln-check-payment instead of being dead code behind a `''` guard.
      =/  pay-hash=@t  (extract-str jon 'payment_hash' 'r_hash')
      =/  mq=melt-quote
        :*  quote-id=quote-id.pend
            amount=amount
            fee-reserve=fee-reserve
            unt='sat'
            request=bolt11.pend
            state=%unpaid
            payment-preimage=''
            payment-hash=pay-hash
            expiry=expiry
            created=now.bowl
        ==
      =.  melt-quotes.st  (~(put by melt-quotes.st) quote-id.pend mq)
      :_  st
      %-  give-json  :_  eyre-id.pend
      %-  pairs:enjs:format
      :~  ['quote' s+quote-id.pend]
          ['amount' (numb:enjs:format amount)]
          ['request' s+request.mq]
          ['fee_reserve' (numb:enjs:format fee-reserve)]
          ['unit' s+'sat']
          ['state' s+'UNPAID']
          ['expiry' (numb:enjs:format (da-to-unix expiry))]
      ==
    ::
    ::  -- melt-pay: LN payment result --
        %melt-pay
      =/  maybe-mq  (~(get by melt-quotes.st) quote-id.pend)
      ?~  maybe-mq
        :_  st  (give-err eyre-id.pend 500 'quote-lost')
      =/  mq  u.maybe-mq
      ::  The pay response is DISPATCH confirmation only. Accept any 2xx (real
      ::  LNbits returns 201 Created on accept; the payment may still be in
      ::  flight). A non-2xx / empty body / non-%finished is AMBIGUOUS, never a
      ::  proven failure -- we keep the quote %pending (proofs stay spent) and
      ::  reply NUT-05 PENDING. We NEVER un-spend or set %failed here; the only
      ::  authoritative failure comes from a later status check (%melt-check).
      =/  is-2xx=?  &((gte status 200) (lth status 300))
      =/  pre-settled=?
        ?&  is-2xx
            ?=(^ maybe-json)
            ?=([%o *] u.maybe-json)
            ::  POSITIVE settlement signal: non-empty preimage AND no error.
            !=('' (extract-str u.maybe-json 'payment_preimage' 'preimage'))
            =('' (extract-str u.maybe-json 'payment_error' 'error'))
        ==
      ?.  pre-settled
        ::  Dispatched but settlement unconfirmed (201 in-flight, empty body,
        ::  non-2xx, or carries an error). Stay %pending; the client re-polls.
        ~&  >>>  [%ecash-ln-pay-dispatched-pending status]
        :_  st
        %-  give-json  :_  eyre-id.pend
        %-  pairs:enjs:format
        :~  ['quote' s+quote-id.pend]
            ['amount' (numb:enjs:format amount.mq)]
            ['request' s+request.mq]
            ['fee_reserve' (numb:enjs:format fee-reserve.mq)]
            ['unit' s+unt.mq]
            ['state' s+'PENDING']
            ['payment_preimage' s+'']
            ['expiry' (numb:enjs:format (da-to-unix expiry.mq))]
            ['change' [%a ~]]
        ==
      ::  Settlement PROVEN in the dispatch response (preimage present, no error).
      ::  pre-settled already verified these; assert to narrow for the compiler.
      ?>  ?=(^ maybe-json)
      ?>  ?=([%o *] u.maybe-json)
      =/  jon  u.maybe-json
      =/  preimage=@t  (extract-str jon 'payment_preimage' 'preimage')
      =/  pay-hash=@t  (extract-str jon 'payment_hash' 'checking_id')
      ::  MIG-3: only ever settle a still-%pending quote. A late/duplicate
      ::  dispatch response landing after an abort/fail (or a prior settle)
      ::  must NOT re-promote it -> re-sign change -> re-emit PAID (double-settle).
      ?.  =(%pending state.mq)
        ~&  >>>  [%ecash-melt-pay-settle-stale quote-id.pend state.mq]
        :_  st
        %-  give-json  :_  eyre-id.pend
        %-  pairs:enjs:format
        :~  ['quote' s+quote-id.pend]
            ['amount' (numb:enjs:format amount.mq)]
            ['request' s+request.mq]
            ['fee_reserve' (numb:enjs:format fee-reserve.mq)]
            ['unit' s+unt.mq]
            ['state' s+(quote-state-text state.mq)]
            ['payment_preimage' s+payment-preimage.mq]
            ['expiry' (numb:enjs:format (da-to-unix expiry.mq))]
            ['change' [%a ~]]
        ==
      =.  melt-quotes.st
        (~(put by melt-quotes.st) quote-id.pend mq(state %paid, payment-preimage preimage, payment-hash pay-hash))
      ::  NUT-08: refund the unused reserve = fee_reserve − actual routing fee.
      ::  FAIL CLOSED: missing/garbage/negative fee -> full reserve (refund 0);
      ::  positive msat fee ceil-rounded to sats and capped at the reserve.
      =/  actual-fee=@ud  (routing-fee-sats jon fee-reserve.mq)
      =/  refund=@ud  (sub fee-reserve.mq actual-fee)
      =/  change-sigs=(list json)  (sign-change-outputs outputs.pend refund)
      =?  melt-change.st  !=(~ change-sigs)
        (~(put by melt-change.st) quote-id.pend change-sigs)
      ::  Settled: the inflight reconciliation record is no longer needed.
      =.  melt-inflight.st  (~(del by melt-inflight.st) quote-id.pend)
      :_  st
      %-  give-json  :_  eyre-id.pend
      %-  pairs:enjs:format
      :~  ['quote' s+quote-id.pend]
          ['amount' (numb:enjs:format amount.mq)]
          ['request' s+request.mq]
          ['fee_reserve' (numb:enjs:format fee-reserve.mq)]
          ['unit' s+unt.mq]
          ['state' s+'PAID']
          ['paid' b+%.y]
          ['payment_preimage' s+preimage]
          ['expiry' (numb:enjs:format (da-to-unix expiry.mq))]
          ['change' [%a change-sigs]]
      ==
    ::
    ::  -- melt-check: check outgoing payment status --
        %melt-check
      =/  maybe-mq  (~(get by melt-quotes.st) quote-id.pend)
      ?~  maybe-mq
        :_  st  (give-err eyre-id.pend 404 'quote-not-found')
      =/  mq  u.maybe-mq
      ::  Resolve the status check into one of three AUTHORITATIVE outcomes.
      =/  is-paid=?
        ?:  =(404 status)  %.n
        ?~  maybe-json  %.n
        ?.  ?=([%o *] u.maybe-json)  %.n
        ?-  -.ln-config.st
          %lnbits  (get-bool p.u.maybe-json 'paid')
          %lnd     =('SUCCEEDED' (get-str p.u.maybe-json 'status'))
          %none    %.n
        ==
      =/  resp-preimage=@t
        ?~  maybe-json  ''
        ?.  ?=([%o *] u.maybe-json)  ''
        (extract-str u.maybe-json 'preimage' 'payment_preimage')
      ::  MELT-1: the AUTO poll must NEVER roll back on absence/ambiguity. A bare
      ::  404 in the in-flight window (a status GET racing the just-dispatched
      ::  %melt-pay, or a decode-hash vs checking_id mismatch) is NOT proof of
      ::  failure -- un-spending while the HTLC settles double-spends + double-pays.
      ::  So the auto path treats ONLY an explicit LND terminal status=='FAILED'
      ::  as confirmed-failed; an LNbits 404 / pending / no-preimage stays PENDING.
      ::  Genuine LNbits failures are recovered via the operator abort (the only
      ::  path authorized to roll back on a 404, and it re-checks LN first).
      =/  confirmed-failed=?
        ?&  ?=(%lnd -.ln-config.st)
            ?=(^ maybe-json)
            ?=([%o *] u.maybe-json)
            =('FAILED' (get-str p.u.maybe-json 'status'))
        ==
      =/  maybe-inflight  (~(get by melt-inflight.st) quote-id.pend)
      ::  MIG-3: only a still-%pending quote may be settled by an auto check. A
      ::  late SETTLED check arriving after an abort/fail (or a prior settle)
      ::  must NOT re-promote -> re-sign change -> re-emit PAID (double-settle).
      ?:  &(is-paid !=('' resp-preimage) =(%pending state.mq))
        ::  SETTLED: lock %paid, sign NUT-08 change from persisted outputs, store
        ::  preimage, clear inflight, reply PAID.
        =/  inflight
          ?~  maybe-inflight  *melt-inflight-entry
          u.maybe-inflight
        ::  FAIL CLOSED on the routing fee (see routing-fee-sats): missing /
        ::  garbage / negative -> full reserve (refund 0); positive ceil-rounded.
        =/  actual-fee=@ud
          ?~  maybe-json  fee-reserve.mq
          (routing-fee-sats u.maybe-json fee-reserve.mq)
        =/  refund=@ud  (sub fee-reserve.mq actual-fee)
        =/  change-sigs=(list json)  (sign-change-outputs change.inflight refund)
        =?  melt-change.st  !=(~ change-sigs)
          (~(put by melt-change.st) quote-id.pend change-sigs)
        =.  melt-quotes.st
          (~(put by melt-quotes.st) quote-id.pend mq(state %paid, payment-preimage resp-preimage))
        =.  melt-inflight.st  (~(del by melt-inflight.st) quote-id.pend)
        :_  st
        %-  give-json  :_  eyre-id.pend
        %-  pairs:enjs:format
        :~  ['quote' s+quote-id.pend]
            ['amount' (numb:enjs:format amount.mq)]
            ['fee_reserve' (numb:enjs:format fee-reserve.mq)]
            ['unit' s+unt.mq]
            ['request' s+request.mq]
            ['state' s+'PAID']
            ['payment_preimage' s+resp-preimage]
            ['expiry' (numb:enjs:format (da-to-unix expiry.mq))]
            ['change' [%a change-sigs]]
        ==
      ?:  &(confirmed-failed ?=(^ maybe-inflight) =(%pending state.mq))
        ::  CONFIRMED FAILED (LND explicit FAILED only -- see MELT-1): un-spend
        ::  EXACTLY the persisted members, decrement (underflow-guarded), set
        ::  %failed, clear inflight, reply UNPAID. Gated on %pending so a late
        ::  FAILED cannot un-spend a quote another event already settled/failed.
        ~&  >>>  [%ecash-melt-confirmed-failed quote-id.pend status]
        =/  inflight  u.maybe-inflight
        =.  spent.st     (~(dif in spent.st) secrets.inflight)
        =.  spent-ys.st  (~(dif in spent-ys.st) ys.inflight)
        =.  total-redeemed-sats.st
          ?:  (gte total-redeemed-sats.st input-total.inflight)
            (sub total-redeemed-sats.st input-total.inflight)
          0
        =.  melt-quotes.st
          (~(put by melt-quotes.st) quote-id.pend mq(state %failed))
        =.  melt-inflight.st  (~(del by melt-inflight.st) quote-id.pend)
        :_  st
        %-  give-json  :_  eyre-id.pend
        %-  pairs:enjs:format
        :~  ['quote' s+quote-id.pend]
            ['amount' (numb:enjs:format amount.mq)]
            ['fee_reserve' (numb:enjs:format fee-reserve.mq)]
            ['unit' s+unt.mq]
            ['request' s+request.mq]
            ['state' s+'UNPAID']
            ['payment_preimage' s+'']
            ['expiry' (numb:enjs:format (da-to-unix expiry.mq))]
            ['change' [%a ~]]
        ==
      ::  STILL PENDING: no definitive signal yet. Leave everything as-is.
      =/  stored-change=(list json)
        =/  mc  (~(get by melt-change.st) quote-id.pend)
        ?~  mc  ~
        u.mc
      :_  st
      %-  give-json  :_  eyre-id.pend
      %-  pairs:enjs:format
      :~  ['quote' s+quote-id.pend]
          ['amount' (numb:enjs:format amount.mq)]
          ['fee_reserve' (numb:enjs:format fee-reserve.mq)]
          ['unit' s+unt.mq]
          ['request' s+request.mq]
          ['state' s+(quote-state-text state.mq)]
          ['payment_preimage' s+payment-preimage.mq]
          ['expiry' (numb:enjs:format (da-to-unix expiry.mq))]
          ['change' [%a stored-change]]
      ==
    ::
    ::  -- melt-abort: operator-authorized abort, LN re-checked (MELT-2) --
        %melt-abort
      =/  maybe-mq  (~(get by melt-quotes.st) quote-id.pend)
      ?~  maybe-mq
        :_  st  (give-err eyre-id.pend 404 'quote-not-found')
      =/  mq  u.maybe-mq
      ::  Settlement detection: same parsing as %melt-check. A bare 404 here
      ::  means LN has no record -> NOT settled -> the operator's asserted
      ::  failure stands and we roll back (the ONLY operator-authorized
      ::  404->rollback path).
      =/  is-settled=?
        ?:  =(404 status)  %.n
        ?~  maybe-json  %.n
        ?.  ?=([%o *] u.maybe-json)  %.n
        ?-  -.ln-config.st
          %lnbits  (get-bool p.u.maybe-json 'paid')
          %lnd     =('SUCCEEDED' (get-str p.u.maybe-json 'status'))
          %none    %.n
        ==
      =/  resp-preimage=@t
        ?~  maybe-json  ''
        ?.  ?=([%o *] u.maybe-json)  ''
        (extract-str u.maybe-json 'preimage' 'payment_preimage')
      =/  maybe-inflight  (~(get by melt-inflight.st) quote-id.pend)
      ::  SETTLED-NOT-ABORTED: LN shows the pay settled and the quote is still
      ::  %pending (MIG-3). Do NOT roll back; SETTLE instead (sign NUT-08 change,
      ::  store preimage, %paid, clear inflight). Fixes MELT-2's loss-on-abort.
      ?:  &(is-settled !=('' resp-preimage) =(%pending state.mq))
        =/  inflight
          ?~  maybe-inflight  *melt-inflight-entry
          u.maybe-inflight
        =/  actual-fee=@ud
          ?~  maybe-json  fee-reserve.mq
          (routing-fee-sats u.maybe-json fee-reserve.mq)
        =/  refund=@ud  (sub fee-reserve.mq actual-fee)
        =/  change-sigs=(list json)  (sign-change-outputs change.inflight refund)
        =?  melt-change.st  !=(~ change-sigs)
          (~(put by melt-change.st) quote-id.pend change-sigs)
        =.  melt-quotes.st
          (~(put by melt-quotes.st) quote-id.pend mq(state %paid, payment-preimage resp-preimage))
        =.  melt-inflight.st  (~(del by melt-inflight.st) quote-id.pend)
        :_  st
        %-  give-json  :_  eyre-id.pend
        %-  pairs:enjs:format
        :~  ['aborted' b+%.n]
            ['result' s+'settled-not-aborted']
            ['quote_id' s+quote-id.pend]
            ['state' s+'PAID']
            ['payment_preimage' s+resp-preimage]
        ==
      ::  NOT SETTLED. CONSERVATIVE (non-force) abort: only an explicit LND
      ::  status==FAILED is a confirmed failure (same predicate as the auto
      ::  %melt-check path). paid:false / IN_FLIGHT / UNKNOWN / 404 /
      ::  SUCCEEDED-without-preimage are AMBIGUOUS -- indistinguishable from
      ::  in-flight for an outbound HTLC, so un-spending here would double-pay a
      ::  live payment. Ambiguous -> leave %pending, do NOT roll back.
      =/  confirmed-failed=?
        ?&  ?=(%lnd -.ln-config.st)
            ?=(^ maybe-json)
            ?=([%o *] u.maybe-json)
            =('FAILED' (get-str p.u.maybe-json 'status'))
        ==
      ?.  &(confirmed-failed =(%pending state.mq) ?=(^ maybe-inflight))
        ::  Ambiguous (or already non-%pending, or no inflight to reverse):
        ::  refuse to touch spend state. Leave the quote %pending for the auto
        ::  poll / a later force abort to resolve.
        ~&  >>>  [%ecash-melt-abort-ambiguous quote-id.pend status]
        :_  st
        %-  give-json  :_  eyre-id.pend
        %-  pairs:enjs:format
        :~  ['aborted' b+%.n]
            ['result' s+'in-flight-or-unconfirmed']
            ['ln_checked' b+%.y]
            ['quote_id' s+quote-id.pend]
            ['state' s+(quote-state-text state.mq)]
        ==
      ::  CONFIRMED FAILED (LND explicit FAILED), still %pending, inflight
      ::  present: un-spend EXACTLY the persisted members, decrement
      ::  (underflow-guarded), %failed, clear inflight. Identical to the auto path.
      ~&  >>>  [%ecash-melt-abort-confirmed-failed quote-id.pend status]
      =/  inflight  u.maybe-inflight
      =.  spent.st     (~(dif in spent.st) secrets.inflight)
      =.  spent-ys.st  (~(dif in spent-ys.st) ys.inflight)
      =.  total-redeemed-sats.st
        ?:  (gte total-redeemed-sats.st input-total.inflight)
          (sub total-redeemed-sats.st input-total.inflight)
        0
      =.  melt-quotes.st  (~(put by melt-quotes.st) quote-id.pend mq(state %failed))
      =.  melt-inflight.st  (~(del by melt-inflight.st) quote-id.pend)
      :_  st
      %-  give-json  :_  eyre-id.pend
      %-  pairs:enjs:format
      :~  ['aborted' b+%.y]
          ['result' s+'aborted-confirmed-failed']
          ['ln_checked' b+%.y]
          ['quote_id' s+quote-id.pend]
          ['unspent_secrets' (numb:enjs:format ~(wyt in secrets.inflight))]
          ['redeemed_decremented' (numb:enjs:format input-total.inflight)]
      ==
    ::
    ::  -- melt-abort-force: operator FORCE abort, LN re-checked (MELT-2) --
    ::  Same LN settlement detection as %melt-abort, but on ANY non-settled
    ::  outcome (ambiguous OR confirmed-failed) the operator has authorized the
    ::  rollback. A SETTLED pay is STILL settled, never lost, even under force.
        %melt-abort-force
      =/  maybe-mq  (~(get by melt-quotes.st) quote-id.pend)
      ?~  maybe-mq
        :_  st  (give-err eyre-id.pend 404 'quote-not-found')
      =/  mq  u.maybe-mq
      =/  is-settled=?
        ?:  =(404 status)  %.n
        ?~  maybe-json  %.n
        ?.  ?=([%o *] u.maybe-json)  %.n
        ?-  -.ln-config.st
          %lnbits  (get-bool p.u.maybe-json 'paid')
          %lnd     =('SUCCEEDED' (get-str p.u.maybe-json 'status'))
          %none    %.n
        ==
      =/  resp-preimage=@t
        ?~  maybe-json  ''
        ?.  ?=([%o *] u.maybe-json)  ''
        (extract-str u.maybe-json 'preimage' 'payment_preimage')
      =/  maybe-inflight  (~(get by melt-inflight.st) quote-id.pend)
      ::  SETTLED-NOT-ABORTED: never lose a settled pay, even under force.
      ?:  &(is-settled !=('' resp-preimage) =(%pending state.mq))
        =/  inflight
          ?~  maybe-inflight  *melt-inflight-entry
          u.maybe-inflight
        =/  actual-fee=@ud
          ?~  maybe-json  fee-reserve.mq
          (routing-fee-sats u.maybe-json fee-reserve.mq)
        =/  refund=@ud  (sub fee-reserve.mq actual-fee)
        =/  change-sigs=(list json)  (sign-change-outputs change.inflight refund)
        =?  melt-change.st  !=(~ change-sigs)
          (~(put by melt-change.st) quote-id.pend change-sigs)
        =.  melt-quotes.st
          (~(put by melt-quotes.st) quote-id.pend mq(state %paid, payment-preimage resp-preimage))
        =.  melt-inflight.st  (~(del by melt-inflight.st) quote-id.pend)
        :_  st
        %-  give-json  :_  eyre-id.pend
        %-  pairs:enjs:format
        :~  ['aborted' b+%.n]
            ['result' s+'settled-not-aborted']
            ['quote_id' s+quote-id.pend]
            ['state' s+'PAID']
            ['payment_preimage' s+resp-preimage]
        ==
      ::  Stale: another event already moved the quote off %pending. No-op.
      ?.  =(%pending state.mq)
        ~&  >>>  [%ecash-melt-abort-force-stale quote-id.pend state.mq]
        :_  st
        %-  give-json  :_  eyre-id.pend
        %-  pairs:enjs:format
        :~  ['aborted' b+%.n]
            ['result' s+'no-op-not-pending']
            ['quote_id' s+quote-id.pend]
            ['state' s+(quote-state-text state.mq)]
        ==
      ::  ABORT-2: %pending with NO inflight record to reverse. Do NOT silently
      ::  no-op an empty default; log loudly + report so the operator uses the
      ::  sync MIG-1 supplied-secrets path (admin-melt-abort %none/force + secrets).
      ?~  maybe-inflight
        ~&  >>>  [%ecash-melt-abort-force-no-inflight quote-id.pend status]
        :_  st
        %-  give-json  :_  eyre-id.pend
        %-  pairs:enjs:format
        :~  ['aborted' b+%.n]
            ['result' s+'no-inflight-record']
            ['ln_checked' b+%.y]
            ['quote_id' s+quote-id.pend]
            ['state' s+(quote-state-text state.mq)]
        ==
      ::  AUTHORIZED ROLLBACK (ambiguous OR confirmed-failed): un-spend EXACTLY
      ::  the persisted members, decrement (underflow-guarded), %failed, clear.
      ~&  >>>  [%ecash-melt-abort-force-rollback quote-id.pend status]
      =/  inflight  u.maybe-inflight
      =.  spent.st     (~(dif in spent.st) secrets.inflight)
      =.  spent-ys.st  (~(dif in spent-ys.st) ys.inflight)
      =.  total-redeemed-sats.st
        ?:  (gte total-redeemed-sats.st input-total.inflight)
          (sub total-redeemed-sats.st input-total.inflight)
        0
      =.  melt-quotes.st  (~(put by melt-quotes.st) quote-id.pend mq(state %failed))
      =.  melt-inflight.st  (~(del by melt-inflight.st) quote-id.pend)
      :_  st
      %-  give-json  :_  eyre-id.pend
      %-  pairs:enjs:format
      :~  ['aborted' b+%.y]
          ['result' s+'aborted-forced']
          ['ln_checked' b+%.y]
          ['quote_id' s+quote-id.pend]
          ['unspent_secrets' (numb:enjs:format ~(wyt in secrets.inflight))]
          ['redeemed_decremented' (numb:enjs:format input-total.inflight)]
      ==
    ==
  ::
  ::  extract-str: get-str with fallback to a second key (both variants in use
  ::  across LNbits vs LND response shapes).
  ::
  ++  extract-str
    |=  [jon=json key1=@t key2=@t]
    ^-  @t
    ?.  ?=([%o *] jon)  ''
    =/  v  (get-str p.jon key1)
    ?.  =('' v)  v
    (get-str p.jon key2)
  ::
  ::  -- HTTP response helpers --
  ::
  ++  give-json
    |=  [jon=json eyre-id=@ta]
    ^-  (list card)
    =/  bod  (as-octs:mimes:html (en:json:html jon))
    (give-http eyre-id 200 [['content-type' 'application/json'] ~] `bod)
  ++  give-err
    |=  [eyre-id=@ta code=@ud msg=@t]
    ^-  (list card)
    =/  bod  (as-octs:mimes:html (en:json:html (pairs:enjs:format ['detail' s+msg]~)))
    (give-http eyre-id code [['content-type' 'application/json'] ~] `bod)
  ++  give-http
    |=  [eyre-id=@ta code=@ud hdrs=header-list:http data=(unit octs)]
    ^-  (list card)
    =/  sec-hdrs=header-list:http
      :~  ['content-security-policy' (crip "default-src 'self'; frame-ancestors 'none'")]
          ['x-frame-options' 'DENY']
          ['x-content-type-options' 'nosniff']
      ==
    =/  all-hdrs=header-list:http  (weld hdrs sec-hdrs)
    =/  id-path  (welp /http-response (limo [eyre-id ~]))
    :~  [%give %fact ~[id-path] %http-response-header !>([code all-hdrs])]
        [%give %fact ~[id-path] %http-response-data !>(data)]
        [%give %kick ~[id-path] ~]
    ==
  --
--
