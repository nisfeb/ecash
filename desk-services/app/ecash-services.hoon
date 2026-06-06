::  ecash-services: credential + services access-control agent.
::  Non-value-bearing; split out of the %ecash mint. Serves /cred/v1 and
::  /services/v1, plus an authenticated admin API at /apps/ecash-services/admin.
::
/-  *ecash-services
/+  default-agent, dbug, *bdhke
/*  dashboard-lines  %txt  /app/dashboard/txt
|%
::  +cred-keyset-old / +state-old: the pre-C4 persisted shape, kept frozen so
::  on-load can decode and migrate it. cred-keyset-old has no service-scoped
::  flag; cred-spent-old is a bare (set @t) keyed only on secret.
+$  cred-keyset-old
  $:  ks-id=@t
      active=?
      keys=(map @ud @t)
      privkeys=(map @ud @)
      created=@da
  ==
+$  state-old
  $:  %0
      cred-keysets=(map @t cred-keyset-old)
      cred-spent=(set @t)
      cred-counter=@ud
      services=(map @t service)
  ==
::  +state-0: the live (post-C4) state. cred-keyset now carries service-scoped;
::  cred-spent is namespaced per keyset as (set [kid=@t secret=@t]);
::  cred-spent-legacy holds pre-migration bare secrets, consulted only as an
::  extra spent signal so no already-redeemed token becomes spendable again.
+$  state-0
  $:  %1
      cred-keysets=(map @t cred-keyset)
      cred-spent=(set [@t @t])
      cred-spent-legacy=(set @t)
      cred-counter=@ud
      services=(map @t service)
  ==
+$  versioned-state  $%(state-old state-0)
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
    hc    ~(. ec [bowl state])
++  on-save   ^-  vase  !>(state)
++  on-load
  |=  old=vase
  |^  ^-  (quip card _this)
      =/  prev=versioned-state  !<(versioned-state old)
      =?  prev  ?=(%0 -.prev)  (state-old-to-0 prev)
      ?>  ?=(%1 -.prev)
      :_  this(state prev)
      :~  [%pass /eyre/connect-cred %arvo %e %connect [`/cred dap.bowl]]
          [%pass /eyre/connect-services %arvo %e %connect [`/services dap.bowl]]
          [%pass /eyre/connect-apps %arvo %e %connect [`/apps/ecash-services dap.bowl]]
      ==
  ::  state-old-to-0: reconstruct service-scoped from the services map (a
  ::  keyset is service-backing iff some service references its ks-id), and
  ::  move old bare spent secrets into cred-spent-legacy (kid unrecoverable).
  ++  state-old-to-0
    |=  o=state-old
    ^-  state-0
    =/  svc-ks=(set @t)
      %-  ~(gas in *(set @t))
      %+  turn  ~(val by services.o)
      |=(s=service ks-id.s)
    =/  upgraded=(map @t cred-keyset)
      %-  ~(run by cred-keysets.o)
      |=  k=cred-keyset-old
      ^-  cred-keyset
      :*  ks-id.k
          active.k
          keys.k
          privkeys.k
          created.k
          service-scoped=(~(has in svc-ks) ks-id.k)
      ==
    :*  %1
        upgraded
        cred-spent=*(set [@t @t])
        cred-spent-legacy=cred-spent.o
        cred-counter.o
        services.o
    ==
  --
++  on-init
  ^-  (quip card _this)
  :_  this
  :~  [%pass /eyre/connect-cred %arvo %e %connect [`/cred dap.bowl]]
      [%pass /eyre/connect-services %arvo %e %connect [`/services dap.bowl]]
      [%pass /eyre/connect-apps %arvo %e %connect [`/apps/ecash-services dap.bowl]]
  ==
++  on-poke
  |=  [=mark =vase]
  ^-  (quip card _this)
  ?+  mark  (on-poke:def mark vase)
      %handle-http-request
    =+  !<([eyre-id=@ta req=inbound-request:eyre] vase)
    =^  cards  state  (handle-http:hc eyre-id req)
    [cards this]
  ==
++  on-watch
  |=  =path
  ^-  (quip card _this)
  ?+  path  (on-watch:def path)
      [%http-response *]  `this
  ==
++  on-leave  on-leave:def
++  on-peek   on-peek:def
++  on-agent  on-agent:def
++  on-arvo
  |=  [=wire =sign-arvo]
  ^-  (quip card _this)
  ?+  wire  (on-arvo:def wire sign-arvo)
      [%eyre %connect-cred ~]      `this
      [%eyre %connect-services ~]  `this
      [%eyre %connect-apps ~]      `this
  ==
++  on-fail   on-fail:def
--
::  -- Helper core --
|%
++  ec
  |_  [=bowl:gall st=state-0]
  ::
  ::  max outputs accepted per issue request (bounds per-event EC work)
  ++  max-batch  ^-  @ud  100
  ::
  ::  host-of-url: extract host[:port] authority from an Origin/Referer url.
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
  ::  csrf-ok: CSRF guard for state-changing admin requests. Safe methods and
  ::  requests with no Origin/Referer (non-browser clients) are allowed; a
  ::  mutating request that carries an Origin/Referer must be same-origin.
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
  ::  -- JSON number parsing (bare digits, no Hoon dot separators) --
  ++  parse-ud
    |=  t=@t  ^-  @ud
    =/  res  (rust (trip t) (bass 10 (plus dit)))
    ?~(res 0 u.res)
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
  ::  -- Service layer helpers ----------------------------------
  ::
  ::  resolve-service: look up a service by name, returning the usable svc
  ::  or an error cord for direct 400 surfacing.
  ::
  ++  resolve-service
    |=  name=@t
    ^-  (each service @t)
    =/  maybe-svc  (~(get by services.st) name)
    ?~  maybe-svc            [%| 'service-not-found']
    =/  svc=service  u.maybe-svc
    ?.  active.svc           [%| 'service-inactive']
    ?:  ?&  ?=(^ expires.svc)
            (gth now.bowl u.expires.svc)
        ==
      [%| 'service-expired']
    [%& svc]
  ::
  ::  service-issue: sign blinded outputs for a service.
  ::
  ::    Enforces per-service max-issuance and stamps the output list with the
  ::    service's backing keyset id before delegating to cred-sign-outputs.
  ::    Crashing signatures (bad curve point, etc.) still land as per-element
  ::    error objects; legitimate ones increment service.issued.
  ::
  ++  service-issue
    |=  [svc=service outputs=(list json)]
    ^-  (each [sigs=(list json) new=service] @t)
    ?:  ?&  ?=(^ max-issuance.svc)
            (gth (add issued.svc (lent outputs)) u.max-issuance.svc)
        ==
      [%| 'service-issuance-cap-reached']
    =/  stamped=(list json)  (stamp-ks-id outputs ks-id.svc)
    =/  sigs=(list json)     (cred-sign-outputs-as stamped %.y)
    =/  new-svc=service      svc(issued (add issued.svc (lent outputs)))
    [%& [sigs new-svc]]
  ::
  ::  service-check: verify proofs against a specific service's keyset.
  ::
  ::    Tokens whose `id` field does not match the service's backing keyset
  ::    are marked invalid — this is how services stay cross-scoped.
  ::
  ++  service-check
    |=  [svc=service proofs=(list json)]
    ^-  (list [secret=@t valid=? spent=?])
    =/  raw  (cred-check-proofs proofs %.y)
    =/  scoped=(list ?)
      %+  turn  proofs
      |=  tok=json
      ?.  ?=([%o *] tok)  %.n
      =((get-str p.tok 'id') ks-id.svc)
    =/  combined=(list [secret=@t valid=? spent=?])
      |-
      ?~  raw  ~
      ?~  scoped  ~
      :-  [secret.i.raw &(valid.i.raw i.scoped) spent.i.raw]
      $(raw t.raw, scoped t.scoped)
    combined
  ::
  ::  stamp-ks-id: rewrite each output's `id` field to match ks-id.
  ::
  ::    Client-submitted blinded outputs may omit or misstate the keyset id;
  ::    service endpoints always sign with the service's backing keyset so
  ::    we overwrite to keep the scoping invariant true.
  ::
  ++  stamp-ks-id
    |=  [outputs=(list json) ks-id=@t]
    ^-  (list json)
    %+  turn  outputs
    |=  msg=json
    ^-  json
    ?.  ?=([%o *] msg)  msg
    [%o (~(put by p.msg) 'id' s+ks-id)]
  ::
  ::  service-to-json: public-facing serialization (no allowlist plaintext).
  ::
  ++  service-to-json
    |=  svc=service
    ^-  json
    %-  pairs:enjs:format
    :~  ['name' s+name.svc]
        ['title' s+title.svc]
        ['description' s+description.svc]
        ['kind' s+?-(kind.svc %single-use 'single-use')]
        ['ks_id' s+ks-id.svc]
        ['active' b+active.svc]
        ['issued' (numb:enjs:format issued.svc)]
        ['redeemed' (numb:enjs:format redeemed.svc)]
        ['allowlist_count' (numb:enjs:format ~(wyt in allowlist.svc))]
        ['allowlist_required' b+!=(~ allowlist.svc)]
        :-  'expires'
        ?~  expires.svc  ~
        (numb:enjs:format (da-to-unix u.expires.svc))
        :-  'max_issuance'
        ?~  max-issuance.svc  ~
        (numb:enjs:format u.max-issuance.svc)
        ['created' (numb:enjs:format (da-to-unix created.svc))]
    ==
  ::
  ::  service-to-json-admin: like service-to-json but includes the plaintext
  ::  allowlist keys. Only call from admin endpoints.
  ::
  ++  service-to-json-admin
    |=  svc=service
    ^-  json
    =/  base=json  (service-to-json svc)
    ?.  ?=([%o *] base)  base
    =/  keys=(list json)
      %+  turn  ~(tap in allowlist.svc)
      |=  k=@t
      s+k
    [%o (~(put by p.base) 'allowlist' [%a keys])]
  ::
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
  ::  da-to-unix: @da to unix epoch seconds
  ++  da-to-unix
    |=  da=@da
    ^-  @ud
    (div (sub da ~1970.1.1) ~s1)
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
  ::  handle-http: route an inbound HTTP request to its handler.
  ::
  ++  handle-http
    |=  [eyre-id=@ta req=inbound-request:eyre]
    ^-  (quip card state-0)
    =/  req-body            body.request.req
    =/  segs=(list @t)      (parse-request-path url.request.req)
    =/  route=(list @t)     [method.request.req segs]
    ::  Admin surface requires a valid ship session. Eyre sets
    ::  authenticated=%.y only for a %ours session, so this already
    ::  guarantees the session ship is our.bowl (no foreign session @p is
    ::  exposed on the http request; cf. =(src.bowl our.bowl) on pokes).
    ?:  ?&  ?=([%apps %ecash-services %admin *] segs)
            !authenticated.req
        ==
      :_  st  (give-err eyre-id 401 'unauthorized')
    ::  CSRF: a state-changing admin request must be same-origin.
    ?:  ?&  ?=([%apps %ecash-services %admin *] segs)
            !(csrf-ok req)
        ==
      :_  st  (give-err eyre-id 403 'forbidden-cross-origin')
    ?+  route  :_  st  (give-err eyre-id 404 'not-found')
        [%'GET' %apps %ecash-services %admin ~]
      :_  st
      (give-http eyre-id 200 [['content-type' 'text/html'] ~] `(as-octs:mimes:html (rap 3 (join `@t`10 `wain`dashboard-lines))))
        [%'GET' %cred %v1 %keys ~]            :_  st  (cred-get-keys eyre-id)
        [%'GET' %cred %v1 %keys @ ~]          :_  st  (cred-get-keys-by-id eyre-id i.t.t.t.t.route)
        [%'GET' %cred %v1 %keysets ~]         :_  st  (cred-get-keysets eyre-id)
        [%'POST' %cred %v1 %issue ~]          (cred-post-issue eyre-id req-body)
        [%'POST' %cred %v1 %verify ~]         :_  st  (cred-post-verify eyre-id req-body)
        [%'POST' %cred %v1 %redeem ~]         (cred-post-redeem eyre-id req-body)
        [%'GET' %services %v1 %list ~]        :_  st  (svc-get-list eyre-id)
        [%'GET' %services %v1 @ ~]            :_  st  (svc-get-detail eyre-id i.t.t.t.route)
        [%'POST' %services %v1 @ %issue ~]    (svc-post-issue eyre-id i.t.t.t.route req-body)
        [%'POST' %services %v1 @ %verify ~]   :_  st  (svc-post-verify eyre-id i.t.t.t.route req-body)
        [%'POST' %services %v1 @ %redeem ~]   (svc-post-redeem eyre-id i.t.t.t.route req-body)
        [%'GET' %apps %ecash-services %admin %api %cred %overview ~]
      :_  st  (admin-cred-overview eyre-id)
        [%'POST' %apps %ecash-services %admin %api %cred %keysets %generate ~]
      (admin-cred-keyset-generate eyre-id)
        [%'POST' %apps %ecash-services %admin %api %cred %keysets %activate ~]
      (admin-cred-keyset-activate eyre-id req-body)
        [%'POST' %apps %ecash-services %admin %api %cred %keysets %deactivate ~]
      (admin-cred-keyset-deactivate eyre-id req-body)
        [%'GET' %apps %ecash-services %admin %api %services ~]
      :_  st  (admin-svc-list eyre-id)
        [%'GET' %apps %ecash-services %admin %api %services @ ~]
      :_  st  (admin-svc-detail eyre-id i.t.t.t.t.t.t.route)
        [%'POST' %apps %ecash-services %admin %api %services %create ~]
      (admin-svc-create eyre-id req-body)
        [%'POST' %apps %ecash-services %admin %api %services %update ~]
      (admin-svc-update eyre-id req-body)
        [%'POST' %apps %ecash-services %admin %api %services %activate ~]
      (admin-svc-activate eyre-id req-body)
        [%'POST' %apps %ecash-services %admin %api %services %deactivate ~]
      (admin-svc-deactivate eyre-id req-body)
        [%'POST' %apps %ecash-services %admin %api %services %delete ~]
      (admin-svc-delete eyre-id req-body)
        [%'POST' %apps %ecash-services %admin %api %services %allowlist %add ~]
      (admin-svc-allowlist-add eyre-id req-body)
        [%'POST' %apps %ecash-services %admin %api %services %allowlist %remove ~]
      (admin-svc-allowlist-remove eyre-id req-body)
    ==
  ::
  ++  compute-cred-ks-id
    |=  keys=(map @ud @t)
    ^-  @t
    =/  sorted=(list [@ud @t])
      %+  sort  ~(tap by keys)
      |=([a=[@ud @t] b=[@ud @t]] (lth -.a -.b))
    =/  pair-cords=(list @t)
      %+  turn  sorted
      |=([amt=@ud pub=@t] (rap 3 ~[(scot %ud amt) ':' pub]))
    =/  canonical=@t
      (rap 3 ~[(rap 3 (join ',' pair-cords)) '|unit:cred'])
    (rap 3 ~['c0' (pad-hex (shax canonical) 64)])
  ::
  ::  has-dup-x: does the output batch contain two B_ points sharing an
  ::    x-coordinate?  This is the B_/-B_ DLEQ nonce-reuse attack shape
  ::    (same x, negated y) that would leak the credential signing key.
  ::    Malformed / missing B_ are skipped; they fail individually downstream.
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
  ::  has-dup-secrets: does this list of [kid secret] keys contain a repeat?
  ::    The redeem paths' per-element spent check consults only the STORED set,
  ::    so without this two identical secrets in one batch both read unspent
  ::    and both get marked + counted (cap/accounting bypass).
  ::
  ++  has-dup-secrets
    |=  keys=(list [@t @t])
    ^-  ?
    =|  seen=(set [@t @t])
    |-  ^-  ?
    ?~  keys  %.n
    ?:  (~(has in seen) i.keys)  %.y
    $(keys t.keys, seen (~(put in seen) i.keys))
  ::
  ::  cred-sign-outputs: PUBLIC signer for /cred/v1/issue. Refuses any
  ::  service-scoped keyset id (treats it as unknown), so service-backing
  ::  keysets can only be signed via the gated /services path.
  ::
  ++  cred-sign-outputs
    |=  outputs=(list json)
    ^-  (list json)
    (cred-sign-outputs-as outputs %.n)
  ::  cred-sign-outputs-as: shared signer. When allow-scoped is %.n, any
  ::  keyset whose .service-scoped is %.y is rejected as unknown. The gated
  ::  service path passes %.y to reach its own keyset.
  ::
  ++  cred-sign-outputs-as
    |=  [outputs=(list json) allow-scoped=?]
    ^-  (list json)
    %+  turn  outputs
    |=  msg=json
    ^-  json
    ?.  ?=([%o *] msg)
      (pairs:enjs:format ['error' s+'invalid-msg']~)
    =/  amt=@ud  (get-num p.msg 'amount')
    ?.  =(0 amt)
      (pairs:enjs:format ['error' s+'credential-amount-must-be-zero']~)
    =/  b-hex=@t  (get-str p.msg 'B_')
    ?:  =('' b-hex)
      (pairs:enjs:format ['error' s+'missing-B_']~)
    =/  maybe-b-pt  (hex-to-pt b-hex)
    ?~  maybe-b-pt
      (pairs:enjs:format ['error' s+'invalid-B_-point']~)
    =/  b-=point  u.maybe-b-pt
    =/  kid=@t  (get-str p.msg 'id')
    ?:  =('' kid)
      (pairs:enjs:format ['error' s+'missing-keyset-id']~)
    =/  maybe-ks  (~(get by cred-keysets.st) kid)
    ?~  maybe-ks
      (pairs:enjs:format ['error' s+'unknown-credential-keyset']~)
    =/  ks  u.maybe-ks
    ?:  &(service-scoped.ks !allow-scoped)
      (pairs:enjs:format ['error' s+'unknown-credential-keyset']~)
    ?.  active.ks
      (pairs:enjs:format ['error' s+'credential-keyset-inactive']~)
    =/  maybe-priv  (~(get by privkeys.ks) 0)
    ?~  maybe-priv
      (pairs:enjs:format ['error' s+'no-credential-key']~)
    =/  priv=@  u.maybe-priv
    =/  c-=point  (blind-sign b- priv)
    =/  c-hex=@t  (pt-to-hex c-)
    ::  Mix the full B_ hex (02/03 prefix differs for B_ vs -B_) into rng so
    ::  every credential output gets distinct entropy within one event.
    =/  rng=@  (shax (cat 3 b-hex (add eny.bowl now.bowl)))
    =/  dleq-es  (dleq-prove b- c- priv rng)
    =/  dleq-map=(map @t json)
      %-  my
      :~  ['e' s+(scalar-to-hex e.dleq-es)]
          ['s' s+(scalar-to-hex s.dleq-es)]
      ==
    %-  pairs:enjs:format
    :~  ['C_' s+c-hex]
        ['amount' (numb:enjs:format 0)]
        ['id' s+kid]
        ['dleq' [%o dleq-map]]
    ==
  ::
  ::  cred-check-proofs: check credential proof sig + spent status (no spending)
  ::
  ++  cred-check-proofs
    |=  [proofs=(list json) allow-scoped=?]
    ^-  (list [kid=@t secret=@t valid=? spent=?])
    %+  turn  proofs
    |=  tok=json
    ?.  ?=([%o *] tok)  ['' '' %.n %.n]
    =/  c-hex=@t   (get-str p.tok 'C')
    =/  secret=@t  (get-str p.tok 'secret')
    =/  kid=@t     (get-str p.tok 'id')
    ?:  |(=('' c-hex) =('' secret) =('' kid))
      [kid secret %.n %.n]
    =/  maybe-ks  (~(get by cred-keysets.st) kid)
    ?~  maybe-ks
      [kid secret %.n %.n]
    =/  ks  u.maybe-ks
    ::  Public /cred (allow-scoped=%.n) must treat a service-scoped keyset as
    ::  unknown, so it can neither probe nor burn a service token. The gated
    ::  /services path passes %.y to reach its own keyset.
    ?:  &(service-scoped.ks !allow-scoped)
      [kid secret %.n %.n]
    =/  maybe-priv  (~(get by privkeys.ks) 0)
    ?~  maybe-priv
      [kid secret %.n %.n]
    =/  priv=@  u.maybe-priv
    =/  maybe-c-pt  (hex-to-pt c-hex)
    ?~  maybe-c-pt
      [kid secret %.n %.n]
    =/  c-pt=point  u.maybe-c-pt
    =/  h-pt=point  (hash-to-curve (crip (trip secret)))
    =/  expected=point  (pt-mul priv h-pt)
    ?.  =(c-pt expected)
      [kid secret %.n %.n]
    =/  is-spent
      ?|  (~(has in cred-spent.st) [kid secret])
          (~(has in cred-spent-legacy.st) secret)
      ==
    [kid secret %.y is-spent]
  ::
  ::  GET /cred/v1/keys — list active credential keysets with keys
  ++  cred-get-keys
    |=  eyre-id=@ta
    ^-  (list card)
    =/  ks-list=(list json)
      %+  murn  ~(tap by cred-keysets.st)
      |=  [id=@t ks=cred-keyset]
      ?.  active.ks  ~
      ::  service-scoped keysets are issued only via the gated /services path;
      ::  do not advertise them as publicly issuable on /cred/v1/keys.
      ?:  service-scoped.ks  ~
      %-  some
      %-  pairs:enjs:format
      :~  ['id' s+ks-id.ks]
          ['active' b+active.ks]
          :-  'keys'
          %-  pairs:enjs:format
          %+  turn  ~(tap by keys.ks)
          |=  [amt=@ud pub=@t]
          [(scot %ud amt) s+pub]
      ==
    (give-json (pairs:enjs:format ['keysets' [%a ks-list]]~) eyre-id)
  ::
  ::  GET /cred/v1/keys/{keyset_id}
  ++  cred-get-keys-by-id
    |=  [eyre-id=@ta kid=@t]
    ^-  (list card)
    =/  maybe-ks  (~(get by cred-keysets.st) kid)
    ?~  maybe-ks
      (give-err eyre-id 404 'credential-keyset-not-found')
    =/  ks  u.maybe-ks
    ::  NB: a service keyset's PUBLIC key is intentionally fetchable by id —
    ::  clients need it to unblind tokens they legitimately obtained, and a
    ::  pubkey cannot forge a signature (the audit rated this disclosure
    ::  harmless). Only signing/verify/redeem are gated (service-scoped).
    =/  resp
      %-  pairs:enjs:format
      :~  :-  'keysets'
          :-  %a
          :~  %-  pairs:enjs:format
              :~  ['id' s+ks-id.ks]
                  ['active' b+active.ks]
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
  ::  GET /cred/v1/keysets — metadata only
  ++  cred-get-keysets
    |=  eyre-id=@ta
    ^-  (list card)
    =/  ks-list=(list json)
      %+  turn  ~(tap by cred-keysets.st)
      |=  [id=@t ks=cred-keyset]
      %-  pairs:enjs:format
      :~  ['id' s+ks-id.ks]
          ['active' b+active.ks]
      ==
    (give-json (pairs:enjs:format ['keysets' [%a ks-list]]~) eyre-id)
  ::
  ::  POST /cred/v1/issue — issue credential tokens
  ++  cred-post-issue
    |=  [eyre-id=@ta req-body=(unit octs)]
    ^-  (quip card state-0)
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_(st (give-err eyre-id 400 p.parsed))
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    ?.  (has-key p.jon 'outputs')
      :_(st (give-err eyre-id 400 'missing-outputs'))
    =/  outputs  (get-array p.jon 'outputs')
    ?:  =(~ outputs)  :_(st (give-err eyre-id 400 'empty-outputs'))
    ?:  (gth (lent outputs) max-batch)  :_(st (give-err eyre-id 400 'batch-too-large'))
    ?:  (has-dup-x outputs)  :_(st (give-err eyre-id 400 'duplicate-output'))
    =/  sigs=(list json)  (cred-sign-outputs outputs)
    =.  cred-counter.st  (add cred-counter.st (lent outputs))
    :_  st
    %-  give-json  :_  eyre-id
    (pairs:enjs:format ['signatures' [%a sigs]]~)
  ::
  ::  POST /cred/v1/verify — check proofs without spending
  ++  cred-post-verify
    |=  [eyre-id=@ta req-body=(unit octs)]
    ^-  (list card)
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  (give-err eyre-id 400 p.parsed)
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    ?.  (has-key p.jon 'proofs')  (give-err eyre-id 400 'missing-proofs')
    =/  proofs  (get-array p.jon 'proofs')
    =/  results  (cred-check-proofs proofs %.n)
    =/  result-json=(list json)
      %+  turn  results
      |=  [kid=@t secret=@t valid=? spent=?]
      %-  pairs:enjs:format
      :~  ['secret' s+secret]
          ['valid' b+valid]
          ['spent' b+spent]
      ==
    %-  give-json  :_  eyre-id
    (pairs:enjs:format ['valid' [%a result-json]]~)
  ::
  ::  POST /cred/v1/redeem — verify and spend credential proofs
  ++  cred-post-redeem
    |=  [eyre-id=@ta req-body=(unit octs)]
    ^-  (quip card state-0)
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_(st (give-err eyre-id 400 p.parsed))
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    ?.  (has-key p.jon 'proofs')  :_(st (give-err eyre-id 400 'missing-proofs'))
    =/  proofs  (get-array p.jon 'proofs')
    =/  results  (cred-check-proofs proofs %.n)
    =/  all-valid  (levy results |=([k=@t s=@t v=? sp=?] &(v !sp)))
    ?.  all-valid
      =/  first-bad
        %-  head
        %+  skim  results
        |=  [k=@t s=@t v=? sp=?]
        |(!v sp)
      =/  err=@t
        ?:  spent.first-bad  'credential-already-spent'
        'invalid-credential'
      :_(st (give-err eyre-id 400 err))
    ::  Reject a batch that names the same [kid secret] twice: per-element
    ::  checks each read only the STORED spent set, so duplicates would all
    ::  pass and be marked/counted as if distinct.
    ?:  (has-dup-secrets (turn results |=([k=@t s=@t v=? sp=?] [k s])))
      :_(st (give-err eyre-id 400 'duplicate-credential'))
    ::  Mark all as spent, namespaced by keyset id
    =.  cred-spent.st
      %-  ~(gas in cred-spent.st)
      (turn results |=([k=@t s=@t v=? sp=?] [k s]))
    =/  result-json=(list json)
      %+  turn  results
      |=  [kid=@t secret=@t valid=? spent=?]
      %-  pairs:enjs:format
      :~  ['secret' s+secret]
          ['redeemed' b+%.y]
      ==
    :_  st
    %-  give-json  :_  eyre-id
    (pairs:enjs:format ['redeemed' [%a result-json]]~)
  ::
  ::  -- Admin credential endpoints --
  ::
  ++  admin-cred-keyset-generate
    |=  eyre-id=@ta
    ^-  (quip card state-0)
    =/  ent  (shax eny.bowl)
    ::  Single key at denomination 0
    =/  k  (mod (shax (add (mul ent (bex 64)) 7)) secp-n)
    =/  k2  ?:(=(0 k) 1 k)
    =/  privkeys=(map @ud @)  (my [0 k2]~)
    =/  pubkeys=(map @ud @t)  (my [0 (pt-to-hex (pubkey k2))]~)
    =/  ks-id=@t  (compute-cred-ks-id pubkeys)
    =/  ks=cred-keyset
      :*  ks-id=ks-id
          active=%.y
          keys=pubkeys
          privkeys=privkeys
          created=now.bowl
          service-scoped=%.n
      ==
    =.  cred-keysets.st  (~(put by cred-keysets.st) ks-id ks)
    :_  st
    %-  give-json  :_  eyre-id
    %-  pairs:enjs:format
    :~  ['id' s+ks-id]
        ['active' b+%.y]
        :-  'keys'
        %-  pairs:enjs:format
        %+  turn  ~(tap by pubkeys)
        |=  [amt=@ud pub=@t]
        [(scot %ud amt) s+pub]
    ==
  ::
  ++  admin-cred-keyset-activate
    |=  [eyre-id=@ta req-body=(unit octs)]
    ^-  (quip card state-0)
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_(st (give-err eyre-id 400 p.parsed))
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    =/  target-id=@t  (get-str p.jon 'id')
    ?:  =('' target-id)  :_(st (give-err eyre-id 400 'missing-id'))
    =/  maybe-ks  (~(get by cred-keysets.st) target-id)
    ?~  maybe-ks  :_(st (give-err eyre-id 404 'credential-keyset-not-found'))
    =.  cred-keysets.st  (~(put by cred-keysets.st) target-id u.maybe-ks(active %.y))
    :_  st
    %-  give-json  :_  eyre-id
    (pairs:enjs:format ['id' s+target-id] ['active' b+%.y] ~)
  ::
  ++  admin-cred-keyset-deactivate
    |=  [eyre-id=@ta req-body=(unit octs)]
    ^-  (quip card state-0)
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_(st (give-err eyre-id 400 p.parsed))
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    =/  target-id=@t  (get-str p.jon 'id')
    ?:  =('' target-id)  :_(st (give-err eyre-id 400 'missing-id'))
    =/  maybe-ks  (~(get by cred-keysets.st) target-id)
    ?~  maybe-ks  :_(st (give-err eyre-id 404 'credential-keyset-not-found'))
    =.  cred-keysets.st  (~(put by cred-keysets.st) target-id u.maybe-ks(active %.n))
    :_  st
    %-  give-json  :_  eyre-id
    (pairs:enjs:format ['id' s+target-id] ['active' b+%.n] ~)
  ::
  ++  admin-cred-overview
    |=  eyre-id=@ta
    ^-  (list card)
    %-  give-json  :_  eyre-id
    %-  pairs:enjs:format
    :~  ['cred_keysets' (numb:enjs:format ~(wyt by cred-keysets.st))]
        ['cred_issued' (numb:enjs:format cred-counter.st)]
        ['cred_spent' (numb:enjs:format (add ~(wyt in cred-spent.st) ~(wyt in cred-spent-legacy.st)))]
        :-  'keysets'
        :-  %a
        %+  turn  ~(tap by cred-keysets.st)
        |=  [id=@t ks=cred-keyset]
        %-  pairs:enjs:format
        :~  ['id' s+ks-id.ks]
            ['active' b+active.ks]
        ==
    ==
  ::
  ::  ============================================================
  ::  Services (non-value-bearing access tokens) — public endpoints
  ::  ============================================================
  ::
  ::  GET /services/v1/list — active services only
  ::
  ++  svc-get-list
    |=  eyre-id=@ta
    ^-  (list card)
    =/  list=(list json)
      %+  murn  ~(tap by services.st)
      |=  [name=@t svc=service]
      ^-  (unit json)
      ?.  active.svc  ~
      `(service-to-json svc)
    (give-json (pairs:enjs:format ['services' [%a list]]~) eyre-id)
  ::
  ::  GET /services/v1/{name} — service detail (public, active-only)
  ::
  ++  svc-get-detail
    |=  [eyre-id=@ta name=@t]
    ^-  (list card)
    =/  resolved  (resolve-service name)
    ?:  ?=(%| -.resolved)
      (give-err eyre-id 404 p.resolved)
    (give-json (service-to-json p.resolved) eyre-id)
  ::
  ::  POST /services/v1/{name}/issue — sign blinded outputs for a service.
  ::
  ::    If the service has a non-empty allowlist, the caller must supply
  ::    `access_key` in the request body whose value is a member of that
  ::    set. Empty allowlist is treated as public.
  ::
  ++  svc-post-issue
    |=  [eyre-id=@ta name=@t req-body=(unit octs)]
    ^-  (quip card state-0)
    =/  resolved  (resolve-service name)
    ?:  ?=(%| -.resolved)  :_  st  (give-err eyre-id 400 p.resolved)
    =/  svc=service  p.resolved
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_  st  (give-err eyre-id 400 p.parsed)
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    ::  allowlist gate: if non-empty, require matching access_key
    ?:  ?&  !=(~ allowlist.svc)
            !(~(has in allowlist.svc) (get-str p.jon 'access_key'))
        ==
      :_  st  (give-err eyre-id 403 'service-access-denied')
    ?.  (has-key p.jon 'outputs')
      :_  st  (give-err eyre-id 400 'missing-outputs')
    =/  outputs  (get-array p.jon 'outputs')
    ?:  =(~ outputs)  :_  st  (give-err eyre-id 400 'empty-outputs')
    ?:  (gth (lent outputs) max-batch)  :_  st  (give-err eyre-id 400 'batch-too-large')
    ?:  (has-dup-x outputs)  :_  st  (give-err eyre-id 400 'duplicate-output')
    =/  res  (service-issue svc outputs)
    ?:  ?=(%| -.res)  :_  st  (give-err eyre-id 400 p.res)
    =.  services.st     (~(put by services.st) name new.p.res)
    =.  cred-counter.st  (add cred-counter.st (lent outputs))
    :_  st
    %-  give-json  :_  eyre-id
    (pairs:enjs:format ['signatures' [%a sigs.p.res]]~)
  ::
  ::  POST /services/v1/{name}/verify — check proofs, no spend
  ::
  ++  svc-post-verify
    |=  [eyre-id=@ta name=@t req-body=(unit octs)]
    ^-  (list card)
    =/  resolved  (resolve-service name)
    ?:  ?=(%| -.resolved)  (give-err eyre-id 400 p.resolved)
    =/  svc=service  p.resolved
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  (give-err eyre-id 400 p.parsed)
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    ?.  (has-key p.jon 'proofs')  (give-err eyre-id 400 'missing-proofs')
    =/  proofs  (get-array p.jon 'proofs')
    =/  results  (service-check svc proofs)
    =/  result-json=(list json)
      %+  turn  results
      |=  [secret=@t valid=? spent=?]
      %-  pairs:enjs:format
      :~  ['secret' s+secret]
          ['valid' b+valid]
          ['spent' b+spent]
      ==
    %-  give-json  :_  eyre-id
    (pairs:enjs:format ['results' [%a result-json]]~)
  ::
  ::  POST /services/v1/{name}/redeem — verify and mark spent (idempotent).
  ::
  ::    Each proof is crypto-checked against the service's keyset. Any
  ::    invalid proof (bad signature or wrong keyset) → 400 for the whole
  ::    batch. Otherwise each token gets a per-element status in the
  ::    response:
  ::
  ::      %fresh   — first time we've seen this secret; spend it.
  ::      %replay  — already in cred-spent; leave state alone, return 200.
  ::
  ::    Replay makes the endpoint safe to retry after network drops. Callers
  ::    that care about first-use-vs-retry semantics can inspect the per-
  ::    token `status` field; callers that don't can treat any 200 as
  ::    "token accepted".
  ::
  ++  svc-post-redeem
    |=  [eyre-id=@ta name=@t req-body=(unit octs)]
    ^-  (quip card state-0)
    =/  resolved  (resolve-service name)
    ?:  ?=(%| -.resolved)  :_  st  (give-err eyre-id 400 p.resolved)
    =/  svc=service  p.resolved
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_  st  (give-err eyre-id 400 p.parsed)
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    ?.  (has-key p.jon 'proofs')  :_  st  (give-err eyre-id 400 'missing-proofs')
    =/  proofs   (get-array p.jon 'proofs')
    =/  results  (service-check svc proofs)
    ?:  (lien results |=([s=@t v=? sp=?] !v))
      :_  st  (give-err eyre-id 400 'invalid-service-token')
    ::  All proofs here share ks-id.svc; de-dup on secret so two identical
    ::  secrets in one batch can't both read unspent and both be counted.
    ?:  (has-dup-secrets (turn results |=([s=@t v=? sp=?] [ks-id.svc s])))
      :_  st  (give-err eyre-id 400 'duplicate-service-token')
    =/  fresh-secrets=(list @t)
      %+  murn  results
      |=  [s=@t v=? sp=?]
      ?:(sp ~ `s)
    =.  cred-spent.st
      %-  ~(gas in cred-spent.st)
      (turn fresh-secrets |=(s=@t [ks-id.svc s]))
    =.  services.st
      %+  ~(put by services.st)  name
      svc(redeemed (add redeemed.svc (lent fresh-secrets)))
    =/  result-json=(list json)
      %+  turn  results
      |=  [secret=@t valid=? spent=?]
      %-  pairs:enjs:format
      :~  ['secret' s+secret]
          ['status' s+?:(spent 'replay' 'fresh')]
      ==
    :_  st
    %-  give-json  :_  eyre-id
    (pairs:enjs:format ['redeemed' [%a result-json]]~)
  ::
  ::  ============================================================
  ::  Services — admin endpoints
  ::  ============================================================
  ::
  ++  admin-svc-list
    |=  eyre-id=@ta
    ^-  (list card)
    =/  list=(list json)
      %+  turn  ~(tap by services.st)
      |=  [name=@t svc=service]
      (service-to-json-admin svc)
    (give-json (pairs:enjs:format ['services' [%a list]]~) eyre-id)
  ::
  ++  admin-svc-detail
    |=  [eyre-id=@ta name=@t]
    ^-  (list card)
    =/  maybe-svc  (~(get by services.st) name)
    ?~  maybe-svc  (give-err eyre-id 404 'service-not-found')
    (give-json (service-to-json-admin u.maybe-svc) eyre-id)
  ::
  ::  POST .../allowlist/add — add an access key to a service
  ::
  ++  admin-svc-allowlist-add
    |=  [eyre-id=@ta req-body=(unit octs)]
    ^-  (quip card state-0)
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_(st (give-err eyre-id 400 p.parsed))
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    =/  name=@t  (get-str p.jon 'name')
    =/  key=@t   (get-str p.jon 'key')
    ?:  =('' name)  :_(st (give-err eyre-id 400 'missing-name'))
    ?:  =('' key)   :_(st (give-err eyre-id 400 'missing-key'))
    =/  maybe-svc  (~(get by services.st) name)
    ?~  maybe-svc  :_(st (give-err eyre-id 404 'service-not-found'))
    =/  svc=service  u.maybe-svc
    =.  allowlist.svc  (~(put in allowlist.svc) key)
    =.  services.st    (~(put by services.st) name svc)
    :_  st
    (give-json (service-to-json-admin svc) eyre-id)
  ::
  ::  POST .../allowlist/remove — remove an access key
  ::
  ++  admin-svc-allowlist-remove
    |=  [eyre-id=@ta req-body=(unit octs)]
    ^-  (quip card state-0)
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_(st (give-err eyre-id 400 p.parsed))
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    =/  name=@t  (get-str p.jon 'name')
    =/  key=@t   (get-str p.jon 'key')
    ?:  =('' name)  :_(st (give-err eyre-id 400 'missing-name'))
    ?:  =('' key)   :_(st (give-err eyre-id 400 'missing-key'))
    =/  maybe-svc  (~(get by services.st) name)
    ?~  maybe-svc  :_(st (give-err eyre-id 404 'service-not-found'))
    =/  svc=service  u.maybe-svc
    =.  allowlist.svc  (~(del in allowlist.svc) key)
    =.  services.st    (~(put by services.st) name svc)
    :_  st
    (give-json (service-to-json-admin svc) eyre-id)
  ::
  ::  POST .../create — auto-generates a fresh cred-keyset for the service
  ::
  ++  admin-svc-create
    |=  [eyre-id=@ta req-body=(unit octs)]
    ^-  (quip card state-0)
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_(st (give-err eyre-id 400 p.parsed))
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    =/  name=@t         (get-str p.jon 'name')
    =/  title=@t        (get-str p.jon 'title')
    =/  description=@t  (get-str p.jon 'description')
    ?:  =('' name)   :_(st (give-err eyre-id 400 'missing-name'))
    ?:  =('' title)  :_(st (give-err eyre-id 400 'missing-title'))
    ?:  (~(has by services.st) name)
      :_(st (give-err eyre-id 409 'service-already-exists'))
    ::  generate the backing cred-keyset
    =/  k   (mod (shax (add (mul (shax eny.bowl) (bex 64)) (sham name))) secp-n)
    =/  k2  ?:(=(0 k) 1 k)
    =/  priv-map=(map @ud @)    (my [0 k2]~)
    =/  pub-map=(map @ud @t)    (my [0 (pt-to-hex (pubkey k2))]~)
    =/  ks-id=@t  (compute-cred-ks-id pub-map)
    =/  ks=cred-keyset
      :*  ks-id=ks-id
          active=%.y
          keys=pub-map
          privkeys=priv-map
          created=now.bowl
          service-scoped=%.y
      ==
    =.  cred-keysets.st  (~(put by cred-keysets.st) ks-id ks)
    ::  optional expires / max-issuance
    =/  expires=(unit @da)
      ?.  (has-key p.jon 'expires')  ~
      `(add ~1970.1.1 (mul ~s1 (get-num p.jon 'expires')))
    =/  max-issuance=(unit @ud)
      ?.  (has-key p.jon 'max_issuance')  ~
      `(get-num p.jon 'max_issuance')
    =/  svc=service
      :*  name=name
          title=title
          description=description
          kind=%single-use
          ks-id=ks-id
          active=%.y
          expires=expires
          max-issuance=max-issuance
          issued=0
          redeemed=0
          created=now.bowl
          allowlist=*(set @t)
      ==
    =.  services.st  (~(put by services.st) name svc)
    :_  st
    (give-json (service-to-json svc) eyre-id)
  ::
  ::  POST .../update — change title/description/expires/max-issuance
  ::
  ++  admin-svc-update
    |=  [eyre-id=@ta req-body=(unit octs)]
    ^-  (quip card state-0)
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_(st (give-err eyre-id 400 p.parsed))
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    =/  name=@t  (get-str p.jon 'name')
    ?:  =('' name)  :_(st (give-err eyre-id 400 'missing-name'))
    =/  maybe-svc  (~(get by services.st) name)
    ?~  maybe-svc  :_(st (give-err eyre-id 404 'service-not-found'))
    =/  svc=service  u.maybe-svc
    =?  title.svc        (has-key p.jon 'title')         (get-str p.jon 'title')
    =?  description.svc  (has-key p.jon 'description')   (get-str p.jon 'description')
    =?  expires.svc      (has-key p.jon 'expires')
      `(add ~1970.1.1 (mul ~s1 (get-num p.jon 'expires')))
    =?  max-issuance.svc  (has-key p.jon 'max_issuance')
      `(get-num p.jon 'max_issuance')
    =.  services.st  (~(put by services.st) name svc)
    :_  st
    (give-json (service-to-json svc) eyre-id)
  ::
  ++  admin-svc-activate
    |=  [eyre-id=@ta req-body=(unit octs)]
    ^-  (quip card state-0)
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_(st (give-err eyre-id 400 p.parsed))
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    =/  name=@t  (get-str p.jon 'name')
    ?:  =('' name)  :_(st (give-err eyre-id 400 'missing-name'))
    =/  maybe-svc  (~(get by services.st) name)
    ?~  maybe-svc  :_(st (give-err eyre-id 404 'service-not-found'))
    =.  services.st  (~(put by services.st) name u.maybe-svc(active %.y))
    :_  st
    %-  give-json  :_  eyre-id
    (pairs:enjs:format ['name' s+name] ['active' b+%.y] ~)
  ::
  ++  admin-svc-deactivate
    |=  [eyre-id=@ta req-body=(unit octs)]
    ^-  (quip card state-0)
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_(st (give-err eyre-id 400 p.parsed))
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    =/  name=@t  (get-str p.jon 'name')
    ?:  =('' name)  :_(st (give-err eyre-id 400 'missing-name'))
    =/  maybe-svc  (~(get by services.st) name)
    ?~  maybe-svc  :_(st (give-err eyre-id 404 'service-not-found'))
    =.  services.st  (~(put by services.st) name u.maybe-svc(active %.n))
    :_  st
    %-  give-json  :_  eyre-id
    (pairs:enjs:format ['name' s+name] ['active' b+%.n] ~)
  ::
  ::  POST .../delete — only if inactive and unused
  ::
  ++  admin-svc-delete
    |=  [eyre-id=@ta req-body=(unit octs)]
    ^-  (quip card state-0)
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_(st (give-err eyre-id 400 p.parsed))
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    =/  name=@t  (get-str p.jon 'name')
    ?:  =('' name)  :_(st (give-err eyre-id 400 'missing-name'))
    =/  maybe-svc  (~(get by services.st) name)
    ?~  maybe-svc  :_(st (give-err eyre-id 404 'service-not-found'))
    =/  svc=service  u.maybe-svc
    ?:  active.svc     :_(st (give-err eyre-id 400 'deactivate-before-delete'))
    ?:  (gth issued.svc 0)
      :_(st (give-err eyre-id 400 'service-has-issued-tokens'))
    =.  services.st  (~(del by services.st) name)
    :_  st
    %-  give-json  :_  eyre-id
    (pairs:enjs:format ['deleted' b+%.y] ['name' s+name] ~)
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
