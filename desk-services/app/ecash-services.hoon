::  ecash-services: credential + services access-control agent.
::  Non-value-bearing; split out of the %ecash mint. Serves /cred/v1 and
::  /services/v1, plus an authenticated admin API at /apps/ecash-services/admin.
::  The decisions live in /lib/ecash-services-rules, which also brings in
::  bdhke, curve and the shared HTTP plumbing (ecash-http).
::
/-  *ecash-services
/+  default-agent, dbug, *ecash-services-rules
/*  dashboard-lines  %txt  /app/dashboard/txt
|%
::  +cred-keyset-0 / +state-0: the pre-C4 persisted shape, kept frozen so
::  on-load can decode and migrate it. cred-keyset-0 has no service-scoped
::  flag; its cred-spent is a bare (set @t) keyed only on secret.
+$  cred-keyset-0
  $:  ks-id=@t
      active=?
      keys=(map @ud @t)
      privkeys=(map @ud @)
      created=@da
  ==
+$  state-0
  $:  %0
      cred-keysets=(map @t cred-keyset-0)
      cred-spent=(set @t)
      cred-counter=@ud
      services=(map @t service)
  ==
::  +state-1: the live state. cred-keyset carries service-scoped;
::  cred-spent is namespaced per keyset as (set [kid=@t secret=@t]);
::  cred-spent-legacy holds pre-migration bare secrets, consulted only as an
::  extra spent signal so no already-redeemed token becomes spendable again.
+$  state-1
  $:  %1
      cred-keysets=(map @t cred-keyset)
      cred-spent=(set [@t @t])
      cred-spent-legacy=(set @t)
      cred-counter=@ud
      services=(map @t service)
  ==
+$  versioned-state  $%(state-0 state-1)
+$  card  card:agent:gall
--
%-  agent:dbug
^-  agent:gall
=<
=|  state-1
=*  state  -
|_  =bowl:gall
+*  this  .
    def   ~(. (default-agent this %.n) bowl)
    hc    ~(. ec [bowl state])
++  on-save   ^-  vase  !>(state)
++  on-load
  |=  old=vase
  ^-  (quip card _this)
  =/  prev=versioned-state  !<(versioned-state old)
  =?  prev  ?=(%0 -.prev)  (state-0-to-1 prev)
  ?>  ?=(%1 -.prev)
  =.  cred-keysets.prev  (retire-orphans cred-keysets.prev services.prev)
  [(binds dap.bowl) this(state prev)]
++  on-init   [(binds dap.bowl) this]
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
  ::  no src/sap gate: gall gives a guest request and a remote ship the same provenance
  ?+  path  (on-watch:def path)
      [%http-response *]  `this
  ==
++  on-leave  on-leave:def
++  on-peek   on-peek:def
++  on-agent  on-agent:def
++  on-arvo
  |=  [=wire =sign-arvo]
  ^-  (quip card _this)
  ?.  ?=([%eyre %bound *] sign-arvo)  (on-arvo:def wire sign-arvo)
  ?:  accepted.sign-arvo  `this
  ~&  >>>  [%ecash-services-bind-failed wire]
  `this
++  on-fail   on-fail:def
--
::  -- Helper core --
|%
++  binds
  |=  dap=term
  ^-  (list card)
  :~  [%pass /eyre/connect-cred %arvo %e %connect [`/cred dap]]
      [%pass /eyre/connect-services %arvo %e %connect [`/services dap]]
      [%pass /eyre/connect-apps %arvo %e %connect [`/apps/ecash-services dap]]
  ==
::
::  state-0-to-1: reconstruct service-scoped from the services map (a
::  keyset is service-backing iff some service references its ks-id), and
::  move old bare spent secrets into cred-spent-legacy (kid unrecoverable).
++  state-0-to-1
  |=  o=state-0
  ^-  state-1
  =/  svc-ks=(set @t)  (silt (turn ~(val by services.o) |=(s=service ks-id.s)))
  =/  upgraded=(map @t cred-keyset)
    %-  ~(run by cred-keysets.o)
    |=  k=cred-keyset-0
    ^-  cred-keyset
    [ks-id.k active.k keys.k privkeys.k created.k (~(has in svc-ks) ks-id.k)]
  [%1 upgraded ~ cred-spent.o cred-counter.o services.o]
::
++  ec
  |_  [=bowl:gall st=state-1]
  ::
  ::  handle-http: route an inbound HTTP request to its handler.
  ::
  ++  handle-http
    |=  [eyre-id=@ta req=inbound-request:eyre]
    ^-  (quip card state-1)
    =/  body                body.request.req
    =/  segs=(list @t)      (parse-request-path url.request.req)
    =/  route=(list @t)     [method.request.req segs]
    ::  Admin surface requires a valid ship session. Eyre sets
    ::  authenticated=%.y only for a %ours session, so this already
    ::  guarantees the session ship is our.bowl (no foreign session @p is
    ::  exposed on the http request; cf. =(src.bowl our.bowl) on pokes).
    ?:  ?&  ?=([%apps %ecash-services %admin *] segs)
            !authenticated.req
        ==
      [(give-err eyre-id 401 'unauthorized') st]
    ::  CSRF: a state-changing admin request must be same-origin.
    ?:  ?&  ?=([%apps %ecash-services %admin *] segs)
            !(csrf-ok req)
        ==
      [(give-err eyre-id 403 'forbidden-cross-origin') st]
    ::  CORS preflight, public routes only (admin OPTIONS stays 404)
    ?:  ?&  ?=(%'OPTIONS' method.request.req)
            ?=(?([%cred %v1 *] [%services %v1 *]) segs)
        ==
      [(give-preflight eyre-id) st]
    ?+  route  [(give-err eyre-id 404 'not-found') st]
        [%'GET' %apps %ecash-services %admin ~]
      [(give-dashboard eyre-id dashboard-lines eny.bowl) st]
        [%'GET' %cred %v1 %keys ~]            [(cred-get-keys eyre-id) st]
        [%'GET' %cred %v1 %keys @ ~]          [(cred-get-keys-by-id eyre-id i.t.t.t.t.route) st]
        [%'GET' %cred %v1 %keysets ~]         [(cred-get-keysets eyre-id) st]
        [%'POST' %cred %v1 %issue ~]          (cred-post-issue eyre-id body)
        [%'POST' %cred %v1 %verify ~]         [(post-verify eyre-id body ~ 'valid') st]
        [%'POST' %cred %v1 %redeem ~]         (cred-post-redeem eyre-id body)
        [%'GET' %services %v1 %list ~]        [(svc-get-list eyre-id) st]
        [%'GET' %services %v1 @ ~]            [(svc-get-detail eyre-id i.t.t.t.route) st]
        [%'POST' %services %v1 @ %issue ~]    (svc-post-issue eyre-id i.t.t.t.route body)
        [%'POST' %services %v1 @ %verify ~]   [(svc-post-verify eyre-id i.t.t.t.route body) st]
        [%'POST' %services %v1 @ %redeem ~]   (svc-post-redeem eyre-id i.t.t.t.route body)
        [%'GET' %apps %ecash-services %admin %api %cred %overview ~]
      [(admin-cred-overview eyre-id) st]
        [%'POST' %apps %ecash-services %admin %api %cred %keysets %generate ~]
      (admin-cred-keyset-generate eyre-id)
        [%'POST' %apps %ecash-services %admin %api %cred %keysets %activate ~]
      (admin-cred-keyset-set eyre-id body &)
        [%'POST' %apps %ecash-services %admin %api %cred %keysets %deactivate ~]
      (admin-cred-keyset-set eyre-id body |)
        [%'GET' %apps %ecash-services %admin %api %services ~]
      [(admin-svc-list eyre-id) st]
        [%'GET' %apps %ecash-services %admin %api %services @ ~]
      [(admin-svc-detail eyre-id i.t.t.t.t.t.t.route) st]
        [%'POST' %apps %ecash-services %admin %api %services %create ~]
      (admin-svc-create eyre-id body)
        [%'POST' %apps %ecash-services %admin %api %services %update ~]
      (admin-svc-update eyre-id body)
        [%'POST' %apps %ecash-services %admin %api %services %activate ~]
      (admin-svc-set eyre-id body &)
        [%'POST' %apps %ecash-services %admin %api %services %deactivate ~]
      (admin-svc-set eyre-id body |)
        [%'POST' %apps %ecash-services %admin %api %services %delete ~]
      (admin-svc-delete eyre-id body)
        [%'POST' %apps %ecash-services %admin %api %services %allowlist %add ~]
      (admin-svc-allowlist eyre-id body &)
        [%'POST' %apps %ecash-services %admin %api %services %allowlist %remove ~]
      (admin-svc-allowlist eyre-id body |)
    ==
  ::
  ::  -- state readers --
  ::
  ++  is-spent
    |=  [kid=@t secret=@t]
    ^-  ?
    ?|  (~(has in cred-spent.st) [kid secret])
        (~(has in cred-spent-legacy.st) secret)
    ==
  ::
  ++  proofs-pre
    |=  [proofs=(list json) scope=(unit @t)]
    ^-  (list checked-proof)
    (turn proofs |=(t=json (proof-pre t cred-keysets.st scope)))
  ::
  ::  redeem-refusal: why a redeem batch must be refused, if it must.
  ::  The cheap checks cover the whole batch before any EC work.
  ++  redeem-refusal
    |=  [pres=(list checked-proof) bad=@t dup=@t]
    ^-  (unit @t)
    ?.  (levy pres |=(p=checked-proof ?=(^ ok.p)))  `bad
    ?:  (has-dup-secrets (turn pres |=(p=checked-proof [kid.p secret.p])))  `dup
    ?.  (levy pres proof-sig-ok)  `bad
    ~
  ::
  ::  read-svc: an admin request naming an existing service
  ++  read-svc
    |=  body=(unit octs)
    ^-  (each [o=(map @t json) svc=service] [@ud @t])
    =/  o  (read-obj body)
    ?:  ?=(%| -.o)  |+[400 p.o]
    =/  name  (get-str p.o 'name')
    ?:  =('' name)  |+[400 'missing-name']
    =/  svc  (~(get by services.st) name)
    ?~  svc  |+[404 'service-not-found']
    &+[p.o u.svc]
  ::
  ::  -- /cred/v1 --
  ::
  ::  GET /cred/v1/keys: active, non-service keysets with their keys.
  ::  Service keysets are issued only through the gated /services path.
  ++  cred-get-keys
    |=  eyre-id=@ta
    ^-  (list card)
    =/  kss=(list json)
      %+  murn  ~(val by cred-keysets.st)
      |=  ks=cred-keyset
      ?.  &(active.ks !service-scoped.ks)  ~
      `(keyset-json ks)
    (give-json (pairs:enjs:format ['keysets' a+kss]~) eyre-id)
  ::
  ::  GET /cred/v1/keys/{keyset_id}
  ::
  ::    A service keyset's PUBLIC key is intentionally fetchable by id:
  ::    clients need it to unblind tokens they legitimately obtained, and a
  ::    pubkey cannot forge a signature. Only signing/verify/redeem are gated.
  ++  cred-get-keys-by-id
    |=  [eyre-id=@ta kid=@t]
    ^-  (list card)
    =/  ks  (~(get by cred-keysets.st) kid)
    ?~  ks  (give-err eyre-id 404 'credential-keyset-not-found')
    (give-json (pairs:enjs:format ['keysets' a+~[(keyset-json u.ks)]]~) eyre-id)
  ::
  ::  GET /cred/v1/keysets: metadata of the non-service keysets
  ++  cred-get-keysets
    |=  eyre-id=@ta
    ^-  (list card)
    =/  kss=(list json)
      %+  murn  ~(val by cred-keysets.st)
      |=  ks=cred-keyset
      ?:  service-scoped.ks  ~
      `(pairs:enjs:format ~[['id' s+ks-id.ks] ['active' b+active.ks]])
    (give-json (pairs:enjs:format ['keysets' a+kss]~) eyre-id)
  ::
  ::  POST /cred/v1/issue
  ++  cred-post-issue
    |=  [eyre-id=@ta body=(unit octs)]
    ^-  (quip card state-1)
    =/  outs  (read-batch body 'outputs')
    ?:  ?=(%| -.outs)  [(give-err eyre-id 400 p.outs) st]
    ?:  (has-dup-x a.p.outs)  [(give-err eyre-id 400 'duplicate-output') st]
    =/  pres  (turn a.p.outs |=(m=json (output-pre m cred-keysets.st ~)))
    =.  cred-counter.st  (add cred-counter.st (n-ready pres))
    :_  st
    (give-json (pairs:enjs:format ['signatures' a+(sign-batch pres eny.bowl)]~) eyre-id)
  ::
  ::  POST /cred/v1/verify and /services/v1/{name}/verify: check proofs
  ::  without spending; the answer's list goes under key
  ++  post-verify
    |=  [eyre-id=@ta body=(unit octs) scope=(unit @t) key=@t]
    ^-  (list card)
    =/  proofs  (read-batch body 'proofs')
    ?:  ?=(%| -.proofs)  (give-err eyre-id 400 p.proofs)
    %-  give-json  :_  eyre-id
    %-  pairs:enjs:format  :_  ~
    :-  key
    :-  %a
    %+  turn  (proofs-pre a.p.proofs scope)
    |=  p=checked-proof
    =/  valid  (proof-sig-ok p)
    %-  pairs:enjs:format
    :~  ['secret' s+secret.p]
        ['valid' b+valid]
        ['spent' b+&(valid (is-spent kid.p secret.p))]
    ==
  ::
  ::  POST /cred/v1/redeem: verify and spend every proof, or none
  ++  cred-post-redeem
    |=  [eyre-id=@ta body=(unit octs)]
    ^-  (quip card state-1)
    =/  proofs  (read-batch body 'proofs')
    ?:  ?=(%| -.proofs)  [(give-err eyre-id 400 p.proofs) st]
    =/  pres  (proofs-pre a.p.proofs ~)
    =/  keys  (turn pres |=(p=checked-proof [kid.p secret.p]))
    =/  no  (redeem-refusal pres 'invalid-credential' 'duplicate-credential')
    ?^  no  [(give-err eyre-id 400 u.no) st]
    ?:  (lien keys is-spent)  [(give-err eyre-id 400 'credential-already-spent') st]
    =.  cred-spent.st  (~(gas in cred-spent.st) keys)
    :_  st
    %-  give-json  :_  eyre-id
    %-  pairs:enjs:format  :_  ~
    :-  'redeemed'
    :-  %a
    %+  turn  keys
    |=([k=@t s=@t] (pairs:enjs:format ~[['secret' s+s] ['redeemed' b+&]]))
  ::
  ::  -- /services/v1 --
  ::
  ::  GET /services/v1/list: active services only
  ++  svc-get-list
    |=  eyre-id=@ta
    ^-  (list card)
    =/  svcs=(list json)
      %+  murn  ~(val by services.st)
      |=  svc=service
      ?.  active.svc  ~
      `(service-to-json svc)
    (give-json (pairs:enjs:format ['services' a+svcs]~) eyre-id)
  ::
  ::  GET /services/v1/{name}: a usable service's detail, else 404
  ++  svc-get-detail
    |=  [eyre-id=@ta name=@t]
    ^-  (list card)
    =/  svc  (resolve-service (~(get by services.st) name) now.bowl)
    ?:  ?=(%| -.svc)  (give-err eyre-id 404 +.p.svc)
    (give-json (service-to-json p.svc) eyre-id)
  ::
  ::  POST /services/v1/{name}/issue: sign blinded outputs for a service.
  ::
  ::    A non-empty allowlist requires an `access_key` in the body that is
  ::    a member. The cap is checked before any signing, counting only the
  ::    outputs that will get a real signature.
  ++  svc-post-issue
    |=  [eyre-id=@ta name=@t body=(unit octs)]
    ^-  (quip card state-1)
    =/  svc  (resolve-service (~(get by services.st) name) now.bowl)
    ?:  ?=(%| -.svc)  [(give-err eyre-id p.svc) st]
    =/  outs  (read-batch body 'outputs')
    ?:  ?=(%| -.outs)  [(give-err eyre-id 400 p.outs) st]
    ?:  ?&  !=(~ allowlist.p.svc)
            !(~(has in allowlist.p.svc) (get-str o.p.outs 'access_key'))
        ==
      [(give-err eyre-id 403 'service-access-denied') st]
    ?:  (has-dup-x a.p.outs)  [(give-err eyre-id 400 'duplicate-output') st]
    =/  pres  (turn a.p.outs |=(m=json (output-pre m cred-keysets.st `ks-id.p.svc)))
    =/  n  (n-ready pres)
    ?.  (cap-ok p.svc n)  [(give-err eyre-id 400 'service-issuance-cap-reached') st]
    =.  services.st  (~(put by services.st) name p.svc(issued (add issued.p.svc n)))
    =.  cred-counter.st  (add cred-counter.st n)
    :_  st
    (give-json (pairs:enjs:format ['signatures' a+(sign-batch pres eny.bowl)]~) eyre-id)
  ::
  ::  POST /services/v1/{name}/verify
  ++  svc-post-verify
    |=  [eyre-id=@ta name=@t body=(unit octs)]
    ^-  (list card)
    =/  svc  (resolve-service (~(get by services.st) name) now.bowl)
    ?:  ?=(%| -.svc)  (give-err eyre-id p.svc)
    (post-verify eyre-id body `ks-id.p.svc 'results')
  ::
  ::  POST /services/v1/{name}/redeem: verify and mark spent (idempotent).
  ::
  ::    Any invalid proof (bad signature or another keyset) refuses the whole
  ::    batch with 400. Otherwise each token's `status` is `fresh` (first
  ::    use: spent now) or `replay` (already spent: state untouched, still
  ::    200), so a retry after a network drop is safe.
  ++  svc-post-redeem
    |=  [eyre-id=@ta name=@t body=(unit octs)]
    ^-  (quip card state-1)
    =/  svc  (resolve-service (~(get by services.st) name) now.bowl)
    ?:  ?=(%| -.svc)  [(give-err eyre-id p.svc) st]
    =/  proofs  (read-batch body 'proofs')
    ?:  ?=(%| -.proofs)  [(give-err eyre-id 400 p.proofs) st]
    =/  pres  (proofs-pre a.p.proofs `ks-id.p.svc)
    =/  no  (redeem-refusal pres 'invalid-service-token' 'duplicate-service-token')
    ?^  no  [(give-err eyre-id 400 u.no) st]
    =/  was=(list [key=[@t @t] spent=?])
      (turn pres |=(p=checked-proof [[kid.p secret.p] (is-spent kid.p secret.p)]))
    =/  fresh=(list [@t @t])
      (murn was |=([k=[@t @t] s=?] ?:(s ~ `k)))
    =.  cred-spent.st  (~(gas in cred-spent.st) fresh)
    =.  services.st
      (~(put by services.st) name p.svc(redeemed (add redeemed.p.svc (lent fresh))))
    :_  st
    %-  give-json  :_  eyre-id
    %-  pairs:enjs:format  :_  ~
    :-  'redeemed'
    :-  %a
    %+  turn  was
    |=  [k=[@t s=@t] spent=?]
    (pairs:enjs:format ~[['secret' s+s.k] ['status' s+?:(spent 'replay' 'fresh')]])
  ::
  ::  -- admin: credential keysets --
  ::
  ++  admin-cred-overview
    |=  eyre-id=@ta
    ^-  (list card)
    =/  owner=(map @t @t)
      (malt (turn ~(val by services.st) |=(s=service [ks-id.s name.s])))
    %-  give-json  :_  eyre-id
    %-  pairs:enjs:format
    :~  ['cred_keysets' (numb:enjs:format ~(wyt by cred-keysets.st))]
        ['cred_issued' (numb:enjs:format cred-counter.st)]
        ['cred_spent' (numb:enjs:format (add ~(wyt in cred-spent.st) ~(wyt in cred-spent-legacy.st)))]
        :-  'keysets'
        :-  %a
        %+  turn  ~(val by cred-keysets.st)
        |=  ks=cred-keyset
        %-  pairs:enjs:format
        :~  ['id' s+ks-id.ks]
            ['active' b+active.ks]
            ['service_scoped' b+service-scoped.ks]
            ::  the owning service's name; null for a plain keyset, or for a
            ::  service keyset whose service was deleted
            ['service' (fall (bind (~(get by owner) ks-id.ks) |=(n=@t `json`s+n)) ~)]
        ==
    ==
  ::
  ++  admin-cred-keyset-generate
    |=  eyre-id=@ta
    ^-  (quip card state-1)
    =/  ks  (gen-cred-keyset eny.bowl now.bowl |)
    =.  cred-keysets.st  (~(put by cred-keysets.st) ks-id.ks ks)
    [(give-json (keyset-json ks) eyre-id) st]
  ::
  ::  activate (on) or deactivate a plain keyset. A service's keyset lives
  ::  and dies with its service.
  ++  admin-cred-keyset-set
    |=  [eyre-id=@ta body=(unit octs) on=?]
    ^-  (quip card state-1)
    =/  o  (read-obj body)
    ?:  ?=(%| -.o)  [(give-err eyre-id 400 p.o) st]
    =/  id  (get-str p.o 'id')
    ?:  =('' id)  [(give-err eyre-id 400 'missing-id') st]
    =/  ks  (~(get by cred-keysets.st) id)
    ?~  ks  [(give-err eyre-id 404 'credential-keyset-not-found') st]
    ?:  service-scoped.u.ks  [(give-err eyre-id 400 'keyset-is-service-scoped') st]
    =.  cred-keysets.st  (~(put by cred-keysets.st) id u.ks(active on))
    [(give-json (pairs:enjs:format ~[['id' s+id] ['active' b+on]]) eyre-id) st]
  ::
  ::  -- admin: services --
  ::
  ++  admin-svc-list
    |=  eyre-id=@ta
    ^-  (list card)
    =/  svcs  (turn ~(val by services.st) service-to-json-admin)
    (give-json (pairs:enjs:format ['services' a+svcs]~) eyre-id)
  ::
  ++  admin-svc-detail
    |=  [eyre-id=@ta name=@t]
    ^-  (list card)
    =/  svc  (~(get by services.st) name)
    ?~  svc  (give-err eyre-id 404 'service-not-found')
    (give-json (service-to-json-admin u.svc) eyre-id)
  ::
  ::  POST .../create: a new service and its own fresh keyset. expires
  ::  (unix seconds) and max_issuance are optional: absent or null for
  ::  none, else a bare non-negative integer.
  ++  admin-svc-create
    |=  [eyre-id=@ta body=(unit octs)]
    ^-  (quip card state-1)
    =/  o  (read-obj body)
    ?:  ?=(%| -.o)  [(give-err eyre-id 400 p.o) st]
    =/  name   (get-str p.o 'name')
    =/  title  (get-str p.o 'title')
    ?:  =('' name)  [(give-err eyre-id 400 'missing-name') st]
    ?.  (valid-service-name name)  [(give-err eyre-id 400 'invalid-service-name') st]
    ?:  =('' title)  [(give-err eyre-id 400 'missing-title') st]
    ?:  (~(has by services.st) name)
      [(give-err eyre-id 409 'service-already-exists') st]
    =/  exp  (opt-ud (~(gut by p.o) 'expires' ~))
    ?~  exp  [(give-err eyre-id 400 'invalid-expires') st]
    =/  max  (opt-ud (~(gut by p.o) 'max_issuance' ~))
    ?~  max  [(give-err eyre-id 400 'invalid-max-issuance') st]
    =/  ks  (gen-cred-keyset eny.bowl now.bowl &)
    =/  svc=service
      :*  name
          title
          (get-str p.o 'description')
          %single-use
          ks-id.ks
          &
          (bind u.exp unix-to-da)
          u.max
          0
          0
          now.bowl
          ~
      ==
    =.  cred-keysets.st  (~(put by cred-keysets.st) ks-id.ks ks)
    =.  services.st  (~(put by services.st) name svc)
    [(give-json (service-to-json svc) eyre-id) st]
  ::
  ::  POST .../update: change title, description, expires or max_issuance.
  ::  An absent field is left alone; null clears expires or max_issuance.
  ++  admin-svc-update
    |=  [eyre-id=@ta body=(unit octs)]
    ^-  (quip card state-1)
    =/  r  (read-svc body)
    ?:  ?=(%| -.r)  [(give-err eyre-id p.r) st]
    =/  o  o.p.r
    =/  svc  svc.p.r
    =/  exp  (opt-ud (~(gut by o) 'expires' ~))
    ?~  exp  [(give-err eyre-id 400 'invalid-expires') st]
    =/  max  (opt-ud (~(gut by o) 'max_issuance' ~))
    ?~  max  [(give-err eyre-id 400 'invalid-max-issuance') st]
    =?  title.svc  (has-key o 'title')  (get-str o 'title')
    =?  description.svc  (has-key o 'description')  (get-str o 'description')
    =?  expires.svc  (has-key o 'expires')  (bind u.exp unix-to-da)
    =?  max-issuance.svc  (has-key o 'max_issuance')  u.max
    =.  services.st  (~(put by services.st) name.svc svc)
    [(give-json (service-to-json svc) eyre-id) st]
  ::
  ::  POST .../activate (on) or .../deactivate
  ++  admin-svc-set
    |=  [eyre-id=@ta body=(unit octs) on=?]
    ^-  (quip card state-1)
    =/  r  (read-svc body)
    ?:  ?=(%| -.r)  [(give-err eyre-id p.r) st]
    =/  name  name.svc.p.r
    =.  services.st  (~(put by services.st) name svc.p.r(active on))
    [(give-json (pairs:enjs:format ~[['name' s+name] ['active' b+on]]) eyre-id) st]
  ::
  ::  POST .../delete: only if inactive and it never issued. Its keyset
  ::  signed nothing and now backs nothing, so it is retired too.
  ++  admin-svc-delete
    |=  [eyre-id=@ta body=(unit octs)]
    ^-  (quip card state-1)
    =/  r  (read-svc body)
    ?:  ?=(%| -.r)  [(give-err eyre-id p.r) st]
    =/  svc  svc.p.r
    ?:  active.svc  [(give-err eyre-id 400 'deactivate-before-delete') st]
    ?:  (gth issued.svc 0)  [(give-err eyre-id 400 'service-has-issued-tokens') st]
    =.  services.st  (~(del by services.st) name.svc)
    =.  cred-keysets.st  (retire-orphans cred-keysets.st services.st)
    [(give-json (pairs:enjs:format ~[['deleted' b+&] ['name' s+name.svc]]) eyre-id) st]
  ::
  ::  POST .../allowlist/add (add) or .../allowlist/remove: an access key
  ++  admin-svc-allowlist
    |=  [eyre-id=@ta body=(unit octs) add=?]
    ^-  (quip card state-1)
    =/  r  (read-svc body)
    ?:  ?=(%| -.r)  [(give-err eyre-id p.r) st]
    =/  key  (get-str o.p.r 'key')
    ?:  =('' key)  [(give-err eyre-id 400 'missing-key') st]
    =/  svc  svc.p.r
    =.  allowlist.svc
      ?:  add  (~(put in allowlist.svc) key)
      (~(del in allowlist.svc) key)
    =.  services.st  (~(put by services.st) name.svc svc)
    [(give-json (service-to-json-admin svc) eyre-id) st]
  --
--
