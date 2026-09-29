::  tessera: blind-signed access tokens. Each service is a Cashu NUT-22
::  auth mint at /tessera/<name>, and takes the same requests from other
::  ships over Ames. This ship also holds tokens other ships issued. The
::  owner runs both through the admin API at /apps/tessera/api. The
::  decisions live in /lib/tessera-rules.
::
/-  *tessera
/+  default-agent, dbug, *tessera-rules
/*  dashboard-lines  %txt  /app/dashboard/txt
/*  icon-svg         %txt  /app/icon-svg/txt
|%
+$  state-0
  $:  %0
      services=(map @t service)
      ::  per keyset id: the hashes of its spent secrets
      spent=(map @t (set @))
      ::  per [service identity]: its quota usage
      used=(map [@t @t] usage)
      ::  held: tokens by [issuer service]
      wallet=(map [ship @t] (list token))
      ::  tokens other ships handed this one, by [giver issuer service],
      ::  waiting for the owner to accept or decline them
      offers=(map [ship ship @t] (list @t))
      pend=(map @uv pending)
      ::  when the prune timer is set for
      prune-at=@da
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
    hc    ~(. tc [bowl state])
++  on-save  ^-  vase  !>(state)
++  on-load
  |=  old=vase
  ^-  (quip card _this)
  =.  state  !<(state-0 old)
  =^  cards  state  prune:hc
  [(weld (binds dap.bowl) cards) this]
++  on-init
  ^-  (quip card _this)
  =^  cards  state  prune:hc
  [(weld (binds dap.bowl) cards) this]
++  on-poke
  |=  [=mark =vase]
  ^-  (quip card _this)
  =^  cards  state
    ?+  mark  (on-poke:def mark vase)
      %handle-http-request  (handle-http:hc !<([@ta inbound-request:eyre] vase))
      %tessera-action       (act:hc !<(action vase))
    ==
  [cards this]
++  on-watch
  |=  =path
  ^-  (quip card _this)
  ::  no src/sap gate: gall gives a guest request and a remote ship the same provenance
  ?+  path  (on-watch:def path)
      [%http-response *]  `this
  ==
++  on-leave  on-leave:def
::  /x/wallet: how many tokens this ship holds, by [issuer service]
++  on-peek
  |=  =path
  ^-  (unit (unit cage))
  ?+  path  (on-peek:def path)
    [%x %wallet ~]  ``noun+!>(`(map [ship @t] @ud)`(~(run by wallet) |=(l=(list token) (lent l))))
  ==
++  on-agent
  |=  [=wire =sign:agent:gall]
  ^-  (quip card _this)
  =^  cards  state  (take:hc wire sign)
  [cards this]
++  on-arvo
  |=  [=wire =sign-arvo]
  ^-  (quip card _this)
  ?:  ?=([%prune ~] wire)
    =^  cards  state  prune:hc
    [cards this]
  ?.  ?=([%eyre %bound *] sign-arvo)  (on-arvo:def wire sign-arvo)
  ?:  accepted.sign-arvo  `this
  ~&  >>>  [%tessera-bind-failed wire]
  `this
++  on-fail   on-fail:def
--
|%
++  binds
  |=  dap=term
  ^-  (list card)
  :~  [%pass /eyre/connect-tessera %arvo %e %connect [`/tessera dap]]
      [%pass /eyre/connect-apps %arvo %e %connect [`/apps/tessera dap]]
  ==
::
++  tc
  |_  [=bowl:gall st=state-0]
  ::
  ::  -- shared by HTTP and Ames --
  ::
  ::  rotated: a service with the keyset for now, the change kept
  ++  rotated
    |=  svc=service
    ^-  [service state-0]
    =/  r  (rotate svc eny.bowl now.bowl)
    =.  services.st  (~(put by services.st) name.svc svc.r)
    =?  spent.st  ?=(^ dead.r)  (~(del by spent.st) u.dead.r)
    [svc.r st]
  ::
  ::  prune: drop quota counts and spent sets that no longer count, and
  ::  come back in an hour (one timer: the last one is cancelled)
  ++  prune
    ^-  (quip card state-0)
    =/  last  prune-at.st
    =.  used.st  (prune-used used.st services.st now.bowl)
    =.  spent.st  (prune-spent spent.st services.st now.bowl)
    =.  prune-at.st  (add now.bowl ~h1)
    :_  st
    :~  [%pass /prune %arvo %b %rest last]
        [%pass /prune %arvo %b %wait prune-at.st]
    ==
  ::
  ++  overview
    ^-  json
    =/  count  |*(l=(list) (numb:enjs:format (lent l)))
    %-  pairs:enjs:format
    :~  ['services' (count ~(val by services.st))]
        ['spent_sets' (count ~(val by spent.st))]
        ['spent' (count (zing (turn ~(val by spent.st) |=(s=(set @) ~(tap in s)))))]
        ['quota_counts' (count ~(val by used.st))]
        ['pending' (count ~(val by pend.st))]
        ['held' (count (zing ~(val by wallet.st)))]
        ['offers' (count ~(val by offers.st))]
        ['next_prune' (numb:enjs:format (da-to-unix prune-at.st))]
    ==
  ::
  ::  issue: sign outputs for an identity (~ for this ship), within the
  ::  cap and its quota; or the status and detail to refuse with
  ++  issue
    |=  [svc=service who=(unit @t) outs=(list [@t point])]
    ^-  (each [sigs=(list json) new=state-0] [@ud @t])
    =/  n  (lent outs)
    ?.  (cap-ok svc n)  |+[403 'issuance-cap-reached']
    =/  use  ?~(who ~ (~(get by used.st) [name.svc u.who]))
    ?:  ?&  ?=(^ who)
            ?=(^ quota.svc)
            (gth n (need (quota-left quota.svc use now.bowl)))
        ==
      |+[429 'quota-exceeded']
    =?  used.st  &(?=(^ who) ?=(^ quota.svc))
      (~(put by used.st) [name.svc u.who] (add-use per.u.quota.svc use now.bowl n))
    =.  services.st  (~(put by services.st) name.svc svc(issued (add issued.svc n)))
    &+[(sign-outputs outs keyset.svc eny.bowl) st]
  ::
  ::  judge: a token's verdict at a service: fresh (unspent until now),
  ::  and burned if asked and the mode burns; or why it is no token of it
  ++  judge
    |=  [svc=service tok=@t burn=?]
    ^-  (each [fresh=? hash=@ new=state-0] @t)
    =*  kid  id.keyset.svc
    =/  gone  (~(gut by spent.st) kid ~)
    =/  v  (check-token tok keyset.svc gone)
    ?:  ?=(%| -.v)  |+p.v
    ?:  |(spent.p.v !burn)  &+[!spent.p.v hash.p.v st]
    =?  spent.st  =(%burn mode.svc)  (~(put by spent.st) kid (~(put in gone) hash.p.v))
    =.  services.st  (~(put by services.st) name.svc svc(redeemed +(redeemed.svc)))
    &+[& hash.p.v st]
  ::
  ::  renew: burn tokens and sign as many new outputs. Nothing new is
  ::  issued, so no policy, quota or cap applies.
  ++  renew
    |=  [svc=service toks=(list json) outs=(each (list [@t point]) @t)]
    ^-  (each [sigs=(list json) new=state-0] @t)
    ?:  ?=(%| -.outs)  |+p.outs
    ?.  =((lent toks) (lent p.outs))  |+'count-mismatch'
    =*  kid  id.keyset.svc
    =/  gone  (~(gut by spent.st) kid ~)
    =/  hs  (check-refresh toks keyset.svc gone)
    ?:  ?=(%| -.hs)  |+p.hs
    =.  spent.st  (~(put by spent.st) kid (~(gas in gone) p.hs))
    &+[(sign-outputs p.outs keyset.svc eny.bowl) st]
  ::
  ::  -- HTTP --
  ::
  ++  handle-http
    |=  [eyre-id=@ta req=inbound-request:eyre]
    ^-  (quip card state-0)
    =/  body  body.request.req
    =/  segs=(list @t)  (parse-request-path url.request.req)
    =/  route=(list @t)  [method.request.req segs]
    ::  the Landscape tile's icon is public
    ?:  =([%'GET' /apps/tessera/icon] route)
      :_  st
      %:  give-http  eyre-id  200  ['content-type' 'image/svg+xml']~
        `(as-octs:mimes:html (rap 3 (join `@t`10 `wain`icon-svg)))
      ==
    ::  the admin page and API need a session of this ship (eyre sets
    ::  authenticated only for ours), and a state change must come from
    ::  our own page
    ?:  ?=([%apps %tessera *] segs)
      ?:  &(!authenticated.req =([%'GET' /apps/tessera] route))
        [(give-http eyre-id 303 ['location' '/~/login?redirect=/apps/tessera']~ ~) st]
      ?.  authenticated.req  [(give-err eyre-id 401 'unauthorized') st]
      ?.  (csrf-ok req)  [(give-err eyre-id 403 'forbidden-cross-origin') st]
      (admin eyre-id route body)
    ?.  ?=([%tessera @ *] segs)  [(give-err eyre-id 404 'not-found') st]
    ?:  ?=(%'OPTIONS' method.request.req)  [(give-preflight eyre-id) st]
    ::  a session of this ship skips the policy and the verifier key, but
    ::  only from our own page: another site's POST could carry the cookie
    =/  owner  &(authenticated.req (csrf-ok req))
    =/  svc  (resolve-service (~(get by services.st) i.t.segs) now.bowl)
    ?:  ?=(%| -.svc)  [(give-err eyre-id p.svc) st]
    =^  cur  st  (rotated p.svc)
    =*  ks  keyset.cur
    ?+  route  [(give-err eyre-id 404 'not-found') st]
      [%'GET' %tessera @ %v1 %info ~]                 [(give-json (info-json cur) eyre-id) st]
      [%'GET' %tessera @ %v1 %auth %blind %keys ~]     [(give-json (keys-json ks) eyre-id) st]
      [%'GET' %tessera @ %v1 %auth %blind %keysets ~]  [(give-json (keysets-json ks) eyre-id) st]
      [%'POST' %tessera @ %v1 %auth %blind %mint ~]    (mint eyre-id req owner cur)
      [%'POST' %tessera @ %redeem ~]                   (redeem eyre-id body owner cur &)
      [%'POST' %tessera @ %check ~]                    (redeem eyre-id body owner cur |)
      [%'POST' %tessera @ %refresh ~]                  (refresh eyre-id body cur)
    ==
  ::
  ++  give-sigs
    |=  [eyre-id=@ta sigs=(list json)]
    ^-  (list card)
    (give-json (pairs:enjs:format ['signatures' a+sigs]~) eyre-id)
  ::
  ::  POST /v1/auth/blind/mint: sign blinded outputs for whoever the
  ::  policy lets in, within the cap and their quota
  ++  mint
    |=  [eyre-id=@ta req=inbound-request:eyre owner=? svc=service]
    ^-  (quip card state-0)
    =/  key  (get-header:http 'clear-auth' header-list.request.req)
    =/  who  (mint-identity policy.svc key owner)
    ?:  ?=(%| -.who)  [(give-err eyre-id p.who) st]
    =/  o  (read-obj body.request.req)
    ?:  ?=(%| -.o)  [(give-err eyre-id 400 p.o) st]
    =/  outs  (read-outputs (get-array p.o 'outputs') id.keyset.svc)
    ?:  ?=(%| -.outs)  [(give-err eyre-id 400 p.outs) st]
    =/  r  (issue svc p.who p.outs)
    ?:  ?=(%| -.r)  [(give-err eyre-id p.r) st]
    [(give-sigs eyre-id sigs.p.r) new.p.r]
  ::
  ::  POST /redeem (use) and /check: for a resource server holding a
  ::  verifier key, or this ship. A redeem answers `fresh` (grant: burned
  ::  now, or valid and unspent in check mode) or `replay` (already spent);
  ::  only fresh grants access, so a retry after a lost answer is safe.
  ++  redeem
    |=  [eyre-id=@ta body=(unit octs) owner=? svc=service use=?]
    ^-  (quip card state-0)
    =/  o  (read-obj body)
    ?:  ?=(%| -.o)  [(give-err eyre-id 400 p.o) st]
    ?.  |(owner (~(has in verifier-keys.svc) (get-str p.o 'key')))
      [(give-err eyre-id 403 'verifier-key-required') st]
    =/  j  (judge svc (get-str p.o 'token') use)
    ?:  ?=(%| -.j)  [(give-err eyre-id 400 p.j) st]
    :_  new.p.j
    ?.  use  (give-json (pairs:enjs:format ['spent' b+!fresh.p.j]~) eyre-id)
    (give-json (pairs:enjs:format ['status' s+?:(fresh.p.j 'fresh' 'replay')]~) eyre-id)
  ::
  ::  POST /refresh: open to any holder, which is how a receiver makes a
  ::  handed-over token its own
  ++  refresh
    |=  [eyre-id=@ta body=(unit octs) svc=service]
    ^-  (quip card state-0)
    =/  o  (read-obj body)
    ?:  ?=(%| -.o)  [(give-err eyre-id 400 p.o) st]
    =/  outs  (read-outputs (get-array p.o 'outputs') id.keyset.svc)
    =/  r  (renew svc (get-array p.o 'tokens') outs)
    ?:  ?=(%| -.r)  [(give-err eyre-id 400 p.r) st]
    [(give-sigs eyre-id sigs.p.r) new.p.r]
  ::
  ::  -- Ames: pokes from ships --
  ::
  ++  act
    |=  a=action
    ^-  (quip card state-0)
    ?-  -.a
      %request   (on-request +.a)
      %present   (on-present +.a)
      %refresh   (on-refresh +.a)
      %verify    (on-verify +.a)
      %answer    (on-answer +.a)
      %transfer  (on-transfer +.a)
      %get       ?>(=(our src):bowl (do-get local +.a))
      %use       ?>(=(our src):bowl (do-use local +.a))
      %ask       ?>(=(our src):bowl (do-ask local +.a))
      %give      ?>(=(our src):bowl (do-give local +.a))
      %accept    ?>(=(our src):bowl (do-accept local +.a))
      %decline   ?>(=(our src):bowl (do-decline local +.a))
    ==
  ::
  ::  local: the agent on this ship that poked us, to answer
  ++  local
    ^-  asker
    ?.  ?=([%gall @ ~] sap.bowl)  [%none ~]
    [%agent i.t.sap.bowl]
  ::
  ::  reply: an answer to the asking ship's %tessera
  ++  reply
    |=  [who=ship rid=@uv =answer]
    ^-  (list card)
    [%pass /answer %agent [who dap.bowl] %poke %tessera-action !>(`action`[%answer rid answer])]~
  ::
  ::  usable: a service a ship may use now, with the keyset for now; or
  ::  the refusal
  ++  usable
    |=  name=@t
    ^-  (each [service state-0] @t)
    =/  svc  (resolve-service (~(get by services.st) name) now.bowl)
    ?:  ?=(%| -.svc)  |+(tail p.svc)
    &+(rotated p.svc)
  ::
  ::  %request: issue to a ship the policy lets in, under its own quota
  ::  (none for this ship)
  ++  on-request
    |=  [rid=@uv name=@t outputs=(list @t)]
    ^-  (quip card state-0)
    =*  who  src.bowl
    =/  u  (usable name)
    ?:  ?=(%| -.u)  [(reply who rid %refused p.u) st]
    =^  svc  st  p.u
    ?.  (ship-ok policy.svc who our.bowl)  [(reply who rid %refused 'not-allowed') st]
    =/  outs  (ames-outputs outputs id.keyset.svc)
    ?:  ?=(%| -.outs)  [(reply who rid %refused p.outs) st]
    =/  r  (issue svc ?:(=(our.bowl who) ~ `(scot %p who)) p.outs)
    ?:  ?=(%| -.r)  [(reply who rid %refused +.p.r) st]
    [(reply who rid %issued id.keyset.svc pub.keyset.svc sigs.p.r) new.p.r]
  ::
  ::  %present: use a token here. With a forward, the answer waits for the
  ::  agent's ack, and a nack gives the token back.
  ++  on-present
    |=  [rid=@uv name=@t tok=@t to=(unit forward)]
    ^-  (quip card state-0)
    =*  who  src.bowl
    =/  u  (usable name)
    ?:  ?=(%| -.u)  [(reply who rid %refused p.u) st]
    =^  svc  st  p.u
    ::  a forward goes only to one of the service's agents, and only if it
    ::  runs: gall would hold a poke to a stopped agent, and the token, for
    ::  good
    =/  no=(unit @t)
      ?~  to  ~
      =/  bad  (forward-refusal agents.svc u.to)
      ?^  bad  bad
      ?.  .^(? %gu /(scot %p our.bowl)/[agent.u.to]/(scot %da now.bowl)/$)
        `'agent-not-running'
      ~
    ?^  no  [(reply who rid %refused u.no) st]
    =/  j  (judge svc tok &)
    ?:  ?=(%| -.j)  [(reply who rid %refused p.j) st]
    ?.  fresh.p.j  [(reply who rid %valid |) new.p.j]
    ?~  to  [(reply who rid %valid &) new.p.j]
    =/  =wire
      :~  %forward  name  id.keyset.svc  (scot %uv hash.p.j)
          (scot %p who)  (scot %uv rid)  (scot %f =(%burn mode.svc))
      ==
    :_  new.p.j
    [%pass wire %agent [our.bowl agent.u.to] %poke %tessera-granted !>(`granted`[name who data.u.to])]~
  ::
  ::  %refresh: a holder's tokens for new ones
  ++  on-refresh
    |=  [rid=@uv name=@t toks=(list @t) outputs=(list @t)]
    ^-  (quip card state-0)
    =*  who  src.bowl
    =/  u  (usable name)
    ?:  ?=(%| -.u)  [(reply who rid %refused p.u) st]
    =^  svc  st  p.u
    =/  outs  (ames-outputs outputs id.keyset.svc)
    =/  r  (renew svc (turn toks |=(t=@t s+t)) outs)
    ?:  ?=(%| -.r)  [(reply who rid %refused p.r) st]
    [(reply who rid %issued id.keyset.svc pub.keyset.svc sigs.p.r) new.p.r]
  ::
  ::  %verify: a verifier ship checks, or burns, a token it was given
  ++  on-verify
    |=  [rid=@uv name=@t tok=@t burn=?]
    ^-  (quip card state-0)
    =*  who  src.bowl
    =/  u  (usable name)
    ?:  ?=(%| -.u)  [(reply who rid %refused p.u) st]
    =^  svc  st  p.u
    ?.  |(=(our.bowl who) (~(has in verifiers.svc) who))
      [(reply who rid %refused 'not-a-verifier') st]
    =/  j  (judge svc tok burn)
    ?:  ?=(%| -.j)  [(reply who rid %refused p.j) st]
    [(reply who rid %valid fresh.p.j) new.p.j]
  ::
  ::  -- holder --
  ::
  ::  tell: answer whoever on this ship asked
  ++  tell
    |=  [=asker rid=@uv =answer]
    ^-  (list card)
    ?-  -.asker
      %none   ~&([%tessera (scot %uv rid) ?:(?=(%issued -.answer) %issued answer)] ~)
      %agent  [%pass /tell %agent [our.bowl dap.asker] %poke %tessera-answer !>([rid answer])]~
    ::
        %http
      =*  id  eyre-id.asker
      ?-  -.answer
        %refused  (give-err id 400 why.answer)
        %valid    (give-json (pairs:enjs:format ['fresh' b+fresh.answer]~) id)
        %done     (give-json (pairs:enjs:format ['done' (numb:enjs:format n.answer)]~) id)
        %issued   (give-err id 500 'unexpected-answer')
      ==
    ==
  ::
  ++  send
    |=  [to=ship rid=@uv a=action]
    ^-  (list card)
    [%pass /request/(scot %uv rid) %agent [to dap.bowl] %poke %tessera-action !>(a)]~
  ::
  ++  holding  |=([issuer=ship name=@t] (~(gut by wallet.st) [issuer name] ~))
  ::
  ::  hold: set what this ship holds of [issuer name]
  ++  hold
    |=  [issuer=ship name=@t toks=(list token)]
    ^+  wallet.st
    ?~  toks  (~(del by wallet.st) [issuer name])
    (~(put by wallet.st) [issuer name] toks)
  ::
  ::  asked: refuse a request id already waiting
  ++  asked  |=(rid=@uv (~(has by pend.st) rid))
  ::
  ::  %get: ask an issuer for n tokens
  ++  do-get
    |=  [=asker rid=@uv issuer=ship name=@t n=@ud]
    ^-  (quip card state-0)
    ?.  &((gth n 0) (lte n bat-max-mint))  [(tell asker rid %refused 'invalid-n') st]
    ?:  (asked rid)  [(tell asker rid %refused 'duplicate-request') st]
    =/  bs  (make-blinds n (shas rid eny.bowl))
    =.  pend.st  (~(put by pend.st) rid [%get asker issuer name bs])
    [(send issuer rid [%request rid name (turn bs |=(b=blind b.b))]) st]
  ::
  ::  %use: present one token, and maybe have the issuer poke one of its
  ::  agents with it
  ++  do-use
    |=  [=asker rid=@uv issuer=ship name=@t to=(unit forward)]
    ^-  (quip card state-0)
    =/  have  (holding issuer name)
    ?~  have  [(tell asker rid %refused 'no-tokens') st]
    ?:  (asked rid)  [(tell asker rid %refused 'duplicate-request') st]
    =.  wallet.st  (hold issuer name t.have)
    =.  pend.st  (~(put by pend.st) rid [%use asker issuer name i.have])
    [(send issuer rid [%present rid name (en-token i.have) to]) st]
  ::
  ::  %ask: check or burn, at its issuer, a token someone gave this ship
  ++  do-ask
    |=  [=asker rid=@uv issuer=ship name=@t tok=@t burn=?]
    ^-  (quip card state-0)
    ?:  (asked rid)  [(tell asker rid %refused 'duplicate-request') st]
    =.  pend.st  (~(put by pend.st) rid [%ask asker issuer])
    [(send issuer rid [%verify rid name tok burn]) st]
  ::
  ::  %give: hand n tokens to another ship
  ++  do-give
    |=  [=asker rid=@uv to=ship issuer=ship name=@t n=@ud]
    ^-  (quip card state-0)
    =/  have  (holding issuer name)
    ?.  &((gth n 0) (lte n bat-max-mint))  [(tell asker rid %refused 'invalid-n') st]
    ?:  (gth n (lent have))  [(tell asker rid %refused 'not-enough-tokens') st]
    ?:  (asked rid)  [(tell asker rid %refused 'duplicate-request') st]
    =.  wallet.st  (hold issuer name (slag n have))
    =.  pend.st  (~(put by pend.st) rid [%give asker to issuer name (scag n have)])
    [(send to rid [%transfer rid issuer name (turn (scag n have) en-token)]) st]
  ::
  ::  %answer: only from the ship the request went to
  ++  on-answer
    |=  [rid=@uv ans=answer]
    ^-  (quip card state-0)
    =/  p  (~(get by pend.st) rid)
    ?~  p  `st
    ::  only the ship the request went to may answer it
    ?.  =(src.bowl (whom u.p))  `st
    ::  a give is settled by the receiver's ack alone: it has nothing to say
    ?:  ?=(%give -.u.p)  `st
    =.  pend.st  (~(del by pend.st) rid)
    ?-  -.u.p
      %ask   [(tell asker.u.p rid ans) st]
    ::
        %get
      ?.  ?=(%issued -.ans)  [(tell asker.u.p rid ans) st]
      =/  toks  (unblind bs.u.p sigs.ans kid.ans pub.ans)
      ?:  ?=(%| -.toks)  [(tell asker.u.p rid %refused p.toks) st]
      ::  a service has one live keyset: tokens held under another are dead
      =/  live  (skim (holding [issuer svc]:u.p) |=(t=token =(id.t kid.ans)))
      =.  wallet.st  (hold issuer.u.p svc.u.p (weld p.toks live))
      [(tell asker.u.p rid %done (lent p.toks)) st]
    ::
        %use
      ::  a bad token is dropped; a refusal for any other reason (the
      ::  service is off, say) gives it back
      =?  wallet.st  &(?=(%refused -.ans) !(lost why.ans))
        (hold issuer.u.p svc.u.p [tok.u.p (holding [issuer svc]:u.p)])
      [(tell asker.u.p rid ans) st]
    ==
  ::
  ::  %transfer: tokens another ship hands this one. They wait as an
  ::  offer until the owner accepts them (a refresh at the issuer, which
  ::  makes them ours) or declines: taking them at once would let any ship
  ::  spend this one's CPU and grow its state. A refusal nacks, and the
  ::  giver gets its tokens back.
  ++  on-transfer
    |=  [rid=@uv issuer=ship name=@t toks=(list @t)]
    ^-  (quip card state-0)
    =/  key  [src.bowl issuer name]
    =/  have  (~(gut by offers.st) key ~)
    =/  full  &(!(~(has by offers.st) key) (gte ~(wyt by offers.st) max-offers))
    =/  no  (offer-refusal name toks have full)
    ?^  no  ~|([%tessera-offer-refused u.no] !!)
    `st(offers (~(put by offers.st) key (weld have toks)))
  ::
  ::  %accept: make an offer ours, by a refresh at its issuer
  ++  do-accept
    |=  [=asker rid=@uv from=ship issuer=ship name=@t]
    ^-  (quip card state-0)
    =/  toks  (~(gut by offers.st) [from issuer name] ~)
    ?~  toks  [(tell asker rid %refused 'no-offer') st]
    ?:  (asked rid)  [(tell asker rid %refused 'duplicate-request') st]
    =.  offers.st  (~(del by offers.st) [from issuer name])
    =/  bs  (make-blinds (lent toks) (shas rid eny.bowl))
    =.  pend.st  (~(put by pend.st) rid [%get asker issuer name bs])
    [(send issuer rid [%refresh rid name toks (turn bs |=(b=blind b.b))]) st]
  ::
  ::  %decline: drop an offer
  ++  do-decline
    |=  [=asker rid=@uv from=ship issuer=ship name=@t]
    ^-  (quip card state-0)
    =/  toks  (~(gut by offers.st) [from issuer name] ~)
    ?~  toks  [(tell asker rid %refused 'no-offer') st]
    :-  (tell asker rid %done (lent toks))
    st(offers (~(del by offers.st) [from issuer name]))
  ::
  ::  -- acks --
  ::
  ++  take
    |=  [=wire =sign:agent:gall]
    ^-  (quip card state-0)
    ?.  ?=(%poke-ack -.sign)  `st
    ?+  wire  `st
        [%forward @ @ @ @ @ @ ~]
      =/  name  i.t.wire
      =/  kid  i.t.t.wire
      =/  hash  (slav %uv i.t.t.t.wire)
      =/  who  (slav %p i.t.t.t.t.wire)
      =/  rid  (slav %uv i.t.t.t.t.t.wire)
      =/  burned  =(& (slav %f i.t.t.t.t.t.t.wire))
      ?~  p.sign  [(reply who rid %valid &) st]
      ::  the agent refused it: the token was not used after all
      =?  spent.st  burned  (~(put by spent.st) kid (~(del in (~(gut by spent.st) kid ~)) hash))
      =/  svc  (~(get by services.st) name)
      =?  services.st  ?=(^ svc)  (~(put by services.st) name u.svc(redeemed (dec redeemed.u.svc)))
      [(reply who rid %refused 'forward-refused') st]
    ::
        [%request @ ~]
      =/  rid  (slav %uv i.t.wire)
      =/  p  (~(get by pend.st) rid)
      ?~  p  `st
      ::  a give is done when the receiver takes it; the rest wait for
      ::  an answer
      ?~  p.sign
        ?.  ?=(%give -.u.p)  `st
        :_  st(pend (~(del by pend.st) rid))
        (tell asker.u.p rid %done (lent toks.u.p))
      =.  pend.st  (~(del by pend.st) rid)
      ::  the ship crashed on it: the asker hears, and tokens come back
      =?  wallet.st  ?=(%use -.u.p)  (hold issuer.u.p svc.u.p [tok.u.p (holding [issuer svc]:u.p)])
      =?  wallet.st  ?=(%give -.u.p)  (hold issuer.u.p svc.u.p (weld toks.u.p (holding [issuer svc]:u.p)))
      [(tell asker.u.p rid %refused 'nacked') st]
    ==
  ::
  ::  -- admin: /apps/tessera/api --
  ::
  ++  admin
    |=  [eyre-id=@ta route=(list @t) body=(unit octs)]
    ^-  (quip card state-0)
    ?+  route  [(give-err eyre-id 404 'not-found') st]
        [%'GET' %apps %tessera ~]
      [(give-dashboard eyre-id dashboard-lines eny.bowl) st]
    ::
        [%'GET' %apps %tessera %api %services ~]
      :_  st
      %+  give-json
        (pairs:enjs:format ['services' a+(turn ~(val by services.st) service-json)]~)
      eyre-id
    ::
        [%'GET' %apps %tessera %api %overview ~]
      [(give-json overview eyre-id) st]
    ::
        [%'POST' %apps %tessera %api %prune ~]
      =^  cards  st  prune
      [(weld cards (give-json overview eyre-id)) st]
    ::
        [%'GET' %apps %tessera %api %wallet ~]
      =/  rows=(list json)
        %+  turn  ~(tap by wallet.st)
        |=  [[issuer=ship name=@t] toks=(list token)]
        %-  pairs:enjs:format
        :~  ['issuer' s+(scot %p issuer)]
            ['service' s+name]
            ['count' (numb:enjs:format (lent toks))]
        ==
      =/  offered=(list json)
        %+  turn  ~(tap by offers.st)
        |=  [[from=ship issuer=ship name=@t] toks=(list @t)]
        %-  pairs:enjs:format
        :~  ['from' s+(scot %p from)]
            ['issuer' s+(scot %p issuer)]
            ['service' s+name]
            ['count' (numb:enjs:format (lent toks))]
        ==
      :_  st
      (give-json (pairs:enjs:format ~[['wallet' a+rows] ['offers' a+offered]]) eyre-id)
    ::
        [%'POST' %apps %tessera %api %services @ ~]
      =/  o  (read-obj body)
      ?:  ?=(%| -.o)  [(give-err eyre-id 400 p.o) st]
      =/  r  (admin-do i.t.t.t.t.t.route p.o)
      ?:  ?=(%| -.r)  [(give-err eyre-id p.r) st]
      [(give-json -.p.r eyre-id) +.p.r]
    ::
        [%'POST' %apps %tessera %api %wallet @ ~]
      =/  o  (read-obj body)
      ?:  ?=(%| -.o)  [(give-err eyre-id 400 p.o) st]
      (wallet-do eyre-id i.t.t.t.t.t.route p.o)
    ==
  ::
  ::  wallet-do: the owner's holder actions. get, use, ask and give answer
  ::  when the other ship does; take answers at once with a token as an
  ::  authA string, to hand to a web client or another ship.
  ++  wallet-do
    |=  [eyre-id=@ta act=@t o=(map @t json)]
    ^-  (quip card state-0)
    =/  =asker  [%http eyre-id]
    =/  rid=@uv  (sham eny.bowl)
    =/  issuer  (slaw %p (get-str o 'issuer'))
    ?~  issuer  [(give-err eyre-id 400 'invalid-issuer') st]
    =/  name  (get-str o 'service')
    ?+  act  [(give-err eyre-id 404 'not-found') st]
        %get  (do-get asker rid u.issuer name (fall (get-ud o 'n') 0))
        %ask  (do-ask asker rid u.issuer name (get-str o 'token') (get-bool o 'burn'))
    ::
        %use
      =/  agent  (get-str o 'agent')
      ?.  |(=('' agent) ((sane %tas) agent))  [(give-err eyre-id 400 'invalid-agent') st]
      (do-use asker rid u.issuer name ?:(=('' agent) ~ `[`@tas`agent (~(gut by o) 'data' ~)]))
    ::
        %give
      =/  to  (slaw %p (get-str o 'to'))
      ?~  to  [(give-err eyre-id 400 'invalid-to') st]
      (do-give asker rid u.to u.issuer name (fall (get-ud o 'n') 0))
    ::
        ?(%accept %decline)
      =/  from  (slaw %p (get-str o 'from'))
      ?~  from  [(give-err eyre-id 400 'invalid-from') st]
      ?:  =(%accept act)  (do-accept asker rid u.from u.issuer name)
      (do-decline asker rid u.from u.issuer name)
    ::
        %take
      =/  have  (holding u.issuer name)
      ?~  have  [(give-err eyre-id 400 'no-tokens') st]
      :_  st(wallet (hold u.issuer name t.have))
      (give-json (pairs:enjs:format ['token' s+(en-token i.have)]~) eyre-id)
    ==
  ::
  ::  admin-do: one admin action on the service the body names
  ::
  ::    create: a new service with its own keyset, closed until the body
  ::    (or a later update) opens it or names who may have tokens
  ::    update: change any fields (see +apply-fields)
  ::    activate, deactivate
  ::    delete: only an inactive service that never issued
  ::    batch: n tokens made here, as authA strings to hand out off-ship
  ++  admin-do
    |=  [act=@t o=(map @t json)]
    ^-  (each [json state-0] [@ud @t])
    =/  name  (get-str o 'name')
    ?:  =(%create act)
      ?.  (valid-service-name name)  |+[400 'invalid-service-name']
      ?:  (~(has by services.st) name)  |+[409 'service-already-exists']
      =/  new  (apply-fields o (new-service name (new-keyset eny.bowl now.bowl ~) now.bowl))
      ?:  ?=(%| -.new)  |+[400 p.new]
      =^  cur  st  (rotated p.new)
      (saved cur)
    =/  svc  (~(get by services.st) name)
    ?~  svc  |+[404 'service-not-found']
    ?+  act  |+[404 'not-found']
      %activate    (saved u.svc(active &))
      %deactivate  (saved u.svc(active |))
      %batch       (batch u.svc o)
    ::
        %update
      =/  new  (apply-fields o u.svc)
      ?:  ?=(%| -.new)  |+[400 p.new]
      ::  a changed window takes a new keyset now: tokens out are dead
      =^  cur  st  (rotated p.new)
      (saved cur)
    ::
        %delete
      ?:  active.u.svc  |+[400 'deactivate-before-delete']
      ?:  (gth issued.u.svc 0)  |+[400 'service-has-issued-tokens']
      :+  %&  (pairs:enjs:format ~[['deleted' b+&] ['name' s+name]])
      st(services (~(del by services.st) name))
    ==
  ::
  ++  saved
    |=  svc=service
    ^-  (each [json state-0] [@ud @t])
    &+[(service-json svc) st(services (~(put by services.st) name.svc svc))]
  ::
  ::  batch: they count toward the cap; the quota is for requesters
  ++  batch
    |=  [svc=service o=(map @t json)]
    ^-  (each [json state-0] [@ud @t])
    =/  n  (get-ud o 'n')
    ?.  &(?=(^ n) (gth u.n 0) (lte u.n max-batch))  |+[400 'invalid-n']
    ?.  (cap-ok svc u.n)  |+[403 'issuance-cap-reached']
    =^  svc  st  (rotated svc)
    =/  toks  (turn (mint-direct u.n keyset.svc eny.bowl) en-token)
    :+  %&  (pairs:enjs:format ['tokens' a+(turn toks |=(t=@t s+t))]~)
    st(services (~(put by services.st) name.svc svc(issued (add issued.svc u.n))))
  --
--
