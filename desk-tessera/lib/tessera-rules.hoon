::  /lib/tessera-rules: %tessera's decisions as pure arms. The agent keeps
::  state and I/O; what decides lives here, where tests reach it.
::  Importing this also brings in blind, bdhke, curve and ecash-http.
::
/-  *tessera
/+  *blind
|%
::  bat-max-mint: most tokens one request may mint or refresh (NUT-22's
::  bat_max_mint). Each costs about three scalar multiplications.
++  bat-max-mint  ^-  @ud  10
::  max-token-bytes: a serialized token's cap, checked before decoding.
::  It fits a token with the largest secret a spent set takes.
++  max-token-bytes  ^-  @ud  4.096
::  max-offers: how many [giver issuer service] offers wait at once
++  max-offers  ^-  @ud  100
::  max-forward-bytes: the most data a forward carries, jammed
++  max-forward-bytes  ^-  @ud  16.384
::
::  -- requests --
::
::  read-obj: a POST body's JSON object, or the 400 detail
++  read-obj
  |=  body=(unit octs)
  ^-  (each (map @t json) @t)
  =/  jon  (parse-object-body body)
  ?:  ?=(%| -.jon)  jon
  ?>  ?=([%o *] p.jon)
  &+p.p.jon
::
::  opt-ud: an optional count or time field: null clears it (`~), a bare
::  non-negative integer sets it (``n), anything else is malformed (~)
++  opt-ud
  |=  v=json
  ^-  (unit (unit @ud))
  ?~  v  `~
  ?.  ?=(%n -.v)  ~
  =/  n  (parse-ud-strict p.v)
  ?~  n  ~
  ``u.n
::
::  opt-quota: null clears the quota (`~); {n, per} with both at least 1,
::  per in seconds, sets it; anything else is malformed (~)
++  opt-quota
  |=  v=json
  ^-  (unit (unit [n=@ud per=@dr]))
  ?~  v  `~
  ?.  ?=([%o *] v)  ~
  =/  n  (get-ud p.v 'n')
  =/  per  (get-ud p.v 'per')
  ?.  &(?=(^ n) ?=(^ per) (gth u.n 0) (gth u.per 0))  ~
  ``[u.n `@dr`(mul ~s1 u.per)]
::
::  str-set: a JSON array of non-empty strings, as a set; else ~
++  str-set
  |=  v=json
  ^-  (unit (set @t))
  ?.  ?=([%a *] v)  ~
  =/  l  (turn p.v |=(j=json ?.(?=([%s *] j) '' p.j)))
  ?:  (lien l |=(s=@t =('' s)))  ~
  `(silt l)
::
++  unix-to-da  |=(s=@ud `@da`(add ~1970.1.1 (mul ~s1 s)))
::
::  -- tokens --
::
::  unpad: t without its trailing '='s
++  unpad
  |=  t=@t
  ^-  @t
  =/  n  (met 3 t)
  |-  ^-  @t
  ?:  =(0 n)  ''
  ?.  =('=' (cut 3 [(dec n) 1] t))  (end [3 n] t)
  $(n (dec n))
::
::  parse-token: 'authA' + base64url(JSON {id, secret, C}), padded as
::  cashu-ts writes it, or not
++  parse-token
  |=  t=@t
  ^-  (unit token)
  ?:  (gth (met 3 t) max-token-bytes)  ~
  ?.  =('authA' (end [3 5] t))  ~
  ::  zuse's decoder takes padding as all or nothing
  =/  raw  (~(de base64:mimes:html | &) (unpad (rsh [3 5] t)))
  ?~  raw  ~
  =/  jon  (de:json:html q.u.raw)
  ?.  ?=([~ %o *] jon)  ~
  =/  tok=token  [(get-str p.u.jon 'id') (get-str p.u.jon 'secret') (get-str p.u.jon 'C')]
  ?:  |(=('' id.tok) =('' secret.tok) =('' c.tok))  ~
  ?:  (gth (met 3 secret.tok) max-secret-bytes)  ~
  `tok
::
::  en-token: a token as cashu-ts writes it
++  en-token
  |=  tok=token
  ^-  @t
  =/  jon  (pairs:enjs:format ~[['id' s+id.tok] ['secret' s+secret.tok] ['C' s+c.tok]])
  (cat 3 'authA' (~(en base64:mimes:html & &) (as-octs:mimes:html (en:json:html jon))))
::
::  +verdict: a presented token is the service's, with the hash its spent
::  set keeps and whether it is spent; or why it isn't
+$  verdict  (each [hash=@ spent=?] @t)
::
::  check-token: is t signed by keyset ks, and is it spent?
++  check-token
  |=  [t=@t ks=keyset spent=(set @)]
  ^-  verdict
  =/  tok  (parse-token t)
  ?~  tok  |+'invalid-token'
  ?.  =(id.ks id.u.tok)  |+'unknown-keyset'
  =/  c  (hex-to-pt c.u.tok)
  ?~  c  |+'invalid-token'
  ?.  (signed-by secret.u.tok u.c priv.ks)  |+'invalid-token'
  =/  h  (shax secret.u.tok)
  &+[h (~(has in spent) h)]
::
::  check-refresh: a refresh's tokens, each good and unspent and none
::  twice, as their hashes; or the 400 detail
++  check-refresh
  |=  [toks=(list json) ks=keyset spent=(set @)]
  ^-  (each (list @) @t)
  ?:  =(~ toks)  |+'empty-tokens'
  ?:  (gth (lent toks) bat-max-mint)  |+'too-many-tokens'
  =|  acc=(list @)
  |-  ^-  (each (list @) @t)
  ?~  toks  &+acc
  ?.  ?=([%s *] i.toks)  |+'invalid-token'
  =/  v  (check-token p.i.toks ks spent)
  ?:  ?=(%| -.v)  |+p.v
  ?:  spent.p.v  |+'token-already-spent'
  ?^  (find ~[hash.p.v] acc)  |+'duplicate-token'
  $(toks t.toks, acc [hash.p.v acc])
::
::  -- issuance --
::
::  new-keyset: a service's key from entropy, under NUT-02's id for unit
::  'auth' and the time it closes
++  new-keyset
  |=  [ent=@ now=@da closes=(unit @da)]
  ^-  keyset
  =/  k  (gen-keys ent ~[1])
  =/  exp  ?~(closes 0 (da-to-unix u.closes))
  [(compute-ks-id pubkeys.k 'auth' 0 exp) (~(got by pubkeys.k) 1) (~(got by privkeys.k) 1) now closes]
::
::  closing: when the window holding now closes; ~ without a window
++  closing
  |=  [window=(unit @dr) now=@da]
  ^-  (unit @da)
  ?~  window  ~
  `(add (mul u.window (div now u.window)) u.window)
::
::  rotate: the service with a keyset for the window holding now. A window
::  that turned, or a window setting that changed, gets a new keyset, and
::  the old one's id comes back so its spent set can go: its tokens are
::  dead.
++  rotate
  |=  [svc=service ent=@ now=@da]
  ^-  [svc=service dead=(unit @t)]
  =/  closes  (closing window.svc now)
  ?:  =(closes closes.keyset.svc)  [svc ~]
  [svc(keyset (new-keyset ent now closes)) `id.keyset.svc]
::
::  prune-used: quota counts still counting: their service has a quota
::  and they are in its window now
++  prune-used
  |=  [used=(map [@t @t] usage) svcs=(map @t service) now=@da]
  ^-  (map [@t @t] usage)
  %-  malt
  %+  skim  ~(tap by used)
  |=  [[name=@t who=@t] =usage]
  =/  svc  (~(get by svcs) name)
  ?~  svc  |
  ?~  quota.u.svc  |
  =(win.usage (div now per.u.quota.u.svc))
::
::  prune-spent: spent sets of keysets still open; a closed keyset's
::  tokens are dead, so its set can go
++  prune-spent
  |=  [spent=(map @t (set @)) svcs=(map @t service) now=@da]
  ^-  (map @t (set @))
  =/  open=(set @t)
    %-  silt
    %+  murn  ~(val by svcs)
    |=  svc=service
    =*  ks  keyset.svc
    ?:  ?&(?=(^ closes.ks) (lte u.closes.ks now))  ~
    `id.ks
  %-  malt
  (skim ~(tap by spent) |=([kid=@t *] (~(has in open) kid)))
::
::  mint-identity: whom an HTTP mint request counts against for quota (~
::  for a session of this ship, which has none), or why it is refused.
::  A key comes as the Clear-auth header.
++  mint-identity
  |=  [=policy key=(unit @t) owner=?]
  ^-  (each (unit @t) [@ud @t])
  ?^  key
    ?.  (~(has in keys.policy) u.key)  |+[401 'invalid-clear-auth']
    &+`(cat 3 'key:' (scot %uv (shax u.key)))
  ?:  owner  &+~
  ?:  open.policy  &+`'open'
  ?~  keys.policy  |+[403 'issuance-closed']
  |+[401 'clear-auth-required']
::
::  used-now: an identity's count in quota window win; an older window's
::  count has lapsed
++  used-now
  |=  [use=(unit usage) win=@ud]
  ^-  @ud
  ?~  use  0
  ?.(=(win win.u.use) 0 n.u.use)
::
::  quota-left: how many more tokens an identity may be issued now; ~ is
::  no limit
++  quota-left
  |=  [q=(unit [n=@ud per=@dr]) use=(unit usage) now=@da]
  ^-  (unit @ud)
  ?~  q  ~
  `(sub n.u.q (min n.u.q (used-now use (div now per.u.q))))
::
::  add-use: an identity's usage after k more tokens now
++  add-use
  |=  [per=@dr use=(unit usage) now=@da k=@ud]
  ^-  usage
  =/  win  (div now per)
  [win (add k (used-now use win))]
::
::  cap-ok: may this service issue n more tokens?
++  cap-ok
  |=  [svc=service n=@ud]
  ^-  ?
  ?~  max-issuance.svc  &
  (lte (add issued.svc n) u.max-issuance.svc)
::
::  read-outputs: a request's blinded outputs, each for amount 1 under
::  keyset kid, as [B_ hex, point]; or the 400 detail. All or none: a
::  wallet pairs signatures with outputs by position.
++  read-outputs
  |=  [outs=(list json) kid=@t]
  ^-  (each (list [@t point]) @t)
  ?:  =(~ outs)  |+'empty-outputs'
  ?:  (gth (lent outs) bat-max-mint)  |+'too-many-outputs'
  ?:  (has-dup-x outs)  |+'duplicate-output'
  =|  acc=(list [@t point])
  |-  ^-  (each (list [@t point]) @t)
  ?~  outs  &+(flop acc)
  ?.  ?=([%o *] i.outs)  |+'invalid-output'
  ?.  =(`1 (get-ud p.i.outs 'amount'))  |+'amount-must-be-1'
  ?.  =(kid (get-str p.i.outs 'id'))  |+'unknown-keyset'
  =/  hex  (get-str p.i.outs 'B_')
  =/  b  (hex-to-pt hex)
  ?~  b  |+'invalid-B_'
  $(outs t.outs, acc [[hex u.b] acc])
::
::  sign-outputs: each output's signature under ks, with its DLEQ proof.
::  ent must be fresh per request.
++  sign-outputs
  |=  [outs=(list [hex=@t b=point]) ks=keyset ent=@]
  ^-  (list json)
  =/  pub  (need (hex-to-pt pub.ks))
  %+  turn  outs
  |=([hex=@t b=point] (sign-blinded hex b 1 id.ks priv.ks pub ent))
::
::  mint-direct: n tokens the issuer makes itself, to hand out off-ship
::  (tickets, invites): a random secret as 64 hex digits, and C = k*Y
++  mint-direct
  |=  [n=@ud ks=keyset ent=@]
  ^-  (list token)
  ?:  =(0 n)  ~
  :_  $(n (dec n))
  =/  secret  (pad-hex (shas n ent) 64)
  [id.ks secret (pt-to-hex (pt-mul priv.ks (hash-to-curve secret)))]
::
::  -- ships --
::
::  rank-index: a rank's place, galaxies first
++  rank-index
  |=  r=rank:title
  ^-  @ud
  ?-  r
    %czar  0
    %king  1
    %duke  2
    %earl  3
    %pawn  4
  ==
::
::  ship-ok: may this ship be issued tokens over Ames? This ship may.
++  ship-ok
  |=  [=policy who=ship our=ship]
  ^-  ?
  ?|  =(our who)
      open.policy
      (~(has in ships.policy) who)
      ?~  rank.policy  |
      (lte (rank-index (clan:title who)) (rank-index u.rank.policy))
  ==
::
::  rank-name, rank-of: the admin API's names for ranks
++  rank-name
  |=  r=rank:title
  ^-  @t
  ?-  r
    %czar  'galaxy'
    %king  'star'
    %duke  'planet'
    %earl  'moon'
    %pawn  'comet'
  ==
++  rank-of
  |=  n=@t
  ^-  (unit rank:title)
  ?+  n  ~
    %galaxy  `%czar
    %star    `%king
    %planet  `%duke
    %moon    `%earl
    %comet   `%pawn
  ==
::
::  ship-set: a JSON array of ships ("~zod"), as a set; else ~
++  ship-set
  |=  v=json
  ^-  (unit (set ship))
  ?.  ?=([%a *] v)  ~
  =/  l  (turn p.v |=(j=json ?.(?=([%s *] j) ~ (slaw %p p.j))))
  ?:  (lien l |=(u=(unit ship) ?=(~ u)))  ~
  `(silt (turn l |=(u=(unit ship) (need u))))
::
::  opt-rank: null clears it (`~), a rank's name sets it; else ~
++  opt-rank
  |=  v=json
  ^-  (unit (unit rank:title))
  ?~  v  `~
  ?.  ?=([%s *] v)  ~
  =/  r  (rank-of p.v)
  ?~(r ~ ``u.r)
::
::  ames-outputs: a ship's B_ hexes, checked as +read-outputs checks a
::  wallet's outputs, under keyset kid
++  ames-outputs
  |=  [bs=(list @t) kid=@t]
  ^-  (each (list [@t point]) @t)
  =/  one=json  (numb:enjs:format 1)
  (read-outputs (turn bs |=(b=@t (pairs:enjs:format ~[['amount' one] ['id' s+kid] ['B_' s+b]]))) kid)
::
::  -- holding --
::
::  make-blinds: n tokens to ask for: random secrets as 64 hex digits,
::  and B_ = Y + rG
++  make-blinds
  |=  [n=@ud ent=@]
  ^-  (list blind)
  ?:  =(0 n)  ~
  :_  $(n (dec n))
  =/  secret  (pad-hex (shas n ent) 64)
  =/  bm  (blind-message secret (shas n (shax ent)))
  [secret blinding-factor.bm (pt-to-hex b-prime.bm)]
::
::  unblind: an issuer's signatures on our blinds, as tokens: each for
::  amount 1 under kid, with a DLEQ proof against pub; or why not
++  unblind
  |=  [bs=(list blind) sigs=(list json) kid=@t pub=@t]
  ^-  (each (list token) @t)
  ?.  =((lent bs) (lent sigs))  |+'count-mismatch'
  =/  k  (hex-to-pt pub)
  ?~  k  |+'invalid-key'
  =|  acc=(list token)
  |-  ^-  (each (list token) @t)
  ?~  bs  &+(flop acc)
  ?~  sigs  &+(flop acc)
  ?.  ?=([%o *] i.sigs)  |+'invalid-signature'
  =/  o  p.i.sigs
  =/  c-  (hex-to-pt (get-str o 'C_'))
  =/  b  (hex-to-pt b.i.bs)
  =/  dl  (get-obj o 'dleq')
  ?.  ?&  ?=(^ c-)
          ?=(^ b)
          =(kid (get-str o 'id'))
          =(`1 (get-ud o 'amount'))
          (dleq-verify u.b u.c- u.k (hex-decode (get-str dl 'e')) (hex-decode (get-str dl 's')))
      ==
    |+'invalid-signature'
  =/  c  (unblind-signature u.c- r.i.bs u.k)
  $(bs t.bs, sigs t.sigs, acc [[kid secret.i.bs (pt-to-hex c)] acc])
::
::  offer-refusal: why tokens handed to this ship can't wait as an offer,
::  if they can't: a service name, tokens that parse, no more than a batch
::  with what the giver already offered, and room for a new offer
++  offer-refusal
  |=  [name=@t toks=(list @t) have=(list @t) full=?]
  ^-  (unit @t)
  ?.  (valid-service-name name)  `'invalid-service-name'
  ?:  =(~ toks)  `'empty-tokens'
  ?:  (gth (add (lent toks) (lent have)) bat-max-mint)  `'too-many-tokens'
  ?:  (lien toks |=(t=@t ?=(~ (parse-token t))))  `'invalid-token'
  ?:  full  `'too-many-offers'
  ~
::
::  forward-refusal: why a presented token's action can't go to this
::  agent, if it can't (the agent must also be running: the agent checks)
++  forward-refusal
  |=  [agents=(set @t) to=forward]
  ^-  (unit @t)
  ?.  (~(has in agents) agent.to)  `'agent-not-allowed'
  ?:  (gth (met 3 (jam data.to)) max-forward-bytes)  `'data-too-large'
  ~
::
::  whom: the ship a request went to, the only one that may answer it
++  whom
  |=  p=pending
  ^-  ship
  ?-  -.p
    %get   issuer.p
    %use   issuer.p
    %ask   issuer.p
    %give  to.p
  ==
::
::  lost: does a refused present mean the token is gone for good?
++  lost
  |=  why=@t
  ^-  ?
  |(=('invalid-token' why) =('unknown-keyset' why))
::
::  -- services --
::
::  valid-service-name: 1..64 of [a-z0-9_-]
++  valid-service-name
  |=  name=@t
  ^-  ?
  ?&  (lte 1 (met 3 name))
      (lte (met 3 name) 64)
      %+  levy  (trip name)
      |=  c=@t
      ?|  &((gte c 'a') (lte c 'z'))
          &((gte c '0') (lte c '9'))
          =('_' c)
          =('-' c)
      ==
  ==
::
::  resolve-service: a service usable now, or the status and detail to
::  refuse it with
++  resolve-service
  |=  [svc=(unit service) now=@da]
  ^-  (each service [@ud @t])
  ?~  svc  |+[404 'service-not-found']
  ?.  active.u.svc  |+[400 'service-inactive']
  ?:  ?&(?=(^ expires.u.svc) (gth now u.expires.u.svc))
    |+[400 'service-expired']
  &+u.svc
::
::  new-service: closed (only this ship issues) until the admin opens it
++  new-service
  |=  [name=@t ks=keyset now=@da]
  ^-  service
  [name '' '' & [| ~ ~ ~] ~ ~ %burn ~ ~ ~ ~ ~ 0 0 now ks]
::
::  apply-fields: svc with an admin request's fields applied, or the 400
::  detail. An absent field is left alone; null clears an optional one.
++  apply-fields
  |=  [o=(map @t json) svc=service]
  ^-  (each service @t)
  =/  open  (~(gut by o) 'open' `json`b+open.policy.svc)
  ?.  ?=([%b *] open)  |+'invalid-open'
  =/  mode  (~(gut by o) 'mode' `json`s+mode.svc)
  ?.  ?=([%s ?(%burn %check)] mode)  |+'invalid-mode'
  =/  keys  (str-set (~(gut by o) 'keys' a+~))
  ?~  keys  |+'invalid-keys'
  =/  vkeys  (str-set (~(gut by o) 'verifier_keys' a+~))
  ?~  vkeys  |+'invalid-verifier-keys'
  =/  ships  (ship-set (~(gut by o) 'ships' a+~))
  ?~  ships  |+'invalid-ships'
  =/  verifiers  (ship-set (~(gut by o) 'verifiers' a+~))
  ?~  verifiers  |+'invalid-verifiers'
  =/  agents  (str-set (~(gut by o) 'agents' a+~))
  ?~  agents  |+'invalid-agents'
  ?.  (levy ~(tap in u.agents) (sane %tas))  |+'invalid-agents'
  =/  rank  (opt-rank (~(gut by o) 'rank' ~))
  ?~  rank  |+'invalid-rank'
  =/  quo  (opt-quota (~(gut by o) 'quota' ~))
  ?~  quo  |+'invalid-quota'
  =/  win  (opt-ud (~(gut by o) 'window' ~))
  ?~  win  |+'invalid-window'
  ?:  =(``0 win)  |+'invalid-window'
  =/  exp  (opt-ud (~(gut by o) 'expires' ~))
  ?~  exp  |+'invalid-expires'
  =/  max  (opt-ud (~(gut by o) 'max_issuance' ~))
  ?~  max  |+'invalid-max-issuance'
  =.  open.policy.svc  p.open
  =.  mode.svc  p.mode
  =?  title.svc  (has-key o 'title')  (get-str o 'title')
  =?  description.svc  (has-key o 'description')  (get-str o 'description')
  =?  keys.policy.svc  (has-key o 'keys')  u.keys
  =?  verifier-keys.svc  (has-key o 'verifier_keys')  u.vkeys
  =?  ships.policy.svc  (has-key o 'ships')  u.ships
  =?  verifiers.svc  (has-key o 'verifiers')  u.verifiers
  =?  agents.svc  (has-key o 'agents')  u.agents
  =?  rank.policy.svc  (has-key o 'rank')  u.rank
  =?  quota.svc  (has-key o 'quota')  u.quo
  =?  window.svc  (has-key o 'window')  (bind u.win |=(s=@ud `@dr`(mul ~s1 s)))
  =?  expires.svc  (has-key o 'expires')  (bind u.exp unix-to-da)
  =?  max-issuance.svc  (has-key o 'max_issuance')  u.max
  ?:  =('' title.svc)  |+'missing-title'
  &+svc
::
::  -- views --
::
::  info-json: NUT-06 info. NUT-21 marks minting as needing a Clear-auth
::  key only where no one may mint without one.
++  info-json
  |=  svc=service
  ^-  json
  =/  nut22=json
    %-  pairs:enjs:format
    :~  ['bat_max_mint' (numb:enjs:format bat-max-mint)]
        ['protected_endpoints' a+~]
    ==
  =/  mint=json  (pairs:enjs:format ~[['method' s+'POST'] ['path' s+'/v1/auth/blind/mint']])
  =/  nut21=json  (pairs:enjs:format ['protected_endpoints' a+~[mint]]~)
  %-  pairs:enjs:format
  :~  ['name' s+title.svc]
      ['description' s+description.svc]
      ['version' s+'tessera/0.1.0']
      :-  'nuts'
      %-  pairs:enjs:format
      ?:  |(open.policy.svc =(~ keys.policy.svc))  ~[['22' nut22]]
      ~[['21' nut21] ['22' nut22]]
  ==
::
::  keys-json: GET /v1/auth/blind/keys
++  keys-json
  |=  ks=keyset
  ^-  json
  =/  one=json
    %-  pairs:enjs:format
    %+  weld  (keyset-meta ks)
    ['keys' (pairs:enjs:format ['1' s+pub.ks]~)]~
  (pairs:enjs:format ['keysets' a+~[one]]~)
::
::  keysets-json: GET /v1/auth/blind/keysets
++  keysets-json
  |=  ks=keyset
  ^-  json
  (pairs:enjs:format ['keysets' a+~[(pairs:enjs:format (keyset-meta ks))]]~)
::
::  keyset-meta: what a wallet needs to derive the id: final_expiry is in
::  it when the keyset closes
++  keyset-meta
  |=  ks=keyset
  ^-  (list [@t json])
  %+  weld  `(list [@t json])`~[['id' s+id.ks] ['unit' s+'auth'] ['active' b+&]]
  ?~  closes.ks  ~
  ['final_expiry' (numb:enjs:format (da-to-unix u.closes.ks))]~
::
::  service-json: the admin view
++  service-json
  |=  svc=service
  ^-  json
  =/  strs  |=(ks=(set @t) `json`a+(turn ~(tap in ks) |=(k=@t s+k)))
  =/  ships  |=(ss=(set ship) `json`a+(turn ~(tap in ss) |=(s=ship s+(scot %p s))))
  %-  pairs:enjs:format
  :~  ['name' s+name.svc]
      ['title' s+title.svc]
      ['description' s+description.svc]
      ['active' b+active.svc]
      ['open' b+open.policy.svc]
      ['keys' (strs keys.policy.svc)]
      ['verifier_keys' (strs verifier-keys.svc)]
      ['ships' (ships ships.policy.svc)]
      ['rank' ?~(rank.policy.svc ~ s+(rank-name u.rank.policy.svc))]
      ['verifiers' (ships verifiers.svc)]
      ['agents' (strs agents.svc)]
      :-  'quota'
      ?~  quota.svc  ~
      %-  pairs:enjs:format
      :~  ['n' (numb:enjs:format n.u.quota.svc)]
          ['per' (numb:enjs:format (div per.u.quota.svc ~s1))]
      ==
      ['window' ?~(window.svc ~ (numb:enjs:format (div u.window.svc ~s1)))]
      ['mode' s+mode.svc]
      ['max_issuance' ?~(max-issuance.svc ~ (numb:enjs:format u.max-issuance.svc))]
      ['expires' ?~(expires.svc ~ (numb:enjs:format (da-to-unix u.expires.svc)))]
      ['issued' (numb:enjs:format issued.svc)]
      ['redeemed' (numb:enjs:format redeemed.svc)]
      ['created' (numb:enjs:format (da-to-unix created.svc))]
      ['keyset' s+id.keyset.svc]
  ==
--
