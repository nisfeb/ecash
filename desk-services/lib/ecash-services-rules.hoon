::  /lib/ecash-services-rules: %ecash-services' decisions as pure arms.
::  The agent keeps state and I/O; what decides lives here, where tests
::  reach it. Importing this also brings in bdhke, curve and ecash-http.
::
/-  *ecash-services
/+  *bdhke, *ecash-http
|%
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
::  read-batch: a POST body's object and its k array (proofs or outputs),
::  or the 400 detail. A null or non-array value reads as empty.
++  read-batch
  |=  [body=(unit octs) k=@t]
  ^-  (each [o=(map @t json) a=(list json)] @t)
  =/  o  (read-obj body)
  ?:  ?=(%| -.o)  o
  ?.  (has-key p.o k)  |+(cat 3 'missing-' k)
  =/  a  (get-array p.o k)
  ?~  a  |+(cat 3 'empty-' k)
  ?:  (gth (lent a) max-batch)  |+'batch-too-large'
  &+[p.o a]
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
++  unix-to-da  |=(s=@ud `@da`(add ~1970.1.1 (mul ~s1 s)))
::
::  -- services --
::
::  valid-service-name: 1..64 of [a-z0-9_-], and not `list`, which
::  GET /services/v1/list would shadow
++  valid-service-name
  |=  name=@t
  ^-  ?
  ?&  (lte 1 (met 3 name))
      (lte (met 3 name) 64)
      !=('list' name)
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
::  cap-ok: may this service sign n more tokens?
++  cap-ok
  |=  [svc=service n=@ud]
  ^-  ?
  ?~  max-issuance.svc  &
  (lte (add issued.svc n) u.max-issuance.svc)
::
::  retire-orphans: deactivate each service keyset whose service is gone.
::  A deleted service issued nothing, so nothing is lost.
++  retire-orphans
  |=  [kss=(map @t cred-keyset) svcs=(map @t service)]
  ^-  (map @t cred-keyset)
  =/  live=(set @t)  (silt (turn ~(val by svcs) |=(s=service ks-id.s)))
  %-  ~(urn by kss)
  |=  [id=@t k=cred-keyset]
  ?.  &(service-scoped.k !(~(has in live) id))  k
  k(active |)
::
::  service-to-json: the public view (no allowlist plaintext)
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
::  service-to-json-admin: the public view plus the plaintext allowlist
++  service-to-json-admin
  |=  svc=service
  ^-  json
  =/  base=json  (service-to-json svc)
  ?>  ?=([%o *] base)
  [%o (~(put by p.base) 'allowlist' a+(turn ~(tap in allowlist.svc) |=(k=@t s+k)))]
::
::  -- credential keysets --
::
::  cred-ks-id: 'c0' || sha256("0:<pk>|unit:cred"), the NUT-02 canonical
::  form (amounts ascending). rev turns shax's little-endian atom into the
::  big-endian digest; keysets made before that keep their stored ids.
++  cred-ks-id
  |=  keys=(map @ud @t)
  ^-  @t
  =/  sorted=(list [@ud @t])
    (sort ~(tap by keys) |=([a=[@ud @t] b=[@ud @t]] (lth -.a -.b)))
  =/  canonical=@t
    %+  rap  3
    :~  (rap 3 (join ',' (turn sorted |=([amt=@ud pub=@t] (rap 3 ~[(scot %ud amt) ':' pub])))))
        '|unit:cred'
    ==
  (rap 3 ~['c0' (pad-hex (rev 3 32 (shax canonical)) 64)])
::
::  gen-cred-keyset: a fresh keyset with one key, at denomination 0
++  gen-cred-keyset
  |=  [ent=@ now=@da scoped=?]
  ^-  cred-keyset
  =/  k  (mod (shax ent) secp-n)
  =/  priv  ?:(=(0 k) 1 k)
  =/  keys=(map @ud @t)  (my [0 (pt-to-hex (pubkey priv))]~)
  [(cred-ks-id keys) & keys (my [0 priv]~) now scoped]
::
::  keyset-json: a credential keyset's public keys
++  keyset-json
  |=  ks=cred-keyset
  ^-  json
  %-  pairs:enjs:format
  :~  ['id' s+ks-id.ks]
      ['active' b+active.ks]
      :-  'keys'
      %-  pairs:enjs:format
      (turn ~(tap by keys.ks) |=([amt=@ud pub=@t] [(scot %ud amt) s+pub]))
  ==
::
::  -- proofs and outputs --
::
::    Every cheap check runs over a whole batch before any EC work. scope
::    says whose keysets a request may use: ~ is the public /cred API,
::    which treats service keysets as unknown; `ks-id is a service's own
::    path, which uses that keyset and no other.
::
::  checked-proof: a proof's [kid secret], and if it passed the cheap
::  checks, its C point and signing key
+$  checked-proof  [kid=@t secret=@t ok=(unit [c=point priv=@])]
::
++  proof-pre
  |=  [tok=json kss=(map @t cred-keyset) scope=(unit @t)]
  ^-  checked-proof
  ?.  ?=([%o *] tok)  ['' '' ~]
  =/  kid  (get-str p.tok 'id')
  =/  secret  (get-str p.tok 'secret')
  =/  no=checked-proof  [kid secret ~]
  ::  spent sets keep the secret: an uncapped one grows state per redeem
  ?:  |(=('' secret) (gth (met 3 secret) max-secret-bytes))  no
  ?:  ?~(scope | !=(kid u.scope))  no
  =/  ks  (~(get by kss) kid)
  ?~  ks  no
  ?:  &(?=(~ scope) service-scoped.u.ks)  no
  =/  priv  (~(get by privkeys.u.ks) 0)
  ?~  priv  no
  =/  c  (hex-to-pt (get-str p.tok 'C'))
  ?~  c  no
  no(ok `[u.c u.priv])
::
::  proof-sig-ok: the EC check, C = k*hash_to_curve(secret)
++  proof-sig-ok
  |=  p=checked-proof
  ^-  ?
  ?~  ok.p  |
  =(c.u.ok.p (pt-mul priv.u.ok.p (hash-to-curve secret.p)))
::
::  has-dup-secrets: does a batch name one [kid secret] twice? Spent checks
::  read only the stored set, so both copies would pass and count.
++  has-dup-secrets
  |=  keys=(list [@t @t])
  ^-  ?
  =|  seen=(set [@t @t])
  |-  ^-  ?
  ?~  keys  |
  ?:  (~(has in seen) i.keys)  &
  $(keys t.keys, seen (~(put in seen) i.keys))
::
::  ready-output: a blinded output that passed its cheap checks
+$  ready-output  [kid=@t b=point priv=@ pub=point]
::
::  output-pre: the cheap checks on one blinded output, or its error
++  output-pre
  |=  [msg=json kss=(map @t cred-keyset) scope=(unit @t)]
  ^-  (each ready-output @t)
  ?.  ?=([%o *] msg)  |+'invalid-msg'
  ::  a credential carries no value: amount must be the number 0 exactly
  ?.  =(`[%n ~.0] (~(get by p.msg) 'amount'))
    |+'credential-amount-must-be-zero'
  =/  b-hex  (get-str p.msg 'B_')
  ?:  =('' b-hex)  |+'missing-B_'
  =/  b  (hex-to-pt b-hex)
  ?~  b  |+'invalid-B_-point'
  ::  a service signs with its own keyset, whatever id the output names
  =/  kid  ?~(scope (get-str p.msg 'id') u.scope)
  ?:  =('' kid)  |+'missing-keyset-id'
  =/  ks  (~(get by kss) kid)
  ?~  ks  |+'unknown-credential-keyset'
  ?:  &(?=(~ scope) service-scoped.u.ks)  |+'unknown-credential-keyset'
  ?.  active.u.ks  |+'credential-keyset-inactive'
  =/  priv  (~(get by privkeys.u.ks) 0)
  ?~  priv  |+'no-credential-key'
  =/  pub  (biff (~(get by keys.u.ks) 0) hex-to-pt)
  ?~  pub  |+'no-credential-key'
  &+[kid u.b u.priv u.pub]
::
::  n-ready: how many outputs will get a real signature
++  n-ready
  |=  pres=(list (each ready-output @t))
  ^-  @ud
  (lent (skim pres |=(p=(each ready-output @t) ?=(%& -.p))))
::
::  sign-batch: C_ = k*B_ and its NUT-12 DLEQ proof for each ready output,
::  an error object for the rest. ent must be fresh per request.
++  sign-batch
  |=  [pres=(list (each ready-output @t)) ent=@]
  ^-  (list json)
  %+  turn  pres
  |=  p=(each ready-output @t)
  ^-  json
  ?:  ?=(%| -.p)  (pairs:enjs:format ['error' s+p.p]~)
  =/  r  p.p
  =/  c  (blind-sign b.r priv.r)
  ::  the compressed B_ (its prefix tells B_ from -B_) keeps each output's
  ::  nonce entropy distinct within one event
  =/  pf  (dleq-prove b.r c priv.r pub.r (shax (cat 3 (pt-to-hex b.r) ent)))
  %-  pairs:enjs:format
  :~  ['C_' s+(pt-to-hex c)]
      ['amount' (numb:enjs:format 0)]
      ['id' s+kid.r]
      :-  'dleq'
      (pairs:enjs:format ~[['e' s+(scalar-to-hex e.pf)] ['s' s+(scalar-to-hex s.pf)]])
  ==
--
