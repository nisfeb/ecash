::  /lib/ecash-http: HTTP and JSON plumbing shared by %ecash and
::  %tessera.
::
::    desk/lib holds the canonical copy; `make sync-libs` copies it to the
::    other desks. Import-free, so the test desk builds it alone.
::
|%
::  -- request caps --
::
::  max inputs, outputs or Ys per request: bounds one event's EC work
++  max-batch  ^-  @ud  100
::  max body bytes, checked BEFORE the JSON decode: de:json allocates the
::  whole body in one serial event
++  max-body-bytes  ^-  @ud  1.048.576
::  max secret bytes. Spent sets keep the raw secret, so without a cap one
::  token could grow state by a whole body per swap. It leaves room for the
::  largest P2PK lock the mint can spend (data + 9 pubkeys + 10 refund keys
::  and their tags, about 1.6 KB): the mint never sees a secret before it is
::  spent, so a smaller cap would freeze tokens it issued in good faith.
++  max-secret-bytes  ^-  @ud  2.048
::
::  -- numbers --
::
::  parse-ud-strict: ~ unless t is 1..20 decimal digits. The digit cap
::  keeps a huge run from costing an O(n^2) bignum build.
++  parse-ud-strict
  |=  t=@t
  ^-  (unit @ud)
  ?:  |(=('' t) (gth (met 3 t) 20))  ~
  (rush t (bass 10 (plus dit)))
::  parse-ud: parse-ud-strict, with anything else read as 0
++  parse-ud
  |=  t=@t
  ^-  @ud
  (fall (parse-ud-strict t) 0)
::  parse-abs: the magnitude of an optionally negative integer (LNbits
::  reports an outgoing payment's fee as negative msat)
++  parse-abs
  |=  t=@t
  ^-  (unit @ud)
  ?.  =('-' (end 3 t))  (parse-ud-strict t)
  (parse-ud-strict (rsh 3 t))
::
::  -- JSON fields: absent, null and mistyped all read as the default --
::
++  has-key  |=([o=(map @t json) k=@t] (~(has by o) k))
::
++  get-str
  |=  [o=(map @t json) k=@t]
  ^-  @t
  =/  v  (~(get by o) k)
  ?.  ?=([~ %s *] v)  ''
  p.u.v
::
++  get-num
  |=  [o=(map @t json) k=@t]
  ^-  @ud
  =/  v  (~(get by o) k)
  ?.  ?=([~ %n *] v)  0
  (parse-ud p.u.v)
::  get-ud: a field that must be a bare non-negative integer, else ~
++  get-ud
  |=  [o=(map @t json) k=@t]
  ^-  (unit @ud)
  =/  v  (~(get by o) k)
  ?.  ?=([~ %n *] v)  ~
  (parse-ud-strict p.u.v)
::
++  get-bool
  |=  [o=(map @t json) k=@t]
  ^-  ?
  =/  v  (~(get by o) k)
  ?.  ?=([~ %b *] v)  %.n
  p.u.v
::
++  get-array
  |=  [o=(map @t json) k=@t]
  ^-  (list json)
  =/  v  (~(get by o) k)
  ?.  ?=([~ %a *] v)  ~
  p.u.v
::
++  get-obj
  |=  [o=(map @t json) k=@t]
  ^-  (map @t json)
  =/  v  (~(get by o) k)
  ?.  ?=([~ %o *] v)  ~
  p.u.v
::
::  extract-str: key1's string, else key2's (LNbits and LND name fields
::  differently)
++  extract-str
  |=  [jon=json key1=@t key2=@t]
  ^-  @t
  ?.  ?=([%o *] jon)  ''
  =/  v  (get-str p.jon key1)
  ?.  =('' v)  v
  (get-str p.jon key2)
::
::  canon-hex: lowercase, so hex keys compare as the points they name
++  canon-hex  |=(t=@t `@t`(crip (cass (trip t))))
::
::  parse-object-body: a POST body as a JSON object, or a 400 detail
++  parse-object-body
  |=  body=(unit octs)
  ^-  (each json @t)
  ?~  body  [%| 'no-body']
  ?:  (gth p.u.body max-body-bytes)  [%| 'body-too-large']
  =/  parsed=(unit json)  (de:json:html q.u.body)
  ?~  parsed  [%| 'invalid-json']
  ?.  ?=([%o *] u.parsed)  [%| 'expected-object']
  [%& u.parsed]
::
::  -- requests --
::
::  parse-request-path: url -> path segments, query dropped. Empty segments
::  are skipped, so a doubled or trailing slash routes like the clean path.
++  parse-request-path
  |=  url=@t
  ^-  (list @t)
  =/  full=tape  (trip url)
  =/  q  (find "?" full)
  =?  full  ?=(^ q)  (scag u.q full)
  (turn (skip (split-tape full '/') |=(s=tape =(~ s))) crip)
::
++  split-tape
  |=  [t=tape c=@]
  ^-  (list tape)
  =|  acc=(list tape)
  =|  cur=tape
  |-
  ?~  t  (flop [(flop cur) acc])
  ?:  =(i.t c)  $(t t.t, acc [(flop cur) acc], cur ~)
  $(t t.t, cur [i.t cur])
::
::  host-of-url: the host[:port] of an Origin or Referer url
++  host-of-url
  |=  url=@t
  ^-  @t
  =/  txt=tape  (trip url)
  =/  s  (find "://" txt)
  =?  txt  ?=(^ s)  (slag (add 3 u.s) txt)
  =/  p  (find "/" txt)
  =?  txt  ?=(^ p)  (scag u.p txt)
  (crip txt)
::
::  csrf-ok: a state-changing request that names its page (Origin, else
::  Referer) must come from this host. Safe methods pass, and so does a
::  request naming no page: browsers always send Origin on a cross-site
::  POST, so only non-browser clients omit both. A proxy must forward Host;
::  X-Forwarded-Host isn't trusted, since a page on an origin approved
::  with |cors-approve could set it.
++  csrf-ok
  |=  req=inbound-request:eyre
  ^-  ?
  ?:  ?=(?(%'GET' %'HEAD' %'OPTIONS') method.request.req)  &
  =/  hdrs  header-list.request.req
  =/  src=(unit @t)
    =/  origin  (get-header:http 'origin' hdrs)
    ?^  origin  origin
    (get-header:http 'referer' hdrs)
  ?~  src  &
  =(`(host-of-url u.src) (get-header:http 'host' hdrs))
::
::  da-to-unix: @da -> unix seconds
++  da-to-unix
  |=  da=@da
  ^-  @ud
  (div (sub da ~1970.1.1) ~s1)
::
::  -- responses --
::
::  give-http: one complete response. An empty eyre-id marks a background
::  request that nobody waits on, which gets no cards.
++  give-http
  |=  [eyre-id=@ta code=@ud hdrs=header-list:http data=(unit octs)]
  ^-  (list card:agent:gall)
  ?:  =('' eyre-id)  ~
  =/  sec=header-list:http
    :~  ['x-frame-options' 'DENY']
        ['x-content-type-options' 'nosniff']
        ['cache-control' 'no-store']
        ::  the public routes serve cookie-less clients from any origin.
        ::  Capitalized as eyre writes it, so for an origin approved with
        ::  |cors-approve eyre's own header replaces this one.
        ['Access-Control-Allow-Origin' '*']
    ==
  =?  sec  !(lien hdrs |=([k=@t v=@t] =('content-security-policy' k)))
    [['content-security-policy' (crip "default-src 'self'; frame-ancestors 'none'")] sec]
  =/  pax=path  [%http-response eyre-id ~]
  :~  [%give %fact ~[pax] %http-response-header !>(`response-header:http`[code (weld hdrs sec)])]
      [%give %fact ~[pax] %http-response-data !>(data)]
      [%give %kick ~[pax] ~]
  ==
::
++  give-json
  |=  [jon=json eyre-id=@ta]
  ^-  (list card:agent:gall)
  %:  give-http  eyre-id  200
    ['content-type' 'application/json']~
    `(as-octs:mimes:html (en:json:html jon))
  ==
::
++  give-err
  |=  [eyre-id=@ta code=@ud msg=@t]
  ^-  (list card:agent:gall)
  %:  give-http  eyre-id  code
    ['content-type' 'application/json']~
    `(as-octs:mimes:html (en:json:html (pairs:enjs:format ['detail' s+msg]~)))
  ==
::
::  give-preflight: answer a CORS preflight for a public route
++  give-preflight
  |=  eyre-id=@ta
  ^-  (list card:agent:gall)
  %:  give-http  eyre-id  204
    :~  ['Access-Control-Allow-Methods' 'GET, POST, OPTIONS']
        ['Access-Control-Allow-Headers' 'Content-Type, Clear-auth']
        ['Access-Control-Max-Age' '86400']
    ==
    ~
  ==
::
::  give-dashboard: an admin page with a fresh CSP nonce spliced into each
::  `__CSP_NONCE__`, so only the page's own inline script runs
++  give-dashboard
  |=  [eyre-id=@ta lines=wain eny=@]
  ^-  (list card:agent:gall)
  =/  nonce=@t  (csp-nonce eny)
  =/  body=@t  (sub-nonce (rap 3 (join `@t`10 lines)) nonce)
  =/  csp=@t
    %-  crip
    ;:  weld
      "default-src 'self'; script-src 'self' 'nonce-"  (trip nonce)  "'; "
      "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
      "object-src 'none'; base-uri 'none'; form-action 'none'; "
      "frame-ancestors 'none'"
    ==
  %:  give-http  eyre-id  200
    :~  ['content-type' 'text/html; charset=utf-8']
        ['content-security-policy' csp]
    ==
    `(as-octs:mimes:html body)
  ==
::
::  csp-nonce: 32 random hex digits
++  csp-nonce
  |=  e=@
  ^-  @t
  (crip (scag 32 (skip (slag 2 (trip (scot %ux (shax e)))) |=(c=@t =('.' c)))))
::
::  sub-nonce: replace every `__CSP_NONCE__` in html
++  sub-nonce
  |=  [html=@t nonce=@t]
  ^-  @t
  =/  hay=tape  (trip html)
  =/  nee=tape  "__CSP_NONCE__"
  =/  non=tape  (trip nonce)
  =|  out=(list tape)
  |-  ^-  @t
  =/  i  (find nee hay)
  ?~  i  (crip `tape`(zing (flop [hay out])))
  $(out [non (scag u.i hay) out], hay (slag (add u.i (lent nee)) hay))
--
