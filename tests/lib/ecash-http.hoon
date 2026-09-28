::  tests for /lib/ecash-http: parsing, CSRF, responses
::
/+  *test, *ecash-http
|%
::  req: a request with every flag set explicitly (a bunt's loobeans are all
::  %.y, which would make every request look like the owner's)
++  req
  |=  [meth=method:http hdrs=header-list:http]
  ^-  inbound-request:eyre
  [| | [%ipv4 .127.0.0.1] [meth '/apps/ecash/admin/api/x' hdrs ~]]
::
++  test-parse-ud-strict
  ;:  weld
    (expect-eq !>(`12) !>((parse-ud-strict '12')))
    (expect-eq !>(`0) !>((parse-ud-strict '0')))
    (expect-eq !>(~) !>((parse-ud-strict '')))
    (expect-eq !>(~) !>((parse-ud-strict '1.5')))
    (expect-eq !>(~) !>((parse-ud-strict '-1')))
    (expect-eq !>(~) !>((parse-ud-strict '1e3')))
    ::  the digit cap as a pair: 20 digits parse, 21 don't
    (expect-eq !>(`(dec (pow 10 20))) !>((parse-ud-strict (crip (reap 20 '9')))))
    (expect-eq !>(~) !>((parse-ud-strict (crip (reap 21 '9')))))
  ==
::
++  test-parse-ud-reads-garbage-as-zero
  ;:  weld
    (expect-eq !>(7) !>((parse-ud '7')))
    (expect-eq !>(0) !>((parse-ud 'x')))
  ==
::
::  LNbits reports an outgoing fee as negative msat
++  test-parse-abs
  ;:  weld
    (expect-eq !>(`2.000) !>((parse-abs '-2000')))
    (expect-eq !>(`2.000) !>((parse-abs '2000')))
    (expect-eq !>(~) !>((parse-abs '-')))
    (expect-eq !>(~) !>((parse-abs '--1')))
  ==
::
::  a JSON null or a mistyped value reads as the default; it used to crash
::  the event (a 500 instead of a 400)
++  test-getters-survive-null-and-mistypes
  =/  o=(map @t json)
    %-  my
    :~  ['nul' ~]
        ['str' s+'hi']
        ['num' n+'42']
        ['bool' b+&]
        ['arr' a+~[n+'1']]
        ['obj' o+(my ['k' s+'v']~)]
    ==
  ;:  weld
    (expect-eq !>('') !>((get-str o 'nul')))
    (expect-eq !>(0) !>((get-num o 'nul')))
    (expect-eq !>(~) !>((get-ud o 'nul')))
    (expect-eq !>(|) !>((get-bool o 'nul')))
    (expect-eq !>(`(list json)`~) !>((get-array o 'nul')))
    (expect-eq !>(`(map @t json)`~) !>((get-obj o 'nul')))
    (expect-eq !>('') !>((get-str o 'num')))
    (expect-eq !>(0) !>((get-num o 'str')))
    (expect-eq !>(|) !>((get-bool o 'str')))
    (expect-eq !>('hi') !>((get-str o 'str')))
    (expect-eq !>(42) !>((get-num o 'num')))
    (expect-eq !>(`42) !>((get-ud o 'num')))
    (expect-eq !>(&) !>((get-bool o 'bool')))
    (expect-eq !>(`(list json)`~[n+'1']) !>((get-array o 'arr')))
    (expect-eq !>(&) !>((has-key o 'nul')))
    (expect-eq !>(|) !>((has-key o 'gone')))
  ==
::
++  test-extract-str-falls-back
  =/  j=json  (pairs:enjs:format ~[['b' s+'2'] ['c' s+'']])
  ;:  weld
    (expect-eq !>('2') !>((extract-str j 'a' 'b')))
    (expect-eq !>('2') !>((extract-str j 'c' 'b')))
    (expect-eq !>('') !>((extract-str s+'x' 'a' 'b')))
  ==
::
++  test-canon-hex
  (expect-eq !>('02abcdef') !>((canon-hex '02AbCdEf')))
::
++  test-parse-object-body
  =/  ok  (as-octs:mimes:html '{"a":1}')
  =/  good=(each json @t)  [%& (pairs:enjs:format ['a' n+'1']~)]
  ;:  weld
    (expect-eq !>(`(each json @t)`[%| 'no-body']) !>((parse-object-body ~)))
    (expect-eq !>(`(each json @t)`[%| 'invalid-json']) !>((parse-object-body `(as-octs:mimes:html '{'))))
    (expect-eq !>(`(each json @t)`[%| 'expected-object']) !>((parse-object-body `(as-octs:mimes:html '[1]'))))
    (expect-eq !>(good) !>((parse-object-body `ok)))
    ::  the size cap as a pair, on the declared length
    (expect-eq !>(good) !>((parse-object-body `ok(p max-body-bytes))))
    (expect-eq !>(`(each json @t)`[%| 'body-too-large']) !>((parse-object-body `ok(p +(max-body-bytes)))))
  ==
::
++  test-parse-request-path
  ;:  weld
    (expect-eq !>(`(list @t)`~['v1' 'keys']) !>((parse-request-path '/v1/keys')))
    ::  trailing and doubled slashes route like the clean path
    (expect-eq !>(`(list @t)`~['v1' 'keys']) !>((parse-request-path '/v1//keys/')))
    (expect-eq !>(`(list @t)`~['a' 'b']) !>((parse-request-path '/a/b?c=/d')))
    (expect-eq !>(`(list @t)`~) !>((parse-request-path '/')))
  ==
::
++  test-host-of-url
  ;:  weld
    (expect-eq !>('mint.example:8443') !>((host-of-url 'https://mint.example:8443/apps/x')))
    (expect-eq !>('mint.example') !>((host-of-url 'https://mint.example')))
    (expect-eq !>('null') !>((host-of-url 'null')))
  ==
::
++  test-csrf-ok
  =/  host  ['host' 'mint.example']
  ;:  weld
    ::  safe methods always pass
    (expect-eq !>(&) !>((csrf-ok (req %'GET' ~[['origin' 'https://evil.example'] host]))))
    ::  no Origin and no Referer: a non-browser client
    (expect-eq !>(&) !>((csrf-ok (req %'POST' ~[host]))))
    (expect-eq !>(&) !>((csrf-ok (req %'POST' ~[['origin' 'https://mint.example'] host]))))
    (expect-eq !>(|) !>((csrf-ok (req %'POST' ~[['origin' 'https://evil.example'] host]))))
    (expect-eq !>(|) !>((csrf-ok (req %'POST' ~[['origin' 'null'] host]))))
    ::  Referer stands in for a missing Origin, and can't smuggle the host
    (expect-eq !>(&) !>((csrf-ok (req %'POST' ~[['referer' 'https://mint.example/apps/ecash/admin'] host]))))
    (expect-eq !>(|) !>((csrf-ok (req %'POST' ~[['referer' 'https://evil.example/?https://mint.example'] host]))))
    ::  X-Forwarded-Host isn't trusted: a page on a |cors-approve'd origin
    ::  could set it. A proxy must forward Host.
    %+  expect-eq  !>(|)
    !>((csrf-ok (req %'POST' ~[['origin' 'https://mint.example'] ['host' '127.0.0.1:8080'] ['x-forwarded-host' 'mint.example']])))
    ::  and a request with neither host header is refused
    (expect-eq !>(|) !>((csrf-ok (req %'POST' ~[['origin' 'https://mint.example']]))))
  ==
::
++  test-da-to-unix
  (expect-eq !>(86.400) !>((da-to-unix ~1970.1.2)))
::
::  headers of the first card give-http makes
++  sent-headers
  |=  cards=(list card:agent:gall)
  ^-  header-list:http
  ?>  ?=([[%give %fact * %http-response-header *] *] cards)
  headers:!<(response-header:http q.cage.p.i.cards)
::
::  a background request (empty eyre-id) has nobody waiting: no cards
++  test-give-http-background-is-silent
  (expect-eq !>(`(list card:agent:gall)`~) !>((give-json s+'x' '')))
::
++  test-give-http-headers
  =/  hs  (sent-headers (give-json s+'x' 'eyre_1'))
  =/  own  (sent-headers (give-http 'eyre_1' 200 ['content-security-policy' 'mine']~ ~))
  =/  csp  |=(h=header-list:http (skim h |=([k=@t v=@t] =('content-security-policy' k))))
  ;:  weld
    (expect-eq !>(3) !>((lent (give-json s+'x' 'eyre_1'))))
    (expect-eq !>(`'no-store') !>((get-header:http 'cache-control' hs)))
    (expect-eq !>(`'*') !>((get-header:http 'Access-Control-Allow-Origin' hs)))
    (expect-eq !>(`'nosniff') !>((get-header:http 'x-content-type-options' hs)))
    ::  the strict CSP by default, and only the caller's when it gives one
    (expect-eq !>(1) !>((lent (csp hs))))
    (expect-eq !>(`header-list:http`~[['content-security-policy' 'mine']]) !>((csp own)))
  ==
::
++  test-sub-nonce-replaces-every-placeholder
  ;:  weld
    (expect-eq !>('<a n="N"><b n="N">') !>((sub-nonce '<a n="__CSP_NONCE__"><b n="__CSP_NONCE__">' 'N')))
    (expect-eq !>('plain') !>((sub-nonce 'plain' 'N')))
  ==
::
++  test-dashboard-csp-carries-the-nonce
  =/  hs  (sent-headers (give-dashboard 'eyre_1' ~['<script nonce="__CSP_NONCE__">'] 7))
  =/  csp  (need (get-header:http 'content-security-policy' hs))
  =/  nonce  (csp-nonce 7)
  ;:  weld
    (expect-eq !>(32) !>((met 3 nonce)))
    (expect-eq !>(&) !>(!=(~ (find (trip (cat 3 'nonce-' nonce)) (trip csp)))))
    ::  scripts run by nonce only, and no form can post off-site
    (expect-eq !>(&) !>(!=(~ (find "script-src 'self' 'nonce-" (trip csp)))))
    (expect-eq !>(&) !>(!=(~ (find "form-action 'none'" (trip csp)))))
  ==
--
