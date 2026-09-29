::  tests for /lib/tessera-rules: tokens, issuance, services
::
/-  *tessera
/+  *test, *tessera-rules
|%
::  key 7's auth keyset: the id cashu-ts 4.11 derives for {1: 7G} with
::  unit 'auth', and 7G from noble
++  kid7  '017f3feb55be8da5a41bb5327f372f6298a080fe3d571c24d109c99b5e4944d622'
++  pub7  '025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc'
++  ks7   ^-  keyset  [kid7 pub7 7 ~2026.1.1 ~]
::  7*Y and 8*Y for the secret 'tessera', from noble
++  c7  '0396c8b2850bee91fef1c26bc0db7bfd999e9c3c9cdc375351032d2938ae9139d1'
++  c8  '0215ba8c769db01d30f2e9d12ebbdc141445311dae73f28700e8e4b68ade71a40f'
::  that token as cashu-ts's AuthManager writes it (padded base64url), and
::  without the padding
++  tok-ts
  %+  rap  3
  :~  'authAeyJpZCI6IjAxN2YzZmViNTViZThkYTVhNDFiYjUzMjdmMzcyZjYyOThhMDgwZmUzZDU3'
      'MWMyNGQxMDljOTliNWU0OTQ0ZDYyMiIsInNlY3JldCI6InRlc3NlcmEiLCJDIjoiMDM5NmM4Yj'
      'I4NTBiZWU5MWZlZjFjMjZiYzBkYjdiZmQ5OTllOWMzYzljZGMzNzUzNTEwMzJkMjkzOGFlOTEz'
      'OWQxIn0='
  ==
++  tok-bare  (end [3 (dec (met 3 tok-ts))] tok-ts)
::  7*Y for the secrets t0..t9, from noble
++  c7t
  ^-  (list @t)
  :~  '031a7773bdf2dd1af08a786ffe53ab5179ad6bb2562184b944df0a941daad0080e'
      '028161c56830a98ab0df8ddbd7d2a4f46425820c3560165d841d1bce3f2f5417ce'
      '0288c863b6e265e0c2fb11a05e76ffe3ea99ff62a89ffd4deabc608902091bc71f'
      '03d78825004da119f97dfd8aee91d3e985e688407c6aed310f4cc775886132dd9c'
      '0385a22ab0571de3e885e2930d073e55f64b7ed1a324217edf0d9a067dd07e9274'
      '03ecffc8e8c6c15c072dd3db97dda1147e46275ab2f17757ffbfea7441c670feda'
      '03148ca7d886f9317b5144268f1d4fc8ac706c55367d9497977bd8ace82f31fed6'
      '03b82363c2cdf0c1e96bda9524731bd5e51d53b938fa3096177a2e7c9f3423fbe9'
      '03d19c432bd7235e114938b780f78eeec8dd2fa0c3d918f73f6b7317ba6dbfab55'
      '0304bf81dbdb606ffe4a4bf2fa4fc27caadcbea8094d00029878f68e198fc41711'
  ==
++  tee  |=(i=@ud (cat 3 't' (dec-cord i)))
::  kG for k = 1..11, from noble: points to blind with
++  kg
  ^-  (list @t)
  :~  '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
      '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
      '02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9'
      '02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13'
      '022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4'
      '03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556'
      '025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc'
      '022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01'
      '03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe'
      '03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7'
      '03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb'
  ==
::  -G: G's x with the other parity
++  neg-g  '0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
::  21G = 7 * 3G, from noble
++  g21  '02352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5'
++  no-pt  (cat 3 '02' (fil 3 64 '0'))
++  one  `json`n+~.1
++  out  |=([b=@t amt=json kid=@t] `json`(pairs:enjs:format ~[['amount' amt] ['id' s+kid] ['B_' s+b]]))
++  outs  |=(n=@ud (turn (scag n kg) |=(b=@t (out b one kid7))))
++  b64  |=(t=@t (cat 3 'authA' (~(en base64:mimes:html | &) (as-octs:mimes:html t))))
++  svc0  (new-service 'x' ks7 ~2026.1.1)
::
::  -- tokens --
::
::  with final_expiry 1790000000 too
++  test-auth-keyset-id-matches-cashu-ts
  ;:  weld
    %+  expect-eq  !>('016ec6b8204405d2351a7b77880d3d3eaefabbd5f330dd2ae150b791bf80c6ae8e')
    !>((compute-ks-id (my [1 (snag 0 kg)]~) 'auth' 0 0))
    %+  expect-eq  !>('01073ec448cb055dabf4e7b999d916842813909ba1879f2e06456ba5e3e17a988c')
    !>((compute-ks-id (my [1 (snag 0 kg)]~) 'auth' 0 1.790.000.000))
    (expect-eq !>(kid7) !>((compute-ks-id (my [1 pub7]~) 'auth' 0 0)))
  ==
::
::  a service's key comes from the entropy, for amount 1, under the auth
::  id, which commits to when the keyset closes
++  test-new-keyset
  =/  ks  (new-keyset 5 ~2026.1.1 ~)
  =/  kc  (new-keyset 5 ~2026.1.1 `~2026.9.21..14.13.20)
  ;:  weld
    (expect-eq !>((mod (shax (add (mul 5 (bex 64)) 1)) secp-n)) !>(priv.ks))
    (expect-eq !>((pt-to-hex (pubkey priv.ks))) !>(pub.ks))
    (expect-eq !>((compute-ks-id (my [1 pub.ks]~) 'auth' 0 0)) !>(id.ks))
    (expect-eq !>([~2026.1.1 ~]) !>([created closes]:ks))
    (expect-eq !>((compute-ks-id (my [1 pub.ks]~) 'auth' 0 1.790.000.000)) !>(id.kc))
    (expect-eq !>(`~2026.9.21..14.13.20) !>(closes.kc))
  ==
::
++  test-parse-token-cashu-ts
  ;:  weld
    (expect-eq !>(`[kid7 'tessera' c7]) !>((parse-token tok-ts)))
    (expect-eq !>(`[kid7 'tessera' c7]) !>((parse-token tok-bare)))
  ==
::
++  test-parse-token-refuses
  ;:  weld
    (expect-eq !>(~) !>((parse-token (cat 3 'authB' (rsh [3 5] tok-ts)))))
    (expect-eq !>(~) !>((parse-token (cat 3 'autha' (rsh [3 5] tok-ts)))))
    (expect-eq !>(~) !>((parse-token 'authA')))
    (expect-eq !>(~) !>((parse-token 'authA!!!!')))
    (expect-eq !>(~) !>((parse-token (b64 '[1]'))))
    (expect-eq !>(~) !>((parse-token (b64 '{"id":"x","secret":"s"}'))))
    (expect-eq !>(~) !>((parse-token (b64 '{"id":"x","secret":"","C":"c"}'))))
    (expect-eq !>(~) !>((parse-token (b64 '{"id":"","secret":"s","C":"c"}'))))
    (expect-eq !>(~) !>((parse-token (b64 '{"id":"x","secret":1,"C":"c"}'))))
  ==
::
::  a secret of 2.048 bytes is taken and one more is not; a token of 4.096
::  bytes is read and one more is refused unread
++  test-parse-token-caps
  =/  js
    |=  [s=@t pad=@ud]
    (rap 3 ~['{"id":"' kid7 '","secret":"' s '","C":"' c7 '","pad":"' (fil 3 pad 'x') '"}'])
  =/  at-cap  (b64 (js 'tessera' 2.892))
  =/  over  (b64 (js 'tessera' 2.893))
  ;:  weld
    (expect-eq !>([4.096 4.097]) !>([(met 3 at-cap) (met 3 over)]))
    (expect-eq !>(`[kid7 'tessera' c7]) !>((parse-token at-cap)))
    (expect-eq !>(~) !>((parse-token over)))
    (expect-eq !>(`[kid7 (fil 3 2.048 's') c7]) !>((parse-token (b64 (js (fil 3 2.048 's') 0)))))
    (expect-eq !>(~) !>((parse-token (b64 (js (fil 3 2.049 's') 0)))))
  ==
::
++  test-unpad
  %+  expect-eq  !>(['ab' 'ab' 'ab' '' 'a=b'])
  !>([(unpad 'ab==') (unpad 'ab=') (unpad 'ab') (unpad '==') (unpad 'a=b')])
::
::  en-token writes what cashu-ts writes: as long, padded, and it reads back
++  test-en-token
  =/  t  (en-token [kid7 'tessera' c7])
  ;:  weld
    (expect-eq !>((met 3 tok-ts)) !>((met 3 t)))
    (expect-eq !>('=') !>((cut 3 [(dec (met 3 t)) 1] t)))
    (expect-eq !>(`[kid7 'tessera' c7]) !>((parse-token t)))
  ==
::
++  test-check-token
  =/  h  (shax 'tessera')
  ;:  weld
    (expect-eq !>(&+[h |]) !>((check-token tok-ts ks7 ~)))
    (expect-eq !>(&+[h &]) !>((check-token tok-ts ks7 (silt ~[h]))))
    (expect-eq !>(|+'unknown-keyset') !>((check-token tok-ts %*(. ks7 id 'other') ~)))
    ::  the same id, another key: C is not its signature
    (expect-eq !>(|+'invalid-token') !>((check-token tok-ts %*(. ks7 priv 8) ~)))
    ::  another secret under the same C, and key 8's C for this secret
    (expect-eq !>(|+'invalid-token') !>((check-token (en-token [kid7 'tesserb' c7]) ks7 ~)))
    (expect-eq !>(|+'invalid-token') !>((check-token (en-token [kid7 'tessera' c8]) ks7 ~)))
    ::  a C that is no point: x = 0 is off the curve
    (expect-eq !>(|+'invalid-token') !>((check-token (en-token [kid7 'tessera' no-pt]) ks7 ~)))
    (expect-eq !>(|+'invalid-token') !>((check-token 'nope' ks7 ~)))
  ==
::
++  test-check-refresh
  =/  ten=(list json)
    (turn (gulf 0 9) |=(i=@ud s+(en-token [kid7 (tee i) (snag i c7t)])))
  =/  hs=(set @)  (silt (turn (gulf 0 9) |=(i=@ud (shax (tee i)))))
  =/  ok  (check-refresh ten ks7 ~)
  ;:  weld
    ::  ten is the most: each good, their hashes
    (expect-eq !>(hs) !>(?:(?=(%& -.ok) (silt p.ok) ~)))
    (expect-eq !>(|+'too-many-tokens') !>((check-refresh [s+tok-ts ten] ks7 ~)))
    (expect-eq !>(|+'empty-tokens') !>((check-refresh ~ ks7 ~)))
    (expect-eq !>(|+'invalid-token') !>((check-refresh ~[n+~.1] ks7 ~)))
    (expect-eq !>(|+'token-already-spent') !>((check-refresh ~[s+tok-ts] ks7 (silt ~[(shax 'tessera')]))))
    ::  padded and not, it is one token
    (expect-eq !>(|+'duplicate-token') !>((check-refresh ~[s+tok-ts s+tok-bare] ks7 ~)))
    ::  one bad token refuses them all
    (expect-eq !>(|+'invalid-token') !>((check-refresh ~[s+tok-ts s+'nope'] ks7 ~)))
  ==
::
::  -- issuance --
::
++  test-mint-identity
  =/  pol=policy  [| (silt ~['k1' 'k2']) ~ ~]
  =/  id1  (mint-identity pol `'k1' |)
  =/  id2  (mint-identity pol `'k2' |)
  ;:  weld
    ::  each key counts apart, under an id that is not the key
    (expect-eq !>(&) !>(?=([%& ~ @] id1)))
    (expect-eq !>(|) !>(=(id1 id2)))
    (expect-eq !>(|) !>(=(id1 &+`'k1')))
    (expect-eq !>(|+[401 'invalid-clear-auth']) !>((mint-identity pol `'k3' |)))
    ::  a wrong key is refused even where anyone may mint, and for the owner
    (expect-eq !>(|+[401 'invalid-clear-auth']) !>((mint-identity [& ~ ~ ~] `'k1' &)))
    (expect-eq !>(&+~) !>((mint-identity pol ~ &)))
    (expect-eq !>(&+~) !>((mint-identity [& ~ ~ ~] ~ &)))
    (expect-eq !>(&+`'open') !>((mint-identity [& ~ ~ ~] ~ |)))
    (expect-eq !>(|+[401 'clear-auth-required']) !>((mint-identity pol ~ |)))
    (expect-eq !>(|+[403 'issuance-closed']) !>((mint-identity [| ~ ~ ~] ~ |)))
  ==
::
++  test-quota
  =/  q  `[3 ~h1]
  =/  now  ~2026.1.1..10.30.00
  =/  win  (div now ~h1)
  =/  next=@da  (mul ~h1 +(win))
  ;:  weld
    (expect-eq !>(~) !>((quota-left ~ `[win 99] now)))
    (expect-eq !>(`3) !>((quota-left q ~ now)))
    (expect-eq !>(`1) !>((quota-left q `[win 2] now)))
    (expect-eq !>(`0) !>((quota-left q `[win 3] now)))
    ::  more used than a lowered quota allows: none, and no crash
    (expect-eq !>(`0) !>((quota-left q `[win 5] now)))
    ::  a count lapses when its window ends, and not before
    (expect-eq !>(`0) !>((quota-left q `[win 3] (dec next))))
    (expect-eq !>(`3) !>((quota-left q `[win 3] next)))
    (expect-eq !>(`3) !>((quota-left q `[(dec win) 3] now)))
    (expect-eq !>([win 3]) !>((add-use ~h1 `[win 2] now 1)))
    (expect-eq !>([+(win) 1]) !>((add-use ~h1 `[win 2] next 1)))
    (expect-eq !>([win 2]) !>((add-use ~h1 ~ now 2)))
  ==
::
++  test-cap-ok
  =/  svc  svc0
  ;:  weld
    (expect-eq !>(&) !>((cap-ok svc 1.000)))
    (expect-eq !>(&) !>((cap-ok svc(max-issuance `2, issued 1) 1)))
    (expect-eq !>(|) !>((cap-ok svc(max-issuance `2, issued 2) 1)))
    (expect-eq !>(|) !>((cap-ok svc(max-issuance `2, issued 0) 3)))
  ==
::
++  test-read-outputs
  =/  ten  (read-outputs (outs 10) kid7)
  ;:  weld
    ::  their B_ hex and points, in order
    %+  expect-eq
      !>(&+~[[(snag 0 kg) (need (hex-to-pt (snag 0 kg)))] [(snag 1 kg) (need (hex-to-pt (snag 1 kg)))]])
    !>((read-outputs (outs 2) kid7))
    ::  ten is the most
    (expect-eq !>(10) !>(?:(?=(%& -.ten) (lent p.ten) 0)))
    (expect-eq !>(|+'too-many-outputs') !>((read-outputs (outs 11) kid7)))
    (expect-eq !>(|+'empty-outputs') !>((read-outputs ~ kid7)))
    ::  B_ and -B_ share an x: the DLEQ nonce-reuse shape
    (expect-eq !>(|+'duplicate-output') !>((read-outputs ~[(out (snag 0 kg) one kid7) (out neg-g one kid7)] kid7)))
    (expect-eq !>(|+'invalid-output') !>((read-outputs ~[s+'x'] kid7)))
    (expect-eq !>(|+'amount-must-be-1') !>((read-outputs ~[(out (snag 0 kg) n+~.2 kid7)] kid7)))
    (expect-eq !>(|+'amount-must-be-1') !>((read-outputs ~[(out (snag 0 kg) n+~.0 kid7)] kid7)))
    (expect-eq !>(|+'amount-must-be-1') !>((read-outputs ~[(out (snag 0 kg) s+'1' kid7)] kid7)))
    (expect-eq !>(|+'unknown-keyset') !>((read-outputs ~[(out (snag 0 kg) one 'other')] kid7)))
    (expect-eq !>(|+'invalid-B_') !>((read-outputs ~[(out no-pt one kid7)] kid7)))
    ::  one bad output refuses them all
    (expect-eq !>(|+'amount-must-be-1') !>((read-outputs (snoc (outs 3) (out (snag 10 kg) n+~.2 kid7)) kid7)))
  ==
::
::  C_ = 7*B_, for amount 1 under the keyset's id, with a DLEQ proof that
::  checks against the keyset's public key
++  test-sign-outputs
  =/  b  (need (hex-to-pt (snag 2 kg)))
  =/  sigs  (sign-outputs ~[[(snag 2 kg) b]] ks7 99)
  ?>  ?=([[%o *] ~] sigs)
  =/  o  p.i.sigs
  =/  dl  (get-obj o 'dleq')
  ;:  weld
    (expect-eq !>([g21 1 kid7]) !>([(get-str o 'C_') (get-num o 'amount') (get-str o 'id')]))
    %+  expect-eq  !>(&)
    !>((dleq-verify b (need (hex-to-pt g21)) (need (hex-to-pt pub7)) (hex-decode (get-str dl 'e')) (hex-decode (get-str dl 's'))))
  ==
::
::  tokens made here: 64-hex secrets, each signed by the key, new ones
::  from new entropy
++  test-mint-direct
  =/  two  (mint-direct 2 ks7 1)
  ?>  ?=([^ ^ ~] two)
  ;:  weld
    (expect-eq !>([kid7 64 & kid7]) !>([id.i.two (met 3 secret.i.two) (is-hex secret.i.two) id.i.t.two]))
    (expect-eq !>(|) !>(=(secret.i.two secret.i.t.two)))
    (expect-eq !>(&) !>((signed-by secret.i.two (need (hex-to-pt c.i.two)) 7)))
    (expect-eq !>(&) !>((signed-by secret.i.t.two (need (hex-to-pt c.i.t.two)) 7)))
    (expect-eq !>(|) !>(=((mint-direct 1 ks7 1) (mint-direct 1 ks7 2))))
    (expect-eq !>(~) !>((mint-direct 0 ks7 1)))
  ==
::
::  -- ships --
::
++  test-ship-ok
  =/  pol=policy  [| ~ (silt ~[~mus]) ~]
  =/  pl=policy  [| ~ ~ `%duke]
  =/  moon  (cat 5 ~sampel-palnet 1)
  ;:  weld
    (expect-eq !>([& | &]) !>([(ship-ok pol ~mus ~lyd) (ship-ok pol ~del ~lyd) (ship-ok pol ~lyd ~lyd)]))
    (expect-eq !>(&) !>((ship-ok [& ~ ~ ~] (bex 64) ~lyd)))
    ::  planets and up: a galaxy, a star and a planet; no moon, no comet
    %+  expect-eq  !>([& & & | |])
    !>([(ship-ok pl ~del ~lyd) (ship-ok pl ~marzod ~lyd) (ship-ok pl ~sampel-palnet ~lyd) (ship-ok pl moon ~lyd) (ship-ok pl (bex 64) ~lyd)])
    ::  stars and up: no planet
    (expect-eq !>([& |]) !>([(ship-ok pl(rank `%king) ~marzod ~lyd) (ship-ok pl(rank `%king) ~sampel-palnet ~lyd)]))
  ==
::
++  test-ship-set
  ;:  weld
    (expect-eq !>(`(silt ~[~zod ~mus])) !>((ship-set a+~[s+'~zod' s+'~mus'])))
    (expect-eq !>(``(set ship)`~) !>((ship-set a+~)))
    (expect-eq !>(~) !>((ship-set a+~[s+'zod'])))
    (expect-eq !>(~) !>((ship-set a+~[s+'~zod' n+~.1])))
    (expect-eq !>(~) !>((ship-set s+'~zod')))
  ==
::
++  test-rank-names
  =/  all=(list rank:title)  ~[%czar %king %duke %earl %pawn]
  ;:  weld
    (expect-eq !>(``%duke) !>((opt-rank s+'planet')))
    (expect-eq !>(`~) !>((opt-rank ~)))
    (expect-eq !>(~) !>((opt-rank s+'duke')))
    (expect-eq !>(~) !>((opt-rank n+~.2)))
    (expect-eq !>(['galaxy' 'star' 'planet' 'moon' 'comet']) !>([(rank-name %czar) (rank-name %king) (rank-name %duke) (rank-name %earl) (rank-name %pawn)]))
    ::  every name reads back as its rank
    (expect-eq !>(all) !>((murn all |=(r=rank:title (rank-of (rank-name r))))))
  ==
::
++  test-ames-outputs
  ;:  weld
    (expect-eq !>(&+~[[(snag 0 kg) (need (hex-to-pt (snag 0 kg)))]]) !>((ames-outputs ~[(snag 0 kg)] kid7)))
    (expect-eq !>(|+'duplicate-output') !>((ames-outputs ~[(snag 0 kg) neg-g] kid7)))
    (expect-eq !>(|+'too-many-outputs') !>((ames-outputs (scag 11 kg) kid7)))
    (expect-eq !>(|+'invalid-B_') !>((ames-outputs ~[no-pt] kid7)))
    (expect-eq !>(|+'empty-outputs') !>((ames-outputs ~ kid7)))
  ==
::
::  -- holding --
::
::  a holder's round trip: its blinds, the issuer's signatures, and tokens
::  the issuer takes
++  test-make-blinds-and-unblind
  =/  bs  (make-blinds 2 42)
  ?>  ?=([^ ^ ~] bs)
  =/  outs  (ames-outputs (turn bs |=(b=blind b.b)) kid7)
  ?>  ?=(%& -.outs)
  =/  toks  (unblind bs (sign-outputs p.outs ks7 9) kid7 pub7)
  ?>  ?=([%& ^ ^ ~] toks)
  =/  other  (make-blinds 2 43)
  ?>  ?=(^ other)
  ;:  weld
    ::  64-hex secrets, each its own, and B_ = Y + rG
    (expect-eq !>([64 &]) !>([(met 3 secret.i.bs) (is-hex secret.i.bs)]))
    (expect-eq !>(|) !>(=(secret.i.bs secret.i.t.bs)))
    (expect-eq !>(b.i.bs) !>((pt-to-hex b-prime:(blind-message secret.i.bs r.i.bs))))
    (expect-eq !>(|) !>(=(secret.i.bs secret.i.other)))
    ::  C = 7*Y: the issuer takes them
    (expect-eq !>(&+[(shax secret.i.bs) |]) !>((check-token (en-token i.p.toks) ks7 ~)))
    (expect-eq !>(&+[(shax secret.i.t.bs) |]) !>((check-token (en-token i.t.p.toks) ks7 ~)))
  ==
::
++  test-unblind-refuses
  =/  bs  (make-blinds 1 42)
  =/  outs  (ames-outputs (turn bs |=(b=blind b.b)) kid7)
  ?>  ?=(%& -.outs)
  =/  sigs  (sign-outputs p.outs ks7 9)
  ?>  ?=([[%o *] ~] sigs)
  =/  sig  p.i.sigs
  =/  with  |=([k=@t v=json] `(list json)`~[[%o (~(put by sig) k v)]])
  ;:  weld
    (expect-eq !>(|+'count-mismatch') !>((unblind bs ~ kid7 pub7)))
    (expect-eq !>(|+'invalid-key') !>((unblind bs sigs kid7 no-pt)))
    ::  a proof against another key: 8G did not sign it
    (expect-eq !>(|+'invalid-signature') !>((unblind bs sigs kid7 (snag 7 kg))))
    (expect-eq !>(|+'invalid-signature') !>((unblind bs sigs 'other' pub7)))
    (expect-eq !>(|+'invalid-signature') !>((unblind bs (with 'amount' n+~.2) kid7 pub7)))
    (expect-eq !>(|+'invalid-signature') !>((unblind bs (with 'C_' s+(snag 0 kg)) kid7 pub7)))
    (expect-eq !>(|+'invalid-signature') !>((unblind bs (with 'dleq' ~) kid7 pub7)))
    (expect-eq !>(|+'invalid-signature') !>((unblind bs ~[s+'x'] kid7 pub7)))
  ==
::
::  an offer names a service, holds tokens that parse, no more than a
::  batch with what the giver already offered, and fits
++  test-offer-refusal
  =/  ten  (reap 10 tok-ts)
  ;:  weld
    (expect-eq !>(~) !>((offer-refusal 'club' ~[tok-ts] ~ |)))
    (expect-eq !>(~) !>((offer-refusal 'club' (reap 9 tok-ts) ~[tok-ts] |)))
    (expect-eq !>(`'too-many-tokens') !>((offer-refusal 'club' ten ~[tok-ts] |)))
    (expect-eq !>(`'too-many-tokens') !>((offer-refusal 'club' [tok-ts ten] ~ |)))
    (expect-eq !>(`'invalid-service-name') !>((offer-refusal 'Club' ~[tok-ts] ~ |)))
    (expect-eq !>(`'empty-tokens') !>((offer-refusal 'club' ~ ~ |)))
    (expect-eq !>(`'invalid-token') !>((offer-refusal 'club' ~[tok-ts 'authAxx'] ~ |)))
    (expect-eq !>(`'too-many-offers') !>((offer-refusal 'club' ~[tok-ts] ~ &)))
  ==
::
::  a forward goes to one of the service's agents, with a small payload
++  test-forward-refusal
  =/  ok  (silt ~['guestbook'])
  ;:  weld
    (expect-eq !>(~) !>((forward-refusal ok [%guestbook 'hi'])))
    (expect-eq !>(`'agent-not-allowed') !>((forward-refusal ok [%hood 'hi'])))
    (expect-eq !>(`'agent-not-allowed') !>((forward-refusal ~ [%guestbook 'hi'])))
    ::  16.384 bytes jammed is the most
    =/  at  (fil 3 16.379 'x')
    (expect-eq !>([16.384 ~]) !>([(met 3 (jam at)) (forward-refusal ok [%guestbook at])]))
    =/  over  (fil 3 16.380 'x')
    (expect-eq !>(`'data-too-large') !>((forward-refusal ok [%guestbook over])))
  ==
::
::  an answer comes from the issuer, or for a give, the receiver
++  test-whom
  =/  tok=token  [kid7 'tessera' c7]
  %+  expect-eq  !>([~lyd ~lyd ~lyd ~del])
  !>  :*  (whom [%get [%none ~] ~lyd 'x' ~])
          (whom [%use [%none ~] ~lyd 'x' tok])
          (whom [%ask [%none ~] ~lyd])
          (whom [%give [%none ~] ~del ~lyd 'x' ~[tok]])
      ==
::
++  test-lost
  %+  expect-eq  !>([& & | |])
  !>([(lost 'invalid-token') (lost 'unknown-keyset') (lost 'service-inactive') (lost 'quota-exceeded')])
::
::  -- windows --
::
::  windows are multiples of their length: a day closes at midnight UTC
++  test-closing
  ;:  weld
    (expect-eq !>(~) !>((closing ~ ~2026.9.21..14.13.20)))
    (expect-eq !>(`~2026.9.22) !>((closing `~d1 ~2026.9.21..14.13.20)))
    (expect-eq !>(`~2026.9.22) !>((closing `~d1 ~2026.9.21)))
    (expect-eq !>(`~2026.9.23) !>((closing `~d1 ~2026.9.22)))
    (expect-eq !>(`~2026.9.21..14.15.00) !>((closing `~m5 ~2026.9.21..14.13.20)))
  ==
::
++  test-rotate
  =/  now  ~2026.9.21..14.13.20
  =/  svc  svc0
  =/  day  svc(window `~d1)
  =/  r1  (rotate day 1 now)
  =/  r2  (rotate svc.r1 2 ~2026.9.21..23.59.59)
  =/  r3  (rotate svc.r1 3 ~2026.9.22)
  =/  r4  (rotate svc.r3(window ~) 4 ~2026.9.22)
  ;:  weld
    ::  no window, nothing to do
    (expect-eq !>([svc ~]) !>((rotate svc 1 now)))
    ::  a window set: a new keyset closing at midnight, the old one dead
    (expect-eq !>([`~2026.9.22 `kid7]) !>([closes.keyset.svc.r1 dead.r1]))
    (expect-eq !>((new-keyset 1 now `~2026.9.22)) !>(keyset.svc.r1))
    ::  the same window, the same keyset
    (expect-eq !>([svc.r1 ~]) !>(r2))
    ::  the next window, a new one
    (expect-eq !>([`~2026.9.23 `id.keyset.svc.r1]) !>([closes.keyset.svc.r3 dead.r3]))
    ::  the window gone, a keyset for good
    (expect-eq !>([~ `id.keyset.svc.r3]) !>([closes.keyset.svc.r4 dead.r4]))
  ==
::
::  quota counts go when their window has, or their service, or its quota
++  test-prune-used
  =/  now  ~2026.9.21..14.13.20
  =/  svc  svc0
  =/  svcs  (malt `(list [@t service])`~[['q' svc(name 'q', quota `[5 ~h1])] ['n' svc(name 'n')]])
  =/  win  (div now ~h1)
  =/  used=(map [@t @t] usage)
    %-  malt
    :~  [['q' 'a'] [win 1]]
        [['q' 'b'] [(dec win) 5]]
        [['n' 'a'] [win 1]]
        [['gone' 'a'] [win 1]]
    ==
  (expect-eq !>((malt ~[[['q' 'a'] [win 1]]])) !>((prune-used used svcs now)))
::
::  spent sets go with their keysets: closed, or no service's
++  test-prune-spent
  =/  now  ~2026.9.21..14.13.20
  =/  svc  svc0
  =/  ks  ks7
  =/  open  svc(name 'o', keyset ks(id 'open', closes `~2026.9.22))
  =/  shut  svc(name 's', keyset ks(id 'shut', closes `now))
  =/  svcs  (malt `(list [@t service])`~[['p' svc(name 'p')] ['o' open] ['s' shut]])
  =/  spent=(map @t (set @))
    (malt ~[[kid7 (silt ~[1])] ['open' (silt ~[2])] ['shut' (silt ~[3])] ['orphan' (silt ~[4])]])
  %+  expect-eq  !>((malt ~[[kid7 (silt ~[1])] ['open' (silt ~[2])]]))
  !>((prune-spent spent svcs now))
::
::  -- services --
::
++  test-valid-service-name
  ;:  weld
    (expect-eq !>(&) !>((valid-service-name 'a')))
    (expect-eq !>(&) !>((valid-service-name 'az09_-')))
    (expect-eq !>(&) !>((valid-service-name (fil 3 64 'a'))))
    (expect-eq !>(|) !>((valid-service-name (fil 3 65 'a'))))
    (expect-eq !>(|) !>((valid-service-name '')))
    ::  the characters just outside each range, and others
    (expect-eq !>(~) !>((skim (trip '`{/:A.~ ') |=(c=@t (valid-service-name c)))))
  ==
::
++  test-resolve-service
  =/  svc  svc0
  =/  now  ~2026.6.1
  ;:  weld
    (expect-eq !>(|+[404 'service-not-found']) !>((resolve-service ~ now)))
    (expect-eq !>(&+svc) !>((resolve-service `svc now)))
    (expect-eq !>(|+[400 'service-inactive']) !>((resolve-service `svc(active |) now)))
    (expect-eq !>(&+svc(expires `now)) !>((resolve-service `svc(expires `now) now)))
    (expect-eq !>(|+[400 'service-expired']) !>((resolve-service `svc(expires `(dec now)) now)))
  ==
::
::  a new service is active, and closed: only this ship issues
++  test-new-service
  =/  svc  svc0
  %+  expect-eq  !>(`service`['x' '' '' & [| ~ ~ ~] ~ ~ %burn ~ ~ ~ ~ ~ 0 0 ~2026.1.1 ks7])
  !>(svc)
::
++  test-apply-fields
  =/  o=(map @t json)
    %-  my
    :~  ['title' s+'T']
        ['description' s+'D']
        ['open' b+&]
        ['mode' s+'check']
        ['keys' a+~[s+'k1' s+'k2']]
        ['verifier_keys' a+~[s+'v']]
        ['ships' a+~[s+'~mus']]
        ['verifiers' a+~[s+'~del']]
        ['agents' a+~[s+'tessera-demo']]
        ['rank' s+'star']
        ['quota' (pairs:enjs:format ~[['n' n+~.5] ['per' n+~.60]])]
        ['window' n+~.86400]
        ['expires' n+~.1790000000]
        ['max_issuance' n+~.9]
    ==
  =/  r  (apply-fields o svc0)
  ?>  ?=(%& -.r)
  =/  s  p.r
  ;:  weld
    (expect-eq !>(['T' 'D' & %check]) !>([title.s description.s open.policy.s mode.s]))
    (expect-eq !>([(silt ~['k1' 'k2']) (silt ~['v'])]) !>([keys.policy.s verifier-keys.s]))
    (expect-eq !>([(silt ~[~mus]) (silt ~[~del]) `%king]) !>([ships.policy.s verifiers.s rank.policy.s]))
    (expect-eq !>((silt ~['tessera-demo'])) !>(agents.s))
    (expect-eq !>([`[5 ~m1] `~d1 `~2026.9.21..14.13.20 `9]) !>([quota.s window.s expires.s max-issuance.s]))
    ::  the rest is left alone
    (expect-eq !>([name created keyset active]:svc0) !>([name created keyset active]:s))
  ==
::
++  test-apply-fields-absent-and-null
  =/  svc  svc0
  =.  title.svc  'T'
  =.  quota.svc  `[5 ~m1]
  =.  max-issuance.svc  `9
  =.  expires.svc  `~2027.1.1
  =.  policy.svc  [& (silt ~['k']) ~ ~]
  =.  mode.svc  %check
  =.  verifiers.svc  (silt ~[~del])
  ;:  weld
    ::  nothing asked, nothing changed
    (expect-eq !>(&+svc) !>((apply-fields ~ svc)))
    ::  null clears quota, window, expires, max_issuance and rank
    %+  expect-eq  !>(&+svc(quota ~, expires ~, max-issuance ~))
    !>((apply-fields (malt ~[['quota' ~] ['expires' ~] ['max_issuance' ~]]) svc))
    %+  expect-eq  !>(&+svc(window ~))
    !>((apply-fields (malt ~[['window' ~]]) svc(window `~d1)))
    %+  expect-eq  !>(&+svc(rank.policy ~))
    !>((apply-fields (malt ~[['rank' ~]]) svc(rank.policy `%duke)))
    ::  an empty list clears verifiers
    (expect-eq !>(&+svc(verifiers ~)) !>((apply-fields (malt ['verifiers' a+~]~) svc)))
    ::  an empty list clears keys
    (expect-eq !>(&+svc(policy [& ~ ~ ~])) !>((apply-fields (malt ['keys' a+~]~) svc)))
  ==
::
++  test-apply-fields-refuses
  =/  svc  %*(. svc0 title 'T')
  =/  go  |=(o=(list [@t json]) (apply-fields (malt o) svc))
  =/  quo  |=(o=(list [@t json]) (go ['quota' (pairs:enjs:format o)]~))
  =/  q1  (quo ~[['n' n+~.1] ['per' n+~.1]])
  ;:  weld
    (expect-eq !>(|+'missing-title') !>((apply-fields ~ svc0)))
    (expect-eq !>(|+'missing-title') !>((go ['title' s+'']~)))
    (expect-eq !>(|+'invalid-open') !>((go ['open' s+'yes']~)))
    (expect-eq !>(|+'invalid-mode') !>((go ['mode' s+'free']~)))
    (expect-eq !>(|+'invalid-keys') !>((go ['keys' a+~[s+'k' s+'']]~)))
    (expect-eq !>(|+'invalid-keys') !>((go ['keys' s+'k']~)))
    (expect-eq !>(|+'invalid-keys') !>((go ['keys' a+~[n+~.1]]~)))
    (expect-eq !>(|+'invalid-verifier-keys') !>((go ['verifier_keys' a+~[s+'']]~)))
    (expect-eq !>(|+'invalid-ships') !>((go ['ships' a+~[s+'mus']]~)))
    (expect-eq !>(|+'invalid-verifiers') !>((go ['verifiers' a+~[s+'~mus' s+'']]~)))
    (expect-eq !>(|+'invalid-rank') !>((go ['rank' s+'duke']~)))
    ::  an agent name must be a term
    (expect-eq !>(|+'invalid-agents') !>((go ['agents' a+~[s+'Demo']]~)))
    (expect-eq !>(|+'invalid-agents') !>((go ['agents' a+~[s+'']]~)))
    ::  the smallest quota is 1 per second
    (expect-eq !>(`[1 ~s1]) !>(?:(?=(%& -.q1) quota.p.q1 ~)))
    (expect-eq !>(|+'invalid-quota') !>((quo ~[['n' n+~.0] ['per' n+~.60]])))
    (expect-eq !>(|+'invalid-quota') !>((quo ~[['n' n+~.1] ['per' n+~.0]])))
    (expect-eq !>(|+'invalid-quota') !>((quo ~[['n' n+~.1]])))
    (expect-eq !>(|+'invalid-quota') !>((go ['quota' n+~.1]~)))
    (expect-eq !>(|+'invalid-expires') !>((go ['expires' s+'soon']~)))
    (expect-eq !>(|+'invalid-window') !>((go ['window' n+~.0]~)))
    (expect-eq !>(|+'invalid-window') !>((go ['window' s+'day']~)))
    (expect-eq !>(`~s1) !>(=/(r (go ['window' n+~.1]~) ?:(?=(%& -.r) window.p.r ~))))
    (expect-eq !>(|+'invalid-max-issuance') !>((go ['max_issuance' n+~.1.5]~)))
  ==
::
::  -- views --
::
::  NUT-21 marks minting as needing a key only where no one may mint
::  without one
++  test-info-json
  =/  nuts
    |=  s=service
    ^-  (map @t json)
    =/  j  (info-json s)
    ?>  ?=([%o *] j)
    (get-obj p.j 'nuts')
  =/  keyed  %*(. svc0 policy `policy`[| (silt ~['k']) ~ ~])
  =/  n21  (need (de:json:html '{"protected_endpoints":[{"method":"POST","path":"/v1/auth/blind/mint"}]}'))
  =/  n22  (need (de:json:html '{"bat_max_mint":10,"protected_endpoints":[]}'))
  ;:  weld
    (expect-eq !>((malt ~[['22' n22]])) !>((nuts svc0)))
    (expect-eq !>((malt ~[['21' n21] ['22' n22]])) !>((nuts keyed)))
    (expect-eq !>((malt ~[['22' n22]])) !>((nuts keyed(open.policy &))))
  ==
::
++  test-keys-json
  =/  ks  ks7
  =/  kc  ks(closes `~2026.9.21..14.13.20)
  ;:  weld
    ::  a keyset that closes says when, as a wallet needs to derive its id
    %+  expect-eq
      !>((need (de:json:html (rap 3 ~['{"keysets":[{"id":"' kid7 '","unit":"auth","active":true,"final_expiry":1790000000}]}']))))
    !>((keysets-json kc))
    %+  expect-eq
      !>((need (de:json:html (rap 3 ~['{"keysets":[{"id":"' kid7 '","unit":"auth","active":true,"final_expiry":1790000000,"keys":{"1":"' pub7 '"}}]}']))))
    !>((keys-json kc))
    %+  expect-eq
      !>((need (de:json:html (rap 3 ~['{"keysets":[{"id":"' kid7 '","unit":"auth","active":true,"keys":{"1":"' pub7 '"}}]}']))))
    !>((keys-json ks7))
    %+  expect-eq
      !>((need (de:json:html (rap 3 ~['{"keysets":[{"id":"' kid7 '","unit":"auth","active":true}]}']))))
    !>((keysets-json ks7))
  ==
::
::  the admin view: quota per in seconds, times in unix seconds
++  test-service-json
  =/  svc  svc0
  =/  want
    %-  need  %-  de:json:html
    %+  rap  3
    :~  '{"name":"x","title":"T","description":"","active":true,"open":false,'
        '"keys":["k"],"verifier_keys":[],"ships":["~mus"],"rank":"planet",'
        '"verifiers":["~del"],"agents":["guestbook"],"quota":{"n":5,"per":60},'
        '"window":86400,"mode":"burn",'
        '"max_issuance":null,"expires":null,"issued":0,"redeemed":0,'
        '"created":1767225600,"keyset":"'  kid7  '"}'
    ==
  %+  expect-eq  !>(want)
  !>  %-  service-json
  %=  svc
    title  'T'
    policy  [| (silt ~['k']) (silt ~[~mus]) `%duke]
    verifiers  (silt ~[~del])
    agents  (silt ~['guestbook'])
    quota  `[5 ~m1]
    window  `~d1
  ==
--
