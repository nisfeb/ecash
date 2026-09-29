::  tests for /lib/blind: the blind-signature core
::
/+  *test, *blind, *bdhke, *curve, *ecash-http
|%
++  g-hex   '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
++  g2-hex  '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
::
::  the id cashu-ts 4.5.1 derives (deriveKeysetId, v1) for keys 1:G 2:2G
::  1024:3G, with no fee and with 1500 ppk: pins the canonical string,
::  including plain decimals ("1024", "1500"; scot gives "1.024")
++  test-compute-ks-id-matches-cashu-ts
  =/  keys=(map @ud @t)
    %-  my
    :~  [1 g-hex]
        [2 g2-hex]
        [1.024 '02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9']
    ==
  ;:  weld
    %+  expect-eq  !>('01f6087bf94d44a807db1093540aab2c211ec92a1e8eeeba5122bcf4b84a2fbe6a')
    !>((compute-ks-id keys 'sat' 0 0))
    %+  expect-eq  !>('0110262e7890585e5148fc3c58446fe78a615b8cb1cf46cb69d774f7ea1941aa9d')
    !>((compute-ks-id keys 'sat' 1.500 0))
  ==
::
::  keys come from the entropy, one per denomination: sha256(ent*2^64 + d)
::  mod n, and a public key that matches each
++  test-gen-keys
  =/  ks  (gen-keys 5 ~[1 2 1.024])
  ;:  weld
    (expect-eq !>(3) !>(~(wyt in (silt ~(val by privkeys.ks)))))
    (expect-eq !>((mod (shax (add (mul 5 (bex 64)) 1)) secp-n)) !>((~(got by privkeys.ks) 1)))
    (expect-eq !>((pt-to-hex (pubkey (~(got by privkeys.ks) 1.024)))) !>((~(got by pubkeys.ks) 1.024)))
  ==
::
++  test-dec-cord
  ;:  weld
    (expect-eq !>('1024') !>((dec-cord 1.024)))
    (expect-eq !>('0') !>((dec-cord 0)))
  ==
::
::  sign, unblind: the token is k*hash_to_curve(secret), signed-by accepts
::  it under k and no other key, and the DLEQ proof verifies
++  test-sign-blinded-round-trip
  =/  bf  (blind-message 'core' 5)
  =/  b-hex  (pt-to-hex b-prime.bf)
  =/  sig  (sign-blinded b-hex b-prime.bf 1 'kid' 11 (pubkey 11) 99)
  ?>  ?=([%o *] sig)
  =/  c-  (need (hex-to-pt (get-str p.sig 'C_')))
  =/  c  (unblind-signature c- blinding-factor.bf (pubkey 11))
  =/  dl  (get-obj p.sig 'dleq')
  ;:  weld
    (expect-eq !>('kid') !>((get-str p.sig 'id')))
    (expect-eq !>(1) !>((get-num p.sig 'amount')))
    (expect-eq !>(&) !>((signed-by 'core' c 11)))
    (expect-eq !>(|) !>((signed-by 'core' c 12)))
    (expect-eq !>(|) !>((signed-by 'other' c 11)))
    %+  expect-eq  !>(&)
    !>((dleq-verify b-prime.bf c- (pubkey 11) (hex-decode (get-str dl 'e')) (hex-decode (get-str dl 's'))))
    (expect-eq !>(&) !>((all-signed ~[sig])))
    (expect-eq !>(|) !>((all-signed ~[sig (pairs:enjs:format ['error' s+'x']~)])))
  ==
--
