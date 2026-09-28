::  tests for /lib/curve: secp256k1 point arithmetic
::
/+  *test, *curve
|%
::  2G and 3G from the published secp256k1 tables
++  two-g
  ^-  point
  :-  0xc604.7f94.41ed.7d6d.3045.406e.95c0.7cd8.5c77.8e4b.8cef.3ca7.abac.09b9.5c70.9ee5
  0x1ae1.68fe.a63d.c339.a3c5.8419.466c.eaee.f7f6.3265.3266.d0e1.2364.31a9.50cf.e52a
++  three-x
  0xf930.8a01.9258.c310.4934.4f85.f89d.5229.b531.c845.836f.99b0.8601.f113.bce0.36f9
::
++  test-pubkey-one-is-the-generator
  (expect-eq !>(pt-gen) !>((pubkey 1)))
::
++  test-pt-mul-matches-published-multiples
  ;:  weld
    (expect-eq !>(two-g) !>((pt-mul 2 pt-gen)))
    (expect-eq !>(three-x) !>(x:(pt-mul 3 pt-gen)))
    ::  the ladder agrees with the affine formulas it replaced
    (expect-eq !>((pt-add two-g pt-gen)) !>((pt-mul 3 pt-gen)))
  ==
::
::  adding a point to itself takes the doubling path
++  test-pt-add-doubles
  ;:  weld
    (expect-eq !>(two-g) !>((pt-add pt-gen pt-gen)))
    (expect-eq !>(two-g) !>((pt-dbl pt-gen)))
  ==
::
::  k and k+n name the same point, and n-1 is -1: the ladder reduces mod n
++  test-pt-mul-works-mod-n
  ;:  weld
    (expect-eq !>((pt-mul 5 pt-gen)) !>((pt-mul (add secp-n 5) pt-gen)))
    (expect-eq !>((pt-neg pt-gen)) !>((pt-mul (dec secp-n) pt-gen)))
    (expect-eq !>((pt-mul 7 two-g)) !>((pt-mul 14 pt-gen)))
  ==
::
::  0 and n give the point at infinity, which a point can't hold
++  test-pt-mul-refuses-zero
  ;:  weld
    (expect-fail |.((pt-mul 0 pt-gen)))
    (expect-fail |.((pt-mul secp-n pt-gen)))
  ==
::
++  test-pt-add-refuses-infinity
  (expect-fail |.((pt-add pt-gen (pt-neg pt-gen))))
::
++  test-hex-round-trip
  ;:  weld
    (expect-eq !>(`pt-gen) !>((hex-to-pt (pt-to-hex pt-gen))))
    ::  odd y takes the 03 prefix and comes back odd
    (expect-eq !>(`(pt-neg pt-gen)) !>((hex-to-pt (pt-to-hex (pt-neg pt-gen)))))
    (expect-eq !>('03') !>((end [3 2] (pt-to-hex (pt-neg pt-gen)))))
    ::  hex is read case-insensitively
    (expect-eq !>(`pt-gen) !>((hex-to-pt '0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798')))
  ==
::
++  test-hex-to-pt-refuses
  =/  gx  '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
  ;:  weld
    ::  uncompressed and unknown prefixes
    (expect-eq !>(~) !>((hex-to-pt (cat 3 '04' gx))))
    (expect-eq !>(~) !>((hex-to-pt (cat 3 '05' gx))))
    ::  one character short, one long
    (expect-eq !>(~) !>((hex-to-pt (cat 3 '02' (end [3 63] gx)))))
    (expect-eq !>(~) !>((hex-to-pt (cat 3 '02' (cat 3 gx '0')))))
    ::  not hex
    (expect-eq !>(~) !>((hex-to-pt (cat 3 '02' (cat 3 (end [3 63] gx) 'g')))))
    ::  x >= p
    (expect-eq !>(~) !>((hex-to-pt (cat 3 '02' (pad-hex secp-p 64)))))
    ::  x = 5 has no curve point (5^3 + 7 is not a square mod p)
    (expect-eq !>(~) !>((hex-to-pt (cat 3 '02' (pad-hex 5 64)))))
  ==
::
++  test-lift-x-picks-the-parity
  ;:  weld
    (expect-eq !>(`pt-gen) !>((lift-x secp-gx &)))
    (expect-eq !>(`(pt-neg pt-gen)) !>((lift-x secp-gx |)))
    (expect-eq !>(~) !>((lift-x secp-p &)))
  ==
::
::  x = 1 is on the curve, so p + 1 would name the same point: an x at or
::  over p is refused, never reduced
++  test-lift-x-refuses-non-canonical-x
  ;:  weld
    (expect-eq !>(&) !>(!=(~ (lift-x 1 &))))
    (expect-eq !>(~) !>((lift-x +(secp-p) &)))
  ==
::
::  the characters just outside each hex range are not hex
++  test-is-hex-edges
  ;:  weld
    (expect-eq !>(&) !>((is-hex '09afAF')))
    (expect-eq !>(|) !>((is-hex '/')))
    (expect-eq !>(|) !>((is-hex ':')))
    (expect-eq !>(|) !>((is-hex '@')))
    (expect-eq !>(|) !>((is-hex 'G')))
    (expect-eq !>(|) !>((is-hex '`')))
    (expect-eq !>(|) !>((is-hex 'g')))
  ==
::
::  hex-decode is total: a non-hex character reads as 0, never a crash
::  or a wrong nibble
++  test-hex-decode-is-total
  ;:  weld
    (expect-eq !>(0xa0f) !>((hex-decode 'a0F')))
    (expect-eq !>(0) !>((hex-decode '/')))
    (expect-eq !>(0) !>((hex-decode 'g')))
    (expect-eq !>(0) !>((hex-decode '@')))
  ==
::
::  fixed width keeps a value's leading zero bytes
++  test-pad-hex-keeps-leading-zeros
  ;:  weld
    (expect-eq !>('0000000000000001') !>((pad-hex 1 16)))
    (expect-eq !>(64) !>((met 3 (scalar-to-hex 0xff))))
  ==
--
