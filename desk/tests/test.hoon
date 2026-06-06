/+  *test, *bdhke, *curve
|%
++  test-pubkey-1-equals-gen
  ^-  tang
  %+  expect-eq
    !>(pt-gen)
  !>((pubkey 1))
++  test-pt-to-hex-len
  ^-  tang
  %+  expect-eq
    !>(66)
  !>((lent (trip (pt-to-hex pt-gen))))
++  test-bdhke-roundtrip
  ^-  tang
  =/  priv  42
  =/  secret  'test-secret'
  =/  h-pt  (hash-to-curve secret)
  =/  k  7
  ::  Additive blinding: B_ = Y + k*G (Cashu NUT-00)
  =/  b-  (pt-add h-pt (pt-mul k pt-gen))
  =/  c-  (blind-sign b- priv)
  ::  Unblind: C = C_ - k*A where A = priv*G
  =/  mint-pub  (pubkey priv)
  =/  c  (unblind-signature c- k mint-pub)
  =/  expected  (pt-mul priv h-pt)
  %+  expect-eq
    !>(expected)
  !>(c)
++  test-dleq-verify
  ^-  tang
  =/  priv  42
  =/  secret  'test-dleq'
  =/  h-pt  (hash-to-curve secret)
  =/  k  7
  ::  Additive blinding: B_ = Y + k*G
  =/  b-  (pt-add h-pt (pt-mul k pt-gen))
  =/  c-  (blind-sign b- priv)
  =/  a-pub  (pubkey priv)
  =/  rng  99
  =/  es  (dleq-prove b- c- priv rng)
  =/  valid  (dleq-verify b- c- a-pub e.es s.es)
  %+  expect-eq
    !>(%.y)
  !>(valid)
++  test-dleq-rejects-wrong-key
  ^-  tang
  =/  priv  42
  =/  wrong-priv  43
  =/  secret  'test-dleq'
  =/  h-pt  (hash-to-curve secret)
  =/  k  7
  ::  Additive blinding: B_ = Y + k*G
  =/  b-  (pt-add h-pt (pt-mul k pt-gen))
  =/  c-  (blind-sign b- priv)
  =/  wrong-pub  (pubkey wrong-priv)
  =/  rng  99
  =/  es  (dleq-prove b- c- priv rng)
  =/  valid  (dleq-verify b- c- wrong-pub e.es s.es)
  %+  expect-eq
    !>(%.n)
  !>(valid)
++  test-htc-is-valid-point
  ^-  tang
  ::  hash-to-curve should return a valid secp256k1 curve point
  =/  pt  (hash-to-curve 'any-secret')
  =/  y2-check  (fadd (fmul (fmul x.pt x.pt) x.pt) 7)
  =/  y2  (mod (mul y.pt y.pt) secp-p)
  %+  expect-eq
    !>(y2-check)
  !>(y2)
--
