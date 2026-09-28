::  tests for /lib/bdhke: hash-to-curve, BDHKE, DLEQ, BIP-340
::
/+  *test, *bdhke, *curve
|%
::  a NUT-00 message: 32 bytes, big-endian, as the atom hash-to-curve reads
++  msg32  |=(n=@ `@`(rev 3 32 n))
::
::  NUT-00's published vectors for 0x00..01 and 0x00..02. (0x00..00 can't
::  be written: an atom has no trailing zero bytes, and secrets reach the
::  mint as JSON strings, which never end in NUL.)
++  test-hash-to-curve-nut00-vectors
  ;:  weld
    %+  expect-eq
      !>('022e7158e11c9506f1aa4248bf531298daa7febd6194f003edcd9b93ade6253acf')
    !>((pt-to-hex (hash-to-curve (msg32 1))))
    %+  expect-eq
      !>('026cdbe15362df59cd1dd3c9c11de8aedac2106eca69236ecd9fbe117af897be4f')
    !>((pt-to-hex (hash-to-curve (msg32 2))))
  ==
::
::  blind, sign, unblind: C = a*hash_to_curve(secret), which is what the
::  mint checks when the token comes back
++  test-bdhke-round-trip
  =/  a  42
  =/  y  (hash-to-curve 'test-secret')
  =/  bf  (blind-message 'test-secret' 7)
  =/  c-  (blind-sign b-prime.bf a)
  =/  c  (unblind-signature c- blinding-factor.bf (pubkey a))
  (expect-eq !>((pt-mul a y)) !>(c))
::
++  test-dleq-proves-and-verifies
  =/  a  42
  =/  b-  (pt-add (hash-to-curve 'dleq') (pt-mul 7 pt-gen))
  =/  c-  (blind-sign b- a)
  =/  pf  (dleq-prove b- c- a (pubkey a) 99)
  ;:  weld
    (expect-eq !>(&) !>((dleq-verify b- c- (pubkey a) e.pf s.pf)))
    ::  under another key, or for another C_, it fails
    (expect-eq !>(|) !>((dleq-verify b- c- (pubkey 43) e.pf s.pf)))
    (expect-eq !>(|) !>((dleq-verify b- (pt-mul 2 c-) (pubkey a) e.pf s.pf)))
  ==
::
::  the wallet's r is the blinding factor (reduced mod n, 0 made 1):
::  B_ = Y + r*G
++  test-blind-message-uses-r
  =/  y  (hash-to-curve 's')
  ;:  weld
    (expect-eq !>([(pt-add y (pt-mul 7 pt-gen)) 7]) !>((blind-message 's' 7)))
    (expect-eq !>(7) !>(blinding-factor:(blind-message 's' (add secp-n 7))))
    (expect-eq !>(1) !>(blinding-factor:(blind-message 's' secp-n)))
  ==
::
::  the nonce comes from the entropy: one B_ under two rngs gets two
::  proofs. A fixed nonce would give the key away from two signatures.
++  test-dleq-nonce-follows-the-entropy
  =/  a  42
  =/  b-  (pt-add (hash-to-curve 'dleq') (pt-mul 7 pt-gen))
  =/  c-  (blind-sign b- a)
  =/  p1  (dleq-prove b- c- a (pubkey a) 99)
  =/  p2  (dleq-prove b- c- a (pubkey a) 100)
  (expect-eq !>(|) !>(=(e.p1 e.p2)))
::
::  B_ and -B_ get different nonces from the same rng (the nonce-reuse
::  attack needs them equal)
++  test-dleq-nonce-binds-the-full-point
  =/  a  42
  =/  b-  (pt-add (hash-to-curve 'dleq') (pt-mul 7 pt-gen))
  =/  nb  (pt-neg b-)
  =/  p1  (dleq-prove b- (blind-sign b- a) a (pubkey a) 99)
  =/  p2  (dleq-prove nb (blind-sign nb a) a (pubkey a) 99)
  (expect-eq !>(|) !>(=(e.p1 e.p2)))
::
::  a wallet checking a hostile mint's proof gets %.n, never a crash
++  test-dleq-verify-is-total
  =/  b-  (hash-to-curve 'x')
  =/  c-  (blind-sign b- 5)
  ;:  weld
    (expect-eq !>(|) !>((dleq-verify b- c- (pubkey 5) 1 0)))
    (expect-eq !>(|) !>((dleq-verify b- c- (pubkey 5) 1 secp-n)))
    (expect-eq !>(|) !>((dleq-verify b- c- (pubkey 5) secp-n 1)))
    ::  s*G = e*A alone (a forged C_ keeps s*B_ - e*C_ finite), and
    ::  s*B_ = e*C_ alone (the wrong A): either would crash pt-add
    (expect-eq !>(|) !>((dleq-verify b- (blind-sign b- 6) (pubkey 5) 3 15)))
    (expect-eq !>(|) !>((dleq-verify b- c- (pubkey 6) 3 15)))
  ==
::
::  BIP-340 test vectors 0 and 1 (checked against noble), pubkeys given
::  as compressed hex the way P2PK secrets carry them
++  test-schnorr-bip340-vectors
  =/  pk0  '02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9'
  =/  sig0  'e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0'
  =/  pk1  '02dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659'
  =/  msg1  (rev 3 32 0x243f.6a88.85a3.08d3.1319.8a2e.0370.7344.a409.3822.299f.31d0.082e.fa98.ec4e.6c89)
  =/  sig1  '6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a'
  ;:  weld
    (expect-eq !>(&) !>((schnorr-verify pk0 0 sig0)))
    (expect-eq !>(&) !>((schnorr-verify pk1 msg1 sig1)))
    ::  x-only: the 03 twin of a key verifies the same signature
    (expect-eq !>(&) !>((schnorr-verify (cat 3 '03' (rsh [3 2] pk0)) 0 sig0)))
    ::  another message, another key
    (expect-eq !>(|) !>((schnorr-verify pk0 1 sig0)))
    (expect-eq !>(|) !>((schnorr-verify pk1 0 sig0)))
  ==
::
++  test-schnorr-refuses-malformed
  =/  pk0  '02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9'
  =/  sig0  'e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0'
  ;:  weld
    ::  one hex digit short, one leading zero long (the same number), and
    ::  a non-hex digit (hex-decode would read 0)
    (expect-eq !>(|) !>((schnorr-verify pk0 0 (end [3 127] sig0))))
    (expect-eq !>(|) !>((schnorr-verify pk0 0 (cat 3 '0' sig0))))
    (expect-eq !>(|) !>((schnorr-verify pk0 0 (cat 3 (end [3 127] sig0) 'z'))))
    ::  a key that isn't a point
    (expect-eq !>(|) !>((schnorr-verify (cat 3 '02' (pad-hex 5 64)) 0 sig0)))
  ==
::
++  test-has-dup-x
  =/  b  (pt-add (hash-to-curve 'dup') (pt-mul 3 pt-gen))
  =/  out  |=(p=point `json`(pairs:enjs:format ['B_' s+(pt-to-hex p)]~))
  ;:  weld
    ::  B_ and -B_ share x
    (expect-eq !>(&) !>((has-dup-x ~[(out b) (out (pt-neg b))])))
    (expect-eq !>(&) !>((has-dup-x ~[(out b) (out b)])))
    (expect-eq !>(|) !>((has-dup-x ~[(out b) (out (pt-mul 2 b))])))
    ::  malformed entries are skipped, not counted
    (expect-eq !>(|) !>((has-dup-x `(list json)`~[~ s+'x' (out b) (pairs:enjs:format ['B_' s+'zz']~)])))
  ==
::
++  test-split-amount
  ;:  weld
    (expect-eq !>(`(list @ud)`~[8 4 1]) !>((split-amount 13)))
    (expect-eq !>(`(list @ud)`~) !>((split-amount 0)))
    (expect-eq !>(`(list @ud)`~[1.024]) !>((split-amount 1.024)))
  ==
--
