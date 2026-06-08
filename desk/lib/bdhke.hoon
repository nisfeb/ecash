::  /lib/bdhke/hoon
::  Blind Diffie-Hellman Key Exchange for Cashu NUT-00
::  Uses secp256k1 from zuse (jetted) via lib/curve.hoon
::
/+  *curve
|%
::
::  -- Hash-to-Curve -----------------------------------------
::
::  Cashu NUT-00 spec: find a valid curve point from a message.
::  Tries SHA256("Secp256k1_HashToCurve_" || SHA256(msg) || counter)
::  as x-coordinate (prefix 0x02) until a valid point is found.
::
++  hash-to-curve
  ::  hash-to-curve: maps a secret to a secp256k1 point deterministically.
  ::  Cashu NUT-00 standard algorithm:
  ::   1. msg_hash = SHA256(DOMAIN_SEPARATOR || message)
  ::   2. x = SHA256(msg_hash || counter_LE_4bytes) as BE integer
  ::   3. Try compressed point 02||x; increment counter if invalid
  ::  Uses shay (explicit-length SHA256) to preserve trailing zero bytes
  ::  and rev to convert LE atom to standard BE x-coordinate.
  |=  msg=@  ^-  point
  =/  domain-sep  'Secp256k1_HashToCurve_Cashu_'
  =/  dlen  (met 3 domain-sep)
  =/  mlen  (met 3 msg)
  ::  Step 1: msg-hash = SHA256(domain-sep || msg)
  =/  step1  (can 3 ~[[dlen domain-sep] [mlen msg]])
  =/  msg-hash  (shay (add dlen mlen) step1)
  =/  counter=@  0
  |-  ^-  point
  ::  Step 2: h = SHA256(msg-hash || counter_LE)
  =/  step2  (can 3 ~[[32 (add (bex 256) msg-hash)] [4 (add (bex 32) counter)]])
  =/  h  (rev 3 32 (shay 36 step2))
  =/  maybe-pt  (hex-to-pt (crip (weld "02" (trip (pad-hex h 64)))))
  ?^  maybe-pt  u.maybe-pt
  $(counter +(counter))
::
::  -- BDHKE Core --------------------------------------------
::
::  Wallet blinds: B_ = Y + r*G (additive blinding per Cashu NUT-00)
::  Returns [B_ blinding-factor] where r is reduced mod n
++  blind-message
  |=  [secret=@t r=@]
  ^-  [b-prime=point blinding-factor=@]
  =/  r-mod=@  (mod r secp-n)
  =?  r-mod  =(0 r-mod)  1
  =/  yy  (hash-to-curve secret)
  =/  r-g  (pt-mul r-mod pt-gen)
  =/  b-prime  (pt-add yy r-g)
  [b-prime r-mod]
::
::  Mint blind-signs: C_ = privkey x B_
++  blind-sign
  |=  [b-=point a=@]  ^-  point
  (pt-mul a b-)
::
::  Wallet unblinds: C = C_ - r*K (additive unblinding per Cashu NUT-00)
::  C_ = blinded signature, r = blinding factor, K = mint pubkey for denom
++  unblind-signature
  |=  [c-=point r=@ mint-key=point]
  ^-  point
  =/  r-k  (pt-mul r mint-key)
  (pt-add c- (pt-neg r-k))
::
::  -- Wallet helpers ------------------------------------------
::
::  Build a single blinded output for swap/mint
::  Returns [B_hex secret blinding-factor]
++  make-output
  |=  [amount=@ud keyset-id=@t eny=@]
  ^-  [b-hex=@t secret=@t blinding-factor=@]
  =/  secret=@t  (pad-hex (shax eny) 64)
  =/  r=@  (shax (cat 3 eny 'blind'))
  =/  [b-prime=point blinding-factor=@]  (blind-message secret r)
  =/  b-hex=@t  (pt-to-hex b-prime)
  =/  check  (mule |.((hex-to-pt b-hex)))
  ?.  ?=([%& *] check)
    $(eny (shax (cat 3 eny 'retry')))
  [b-hex secret blinding-factor]
::
::  Split amount into powers of 2 (standard Cashu denominations)
++  split-amount
  |=  total=@ud
  ^-  (list @ud)
  ?:  =(0 total)  ~
  =/  acc=(list @ud)  ~
  =/  bit=@ud  0
  |-
  ?:  (gte (bex bit) (mul 2 total))
    acc
  ?:  =((mod (div total (bex bit)) 2) 1)
    $(bit +(bit), acc [(bex bit) acc])
  $(bit +(bit))
::
::  -- DLEQ Proof --------------------------------------------
::
::  Prove C_ = axB_ (same scalar a as in A = axG), without revealing a.
::  Fiat-Shamir sigma protocol.
::
::  uncomp-hex: a point as NUT-12/cashu-ts uncompressed hex (04 || x || y).
::
++  uncomp-hex
  |=  p=point
  ^-  @t
  (crip :(weld "04" (trip (pad-hex x.p 64)) (trip (pad-hex y.p 64))))
::  hash-e: NUT-12 challenge. SHA256 over the ASCII concatenation of the four
::  points' uncompressed hex; big-endian digest, sent raw (not reduced mod n).
::
++  hash-e
  |=  pts=(list point)
  ^-  @
  =/  msg=@t  (crip (zing (turn pts |=(p=point (trip (uncomp-hex p))))))
  (rev 3 32 (shax msg))
::  dleq-prove (NUT-12): e = hash-e(R1, R2, A, C_); s = r + a*e (mod n).
::
++  dleq-prove
  |=  [b-=point c-=point a=@ rng=@]
  ^-  [e=@ s=@]
  ::  Bind the nonce to the FULL uncompressed encodings of both B_ and C_
  ::  (not just x.b-). -B_ negates y, and C_=a*B_ negates with it, so the
  ::  nonce differs for B_ vs -B_ even when rng is identical. This closes
  ::  the DLEQ nonce-reuse key-recovery attack. Still deterministic; still
  ::  mixes rng. e/s semantics and dleq-verify are unchanged.
  =/  bh=@t  (uncomp-hex b-)
  =/  ch=@t  (uncomp-hex c-)
  =/  r-raw
    %-  shax
    %+  can  3
    :~  [32 (add (bex 256) a)]
        [(met 3 bh) bh]
        [(met 3 ch) ch]
        [32 (add (bex 256) rng)]
    ==
  =/  r  (mod r-raw secp-n)
  =.  r  ?:(=(0 r) 1 r)
  =/  big-a   (pt-mul a pt-gen)
  =/  r1      (pt-mul r pt-gen)
  =/  r2      (pt-mul r b-)
  =/  e  (hash-e ~[r1 r2 big-a c-])
  =/  s  (sadd r (smul a (mod e secp-n)))
  [e s]
::
::  Verify a DLEQ proof (NUT-12): R1 = s*G - e*A, R2 = s*B_ - e*C_.
++  dleq-verify
  |=  [b-=point c-=point a-pub=point e=@ s=@]
  ^-  ?
  =/  em  (mod e secp-n)
  =/  r1-p  (pt-add (pt-mul s pt-gen) (pt-neg (pt-mul em a-pub)))
  =/  r2-p  (pt-add (pt-mul s b-) (pt-neg (pt-mul em c-)))
  =(e (hash-e ~[r1-p r2-p a-pub c-]))
::
::  -- BIP-340 Schnorr Signature Verification (NUT-11) ----------
::
++  schnorr-verify
  |=  [pub=@t msg=@ sig=@t]
  ^-  ?
  =/  maybe-p  (hex-to-pt pub)
  ?~  maybe-p  %.n
  =/  p=point  u.maybe-p
  =/  pk-x  x.p
  ::  BIP-340: lift to even-y point
  =/  p-even  ?:(=(0 (mod y.p 2)) p (pt-neg p))
  ::  Parse 64-byte sig (128 hex) into r and s
  =/  sig-chars  (trip sig)
  ?.  =(128 (lent sig-chars))  %.n
  =/  r  (hex-decode (crip (scag 64 sig-chars)))
  =/  s  (hex-decode (crip (slag 64 sig-chars)))
  ?.  (lth r secp-p)  %.n
  ?.  (lth s secp-n)  %.n
  ?:  =(0 s)  %.n
  ::  e = tagged_hash("BIP0340/challenge", r || P.x || msg) mod n
  ::  BIP-340: shax/shay LE bytes = standard SHA256 byte order in can payload
  ::  hex-decode integers (r, pk-x) need rev to match standard byte order
  ::  shax outputs (tag-hash, msg) already have correct LE bytes
  =/  tag-hash  (shax 'BIP0340/challenge')
  =/  ch-payload
    %+  can  3
    :~  [32 (add (bex 256) tag-hash)]
        [32 (add (bex 256) tag-hash)]
        [32 (add (bex 256) (rev 3 32 r))]
        [32 (add (bex 256) (rev 3 32 pk-x))]
        [32 (add (bex 256) msg)]
    ==
  =/  e  (mod (rev 3 32 (shay 160 ch-payload)) secp-n)
  ?:  =(0 e)  %.n
  ::  R = s*G - e*P  (s*G uses jetted priv-to-pub)
  =/  sg  (pt-mul s pt-gen)
  =/  ep  (pt-mul e p-even)
  ::  BIP-340: R = s*G - e*P must not be the point at infinity (=> invalid).
  ::  sg + (-ep) is infinity exactly when sg == ep; affine pt-add would crash on
  ::  that mutual-inverse case, so reject it here (return %.n) instead.
  ?:  =(sg ep)  %.n
  =/  r-pt  (pt-add sg (pt-neg ep))
  ::  Verify: R.x == r and R.y is even
  ?.  =(x.r-pt r)  %.n
  =(0 (mod y.r-pt 2))
--
