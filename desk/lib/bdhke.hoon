::  /lib/bdhke/hoon
::  Blind Diffie-Hellman Key Exchange for Cashu NUT-00, DLEQ proofs
::  (NUT-12) and BIP-340 verification (NUT-11), on lib/curve.hoon.
::
/+  *curve
|%
::
::  -- Hash-to-Curve -----------------------------------------
::
::  Cashu NUT-00:
::   1. msg_hash = SHA256("Secp256k1_HashToCurve_Cashu_" || message)
::   2. x = SHA256(msg_hash || counter as 4 little-endian bytes), big-endian
::   3. the point 02||x if it is on the curve, else counter+1 and retry
::  shay (explicit-length SHA256) keeps trailing zero bytes; rev turns
::  the little-endian digest atom into the big-endian x.
++  hash-to-curve
  |=  msg=@  ^-  point
  =/  domain-sep  'Secp256k1_HashToCurve_Cashu_'
  =/  dlen  (met 3 domain-sep)
  =/  mlen  (met 3 msg)
  =/  msg-hash  (shay (add dlen mlen) (can 3 ~[[dlen domain-sep] [mlen msg]]))
  =/  counter=@  0
  |-  ^-  point
  =/  h  (rev 3 32 (shay 36 (can 3 ~[[32 msg-hash] [4 counter]])))
  =/  pt  (lift-x h &)
  ?^  pt  u.pt
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
  =/  [b-prime=point blinding-factor=@]
    (blind-message secret (shax (cat 3 eny 'blind')))
  [(pt-to-hex b-prime) secret blinding-factor]
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
::  has-dup-x: do two B_ in a batch share an x-coordinate? That is the
::  B_/-B_ DLEQ nonce-reuse attack shape (same x, negated y). Malformed or
::  missing B_ are skipped here; callers reject them on their own.
++  has-dup-x
  |=  outputs=(list json)
  ^-  ?
  =|  seen=(set @)
  |-  ^-  ?
  ?~  outputs  %.n
  =/  msg  i.outputs
  ?.  ?=([%o *] msg)  $(outputs t.outputs)
  =/  b  (~(get by p.msg) 'B_')
  ?.  ?=([~ %s *] b)  $(outputs t.outputs)
  =/  mb  (hex-to-pt p.u.b)
  ?~  mb  $(outputs t.outputs)
  ?:  (~(has in seen) x.u.mb)  %.y
  $(outputs t.outputs, seen (~(put in seen) x.u.mb))
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
::    big-a is the mint's public key a*G for this denomination. The caller
::    already has it, and recomputing it here was a quarter of the work
::    of signing an output.
::
++  dleq-prove
  |=  [b-=point c-=point a=@ big-a=point rng=@]
  ^-  [e=@ s=@]
  ::  Bind the nonce to the FULL uncompressed encodings of both B_ and C_
  ::  (not just x.b-). -B_ negates y, and C_=a*B_ negates with it, so the
  ::  nonce differs for B_ vs -B_ even when rng is identical. This closes
  ::  the DLEQ nonce-reuse key-recovery attack.
  =/  bh=@t  (uncomp-hex b-)
  =/  ch=@t  (uncomp-hex c-)
  =/  r-raw
    %-  shax
    %+  can  3
    :~  [32 a]
        [(met 3 bh) bh]
        [(met 3 ch) ch]
        [32 rng]
    ==
  =/  r  (mod r-raw secp-n)
  =.  r  ?:(=(0 r) 1 r)
  =/  r1  (pt-mul r pt-gen)
  =/  r2  (pt-mul r b-)
  =/  e  (hash-e ~[r1 r2 big-a c-])
  =/  s  (sadd r (smul a (mod e secp-n)))
  [e s]
::
::  Verify a DLEQ proof (NUT-12): R1 = s*G - e*A, R2 = s*B_ - e*C_.
::  Total: out-of-range e or s, or an R at infinity, is %.n, not a crash.
++  dleq-verify
  |=  [b-=point c-=point a-pub=point e=@ s=@]
  ^-  ?
  =/  em  (mod e secp-n)
  ?:  |(=(0 em) =(0 s) (gte s secp-n))  %.n
  =/  sg  (pt-mul s pt-gen)
  =/  ea  (pt-mul em a-pub)
  =/  sb  (pt-mul s b-)
  =/  ec  (pt-mul em c-)
  ?:  |(=(sg ea) =(sb ec))  %.n
  =/  r1-p  (pt-add sg (pt-neg ea))
  =/  r2-p  (pt-add sb (pt-neg ec))
  =(e (hash-e ~[r1-p r2-p a-pub c-]))
::
::  -- BIP-340 Schnorr Signature Verification (NUT-11) ----------
::
::  schnorr-verify: pub is a compressed key (its x is the BIP-340 key),
::  msg the 32-byte message as shax gives it, sig 128 hex digits. Runs
::  zuse's verify, which vere jets (%sove); zuse reads all three as
::  big-endian integers.
++  schnorr-verify
  |=  [pub=@t msg=@ sig=@t]
  ^-  ?
  =/  p  (hex-to-pt pub)
  ?~  p  %.n
  ?.  &(=(128 (met 3 sig)) (is-hex sig))  %.n
  (verify:schnorr:secp256k1:secp:crypto x.u.p (rev 3 32 msg) (hex-decode sig))
--
