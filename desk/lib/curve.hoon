::  /lib/curve/hoon
::  secp256k1 — hybrid: jetted pubkey gen from zuse + pure Hoon BDHKE ops
::
::  Key generation uses priv-to-pub:secp256k1:secp:crypto (jetted in vere).
::  BDHKE scalar mults (blind-sign, hash-to-curve) use pure Hoon double-and-add.
::
|%
::  -- Constants (computed at runtime) --
++  secp-p  (sub (bex 256) (add (bex 32) 977))
++  secp-n
  =/  n0  (lsh [0 240] 0xffff)
  =/  n1  (lsh [0 224] 0xffff)
  =/  n2  (lsh [0 208] 0xffff)
  =/  n3  (lsh [0 192] 0xffff)
  =/  n4  (lsh [0 176] 0xffff)
  =/  n5  (lsh [0 160] 0xffff)
  =/  n6  (lsh [0 144] 0xffff)
  =/  n7  (lsh [0 128] 0xfffe)
  =/  n8  (lsh [0 112] 0xbaae)
  =/  n9  (lsh [0 96] 0xdce6)
  =/  n10  (lsh [0 80] 0xaf48)
  =/  n11  (lsh [0 64] 0xa03b)
  =/  n12  (lsh [0 48] 0xbfd2)
  =/  n13  (lsh [0 32] 0x5e8c)
  =/  n14  (lsh [0 16] 0xd036)
  =/  n15  0x4141
  (add n0 (add n1 (add n2 (add n3 (add n4 (add n5 (add n6 (add n7 (add n8 (add n9 (add n10 (add n11 (add n12 (add n13 (add n14 n15)))))))))))))))
++  secp-gx
  =/  g0  (lsh [0 240] 0x79be)
  =/  g1  (lsh [0 224] 0x667e)
  =/  g2  (lsh [0 208] 0xf9dc)
  =/  g3  (lsh [0 192] 0xbbac)
  =/  g4  (lsh [0 176] 0x55a0)
  =/  g5  (lsh [0 160] 0x6295)
  =/  g6  (lsh [0 144] 0xce87)
  =/  g7  (lsh [0 128] 0xb07)
  =/  g8  (lsh [0 112] 0x29b)
  =/  g9  (lsh [0 96] 0xfcdb)
  =/  g10  (lsh [0 80] 0x2dce)
  =/  g11  (lsh [0 64] 0x28d9)
  =/  g12  (lsh [0 48] 0x59f2)
  =/  g13  (lsh [0 32] 0x815b)
  =/  g14  (lsh [0 16] 0x16f8)
  =/  g15  0x1798
  (add g0 (add g1 (add g2 (add g3 (add g4 (add g5 (add g6 (add g7 (add g8 (add g9 (add g10 (add g11 (add g12 (add g13 (add g14 g15)))))))))))))))
++  secp-gy
  =/  y0  (lsh [0 240] 0x483a)
  =/  y1  (lsh [0 224] 0xda77)
  =/  y2  (lsh [0 208] 0x26a3)
  =/  y3  (lsh [0 192] 0xc465)
  =/  y4  (lsh [0 176] 0x5da4)
  =/  y5  (lsh [0 160] 0xfbfc)
  =/  y6  (lsh [0 144] 0xe11)
  =/  y7  (lsh [0 128] 0x8a8)
  =/  y8  (lsh [0 112] 0xfd17)
  =/  y9  (lsh [0 96] 0xb448)
  =/  y10  (lsh [0 80] 0xa685)
  =/  y11  (lsh [0 64] 0x5419)
  =/  y12  (lsh [0 48] 0x9c47)
  =/  y13  (lsh [0 32] 0xd08f)
  =/  y14  (lsh [0 16] 0xfb10)
  =/  y15  0xd4b8
  (add y0 (add y1 (add y2 (add y3 (add y4 (add y5 (add y6 (add y7 (add y8 (add y9 (add y10 (add y11 (add y12 (add y13 (add y14 y15)))))))))))))))
::
::  -- Types --
+$  point  [x=@ y=@]
+$  mpoint  (unit point)
::  jpoint: a Jacobian point representing affine (x/z^2, y/z^3); z=0 is infinity
+$  jpoint  [x=@ y=@ z=@]
::
::  -- Field arithmetic (mod secp-p) --
++  powmod
  |=  [base=@ exp=@ m=@]
  ^-  @
  ?:  =(1 m)  0
  =/  r  1
  =/  b  (mod base m)
  |-  ^-  @
  ?:  =(0 exp)  r
  ?:  =((mod exp 2) 1)
    %=  $  r  (mod (mul r b) m)  exp  (div exp 2)  b  (mod (mul b b) m)  ==
  %=  $  exp  (div exp 2)  b  (mod (mul b b) m)  ==
++  fadd
  |=  [a=@ b=@]  ^-  @
  (mod (add a b) secp-p)
++  fsub
  |=  [a=@ b=@]  ^-  @
  (mod (add a (sub secp-p (mod b secp-p))) secp-p)
++  fmul
  |=  [a=@ b=@]  ^-  @
  (mod (mul a b) secp-p)
++  finv
  |=  a=@  ^-  @
  (powmod a (sub secp-p 2) secp-p)
++  fdiv
  |=  [a=@ b=@]  ^-  @
  (fmul a (finv b))
::  -- Scalar arithmetic (mod secp-n) --
++  sadd
  |=  [a=@ b=@]  ^-  @
  (mod (add a b) secp-n)
++  ssub
  |=  [a=@ b=@]  ^-  @
  (mod (add a (sub secp-n (mod b secp-n))) secp-n)
++  smul
  |=  [a=@ b=@]  ^-  @
  (mod (mul a b) secp-n)
++  sinv
  |=  a=@  ^-  @
  (powmod a (sub secp-n 2) secp-n)
::
::  -- Point operations (pure Hoon, for BDHKE) --
++  pt-gen  ^-  point  [secp-gx secp-gy]
++  pt-neg
  |=  p=point  ^-  point
  [x.p (fsub 0 y.p)]
++  pt-add
  |=  [p=point q=point]  ^-  point
  ?:  =(x.p x.q)
    ?:  =(y.p y.q)  (pt-dbl p)
    ::  P + (-P) is the point at infinity; secp doesn't model it, so crash
    ::  loudly — any caller that relies on the old silent pt-gen fallback
    ::  was masking a bug.
    ~|  %pt-add-point-at-infinity
    !!
  =/  lam  (fdiv (fsub y.q y.p) (fsub x.q x.p))
  =/  x3   (fsub (fsub (fmul lam lam) x.p) x.q)
  [x3 (fsub (fmul lam (fsub x.p x3)) y.p)]
++  pt-dbl
  |=  p=point  ^-  point
  ?:  =(0 y.p)
    ::  2*P where y=0: the doubled point is the point at infinity. crash
    ::  rather than silently returning a meaningless generator point.
    ~|  %pt-dbl-point-at-infinity
    !!
  =/  lam  (fdiv (fmul 3 (fmul x.p x.p)) (fmul 2 y.p))
  =/  x3   (fsub (fsub (fmul lam lam) x.p) x.p)
  [x3 (fsub (fmul lam (fsub x.p x3)) y.p)]
::  -- Jacobian coordinates (defer the per-op modular inverse in scalar mult) --
::    pt-mul does its double-and-add in Jacobian (no inverses), then converts
::    back to affine with a single inverse — vs one inverse per affine pt-add/
::    pt-dbl before. Formulas: dbl-2009-l and add-2007-bl (a=0).
++  jac-inf  ^-  jpoint  [1 1 0]
++  jac-dbl
  |=  j=jpoint  ^-  jpoint
  ?:  =(0 z.j)  j
  ?:  =(0 y.j)  jac-inf
  =/  aa  (fmul x.j x.j)
  =/  bb  (fmul y.j y.j)
  =/  cc  (fmul bb bb)
  =/  xb  (fadd x.j bb)
  =/  dd  (fmul 2 (fsub (fsub (fmul xb xb) aa) cc))
  =/  ee  (fmul 3 aa)
  =/  ff  (fmul ee ee)
  =/  x3  (fsub ff (fmul 2 dd))
  =/  y3  (fsub (fmul ee (fsub dd x3)) (fmul 8 cc))
  =/  z3  (fmul 2 (fmul y.j z.j))
  [x3 y3 z3]
++  jac-add
  |=  [j1=jpoint j2=jpoint]  ^-  jpoint
  ?:  =(0 z.j1)  j2
  ?:  =(0 z.j2)  j1
  =/  z1z1  (fmul z.j1 z.j1)
  =/  z2z2  (fmul z.j2 z.j2)
  =/  u1  (fmul x.j1 z2z2)
  =/  u2  (fmul x.j2 z1z1)
  =/  s1  (fmul y.j1 (fmul z.j2 z2z2))
  =/  s2  (fmul y.j2 (fmul z.j1 z1z1))
  ?:  =(u1 u2)
    ?:  =(s1 s2)  (jac-dbl j1)
    jac-inf
  =/  hh  (fsub u2 u1)
  =/  ii  (fmul (fmul 2 hh) (fmul 2 hh))
  =/  jj  (fmul hh ii)
  =/  rr  (fmul 2 (fsub s2 s1))
  =/  vv  (fmul u1 ii)
  =/  x3  (fsub (fsub (fmul rr rr) jj) (fmul 2 vv))
  =/  y3  (fsub (fmul rr (fsub vv x3)) (fmul 2 (fmul s1 jj)))
  =/  zz  (fadd z.j1 z.j2)
  =/  z3  (fmul (fsub (fsub (fmul zz zz) z1z1) z2z2) hh)
  [x3 y3 z3]
++  jac-to-affine
  |=  j=jpoint  ^-  point
  ?:  =(0 z.j)  ~|(%jac-to-affine-infinity !!)
  =/  zi   (finv z.j)
  =/  zi2  (fmul zi zi)
  =/  zi3  (fmul zi2 zi)
  [(fmul x.j zi2) (fmul y.j zi3)]
++  pt-mul
  |=  [k=@ p=point]  ^-  point
  ?>  !=(0 k)
  ::  k * G: jetted priv-to-pub (fast). k * P: constant-time Montgomery ladder
  ::  in Jacobian coords (one modular inverse total, at the final to-affine).
  ?:  =(p pt-gen)
    (priv-to-pub:secp256k1:secp:crypto k)
  ::  Left-to-right Montgomery ladder: iterate a FIXED 256 bit positions (widened
  ::  only if k somehow exceeds 256 bits, which never happens for real scalars
  ::  < secp-n; the widening only preserves identical output for pathological k).
  ::  Invariant maintained every step: r1 = r0 + base. Each iteration does exactly
  ::  one jac-add and one jac-dbl regardless of the bit value, so the work and the
  ::  loop count depend only on the fixed width, not on the secret scalar's bits.
  ::  Leading zero bits (k < 2^256) keep r0 = infinity, r1 = base, since jac-add
  ::  treats jac-inf as the identity and jac-dbl leaves infinity unchanged.
  =/  base=jpoint  [x.p y.p 1]
  =/  nbits=@      (max 256 (met 0 k))
  =/  r0=jpoint    jac-inf
  =/  r1=jpoint    base
  =/  i=@          nbits
  |-  ^-  point
  ?:  =(0 i)  (jac-to-affine r0)
  =/  bit=@  (cut 0 [(dec i) 1] k)
  ?:  =(0 bit)
    %=  $
      i   (dec i)
      r1  (jac-add r0 r1)
      r0  (jac-dbl r0)
    ==
  %=  $
    i   (dec i)
    r0  (jac-add r0 r1)
    r1  (jac-dbl r1)
  ==
::
::  -- Public key (jetted via zuse for k*G, fast) --
++  pubkey
  |=  priv=@  ^-  point
  (priv-to-pub:secp256k1:secp:crypto priv)
::
::  -- Point compression (zuse uses atom encoding) --
++  pt-compress
  |=  p=point  ^-  @
  ::  zuse compress-point: [32 x.p] [1 (add 2 parity)] little-endian
  (compress-point:secp256k1:secp:crypto p)
::
::  -- Hex encoding --
++  pad-hex
  |=  [n=@ chars=@]  ^-  @t
  =/  raw     (trip (scot %ux n))
  =/  nodots  (skim (slag 2 raw) |=(c=@ !=(c '.')))
  =/  cur     (lent nodots)
  =/  need    (sub chars cur)
  (crip (weld (reap need '0') nodots))
++  is-hex-char
  |=  c=@  ^-  ?
  ?|  &((gte c '0') (lte c '9'))
      &((gte c 'A') (lte c 'F'))
      &((gte c 'a') (lte c 'f'))
  ==
++  is-hex
  |=  hex=@t  ^-  ?
  (levy (trip hex) is-hex-char)
++  hex-decode
  |=  hex=@t  ^-  @
  %+  roll  (trip hex)
  |=  [c=@ acc=@]
  ::  total: non-hex chars decode to nibble 0 (never underflow/crash);
  ::  callers gate untrusted input with is-hex / hex-to-pt up front.
  =/  nib
    ?:  &((gte c '0') (lte c '9'))  (sub c '0')
    ?:  &((gte c 'A') (lte c 'F'))  (add 10 (sub c 'A'))
    ?:  &((gte c 'a') (lte c 'f'))  (add 10 (sub c 'a'))
    0
  (add (mul acc 16) nib)
++  pt-to-hex
  |=  p=point  ^-  @t
  =/  prefix  ?:(=(0 (mod y.p 2)) '02' '03')
  (crip (weld (trip prefix) (trip (pad-hex x.p 64))))
++  hex-to-pt
  |=  hex=@t  ^-  mpoint
  ?.  =(66 (lent (trip hex)))  ~
  =/  chars    (trip hex)
  =/  prefix   (crip (scag 2 chars))
  ?.  |(=(prefix '02') =(prefix '03'))  ~
  =/  x-hex    (crip (slag 2 chars))
  ?.  (is-hex x-hex)  ~
  =/  x        (hex-decode x-hex)
  ?.  (lth x secp-p)  ~
  =/  y2   (fadd (fmul (fmul x x) x) 7)
  =/  y1   (powmod y2 (div (add secp-p 1) 4) secp-p)
  ?.  =(y2 (mod (mul y1 y1) secp-p))  ~
  =/  want-even  =(prefix '02')
  =/  y  ?:(=(want-even =(0 (mod y1 2))) y1 (fsub 0 y1))
  `[x y]
++  scalar-to-hex
  |=  s=@  ^-  @t
  (pad-hex s 64)
--
