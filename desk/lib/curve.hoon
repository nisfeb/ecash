::  /lib/curve/hoon
::  secp256k1 point arithmetic in pure Hoon, for BDHKE.
::
::    Every scalar multiplication, k*G included, runs the fixed-length
::    Montgomery ladder in +pt-mul. zuse's priv-to-pub is not jetted and
::    its double-and-add leaks the scalar's bit length, so nothing here
::    uses it.
::
|%
::  -- Constants --
++  secp-p  0xffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.fffe.ffff.fc2f
++  secp-n  0xffff.ffff.ffff.ffff.ffff.ffff.ffff.fffe.baae.dce6.af48.a03b.bfd2.5e8c.d036.4141
++  secp-gx  0x79be.667e.f9dc.bbac.55a0.6295.ce87.0b07.029b.fcdb.2dce.28d9.59f2.815b.16f8.1798
++  secp-gy  0x483a.da77.26a3.c465.5da4.fbfc.0e11.08a8.fd17.b448.a685.5419.9c47.d08f.fb10.d4b8
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
++  smul
  |=  [a=@ b=@]  ^-  @
  (mod (mul a b) secp-n)
::
::  -- Point operations (affine) --
++  pt-gen  ^-  point  [secp-gx secp-gy]
++  pt-neg
  |=  p=point  ^-  point
  [x.p (fsub 0 y.p)]
++  pt-add
  |=  [p=point q=point]  ^-  point
  ?:  =(x.p x.q)
    ?:  =(y.p y.q)  (pt-dbl p)
    ::  P + (-P) is the point at infinity, which point can't hold: crash
    ~|  %pt-add-point-at-infinity
    !!
  =/  lam  (fdiv (fsub y.q y.p) (fsub x.q x.p))
  =/  x3   (fsub (fsub (fmul lam lam) x.p) x.q)
  [x3 (fsub (fmul lam (fsub x.p x3)) y.p)]
++  pt-dbl
  |=  p=point  ^-  point
  ?:  =(0 y.p)
    ::  2P with y=0 is the point at infinity: crash
    ~|  %pt-dbl-point-at-infinity
    !!
  =/  lam  (fdiv (fmul 3 (fmul x.p x.p)) (fmul 2 y.p))
  =/  x3   (fsub (fsub (fmul lam lam) x.p) x.p)
  [x3 (fsub (fmul lam (fsub x.p x3)) y.p)]
::  -- Jacobian coordinates (defer the per-op modular inverse in scalar mult) --
::    pt-mul works in Jacobian coordinates (no inverses) and converts back
::    to affine with one inverse. Formulas: dbl-2009-l and add-2007-bl (a=0).
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
::  pt-mul: k*P by a left-to-right Montgomery ladder.
::
::    The ladder runs over kk = k + n, or k + 2n when k + n is still
::    below 2^256 (nP is infinity, so kk*P = k*P). kk always has exactly
::    257 bits with the top one set, so every scalar takes the same 257
::    steps, and the infinity shortcut in jac-add is taken only on the
::    first step, whatever k's leading zeros. Each step does one jac-add
::    and one jac-dbl. Invariant: r1 = r0 + P.
++  pt-mul
  |=  [k=@ p=point]  ^-  point
  =/  k0=@  (mod k secp-n)
  ?>  !=(0 k0)
  =/  kk=@  (add k0 secp-n)
  =?  kk  (lth kk (bex 256))  (add kk secp-n)
  =/  r0=jpoint  jac-inf
  =/  r1=jpoint  [x.p y.p 1]
  =/  i=@  257
  |-  ^-  point
  ?:  =(0 i)  (jac-to-affine r0)
  ?:  =(0 (cut 0 [(dec i) 1] kk))
    $(i (dec i), r1 (jac-add r0 r1), r0 (jac-dbl r0))
  $(i (dec i), r0 (jac-add r0 r1), r1 (jac-dbl r1))
::
::  pubkey: k*G
++  pubkey
  |=  priv=@  ^-  point
  (pt-mul priv pt-gen)
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
::  lift-x: the curve point with this x and the y parity asked for, if any
++  lift-x
  |=  [x=@ even=?]
  ^-  mpoint
  ?.  (lth x secp-p)  ~
  =/  y2  (fadd (fmul (fmul x x) x) 7)
  =/  y1  (powmod y2 (div (add secp-p 1) 4) secp-p)
  ?.  =(y2 (mod (mul y1 y1) secp-p))  ~
  `[x ?:(=(even =(0 (mod y1 2))) y1 (fsub 0 y1))]
++  hex-to-pt
  |=  hex=@t  ^-  mpoint
  =/  chars  (trip hex)
  ?.  =(66 (lent chars))  ~
  =/  prefix  (crip (scag 2 chars))
  ?.  |(=(prefix '02') =(prefix '03'))  ~
  =/  x-hex  (crip (slag 2 chars))
  ?.  (is-hex x-hex)  ~
  (lift-x (hex-decode x-hex) =(prefix '02'))
++  scalar-to-hex
  |=  s=@  ^-  @t
  (pad-hex s 64)
--
