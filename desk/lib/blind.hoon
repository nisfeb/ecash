::  /lib/blind: the blind-signature core of a Cashu-style issuer, whatever
::  its tokens stand for. %ecash (money) and %tessera (access) both build
::  on it: keys, NUT-02 keyset ids, signing a blinded message with its
::  DLEQ proof, and checking a token's signature. `make sync-libs` copies
::  it to the tessera desk.
::
/+  *bdhke, *ecash-http
|%
::  dec-cord: plain decimal. (scot %ud 1024) is '1.024', which is not what
::  wallets write for an amount, a fee or a key's denomination.
++  dec-cord  |=(n=@ud `@t`(crip (a-co:co n)))
::
::  gen-keys: a keyset's private and public keys for these denominations,
::  from entropy: sha256(ent*2^64 + d) mod n, 0 made 1
++  gen-keys
  |=  [ent=@ denoms=(list @ud)]
  ^-  [privkeys=(map @ud @) pubkeys=(map @ud @t)]
  =/  privs=(map @ud @)
    %-  malt
    %+  turn  denoms
    |=  d=@ud
    ^-  [@ud @]
    =/  k  (mod (shax (add (mul ent (bex 64)) d)) secp-n)
    [d ?:(=(0 k) 1 k)]
  [privs (~(run by privs) |=(k=@ (pt-to-hex (pubkey k))))]
::
::  compute-ks-id: NUT-02 v2 keyset id, '01' || sha256(canonical), where
::  canonical is "<amt>:<pk>,...|unit:<unt>[|input_fee_ppk:<n>][|final_expiry:<n>]"
::  with amounts ascending
++  compute-ks-id
  |=  [keys=(map @ud @t) unt=@t input-fee-ppk=@ud final-expiry=@ud]
  ^-  @t
  =/  sorted=(list [@ud @t])
    (sort ~(tap by keys) |=([a=[@ud @t] b=[@ud @t]] (lth -.a -.b)))
  =/  pieces=(list @t)
    :~  (rap 3 (join ',' (turn sorted |=([amt=@ud pub=@t] (rap 3 ~[(dec-cord amt) ':' pub])))))
        '|unit:'
        unt
    ==
  =?  pieces  (gth input-fee-ppk 0)
    (weld pieces `(list @t)`~['|input_fee_ppk:' (dec-cord input-fee-ppk)])
  =?  pieces  (gth final-expiry 0)
    (weld pieces `(list @t)`~['|final_expiry:' (dec-cord final-expiry)])
  ::  shax gives a little-endian atom; rev makes it the big-endian digest
  ::  NUT-02 and cashu-ts hash to
  (rap 3 ~['01' (pad-hex (rev 3 32 (shax (rap 3 pieces))) 64)])
::
::  sign-blinded: C_ = a*B_ with its NUT-12 DLEQ proof, as the signature
::  JSON wallets read. pub is a*G, the key the keyset publishes for amt;
::  b-hex is B_ as the wallet sent it.
++  sign-blinded
  |=  [b-hex=@t b=point amt=@ud kid=@t priv=@ pub=point ent=@]
  ^-  json
  =/  c  (blind-sign b priv)
  ::  the full B_ hex (02/03 differs for B_ and -B_) gives each output of
  ::  one event its own nonce entropy
  =/  dleq  (dleq-prove b c priv pub (shax (cat 3 b-hex (add ent amt))))
  %-  pairs:enjs:format
  :~  ['C_' s+(pt-to-hex c)]
      ['amount' (numb:enjs:format amt)]
      ['id' s+kid]
      ['dleq' (pairs:enjs:format ~[['e' s+(scalar-to-hex e.dleq)] ['s' s+(scalar-to-hex s.dleq)]])]
  ==
::
::  signed-by: is C the signature of key priv on this secret, C = k*Y?
++  signed-by
  |=  [secret=@t c=point priv=@]
  ^-  ?
  =(c (pt-mul priv (hash-to-curve secret)))
::
::  all-signed: did every output get a signature, not an error object?
++  all-signed
  |=  sigs=(list json)
  ^-  ?
  (levy sigs |=(j=json &(?=([%o *] j) (has-key p.j 'C_'))))
--
