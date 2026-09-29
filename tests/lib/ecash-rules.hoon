::  tests for /lib/ecash-rules: the mint's rules
::
/-  *ecash
/+  *test, *ecash-rules, *ecash-http, *bdhke, *curve
|%
::  -- fixtures (public keys precomputed with noble, so no fixture costs a
::  scalar multiplication) --
::
::  ks-a: active, no fee, denominations 1 2 4 with keys 11 12 13
++  ks-a
  ^-  keyset
  :*  'ks-a'  &  'sat'  0
      %-  my
      :~  [1 '03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb']
          [2 '03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a']
          [4 '03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8']
      ==
      (my ~[[1 11] [2 12] [4 13]])
      ~2026.1.1
  ==
::  ks-b: inactive, 1500 ppk, denomination 1 with key 21
++  ks-b
  ^-  keyset
  :*  'ks-b'  |  'sat'  1.500
      (my [1 '02352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5']~)
      (my ~[[1 21]])
      ~2026.1.1
  ==
++  sets  ^-  (map @t keyset)  (my ~[['ks-a' ks-a] ['ks-b' ks-b]])
++  now  ~2026.6.1
::
::  token: a proof the mint signed: C = k * hash_to_curve(secret)
++  token
  |=  [secret=@t amt=@ud kid=@t k=@]
  ^-  json
  %-  pairs:enjs:format
  :~  ['secret' s+secret]
      ['amount' (numb:enjs:format amt)]
      ['id' s+kid]
      ['C' s+(pt-to-hex (pt-mul k (hash-to-curve secret)))]
  ==
++  with
  |=  [j=json k=@t v=json]
  ^-  json
  ?>  ?=([%o *] j)
  o+(~(put by p.j) k v)
::  output: a blinded message for B_ = the point with this hex
++  output
  |=  [b=@t amt=@ud kid=@t]
  ^-  json
  (pairs:enjs:format ~[['B_' s+b] ['amount' (numb:enjs:format amt)] ['id' s+kid]])
++  g-hex   '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
++  ng-hex  '0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
++  g2-hex  '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
::
::  -- keysets --
::
++  test-default-denoms-run-1-to-2-pow-20
  ;:  weld
    (expect-eq !>(21) !>((lent default-denoms)))
    (expect-eq !>(`(list @ud)`~[1 2 4]) !>((scag 3 default-denoms)))
    (expect-eq !>(1.048.576) !>((rear default-denoms)))
  ==
::
::  outputs-needed: how many power-of-two outputs pay a, with top the
::  largest denomination (the greedy split wallets use)
++  outputs-needed
  |=  [a=@ud top=@ud]
  ^-  @ud
  (add (div a top) (lent (split-amount (mod a top))))
::
::  max-amount is payable in max-batch outputs; the first amount that is
::  not lies above it. 1..512: 91*512 = 46592, and 47615 needs 101.
++  test-max-amount
  =/  small  (malt (turn (gulf 0 9) |=(i=@ud [`@ud`(bex i) 'k'])))
  =/  big    (malt (turn (gulf 0 20) |=(i=@ud [`@ud`(bex i) 'k'])))
  ;:  weld
    (expect-eq !>(46.592) !>((max-amount small)))
    (expect-eq !>(83.886.080) !>((max-amount big)))
    (expect-eq !>(0) !>((max-amount ~)))
    (expect-eq !>(&) !>((lte (outputs-needed 46.592 512) max-batch)))
    (expect-eq !>(&) !>((gth (outputs-needed 47.615 512) max-batch)))
    (expect-eq !>(&) !>((lte (outputs-needed 83.886.080 1.048.576) max-batch)))
  ==
::
::  -- amounts and fees --
::
++  test-compute-fee
  =/  p  |=(kid=@t (pairs:enjs:format ['id' s+kid]~))
  ;:  weld
    (expect-eq !>(0) !>((compute-fee ~ sets 'ks-a')))
    (expect-eq !>(0) !>((compute-fee ~[(p 'ks-a')] sets 'ks-a')))
    ::  1500 ppk is 2 sats (ceil), two proofs 3000 ppk is 3
    (expect-eq !>(2) !>((compute-fee ~[(p 'ks-b')] sets 'ks-a')))
    (expect-eq !>(3) !>((compute-fee ~[(p 'ks-b') (p 'ks-b')] sets 'ks-a')))
    ::  a missing id pays the active keyset's fee, so dropping it saves nothing
    (expect-eq !>(2) !>((compute-fee ~[(pairs:enjs:format ~)] sets 'ks-b')))
    ::  unknown keysets add nothing (verify-proofs refuses them)
    (expect-eq !>(0) !>((compute-fee ~[(p 'nope') s+'x'] sets 'ks-a')))
  ==
::
++  test-amount-total
  %+  expect-eq  !>(7)
  !>((amount-total ~[(output g-hex 3 'x') (output g-hex 4 'x') s+'junk']))
::
++  test-melt-fee-reserve
  ;:  weld
    ::  bps of the amount, with a floor
    (expect-eq !>(100) !>((melt-fee-reserve 10.000 100 10)))
    (expect-eq !>(10) !>((melt-fee-reserve 100 100 10)))
  ==
::
::  change = unused reserve + what the inputs paid beyond amount + reserve
++  test-melt-change
  ;:  weld
    (expect-eq !>(13) !>((melt-change 10 2 5)))
    (expect-eq !>(8) !>((melt-change 10 2 0)))
    (expect-eq !>(5) !>((melt-change 10 10 5)))
    ::  a fee over the reserve never eats the excess
    (expect-eq !>(5) !>((melt-change 10 11 5)))
  ==
::
::  -- proofs --
::
++  test-verify-proofs-accepts
  =/  t1  (token 'one' 1 'ks-a' 11)
  =/  t2  (token 'two' 4 'ks-a' 13)
  =/  r  (verify-proofs ~[t1 t2] ~ ~ sets 'ks-a' now)
  ?>  ?=(%& -.r)
  ;:  weld
    (expect-eq !>(5) !>(total.p.r))
    (expect-eq !>((sy ~['one' 'two'])) !>(spent.p.r))
    (expect-eq !>(&) !>((~(has in spent-ys.p.r) (pt-to-hex (hash-to-curve 'one')))))
  ==
::
::  a proof with no id is checked against the active keyset
++  test-verify-proofs-empty-id-means-active
  =/  t  (with (token 's' 2 'ks-a' 12) 'id' s+'')
  =/  r  (verify-proofs ~[t] ~ ~ sets 'ks-a' now)
  (expect-eq !>(`(unit @ud)``2) !>(?:(?=(%& -.r) `total.p.r ~)))
::
++  test-verify-proofs-refuses
  =/  ok  (token 'ok' 1 'ks-a' 11)
  =/  v  |=(ins=(list json) (verify-proofs ins (sy ~['spent']) ~ sets 'ks-a' now))
  =/  err  |=(r=(each [@ud (set @t) (set @t)] @t) ?:(?=(%& -.r) '' p.r))
  ;:  weld
    (expect-eq !>('invalid-proof') !>((err (v ~[s+'x']))))
    (expect-eq !>('token-already-spent') !>((err (v ~[(token 'spent' 1 'ks-a' 11)]))))
    ::  twice in one batch
    (expect-eq !>('token-already-spent') !>((err (v ~[ok ok]))))
    (expect-eq !>('unknown-keyset') !>((err (v ~[(with ok 'id' s+'nope')]))))
    (expect-eq !>('unknown-denomination') !>((err (v ~[(with ok 'amount' n+'8')]))))
    (expect-eq !>('invalid-C-point') !>((err (v ~[(with ok 'C' s+'02zz')]))))
    ::  signed under the key for 2, claimed as a 1
    (expect-eq !>('invalid-token-signature') !>((err (v ~[(token 'ok' 1 'ks-a' 12)]))))
    ::  a well-known secret of a kind the mint doesn't enforce
    %+  expect-eq  !>('unsupported-spending-condition')
    !>((err (v ~[(token '["HTLC",{"nonce":"n","data":"00","tags":[]}]' 1 'ks-a' 11)])))
  ==
::
::  the secret cap as a pair: 2048 bytes spend, 2049 are refused
++  test-verify-proofs-secret-cap
  =/  at-cap  (crip (reap 2.048 'a'))
  =/  over  (crip (reap 2.049 'a'))
  =/  r  (verify-proofs ~[(token at-cap 1 'ks-a' 11)] ~ ~ sets 'ks-a' now)
  ;:  weld
    (expect-eq !>(`(unit @ud)``1) !>(?:(?=(%& -.r) `total.p.r ~)))
    %+  expect-eq  !>(`(each [@ud (set @t) (set @t)] @t)`[%| 'secret-too-long'])
    !>((verify-proofs ~[(token over 1 'ks-a' 11)] ~ ~ sets 'ks-a' now))
  ==
::
::  the cheap checks cover the whole batch before any EC work: a batch whose
::  first proof has a bad signature and whose second is spent is refused as
::  spent
++  test-verify-proofs-cheap-checks-first
  =/  bad  (token 'bad' 1 'ks-a' 12)
  =/  gone  (token 'gone' 1 'ks-a' 11)
  %+  expect-eq  !>(`(each [@ud (set @t) (set @t)] @t)`[%| 'token-already-spent'])
  !>((verify-proofs ~[bad gone] (sy ~['gone']) ~ sets 'ks-a' now))
::
::  -- P2PK --
::
::  pk: a key's compressed hex (101-103 precomputed with noble)
++  pk
  |=  k=@
  ^-  @t
  ?:  =(101 k)  '02311091dd9860e8e20ee13473c1155f5f69635e394704eaa74009452246cfa9b3'
  ?:  =(102 k)  '023049f7ffc71d744bd9bed6f42dc6a28974e3a1b9d30671f800e5d46389103c7e'
  ?:  =(103 k)  '0234c1fd04d301be89b31c0442d3e6ac24883928b45a9340781867d4232ec2dbdf'
  (pt-to-hex (pubkey k))
::  sig: a BIP-340 signature by k over sha256(secret), as a witness carries
++  sig
  |=  [k=@ secret=@t]
  ^-  @t
  (pad-hex (sign:schnorr:secp256k1:secp:crypto k (rev 3 32 (shax secret)) 0) 128)
::  p2pk: a P2PK secret locked to data with these tags
++  p2pk
  |=  [data=@t tags=(list (list @t))]
  ^-  @t
  %-  en:json:html
  :-  %a
  :~  s+'P2PK'
      %-  pairs:enjs:format
      :~  ['nonce' s+'n']
          ['data' s+data]
          ['tags' a+(turn tags |=(t=(list @t) a+(turn t |=(v=@t s+v))))]
      ==
  ==
::  spend: a proof carrying a P2PK secret and witness signatures, checked
++  spend
  |=  [secret=@t sigs=(list @t) when=@da]
  ^-  (unit @t)
  =/  wit  (en:json:html (pairs:enjs:format ['signatures' a+(turn sigs |=(s=@t s+s))]~))
  =/  tok  (pairs:enjs:format ~[['secret' s+secret] ['witness' s+wit]])
  (check-p2pk tok secret (need (parse-wk-secret secret)) when)
::
++  test-p2pk-single-key
  =/  sec  (p2pk (pk 101) ~)
  ;:  weld
    (expect-eq !>(~) !>((spend sec ~[(sig 101 sec)] now)))
    (expect-eq !>(`'missing-witness-signatures') !>((spend sec ~ now)))
    (expect-eq !>(`'insufficient-p2pk-signatures') !>((spend sec ~[(sig 102 sec)] now)))
  ==
::
::  n-of-m counts distinct signers: one key can't fill two slots, by a
::  repeated signature or by naming its 02/03 twin
++  test-p2pk-multisig
  =/  sec  (p2pk (pk 101) ~[~['n_sigs' '2'] ~['pubkeys' (pk 102) (pk 103)]])
  =/  twin  (cat 3 ?:(=('02' (end [3 2] (pk 101))) '03' '02') (rsh [3 2] (pk 101)))
  =/  sec2  (p2pk (pk 101) ~[~['n_sigs' '2'] ~['pubkeys' twin]])
  ;:  weld
    (expect-eq !>(~) !>((spend sec ~[(sig 101 sec) (sig 103 sec)] now)))
    (expect-eq !>(`'insufficient-p2pk-signatures') !>((spend sec ~[(sig 101 sec)] now)))
    (expect-eq !>(`'insufficient-p2pk-signatures') !>((spend sec ~[(sig 101 sec) (sig 101 sec)] now)))
    (expect-eq !>(`'insufficient-p2pk-signatures') !>((spend sec2 ~[(sig 101 sec2)] now)))
  ==
::
::  after the locktime the refund keys spend; with no refund key anyone can
++  test-p2pk-locktime
  =/  lock  (crip (a-co:co (da-to-unix now)))
  =/  refund  (p2pk (pk 101) ~[~['locktime' lock] ~['refund' (pk 102)]])
  =/  open  (p2pk (pk 101) ~[~['locktime' lock]])
  =/  later  (add now ~s1)
  ;:  weld
    ::  at the locktime itself the lock still holds
    (expect-eq !>(`'insufficient-p2pk-signatures') !>((spend open ~[(sig 102 open)] now)))
    (expect-eq !>(~) !>((spend open ~ later)))
    (expect-eq !>(~) !>((spend refund ~[(sig 102 refund)] later)))
    (expect-eq !>(`'invalid-refund-signature') !>((spend refund ~[(sig 103 refund)] later)))
    (expect-eq !>(`'missing-witness-signatures') !>((spend refund ~ later)))
  ==
::
++  test-p2pk-refuses-bad-tags
  ;:  weld
    %+  expect-eq  !>(`'invalid-locktime')
    !>((spend (p2pk (pk 101) ~[~['locktime' 'soon']]) ~ now))
    %+  expect-eq  !>(`'invalid-n-sigs')
    !>((spend (p2pk (pk 101) ~[~['n_sigs' 'two']]) ~ now))
    %+  expect-eq  !>(`'unsupported-sigflag')
    !>((spend (p2pk (pk 101) ~[~['sigflag' 'SIG_ALL']]) ~ now))
  ==
::
::  the witness cap as a pair: 10 signatures are read, 11 are refused
++  test-p2pk-sig-cap
  =/  sec  (p2pk (pk 101) ~)
  =/  junk  (reap 9 (pad-hex 1 128))
  ;:  weld
    (expect-eq !>(~) !>((spend sec (snoc junk (sig 101 sec)) now)))
    (expect-eq !>(`'insufficient-p2pk-signatures') !>((spend sec (snoc (snoc junk (pad-hex 2 128)) (sig 101 sec)) now)))
  ==
::
::  the secret cap leaves room for the largest lock the key caps allow:
::  data + 9 pubkeys + 10 refund keys, with every tag set
++  test-p2pk-largest-lock-fits-the-secret-cap
  =/  keys  (turn (gulf 1 9) |=(i=@ (pad-hex i 66)))
  =/  sec
    %+  p2pk  (pk 101)
    :~  ['pubkeys' keys]
        ['refund' (snoc keys (pad-hex 10 66))]
        ~['n_sigs' '1']
        ~['n_sigs_refund' '1']
        ~['locktime' '99999999999']
        ~['sigflag' 'SIG_INPUTS']
    ==
  ;:  weld
    (expect-eq !>(&) !>((lte (met 3 sec) max-secret-bytes)))
    (expect-eq !>(~) !>((spend sec ~[(sig 101 sec)] now)))
  ==
::
::  the pubkey cap as a pair: 10 keys can be satisfied, 11 can't
++  test-p2pk-key-cap
  =/  junk  (turn (gulf 1 9) |=(i=@ (pad-hex i 66)))
  =/  at-cap  (p2pk (pk 101) ~[['pubkeys' junk]])
  =/  over  (p2pk (pk 101) ~[['pubkeys' (snoc junk (pad-hex 10 66))]])
  ;:  weld
    (expect-eq !>(~) !>((spend at-cap ~[(sig 101 at-cap)] now)))
    (expect-eq !>(`'insufficient-p2pk-signatures') !>((spend over ~[(sig 101 over)] now)))
  ==
::
++  test-parse-wk-secret
  ;:  weld
    %+  expect-eq  !>(`[kind='P2PK' data='d' tags=`(list (list @t))`~[~['a' 'b']]])
    !>((parse-wk-secret '["P2PK",{"nonce":"n","data":"d","tags":[["a","b"]]}]'))
    (expect-eq !>(~) !>((parse-wk-secret 'plain-secret')))
    (expect-eq !>(~) !>((parse-wk-secret '["P2PK",{"data":"d"},1]')))
    (expect-eq !>(~) !>((parse-wk-secret '[1,{"data":"d"}]')))
    (expect-eq !>(~) !>((parse-wk-secret '["P2PK",{"nonce":"n"}]')))
  ==
::
::  -- outputs --
::
++  test-output-error
  =/  e  |=(os=(list json) (output-error os sets 'ks-a' ~ |))
  ;:  weld
    (expect-eq !>(~) !>((e ~[(output g-hex 1 'ks-a') (output g2-hex 4 'ks-a')])))
    (expect-eq !>(`'invalid-msg') !>((e ~[s+'x'])))
    (expect-eq !>(`'missing-B_') !>((e ~[(output '' 1 'ks-a')])))
    (expect-eq !>(`'invalid-B_-point') !>((e ~[(output '02zz' 1 'ks-a')])))
    ::  B_ and -B_ share x
    (expect-eq !>(`'duplicate-output') !>((e ~[(output g-hex 1 'ks-a') (output ng-hex 1 'ks-a')])))
    (expect-eq !>(`'unknown-keyset') !>((e ~[(output g-hex 1 'nope')])))
    (expect-eq !>(`'inactive-keyset') !>((e ~[(output g-hex 1 'ks-b')])))
    (expect-eq !>(`'unknown-denomination') !>((e ~[(output g-hex 8 'ks-a')])))
    ::  no id means the active keyset
    (expect-eq !>(~) !>((e ~[(output g-hex 1 '')])))
  ==
::
::  a B_ the mint already signed is refused, however its hex is cased
++  test-output-error-already-signed
  =/  signed=(map @t restored-sig)  (my ~[[g-hex [1 'ks-a' 'c' 'e' 's']]])
  =/  upper  (crip (cuss (trip g-hex)))
  ;:  weld
    (expect-eq !>(`'output-already-signed') !>((output-error ~[(output g-hex 1 'ks-a')] sets 'ks-a' signed |)))
    (expect-eq !>(`'output-already-signed') !>((output-error ~[(output upper 1 'ks-a')] sets 'ks-a' signed |)))
  ==
::
::  blank change outputs skip the keyset and amount checks, not the rest
++  test-output-error-blank
  ;:  weld
    (expect-eq !>(~) !>((output-error ~[(output g-hex 0 'ks-b')] sets 'ks-a' ~ &)))
    (expect-eq !>(`'invalid-B_-point') !>((output-error ~[(output '02zz' 0 '')] sets 'ks-a' ~ &)))
  ==
::
::  sign, unblind, and the token verifies: the full BDHKE path through the
::  mint's signer, plus its DLEQ proof
++  test-sign-outputs-round-trip
  =/  bf  (blind-message 'round' 5)
  =/  sigs  (sign-outputs ~[(output (pt-to-hex b-prime.bf) 2 'ks-a')] sets 'ks-a' 99)
  ?>  ?=([[%o *] ~] sigs)
  =/  s  p.i.sigs
  =/  c-  (need (hex-to-pt (get-str s 'C_')))
  =/  c  (unblind-signature c- blinding-factor.bf (pubkey 12))
  =/  dl  (get-obj s 'dleq')
  ;:  weld
    (expect-eq !>('ks-a') !>((get-str s 'id')))
    (expect-eq !>(2) !>((get-num s 'amount')))
    (expect-eq !>((pt-mul 12 (hash-to-curve 'round'))) !>(c))
    %+  expect-eq  !>(&)
    !>((dleq-verify b-prime.bf c- (pubkey 12) (hex-decode (get-str dl 'e')) (hex-decode (get-str dl 's'))))
    (expect-eq !>(&) !>((all-signed sigs)))
  ==
::
::  an output with no keyset id is signed under the active keyset
++  test-sign-outputs-empty-id-means-active
  =/  sigs  (sign-outputs ~[(output g-hex 1 '')] sets 'ks-a' 1)
  ?>  ?=([[%o *] ~] sigs)
  (expect-eq !>('ks-a') !>((get-str p.i.sigs 'id')))
::
::  change keeps positions: an unsignable blank gets an error in its slot,
::  and the split amounts go on in order
++  test-sign-change-outputs-keeps-positions
  =/  sigs
    %:  sign-change-outputs
      ~[(output g-hex 0 '') (output '02zz' 0 '') (output g2-hex 0 '')]
      7  sets  'ks-a'  1
    ==
  =/  amt  |=(j=json ?>(?=([%o *] j) (get-num p.j 'amount')))
  =/  has-err  |=(j=json ?>(?=([%o *] j) (has-key p.j 'error')))
  ;:  weld
    (expect-eq !>(3) !>((lent sigs)))
    (expect-eq !>(4) !>((amt (snag 0 sigs))))
    (expect-eq !>(&) !>((has-err (snag 1 sigs))))
    (expect-eq !>(1) !>((amt (snag 2 sigs))))
    (expect-eq !>(|) !>((all-signed sigs)))
    ::  more blanks than amounts: the extras are left unsigned
    (expect-eq !>(1) !>((lent (sign-change-outputs ~[(output g-hex 0 '') (output g2-hex 0 '')] 1 sets 'ks-a' 1))))
    (expect-eq !>(0) !>((lent (sign-change-outputs ~[(output g-hex 0 '')] 0 sets 'ks-a' 1))))
  ==
::
::  restore records pair outputs and signatures by index, keyed by the
::  lowercased B_, and skip error results
++  test-restore-entries
  =/  sig-a  (pairs:enjs:format ~[['C_' s+'c1'] ['amount' n+'2'] ['id' s+'ks-a'] ['dleq' (pairs:enjs:format ~[['e' s+'e1'] ['s' s+'s1']])]])
  =/  err  (pairs:enjs:format ['error' s+'x']~)
  =/  upper  (crip (cuss (trip g-hex)))
  ;:  weld
    %+  expect-eq
      !>((my ~[[g-hex `restored-sig`[2 'ks-a' 'c1' 'e1' 's1']]]))
    !>((restore-entries ~[(output upper 2 'ks-a') (output g2-hex 1 'ks-a')] ~[sig-a err]))
    ::  a signature for an output with no B_ is recorded under no key
    %+  expect-eq  !>(`(map @t restored-sig)`~)
    !>((restore-entries ~[(output '' 2 'ks-a')] ~[sig-a]))
  ==
::
::  -- Lightning --
::
++  test-valid-bolt11
  ;:  weld
    (expect-eq !>(&) !>((valid-bolt11 'lnbc10n1pjq8x2tpp5Qz9')))
    (expect-eq !>(|) !>((valid-bolt11 '')))
    ::  every letter case and digit, and the characters just outside them
    (expect-eq !>(&) !>((valid-bolt11 'azAZ09')))
    (expect-eq !>(|) !>((valid-bolt11 'a@')))
    (expect-eq !>(|) !>((valid-bolt11 'a[')))
    (expect-eq !>(|) !>((valid-bolt11 'a`')))
    (expect-eq !>(|) !>((valid-bolt11 'a{')))
    (expect-eq !>(|) !>((valid-bolt11 'a:')))
    ::  it lands in a URL path: no path or query characters
    (expect-eq !>(|) !>((valid-bolt11 'lnbc/../v1/balance')))
    (expect-eq !>(|) !>((valid-bolt11 'lnbc?x=1')))
    (expect-eq !>(|) !>((valid-bolt11 'lnbc%2f')))
    ::  the length cap as a pair
    (expect-eq !>(&) !>((valid-bolt11 (crip (reap 4.096 'a')))))
    (expect-eq !>(|) !>((valid-bolt11 (crip (reap 4.097 'a')))))
  ==
::
++  obj  |=(l=(list [@t json]) `(unit json)``(pairs:enjs:format l))
::
++  test-ln-settled-sats
  ;:  weld
    (expect-eq !>(5) !>((ln-settled-sats (my ['details' (pairs:enjs:format ['amount' n+'5000']~)]~))))
    (expect-eq !>(6) !>((ln-settled-sats (my ['amount_msat' n+'6000']~))))
    (expect-eq !>(7) !>((ln-settled-sats (my ['amt_paid_sat' n+'7']~))))
    ::  a zero field is no amount: the next field is read
    (expect-eq !>(5) !>((ln-settled-sats (my ~[['details' (pairs:enjs:format ['amount' n+'0']~)] ['amount_msat' n+'5000']]))))
    (expect-eq !>(7) !>((ln-settled-sats (my ~[['amt_paid_sat' s+'0'] ['value' s+'7']]))))
    ::  LND sends int64 as a string
    (expect-eq !>(8) !>((ln-settled-sats (my ['amt_paid_sat' s+'8']~))))
    (expect-eq !>(0) !>((ln-settled-sats ~)))
  ==
::
++  test-b64-hex
  ;:  weld
    ::  LND's base64 r_hash / preimage bytes, as hex
    (expect-eq !>('00ff10') !>((b64-hex 'AP8Q')))
    ::  64 hex digits are a hex hash or preimage already, though they are
    ::  also valid base64
    =/  hx  '6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de3341'
    (expect-eq !>(hx) !>((b64-hex hx)))
    (expect-eq !>('not base64!') !>((b64-hex 'not base64!')))
  ==
::
++  test-invoice-paid
  =/  lnbits=ln-backend  [%lnbits 'u' 'k']
  =/  lnd=ln-backend  [%lnd 'u' 'm']
  ;:  weld
    ::  LNbits paid:true with no amount is trusted (bolt11 is all or nothing)
    (expect-eq !>(&) !>((invoice-paid lnbits (obj ['paid' b+&]~) 10)))
    (expect-eq !>(&) !>((invoice-paid lnbits (obj ~[['paid' b+&] ['amount' n+'10000']]) 10)))
    ::  but an explicitly short amount is refused
    (expect-eq !>(|) !>((invoice-paid lnbits (obj ~[['paid' b+&] ['amount' n+'9000']]) 10)))
    (expect-eq !>(|) !>((invoice-paid lnbits (obj ['paid' b+|]~) 10)))
    (expect-eq !>(&) !>((invoice-paid lnd (obj ~[['state' s+'SETTLED'] ['amt_paid_sat' s+'10']]) 10)))
    (expect-eq !>(|) !>((invoice-paid lnd (obj ~[['state' s+'OPEN'] ['amt_paid_sat' s+'10']]) 10)))
    (expect-eq !>(|) !>((invoice-paid [%none ~] (obj ['paid' b+&]~) 10)))
    (expect-eq !>(|) !>((invoice-paid lnbits ~ 10)))
  ==
::
::  only a settled pay and LND's explicit FAILED are definite: a 404,
::  paid:false or IN_FLIGHT can be a pay still in flight
++  test-pay-status
  =/  lnbits=ln-backend  [%lnbits 'u' 'k']
  =/  lnd=ln-backend  [%lnd 'u' 'm']
  ;:  weld
    (expect-eq !>(%settled) !>((pay-status lnbits 200 (obj ['paid' b+&]~))))
    (expect-eq !>(%unknown) !>((pay-status lnbits 200 (obj ['paid' b+|]~))))
    (expect-eq !>(%unknown) !>((pay-status lnbits 200 (obj ['status' s+'failed']~))))
    (expect-eq !>(%unknown) !>((pay-status lnbits 404 (obj ['paid' b+&]~))))
    (expect-eq !>(%settled) !>((pay-status lnd 200 (obj ['status' s+'SUCCEEDED']~))))
    (expect-eq !>(%failed) !>((pay-status lnd 200 (obj ['status' s+'FAILED']~))))
    (expect-eq !>(%unknown) !>((pay-status lnd 200 (obj ['status' s+'IN_FLIGHT']~))))
    (expect-eq !>(%unknown) !>((pay-status lnd 404 (obj ['status' s+'FAILED']~))))
    (expect-eq !>(%unknown) !>((pay-status lnd 200 ~)))
    (expect-eq !>(%unknown) !>((pay-status [%none ~] 200 (obj ['paid' b+&]~))))
  ==
::
++  test-pay-settled
  ;:  weld
    (expect-eq !>(&) !>((pay-settled 201 (obj ['payment_preimage' s+'ab']~))))
    (expect-eq !>(&) !>((pay-settled 200 (obj ['preimage' s+'ab']~))))
    (expect-eq !>(|) !>((pay-settled 201 (obj ['payment_hash' s+'h']~))))
    (expect-eq !>(|) !>((pay-settled 201 (obj ~[['preimage' s+'ab'] ['error' s+'x']]))))
    (expect-eq !>(|) !>((pay-settled 500 (obj ['preimage' s+'ab']~))))
    (expect-eq !>(|) !>((pay-settled 300 (obj ['preimage' s+'ab']~))))
    (expect-eq !>(|) !>((pay-settled 199 (obj ['preimage' s+'ab']~))))
  ==
::
::  a refusal made before any HTLC existed: an LNbits 4xx, not 408/429,
::  with a recognizable error and no payment named
++  test-pay-rejected
  =/  lnbits=ln-backend  [%lnbits 'u' 'k']
  =/  body  (obj ['detail' s+'Insufficient balance.']~)
  ;:  weld
    (expect-eq !>(&) !>((pay-rejected lnbits 400 body)))
    (expect-eq !>(&) !>((pay-rejected lnbits 499 body)))
    (expect-eq !>(|) !>((pay-rejected lnbits 399 body)))
    (expect-eq !>(|) !>((pay-rejected lnbits 500 body)))
    (expect-eq !>(|) !>((pay-rejected lnbits 408 body)))
    (expect-eq !>(|) !>((pay-rejected lnbits 429 body)))
    (expect-eq !>(|) !>((pay-rejected lnbits 400 (obj ~[['detail' s+'x'] ['checking_id' s+'c']]))))
    (expect-eq !>(|) !>((pay-rejected lnbits 400 (obj ~[['detail' s+'x'] ['payment_hash' s+'h']]))))
    (expect-eq !>(|) !>((pay-rejected lnbits 400 (obj ['other' s+'x']~))))
    (expect-eq !>(|) !>((pay-rejected lnbits 400 ~)))
    (expect-eq !>(|) !>((pay-rejected [%lnd 'u' 'm'] 400 body)))
  ==
::
::  fail closed: an unreadable fee is the whole cap
++  test-routing-fee-sats
  =/  f  |=(l=(list [@t json]) (routing-fee-sats (pairs:enjs:format l) 10))
  ;:  weld
    (expect-eq !>(3) !>((f ['fee_sat' n+'3']~)))
    (expect-eq !>(3) !>((f ['fee_sat' s+'3']~)))
    (expect-eq !>(4) !>((f ['payment_route' (pairs:enjs:format ['total_fees' s+'4']~)]~)))
    ::  msat rounds up
    (expect-eq !>(2) !>((f ['total_fees_msat' n+'1500']~)))
    (expect-eq !>(1) !>((f ['fee' n+'1000']~)))
    ::  LNbits' negative fee is its magnitude
    (expect-eq !>(2) !>((f ['fee' n+'-2000']~)))
    (expect-eq !>(2) !>((f ['details' (pairs:enjs:format ['fee' n+'-2000']~)]~)))
    (expect-eq !>(0) !>((f ['fee' n+'0']~)))
    (expect-eq !>(10) !>((f ~)))
    (expect-eq !>(10) !>((f ['fee' s+'lots']~)))
    (expect-eq !>(10) !>((f ['fee_sat' n+'99']~)))
    (expect-eq !>(10) !>((routing-fee-sats s+'x' 10)))
  ==
::
::  -- quotes --
::
++  test-quote-state-text
  ;:  weld
    (expect-eq !>('PENDING') !>((quote-state-text %pending)))
    ::  a failed melt is retryable, so wallets see it unpaid
    (expect-eq !>('UNPAID') !>((quote-state-text %failed)))
  ==
::
++  test-quote-methods
  =/  mq=mint-quote  ['q' 1 'sat' 'self-mint' '' %paid now now]
  =/  lq=melt-quote  ['q' 1 0 'sat' 'self-melt' %unpaid '' '' now now]
  ;:  weld
    (expect-eq !>('self') !>((mint-quote-method mq)))
    (expect-eq !>('bolt11') !>((mint-quote-method mq(request 'lnbc1'))))
    (expect-eq !>('self') !>((melt-quote-method lq)))
    (expect-eq !>('bolt11') !>((melt-quote-method lq(payment-hash 'h'))))
  ==
::
::  cleanup keeps a quote until expiry; a %paid mint quote (a deposit not
::  yet minted) for good; an unpaid bolt11 one for the grace after expiry
++  test-keep-mint-quote
  =/  q=mint-quote  ['q' 1 'sat' 'lnbc1' 'chk' %unpaid now now]
  ;:  weld
    (expect-eq !>(&) !>((keep-mint-quote q (sub now ~s1))))
    (expect-eq !>(&) !>((keep-mint-quote q (add now (sub quote-grace ~s1)))))
    (expect-eq !>(|) !>((keep-mint-quote q (add now quote-grace))))
    (expect-eq !>(&) !>((keep-mint-quote q(state %paid) (add now ~d365))))
    ::  before expiry every quote is kept, whatever its state
    (expect-eq !>(&) !>((keep-mint-quote q(state %issued) (sub now ~s1))))
    (expect-eq !>(&) !>((keep-mint-quote q(checking-id '') (sub now ~s1))))
    ::  no invoice (self, or never created) and issued quotes get no grace
    (expect-eq !>(|) !>((keep-mint-quote q(checking-id '') now)))
    (expect-eq !>(|) !>((keep-mint-quote q(state %issued) now)))
  ==
::
::  one Lightning check, in the first day after expiry
++  test-recheck-mint-quote
  =/  q=mint-quote  ['q' 1 'sat' 'lnbc1' 'chk' %unpaid now now]
  ;:  weld
    (expect-eq !>(|) !>((recheck-mint-quote q (sub now ~s1))))
    (expect-eq !>(&) !>((recheck-mint-quote q now)))
    (expect-eq !>(&) !>((recheck-mint-quote q (add now (sub ~d1 ~s1)))))
    (expect-eq !>(|) !>((recheck-mint-quote q (add now ~d1))))
    (expect-eq !>(|) !>((recheck-mint-quote q(checking-id '') now)))
    (expect-eq !>(|) !>((recheck-mint-quote q(state %paid) now)))
  ==
::
++  test-keep-melt-quote
  =/  q=melt-quote  ['q' 1 0 'sat' 'lnbc1' %unpaid '' 'h' now now]
  ;:  weld
    (expect-eq !>(&) !>((keep-melt-quote q (sub now ~s1))))
    (expect-eq !>(|) !>((keep-melt-quote q now)))
    (expect-eq !>(|) !>((keep-melt-quote q(state %failed) (add now ~d1))))
    ::  pending owes a settle-or-rollback decision, kept whatever its age;
    ::  paid, for paid-melt-life (its change is also in the restore map)
    (expect-eq !>(&) !>((keep-melt-quote q(state %pending) (add now ~d365))))
    (expect-eq !>(&) !>((keep-melt-quote q(state %paid) (add now (sub paid-melt-life ~s1)))))
    (expect-eq !>(|) !>((keep-melt-quote q(state %paid) (add now paid-melt-life))))
    (expect-eq !>(|) !>((keep-melt-quote q(state %unpaid) (add now ~s1))))
  ==
--
