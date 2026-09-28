::  tests for /lib/ecash-services-rules: %ecash-services' decisions
::
/-  *ecash-services
/+  *test, *ecash-services-rules, *ecash-http, *bdhke, *curve
|%
::  -- fixtures (public keys precomputed with noble) --
::
++  now  ~2026.6.1
++  g-hex  '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
::  plain: a public credential keyset, key 11
++  plain
  ^-  cred-keyset
  :*  'c0plain'  &
      (my [0 '03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb']~)
      (my [0 11]~)
      now  |
  ==
::  scoped: a service's keyset, key 12
++  scoped
  ^-  cred-keyset
  :*  'c0svc'  &
      (my [0 '03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a']~)
      (my [0 12]~)
      now  &
  ==
++  kss  ^-  (map @t cred-keyset)  (my ~[['c0plain' plain] ['c0svc' scoped]])
++  svc
  ^-  service
  ['chat' 'Chat' '' %single-use 'c0svc' & ~ ~ 0 0 now ~]
::
::  cred: a credential the mint signed, C = k*hash_to_curve(secret)
++  cred
  |=  [secret=@t kid=@t k=@]
  ^-  json
  %-  pairs:enjs:format
  :~  ['secret' s+secret]
      ['amount' n+'0']
      ['id' s+kid]
      ['C' s+(pt-to-hex (pt-mul k (hash-to-curve secret)))]
  ==
++  output
  |=  [b=@t amt=json kid=@t]
  ^-  json
  (pairs:enjs:format ~[['B_' s+b] ['amount' amt] ['id' s+kid]])
++  body  |=(t=@t `(unit octs)``(as-octs:mimes:html t))
::
::  -- requests --
::
++  test-read-batch
  =/  r  |=(t=@t (read-batch (body t) 'proofs'))
  =/  err  |=(e=(each [o=(map @t json) a=(list json)] @t) ?:(?=(%& -.e) '' p.e))
  =/  of  |=(n=@ud `@t`(rap 3 (weld `(list @t)`~['{"proofs":['] (weld (join ',' (reap n '1')) `(list @t)`~[']}']))))
  =/  hundred  (of 100)
  =/  over  (of 101)
  ;:  weld
    (expect-eq !>('missing-proofs') !>((err (r '{}'))))
    (expect-eq !>('empty-proofs') !>((err (r '{"proofs":[]}'))))
    ::  null and non-arrays read as empty
    (expect-eq !>('empty-proofs') !>((err (r '{"proofs":null}'))))
    (expect-eq !>('empty-proofs') !>((err (r '{"proofs":{}}'))))
    ::  the batch cap as a pair
    (expect-eq !>('') !>((err (r hundred))))
    (expect-eq !>('batch-too-large') !>((err (r over))))
    (expect-eq !>('expected-object') !>((err (r '[1]'))))
  ==
::
::  null clears, a bare integer sets, anything else is malformed
++  test-opt-ud
  ;:  weld
    (expect-eq !>(`(unit (unit @ud))``~) !>((opt-ud ~)))
    (expect-eq !>(`(unit (unit @ud))```5) !>((opt-ud n+'5')))
    (expect-eq !>(`(unit (unit @ud))`~) !>((opt-ud n+'1.5')))
    (expect-eq !>(`(unit (unit @ud))`~) !>((opt-ud n+'-1')))
    (expect-eq !>(`(unit (unit @ud))`~) !>((opt-ud s+'5')))
  ==
::
++  test-unix-to-da
  (expect-eq !>(~1970.1.2) !>((unix-to-da 86.400)))
::
::  -- services --
::
++  test-valid-service-name
  ;:  weld
    (expect-eq !>(&) !>((valid-service-name 'chat')))
    (expect-eq !>(&) !>((valid-service-name 'a_b-9')))
    ::  the length cap as a pair
    (expect-eq !>(&) !>((valid-service-name (crip (reap 64 'a')))))
    (expect-eq !>(|) !>((valid-service-name (crip (reap 65 'a')))))
    (expect-eq !>(|) !>((valid-service-name '')))
    ::  GET /services/v1/list would shadow it
    (expect-eq !>(|) !>((valid-service-name 'list')))
    ::  URL segments aren't percent-decoded, so only safe characters
    (expect-eq !>(|) !>((valid-service-name 'Chat')))
    (expect-eq !>(|) !>((valid-service-name 'a/b')))
    (expect-eq !>(|) !>((valid-service-name 'a b')))
    (expect-eq !>(|) !>((valid-service-name 'a%2f')))
  ==
::
++  test-resolve-service
  =/  err  |=(e=(each service [@ud @t]) ?:(?=(%& -.e) [0 ''] p.e))
  ;:  weld
    (expect-eq !>([404 'service-not-found']) !>((err (resolve-service ~ now))))
    (expect-eq !>([400 'service-inactive']) !>((err (resolve-service `%*(. svc active |) now))))
    ::  usable through its expiry instant, refused after
    (expect-eq !>([0 '']) !>((err (resolve-service `%*(. svc expires `now) now))))
    (expect-eq !>([400 'service-expired']) !>((err (resolve-service `%*(. svc expires `now) (add now ~s1)))))
    (expect-eq !>([0 '']) !>((err (resolve-service `svc now))))
  ==
::
::  the issuance cap as a pair
++  test-cap-ok
  ;:  weld
    (expect-eq !>(&) !>((cap-ok svc 1.000)))
    (expect-eq !>(&) !>((cap-ok %*(. svc issued 8, max-issuance `10) 2)))
    (expect-eq !>(|) !>((cap-ok %*(. svc issued 8, max-issuance `10) 3)))
    (expect-eq !>(|) !>((cap-ok %*(. svc max-issuance `0) 1)))
  ==
::
::  a deleted service's keyset is deactivated; a live one's and a plain
::  keyset are left alone
++  test-retire-orphans
  =/  after  (retire-orphans kss ~)
  =/  kept  (retire-orphans kss (my ['chat' svc]~))
  ;:  weld
    (expect-eq !>(|) !>(active:(~(got by after) 'c0svc')))
    (expect-eq !>(&) !>(active:(~(got by after) 'c0plain')))
    (expect-eq !>(&) !>(active:(~(got by kept) 'c0svc')))
  ==
::
::  the public view never carries the allowlist's plaintext keys
++  test-service-json-hides-the-allowlist
  =/  s  %*(. svc allowlist (sy ~['secret-key']), expires `now, max-issuance `5)
  =/  pub  (service-to-json s)
  =/  adm  (service-to-json-admin s)
  ?>  &(?=([%o *] pub) ?=([%o *] adm))
  ;:  weld
    (expect-eq !>(|) !>((has-key p.pub 'allowlist')))
    (expect-eq !>(1) !>((get-num p.pub 'allowlist_count')))
    (expect-eq !>(&) !>((get-bool p.pub 'allowlist_required')))
    (expect-eq !>(`(list json)`~[s+'secret-key']) !>((get-array p.adm 'allowlist')))
    (expect-eq !>(5) !>((get-num p.pub 'max_issuance')))
  ==
::
::  no expiry or cap is sent as null
++  test-service-json-nulls
  =/  j  (service-to-json svc)
  ?>  ?=([%o *] j)
  ;:  weld
    (expect-eq !>(`(unit json)``~) !>((~(get by p.j) 'expires')))
    (expect-eq !>(`(unit json)``~) !>((~(get by p.j) 'max_issuance')))
  ==
::
::  -- credential keysets --
::
::  sha256("0:<G>|unit:cred") by sha256sum, as the big-endian digest
++  test-cred-ks-id
  %+  expect-eq
    !>('c0ee745b1c6566f358d24340f0f5f9c96867ad48f1f613ffd5c574218a02acc01f')
  !>((cred-ks-id (my [0 g-hex]~)))
::
++  test-gen-cred-keyset
  =/  ks  (gen-cred-keyset 7 now &)
  ;:  weld
    ::  the key comes from the entropy
    (expect-eq !>((mod (shax 7) secp-n)) !>((~(got by privkeys.ks) 0)))
    (expect-eq !>(ks-id.ks) !>((cred-ks-id keys.ks)))
    (expect-eq !>(`(pt-to-hex (pubkey (~(got by privkeys.ks) 0)))) !>((~(get by keys.ks) 0)))
    (expect-eq !>(&) !>(service-scoped.ks))
  ==
::
::  -- proofs --
::
++  test-proof-pre
  =/  ok  (cred 'one' 'c0plain' 11)
  =/  pass  |=(p=checked-proof !=(~ ok.p))
  =/  with  |=([k=@t v=json] ?>(?=([%o *] ok) `json`o+(~(put by p.ok) k v)))
  ;:  weld
    (expect-eq !>(&) !>((pass (proof-pre ok kss ~))))
    ::  the public API treats a service's keyset as unknown
    (expect-eq !>(|) !>((pass (proof-pre (cred 'one' 'c0svc' 12) kss ~))))
    ::  a service's path takes its own keyset and no other
    (expect-eq !>(&) !>((pass (proof-pre (cred 'one' 'c0svc' 12) kss `'c0svc'))))
    (expect-eq !>(|) !>((pass (proof-pre ok kss `'c0svc'))))
    (expect-eq !>(|) !>((pass (proof-pre (with 'id' s+'nope') kss ~))))
    (expect-eq !>(|) !>((pass (proof-pre (with 'C' s+'02zz') kss ~))))
    (expect-eq !>(|) !>((pass (proof-pre (with 'secret' s+'') kss ~))))
    ::  the secret cap as a pair
    (expect-eq !>(&) !>((pass (proof-pre (with 'secret' s+(crip (reap 2.048 'a'))) kss ~))))
    (expect-eq !>(|) !>((pass (proof-pre (with 'secret' s+(crip (reap 2.049 'a'))) kss ~))))
    (expect-eq !>(|) !>((pass (proof-pre s+'x' kss ~))))
  ==
::
++  test-proof-sig-ok
  ;:  weld
    (expect-eq !>(&) !>((proof-sig-ok (proof-pre (cred 'one' 'c0plain' 11) kss ~))))
    ::  signed with another key
    (expect-eq !>(|) !>((proof-sig-ok (proof-pre (cred 'one' 'c0plain' 12) kss ~))))
    (expect-eq !>(|) !>((proof-sig-ok ['c0plain' 'one' ~])))
  ==
::
++  test-has-dup-secrets
  ;:  weld
    (expect-eq !>(&) !>((has-dup-secrets ~[['k' 'a'] ['k' 'b'] ['k' 'a']])))
    ::  the same secret under two keysets is two credentials
    (expect-eq !>(|) !>((has-dup-secrets ~[['k' 'a'] ['j' 'a']])))
  ==
::
::  -- outputs --
::
++  test-output-pre
  =/  err  |=(e=(each ready-output @t) ?:(?=(%& -.e) '' p.e))
  ;:  weld
    (expect-eq !>('') !>((err (output-pre (output g-hex n+'0' 'c0plain') kss ~))))
    ::  a credential carries no value: the number 0 exactly
    (expect-eq !>('credential-amount-must-be-zero') !>((err (output-pre (output g-hex n+'1' 'c0plain') kss ~))))
    (expect-eq !>('credential-amount-must-be-zero') !>((err (output-pre (output g-hex s+'0' 'c0plain') kss ~))))
    (expect-eq !>('credential-amount-must-be-zero') !>((err (output-pre (output g-hex n+'0.0' 'c0plain') kss ~))))
    (expect-eq !>('credential-amount-must-be-zero') !>((err (output-pre (pairs:enjs:format ['B_' s+g-hex]~) kss ~))))
    (expect-eq !>('missing-B_') !>((err (output-pre (output '' n+'0' 'c0plain') kss ~))))
    (expect-eq !>('invalid-B_-point') !>((err (output-pre (output '02zz' n+'0' 'c0plain') kss ~))))
    (expect-eq !>('missing-keyset-id') !>((err (output-pre (output g-hex n+'0' '') kss ~))))
    (expect-eq !>('unknown-credential-keyset') !>((err (output-pre (output g-hex n+'0' 'c0svc') kss ~))))
    ::  a service signs with its own keyset whatever the output names
    (expect-eq !>('') !>((err (output-pre (output g-hex n+'0' 'c0plain') kss `'c0svc'))))
    %+  expect-eq  !>('credential-keyset-inactive')
    !>((err (output-pre (output g-hex n+'0' 'c0plain') (~(put by kss) 'c0plain' %*(. plain active |)) ~)))
    (expect-eq !>('invalid-msg') !>((err (output-pre s+'x' kss ~))))
  ==
::
::  sign, unblind: the token is k*hash_to_curve(secret), with a valid DLEQ;
::  refused outputs keep their slot as error objects
++  test-sign-batch
  =/  bf  (blind-message 'cred' 5)
  =/  good  (output-pre (output (pt-to-hex b-prime.bf) n+'0' 'c0plain') kss ~)
  =/  bad  (output-pre s+'x' kss ~)
  =/  sigs  (sign-batch ~[good bad] 42)
  ?>  ?=([[%o *] [%o *] ~] sigs)
  =/  s  p.i.sigs
  =/  c-  (need (hex-to-pt (get-str s 'C_')))
  =/  dl  (get-obj s 'dleq')
  ;:  weld
    (expect-eq !>(1) !>((n-ready ~[good bad])))
    (expect-eq !>((pt-mul 11 (hash-to-curve 'cred'))) !>((unblind-signature c- blinding-factor.bf (pubkey 11))))
    %+  expect-eq  !>(&)
    !>((dleq-verify b-prime.bf c- (pubkey 11) (hex-decode (get-str dl 'e')) (hex-decode (get-str dl 's'))))
    (expect-eq !>('invalid-msg') !>((get-str p.i.t.sigs 'error')))
  ==
--
