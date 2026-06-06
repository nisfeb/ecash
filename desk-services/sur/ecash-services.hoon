::  ecash-services: shared types for the credential + services access-control
::  agent (%ecash-services). Non-value-bearing; split out of the %ecash mint.
::
|%
::  +cred-keyset: credential-extension keyset (single key at denom 0)
::
+$  cred-keyset
  $:  ks-id=@t
      active=?
      keys=(map @ud @t)
      privkeys=(map @ud @)
      created=@da
      ::  .service-scoped: %.y for keysets that back a named service. These
      ::  MUST NOT be signed via the public /cred endpoint; only the gated
      ::  /services/{name}/issue path (allowlist + cap) may sign them.
      service-scoped=?
  ==
::
::  +service-kind: which credential flavour a service issues
::
::    Phase 1 only supports single-use credentials. %time-limited is reserved
::    for a later phase that rotates sub-keysets per time window.
::
+$  service-kind  ?(%single-use)
::
::  +service: a named access-control scope backed by a cred-keyset.
::
::    Services are non-value-bearing: tokens carry no sats and are only used
::    to grant access to a resource (chat room, API tier, etc.).
::
+$  service
  $:  name=@t
      title=@t
      description=@t
      kind=service-kind
      ks-id=@t
      active=?
      expires=(unit @da)
      max-issuance=(unit @ud)
      issued=@ud
      redeemed=@ud
      created=@da
      ::  .allowlist: if non-empty, caller must supply an `access_key` in the
      ::  /issue body whose value is in this set. Empty allowlist = public.
      allowlist=(set @t)
  ==
--
