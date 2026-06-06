::  ecash: shared types for Cashu mint agent
::
::    Types here are imported by the %ecash agent and any client / library
::    code. State versions and migration-only shapes stay inside app/ecash.hoon.
::
|%
::  +keyset: a Cashu NUT-02 keyset; public keys are hex, privs raw atoms
::
+$  keyset
  $:  ks-id=@t
      active=?
      unt=@t
      input-fee-ppk=@ud
      keys=(map @ud @t)
      privkeys=(map @ud @)
      created=@da
  ==
::
::  +quote-state: quote lifecycle states per NUT-04/05
::
::    %failed marks a melt whose Lightning pay definitively failed and whose
::    inputs were rolled back; it is retryable (re-submit allowed) and is
::    serialized to wallets as UNPAID per NUT-05.
+$  quote-state  ?(%unpaid %pending %paid %issued %failed)
::
::  +mint-quote: a pending deposit of sats into the mint
::
+$  mint-quote
  $:  quote-id=@t
      amount=@ud
      unt=@t
      request=@t
      checking-id=@t
      state=quote-state
      expiry=@da
      created=@da
  ==
::
::  +melt-quote: a pending withdrawal of sats out of the mint
::
+$  melt-quote
  $:  quote-id=@t
      amount=@ud
      fee-reserve=@ud
      unt=@t
      request=@t
      state=quote-state
      payment-preimage=@t
      payment-hash=@t
      expiry=@da
      created=@da
  ==
::
::  +ln-backend: Lightning integration configuration
::
::    %lnbits and %lnd hold their HTTP auth; %none disables bolt11 methods.
::
+$  ln-backend
  $%  [%lnbits url=@t api-key=@t]
      [%lnd url=@t macaroon=@t]
      [%none ~]
  ==
::
::  +pending-req: in-flight iris HTTP request awaiting response
::
::    pending-req is the pre-state-12 (frozen) shape; live code uses
::    pending-req-v2 below. Kept so on-load can decode persisted pending.
+$  pending-req
  $%  [%mint-quote-create eyre-id=@ta quote-id=@t amount=@ud]
      [%mint-quote-check eyre-id=@ta quote-id=@t]
      [%melt-quote-create eyre-id=@ta quote-id=@t bolt11=@t]
      [%melt-pay eyre-id=@ta quote-id=@t outputs=(list json)]
      [%melt-check eyre-id=@ta quote-id=@t]
  ==
::  +pending-req-v2: live (state-12) in-flight request. The %melt-pay variant
::  carries the exact secrets/ys marked spent + the input total, so a
::  definitively-failed Lightning pay can be rolled back (un-spent) and the
::  quote reset to a retryable state.
+$  pending-req-v2
  $%  [%mint-quote-create eyre-id=@ta quote-id=@t amount=@ud]
      [%mint-quote-check eyre-id=@ta quote-id=@t]
      [%melt-quote-create eyre-id=@ta quote-id=@t bolt11=@t]
      [%melt-pay eyre-id=@ta quote-id=@t outputs=(list json) secrets=(set @t) ys=(set @t) input-total=@ud]
      [%melt-check eyre-id=@ta quote-id=@t]
      ::  %melt-abort: CONSERVATIVE operator abort of a stuck %pending bolt11 melt.
      ::  Settles if LN shows it settled (SUCCEEDED/paid + preimage), rolls back
      ::  ONLY on an explicit LND status==FAILED (same predicate as the auto
      ::  %melt-check path), and otherwise leaves the quote %pending -- paid:false
      ::  / IN_FLIGHT / 404 are indistinguishable from in-flight for an outbound
      ::  HTLC, so un-spending there would double-pay a live payment.
      [%melt-abort eyre-id=@ta quote-id=@t]
      ::  %melt-abort-force: operator FORCE abort (body "force":true). Same LN
      ::  re-check, but on ANY non-settled outcome (ambiguous OR failed) the
      ::  operator authorizes the rollback. SETTLED still settles (never lose a
      ::  settled pay, even under force). Widening this $% needs NO migration.
      [%melt-abort-force eyre-id=@ta quote-id=@t]
  ==
::  +melt-inflight-entry: durable reconciliation data for an in-flight bolt11
::  melt, keyed by quote-id on state. Lets the %pending recheck path AND an
::  admin abort settle (sign change) or roll back (un-spend exactly these
::  members, decrement by input-total) even after a restart/migration, since
::  the volatile `pending` map is per-event and lost across an upgrade.
::
+$  melt-inflight-entry
  $:  secrets=(set @t)
      ys=(set @t)
      input-total=@ud
      change=(list json)
  ==
::
::  +cred-keyset: credential-extension keyset (single key at denom 0)
::
+$  cred-keyset
  $:  ks-id=@t
      active=?
      keys=(map @ud @t)
      privkeys=(map @ud @)
      created=@da
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
::    .name: short URL-safe slug (e.g. 'chat')
::    .title / .description: human-readable metadata
::    .kind: credential flavour (phase 1: always %single-use)
::    .ks-id: backing cred-keyset the service uses to sign and verify
::    .active: whether issue/verify/redeem endpoints are open
::    .expires: optional hard cutoff after which all flows return 400
::    .max-issuance: optional cap on total tokens the service will issue
::    .issued / .redeemed: running counters for admin stats
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
