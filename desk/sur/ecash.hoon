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
::    A self-method quote has request 'self-mint'.
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
::    A self-method quote has an empty payment-hash; a bolt11 quote always
::    carries the invoice's hash.
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
::  +pending-req-v2: an in-flight iris request, keyed by its wire.
::
::    An empty eyre-id marks a background request (a quote poll answers at
::    once and checks Lightning behind it): its answer updates state and
::    sends no HTTP response. The %melt-pay variant carries the exact
::    secrets/ys marked spent + the input total, so a definitively-failed
::    Lightning pay can be rolled back.
+$  pending-req-v2
  $%  [%mint-quote-create eyre-id=@ta quote-id=@t amount=@ud]
      [%mint-quote-check eyre-id=@ta quote-id=@t]
      [%melt-quote-create eyre-id=@ta quote-id=@t bolt11=@t]
      [%melt-pay eyre-id=@ta quote-id=@t outputs=(list json) secrets=(set @t) ys=(set @t) input-total=@ud]
      [%melt-check eyre-id=@ta quote-id=@t]
      ::  %melt-abort: CONSERVATIVE operator abort of a stuck %pending bolt11 melt.
      ::  Settles if LN shows it settled, rolls back ONLY on an explicit LND
      ::  status==FAILED (same predicate as the auto %melt-check path), and
      ::  otherwise leaves the quote %pending -- paid:false / IN_FLIGHT / 404
      ::  are indistinguishable from in-flight for an outbound HTLC, so
      ::  un-spending there would double-pay a live payment.
      [%melt-abort eyre-id=@ta quote-id=@t]
      ::  %melt-abort-force: operator FORCE abort (body "force":true). Same LN
      ::  re-check, but on ANY non-settled outcome (ambiguous OR failed) the
      ::  operator authorizes the rollback. SETTLED still settles (never lose a
      ::  settled pay, even under force).
      [%melt-abort-force eyre-id=@ta quote-id=@t]
      ::  %melt-abort-named: a forced abort of a melt stuck from before
      ::  inflight records existed, un-spending what the operator names
      [%melt-abort-named eyre-id=@ta quote-id=@t secrets=(set @t) ys=(set @t)]
      ::  %ln-test: the admin "test connection" call to the backend
      [%ln-test eyre-id=@ta ~]
  ==
::  +melt-inflight-entry: durable reconciliation data for an in-flight bolt11
::  melt, keyed by quote-id on state. Lets the %pending recheck path AND an
::  admin abort settle (sign change) or roll back (un-spend exactly these
::  members, decrement by input-total) even after a restart/migration, since
::  the volatile `pending` map is per-event and lost across an upgrade.
::
::    .excess: what the inputs paid beyond amount + fee reserve + input fee,
::    returned as NUT-08 change along with the unused reserve.
::    .started: when this attempt was made. A quote can fail, roll back and
::    be melted again; each Lightning request carries its attempt in its
::    wire, so a late answer about an old attempt can't roll back a new one.
::
+$  melt-inflight-entry
  $:  secrets=(set @t)
      ys=(set @t)
      input-total=@ud
      change=(list json)
      excess=@ud
      started=@da
  ==
::
::  +restored-sig: a signature the mint issued, kept by its B_ for NUT-09
::
+$  restored-sig  [amount=@ud id=@t c-hex=@t e=@t s=@t]
--
