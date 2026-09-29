::  tessera: blind-signed access tokens
::
::    A token is a Cashu NUT-22 blind auth token: amount 1 in unit 'auth',
::    [id secret C], written 'authA' + base64url {id, secret, C}. Each
::    service is its own auth mint, with its own keyset and spent set.
::    Every ship that runs %tessera is an issuer for its own services and
::    a holder of tokens from other ships.
::
|%
::  +keyset: a service's key, for amount 1. A windowed service's keyset
::  closes with its window, and its tokens with it: NUT-02's final_expiry,
::  which its id commits to.
+$  keyset
  $:  id=@t
      pub=@t
      priv=@
      created=@da
      closes=(unit @da)
  ==
::
::  +policy: who may be issued tokens. This ship always may.
::
::    .open: anyone
::    .keys: an HTTP client sending one of these as its Clear-auth header
::    .ships: these ships, over Ames
::    .rank: or any ship of at least this rank (%duke: planets and up)
+$  policy
  $:  open=?
      keys=(set @t)
      ships=(set ship)
      rank=(unit rank:title)
  ==
::
::  +service: a named scope with its own auth mint
::
::    .quota: at most n tokens per identity (a ship, a key, or all open
::    HTTP clients together) per `per`
::    .window: tokens last until the end of the window they were issued
::    in (windows are multiples of it, from the start of time: days start
::    at midnight UTC); ~ is for good
::    .mode: %burn spends a token when it is used; %check only checks it
::    (a membership gate that can be shown again, linking its uses)
::    .verifiers, .verifier-keys: the ships and the HTTP resource servers
::    that may redeem or check this service's tokens
::    .agents: the agents on this ship a presented token may be delivered
::    to (see +forward)
+$  service
  $:  name=@t
      title=@t
      description=@t
      active=?
      =policy
      quota=(unit [n=@ud per=@dr])
      window=(unit @dr)
      mode=?(%burn %check)
      verifiers=(set ship)
      verifier-keys=(set @t)
      agents=(set @t)
      max-issuance=(unit @ud)
      expires=(unit @da)
      issued=@ud
      redeemed=@ud
      created=@da
      =keyset
  ==
::
::  +token: a token as it is held and presented (C is compressed hex)
+$  token  [id=@t secret=@t c=@t]
::
::  +usage: tokens issued to one identity in quota window `win`
+$  usage  [win=@ud n=@ud]
::
::  +blind: a token being made: its secret, blinding factor r and B_ hex
+$  blind  [secret=@t r=@ b=@t]
::
::  +asker: who on this ship hears the answer to a request it made: a
::  local agent (as a %tessera-answer poke), an admin HTTP request, or no
::  one
+$  asker  $%([%agent dap=term] [%http eyre-id=@ta] [%none ~])
::
::  +pending: a request out to another ship, by its id
+$  pending
  $%  [%get =asker issuer=ship svc=@t bs=(list blind)]
      [%use =asker issuer=ship svc=@t tok=token]
      [%ask =asker issuer=ship]
      [%give =asker to=ship issuer=ship svc=@t toks=(list token)]
  ==
::
::  +forward: the poke an issuer delivers to one of its own agents when a
::  presented token is good, as %tessera-granted. The agent must be one of
::  the service's, and running.
+$  forward  [agent=term data=*]
+$  granted  [svc=@t who=ship data=*]
::
::  +action: every poke to %tessera, mark %tessera-action. Tokens travel
::  as authA strings, blinded outputs as B_ hex. rid is the asker's.
+$  action
  $%  ::  to an issuer, from any ship
      [%request rid=@uv svc=@t outputs=(list @t)]
      [%present rid=@uv svc=@t token=@t to=(unit forward)]
      [%refresh rid=@uv svc=@t tokens=(list @t) outputs=(list @t)]
      ::  to an issuer, from one of the service's verifier ships
      [%verify rid=@uv svc=@t token=@t burn=?]
      ::  to a holder: an issuer's answer, or tokens handed over, which
      ::  wait as an offer until the owner accepts or declines them
      [%answer rid=@uv =answer]
      [%transfer rid=@uv issuer=ship svc=@t tokens=(list @t)]
      ::  from this ship only (its owner or its apps), answered as
      ::  %tessera-answer [rid answer] to the asking agent
      [%get rid=@uv issuer=ship svc=@t n=@ud]
      [%use rid=@uv issuer=ship svc=@t to=(unit forward)]
      [%ask rid=@uv issuer=ship svc=@t token=@t burn=?]
      [%give rid=@uv to=ship issuer=ship svc=@t n=@ud]
      [%accept rid=@uv from=ship issuer=ship svc=@t]
      [%decline rid=@uv from=ship issuer=ship svc=@t]
  ==
::
::  +answer: %issued carries the signatures as a wallet reads them, and
::  the key to check their DLEQ proofs against. %valid says whether the
::  token was fresh (unspent until now); for a present, only fresh
::  delivered anything. %done counts the tokens a get or an accept
::  stored, a give handed over, or a decline dropped.
+$  answer
  $%  [%issued kid=@t pub=@t sigs=(list json)]
      [%valid fresh=?]
      [%done n=@ud]
      [%refused why=@t]
  ==
--
