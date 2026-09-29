::  tessera-demo: a guestbook that takes a post only with a token. It is
::  the smallest app %tessera can gate, and the pattern for any other:
::
::    1. a holder presents a token of service `guestbook` to this ship's
::       %tessera, naming this agent and the post as data;
::    2. %tessera burns it and pokes this agent with %tessera-granted;
::    3. this agent trusts that poke only from %tessera on this ship.
::
::  Not started on install: |rein %tessera [& %tessera-demo]. Posts are
::  public at GET /apps/tessera-demo/posts.
::
/-  *tessera
/+  default-agent, *ecash-http
|%
+$  post  [who=ship text=@t at=@da]
+$  state-0  [%0 posts=(list post)]
+$  card  card:agent:gall
--
=|  state-0
=*  state  -
^-  agent:gall
|_  =bowl:gall
+*  this  .
    def   ~(. (default-agent this %.n) bowl)
++  on-init
  :_  this
  [%pass /eyre %arvo %e %connect [`/apps/tessera-demo dap.bowl]]~
++  on-save  !>(state)
++  on-load  |=(old=vase `this(state !<(state-0 old)))
++  on-poke
  |=  [=mark =vase]
  ^-  (quip card _this)
  ?+  mark  (on-poke:def mark vase)
      %tessera-granted
    ::  the one check a gated app needs: this ship's %tessera sent it
    ?>  &(=(our src):bowl =(/gall/tessera sap.bowl))
    =+  !<(=granted vase)
    ?>  =('guestbook' svc.granted)
    ::  the holder sends the post as JSON {"text": "..."}
    =/  jon  ((soft json) data.granted)
    ?>  ?=([~ %o *] jon)
    =/  text  (get-str p.u.jon 'text')
    ?>  &(!=('' text) (lte (met 3 text) 280))
    `this(posts [[who.granted text now.bowl] posts])
  ::
      %handle-http-request
    =+  !<([eyre-id=@ta req=inbound-request:eyre] vase)
    :_  this
    ?.  ?&  ?=(%'GET' method.request.req)
            =(/apps/tessera-demo/posts (parse-request-path url.request.req))
        ==
      (give-err eyre-id 404 'not-found')
    %+  give-json
      :-  %a
      %+  turn  posts
      |=  p=post
      (pairs:enjs:format ~[['who' s+(scot %p who.p)] ['text' s+text.p] ['at' (numb:enjs:format (da-to-unix at.p))]])
    eyre-id
  ==
++  on-watch
  |=  =path
  ?+  path  (on-watch:def path)
    [%http-response *]  `this
  ==
++  on-leave  on-leave:def
++  on-peek   on-peek:def
++  on-agent  on-agent:def
++  on-arvo   |=([wire sign-arvo] `this)
++  on-fail   on-fail:def
--
