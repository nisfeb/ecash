::  %txt: plain-text file mark (wain = list of lines)
::
::    The upstream mar/txt.hoon in %base has a broken grab.mime that cues
::    raw bytes. This override reads raw text and splits on newlines.
::
/?    310
|_  non=wain
++  grab
  |%
  ++  noun  wain
  ++  mime
    |=  [p=mite q=octs]
    ^-  wain
    (to-wain:format q.q)
  --
++  grow
  |%
  ++  noun  non
  ++  mime
    :-  /text/plain
    %-  as-octs:mimes:html
    (of-wain:format non)
  --
++  grad  %noun
--
