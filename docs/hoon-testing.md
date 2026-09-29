# Hoon testing

The rules of the mint and of `%tessera` are tested as Hoon unit suites on
a separate test desk,
with [nisfeb/hoon-test-kit](https://github.com/nisfeb/hoon-test-kit)
vendored at `scripts/hoon-test-kit/` (the version is in
`scripts/hoon-test-kit/.kit-version`). The kit's `PLAYBOOK.md` is the
method; this page is what it found here. Keep it current: a new trap or a
new triage verdict goes here in the same change.

## What is tested, and where

An agent's own arms can't be built by a test, so everything that decides
lives in libs and the agents keep only state and I/O:

| lib | what it decides |
|---|---|
| `desk/lib/curve.hoon` | secp256k1 arithmetic, point encoding |
| `desk/lib/bdhke.hoon` | hash-to-curve, BDHKE, DLEQ (NUT-12), BIP-340 verify (NUT-11), duplicate-x |
| `desk/lib/ecash-http.hoon` | JSON and request parsing, CSRF, response headers, the dashboard CSP |
| `desk/lib/blind.hoon` | keys from entropy, NUT-02 keyset ids, signing a blinded message with its DLEQ proof, token checks |
| `desk/lib/ecash-rules.hoon` | fees, proof checks, output checks, P2PK, what a Lightning answer means, quote lifetimes |
| `desk-tessera/lib/tessera-rules.hoon` | authA tokens, token checks, refresh, who may mint (keys, ships, ranks), quotas, windows and rotation, pruning, a holder's blinding and unblinding, admin fields |

Suites are `tests/lib/<lib>.hoon`, one per lib: 120 tests. Expected values
come from outside the code under test wherever one exists: NUT-00's
hash-to-curve vectors, BIP-340's test vectors (checked against noble),
NUT-02 keyset ids computed by cashu-ts (4.5.1 for units `sat`; 4.11 for
`auth`, with and without `final_expiry`), an `authA` token as cashu-ts's
`AuthManager` writes it, and secp256k1's published multiples of G. Public
keys and signatures in fixtures are precomputed with noble, so a fixture
costs no scalar multiplication.

The JS suites at the repo root drive the agents over HTTP on a dev ship:
that is the only layer that sees routing, auth, the Lightning round trips,
and (`test-tessera-ships.mjs`, on three ships) Ames. See the README's
Testing section.

## Running

Once per ship, in its dojo:

```
|new-desk %ecash-test
|mount %ecash-test
```

then from the repo root:

```sh
scripts/hoon-test-kit/hoon-test.sh <pier> setup     # lib/test.hoon and marks from the ship's %base
scripts/hoon-test-kit/hoon-test.sh <pier>           # every suite; exit 0 = pass
scripts/hoon-test-kit/hoon-test.sh <pier> ecash-rules
scripts/hoon-test-kit/hoon-mutate.py <pier> --list  # size a mutation run first
scripts/hoon-test-kit/hoon-mutate.py <pier>         # boundary,conjunct
```

`hoon-test.conf` lists the libs, the suites and the two `sur` files the
rules libs import. The whole run takes about 10 s on a vere 4.6 ship.
The desks declare zuse 408 only. The suites also passed on 409 (vere
4.3) on 2026-09-28, but 409 is no longer supported.

## Mutation runs

### Pass 1: boundary, conjunct (2026-09-28, mint libs)

137 mutants: 99 killed, 27 survived, 11 no-build. The no-builds are the
expected shapes (a tall `?&` split across lines; a `?=` whose narrowing the
other branch needs).

Equivalent (no output can differ):

| site | why |
|---|---|
| `curve +pt-mul` `lth`→`lte` on `kk` vs 2^256 | at kk = 2^256 adding n again still gives a 257-bit multiple of the same point |
| `curve +hex-decode` `gte`→`gth` on `'0'` | `'0'` falls through to nibble 0 either way |
| `curve +lift-x` `lth`→`lte` | x = p has no point (7 is not a square mod p) |
| `bdhke +split-amount` `gte`→`gth` | the extra bit it visits is 0 |
| `ecash-http +parse-ud-strict` drop `=('' t)` | `rush` fails on `''` anyway |
| `ecash-rules +compute-ks-id` sort `lth`→`lte` | map keys are unique: no ties |
| `ecash-rules +max-amount` `lte`→`lth` | at m = max-batch both branches give 0 |
| `ecash-rules +count-valid-sigs` `gte`→`gth` (early exit) | a cost bound: the caller compares against the same threshold |

Real gaps, closed (each rechecked with `--only <arm>` until killed):

| arm | the missing test |
|---|---|
| `curve +is-hex-char` | the characters just outside each range (`/`, `:`, `@`, `G`, backtick, `g`) |
| `curve +hex-decode` | totality on non-hex (no crash, no wrong nibble) |
| `curve +lift-x` | a non-canonical x = p + 1 (x = 1 is on the curve) |
| `bdhke +dleq-verify` | each infinity guard alone: the old case made both true |
| `bdhke +schnorr-verify` | a 129-digit signature (a leading 0: the same number) |
| `ecash-rules +count-valid-sigs` | the witness cap as a pair, 10 signatures read and 11 refused |
| `ecash-rules +valid-bolt11` | both cases' letter bounds and their neighbours |
| `ecash-rules +ln-settled-sats` | a present zero falls through to the next field (twice) |
| `ecash-rules +keep-mint-quote` | an issued quote before its expiry is kept |
| `ecash-rules +restore-entries` | a signature for an output with no B_ is keyed nowhere |

### Pass 2: branch, equal, flag

238 mutants over all five libs. The first one, `curve +powmod` with its
`?:` flipped, spins forever and **killed the ship** (vere 4.6 segfault; the
snapshot was corrupt and the pier had to be replayed from its event log).
Arms whose loop ends on a numeric test are left out of branch runs:

- `+powmod`, `+pt-mul`, `+hash-to-curve`, `+split-amount`

The Jacobian core's branch mutants (`+jac-dbl`, `+jac-add`,
`+jac-to-affine`) make nearly every test crash deep in the ladder. The
suites catch them, but the report is then too big to come back over
conn.sock (the ship logs `newt: write canceled`), and the runner reads that
as a dead ship. The ship is fine; those arms are covered by the published
multiples of G and the NUT-00/BIP-340 vectors, and are left out of branch
passes too. Before the resumed run, `+pt-dbl`'s branch mutant survived:
nothing added a point to itself. `test-pt-add-doubles` now kills it.

The rest of the pass ran one arm per `--only` call: a loop over the arms
that, after any arm ending "not answering", requires a clean `hoon-test.sh`
run before going on. Over 65 arms: 154 killed, 8 survived, and the
no-builds are the expected `?.`↔`?:` flips after a `?=`. One timeout,
`+lift-x` with its guard flipped, spins `+hash-to-curve`'s retry loop: a
break the suites detect.

The 8 survivors were 4 real gaps, two of them about key safety:

| arm | the missing test |
|---|---|
| `ecash-rules +gen-ks-keys`, `ecash-services-rules +gen-cred-keyset` | keys come from the entropy and differ per denomination: flipping `=(0 k)` gave every denomination the private key 1, and nothing noticed |
| `bdhke +dleq-prove` | one B_ under two entropies gets two proofs: a fixed nonce gives the key away from two signatures, and nothing noticed |
| `bdhke +blind-message` | the wallet's r is the blinding factor (mod n, 0 made 1) |
| `ecash-rules +sign-outputs` | an output with no keyset id is signed under the active keyset |

Rechecked with `--only`: all 9 of those arms' mutants are killed.

### Pass 3: `%tessera`'s rules (2026-09-28)

All five operators over `tessera-rules`, in two runs as the phases landed.
The first, over the HTTP issuer's arms: 95 mutants, 76 killed, 19 no-build,
none survived. The second, over the arms for ships, windows and pruning: 36
mutants, 27 killed, 9 no-build, none survived. A third, after a review
added offers and forward agents (`+offer-refusal`, `+forward-refusal`,
`+apply-fields`): 17 mutants, 15 killed, 2 no-build, none survived. The
no-builds are the expected `?.`↔`?:` flips after a `?=` or a `?~`.

The first run also mutated `ecash-services-rules`' arms of the same names:
4 survivors in `+valid-service-name` (a one-letter name, and the characters
just outside `a-z`). That lib has since been retired with `%ecash-services`.

The agent's own guards are proven on dev ships instead, by breaking each one
and watching `test-tessera-ships.mjs` fail: the quota count (5 checks fail),
the un-burn of a token whose forward was refused (2), the verifier check
(1), and giving a refused token back to the holder (4). The forward-agent
checks and holding hand-overs as offers each have a check that fails
without them (a present to an agent outside the list, or to one that isn't
running; an offer that is not yet held). The check that only
the asked ship may answer a request is not reachable from HTTP. On
2026-09-28 it was proven live: ~mus asked ~lyd for 10 tokens while ~del
answered the same request id first. With the check, ~mus stored the 10;
without it, it stored none. `+whom`, the ship an answer must come from, is
unit-tested.

## Traps met here

- **`?=` takes a wing.** `?=(%& -:(f x))` doesn't build; bind the result
  with `=/` first.
- **An arm name can't hold `^`.** `++  test-...-2^20` is a syntax error.
- **A fixture arm can't be changed in place.** `svc(active |)` changes
  the subject, not the arm's product: write `%*(. svc active |)`.
- **`my` over a `turn` fails** (`find-fork`); `malt` works.
- **A tape can't hold `{`** (it opens interpolation); build JSON text from
  cords with `rap`.
- **vere 4.3 keeps conn.sock open after it answers**, so every kit call
  waits out socat's `T`. Run the kit on a 4.6 ship, or set `T` small on a
  4.3 one.
- **A pier under a long path can't be reached**: conn.sock's path must be
  under 108 bytes. Point the kit at a short symlink.
- **`b64-hex`'s test prints `%base-64-padding-err-one`** on the ship: that
  is `de:base64` refusing the non-base64 case, as intended.
- **The kit's `expect-eq` checks types too**: the actual must nest in the
  expected. A constant tuple like `!>(['x' '' & ...])` fails against a
  `service`; cast it (`` !>(`service`[...]) ``).
- **`x(field v)` changes the field's type**, not just its value. A list
  of `svc(name 'p')`, `svc(name 'o')` has the first one's constant type, so
  `malt` of it fails; cast the list. `%*(. arm policy [...])` loses the
  faces inside: cast the new value (`` `policy`[...] ``).
- **`(gulf 1 0)` crashes**: `gulf` asserts its bounds. A count of 0 needs
  its own case.
- **`(~(gut by o) k b+x)` forks without faces**, so `p.v` doesn't resolve
  after a `?=`: cast the default to `json`.
- **An arm named `roll` shadows the stdlib fold** in everything that
  imports the lib.
- **`(slav %f t)` is a bare atom**, not a loobean: compare it with `&`.
