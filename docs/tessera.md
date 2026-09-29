# Tessera: blind-signed access tokens

`%tessera` issues **access tokens** rather than money: passes, credits,
tickets and invites that other ships and web clients present to reach a
resource. It runs next to the `%ecash` mint and shares its blind-signature
core (`desk/lib/blind.hoon`), but holds no value.

- **The token** is a Cashu NUT-22 blind auth token (a "BAT"): a proof of
  amount 1 in unit `auth`, written `authA` + base64url(JSON `{id, secret,
  C}`). Issuance comes with a NUT-12 DLEQ proof. A cashu-ts `AuthManager`
  works against a service unmodified.
- **Each service is its own auth mint**, with its own keyset, spent set and
  URL: `https://<your ship>/tessera/<name>`. Tiers are separate services.
- **Credits are a count of tokens.** Using one token is one use.
- **Every ship that runs `%tessera`** is an issuer for its own services and a
  holder of tokens other ships issued, so ships trade tokens over Ames.

Over Ames the issuer sees which ship asks and which presents, so between
ships tokens are capabilities and quota accounting, not anonymity.
Unlinkability holds where the presenter isn't identified: anonymous HTTP, or
tokens that changed hands.

## Install

```
|new-desk %tessera
|mount %tessera
```
```bash
./build.sh tessera -p /path/to/your/pier/tessera
```
```
|commit %tessera
|install our %tessera
```

The dashboard is at `/apps/tessera`, and is also a Landscape tile. The desk
also carries `%tessera-demo`, a guestbook gated by tokens (see [Gating an
app](#gating-an-app)). It isn't started on install: `|rein %tessera [&
%tessera-demo]`.

## Services

A service is created closed: only this ship can get its tokens. Then you
set who else may have them, and how they are used.

| Field | Meaning |
|---|---|
| `open` | anyone may be issued tokens, over HTTP or Ames |
| `keys` | web clients sending one of these as their `Clear-auth` header |
| `ships` | these ships, over Ames |
| `rank` | or any ship of at least this rank: `galaxy`, `star`, `planet` (planets and up keeps free comets out), `moon`, `comet` |
| `quota` | `{n, per}`: at most n tokens per identity per `per` seconds. Each ship and each key counts apart; all open HTTP clients share one count |
| `window` | seconds: tokens last until the end of the window they were issued in. Windows are multiples of the length from the start of time, so a day (86400) ends at midnight UTC. Unset, tokens last for good |
| `mode` | `burn` (default): a token is used once. `check`: a token is checked but not spent, a membership gate that can be shown again (at the cost of linking its uses) |
| `verifiers` | ships that may check or burn this service's tokens that they are shown |
| `verifier_keys` | HTTP resource servers that may check or burn them |
| `agents` | agents on this ship that a presented token may be delivered to (see [Gating an app](#gating-an-app)) |
| `max_issuance` | a cap on tokens ever issued |
| `expires` | unix seconds: the service stops, and its tokens with it |

A service with a `window` gets a new keyset for each window, and its keyset
id commits to the time it closes (NUT-02's `final_expiry`), so wallets know
too. The old keyset, and its spent set, are dropped when the window turns.
Changing a service's window starts a new keyset at once: the tokens already
out stop working.

## Web clients (cashu-ts)

```js
import { AuthManager } from '@cashu/cashu-ts';

const auth = new AuthManager('https://ship.example/tessera/chat', { desiredPoolSize: 10 });
auth.setCAT(clientKey);   // only for a service gated by keys
const bat = await auth.getBlindAuthToken({ method: 'POST', path: '/api/post' });
await fetch('https://chat.example/api/post', { method: 'POST', headers: { 'Blind-auth': bat }, body });
```

`AuthManager` reads `/v1/info`, checks that the keys derive the keyset id,
mints in batches of `bat_max_mint` (10), and checks each token's DLEQ proof.
It loads the keyset once, so for a service with a `window`, make a new
`AuthManager` when the window turns: its pooled tokens are dead by then.

| Route | |
|---|---|
| `GET /tessera/<name>/v1/info` | NUT-06, with `nuts.22 {bat_max_mint, protected_endpoints}`; `nuts.21` marks minting as needing `Clear-auth` where no one can mint without a key |
| `GET /tessera/<name>/v1/auth/blind/keys` | the service's keyset: unit `auth`, one key for amount 1, `final_expiry` when it closes |
| `GET /tessera/<name>/v1/auth/blind/keysets` | the same, without keys |
| `POST /tessera/<name>/v1/auth/blind/mint` | `{outputs}` → `{signatures}`. All or none: each output is amount 1 under the service's keyset id |
| `POST /tessera/<name>/refresh` | `{tokens, outputs}` → `{signatures}`: burn tokens and sign as many new outputs. Open to any holder: it is how a receiver makes handed-over tokens its own |

## Resource servers

A server that accepts tokens asks the issuer about each one, with a verifier
key the issuer's owner gave it:

```bash
curl -X POST https://ship.example/tessera/chat/redeem \
  -H 'content-type: application/json' -d '{"token":"authA...","key":"<verifier key>"}'
# {"status":"fresh"}   grant: the token is burned now
# {"status":"replay"}  deny: it was already spent
```

Only `fresh` grants access, so retrying after a lost answer is safe. In
`check` mode a redeem never burns, and every showing of a good token is
`fresh` until it is refreshed away. `POST /tessera/<name>/check` answers
`{"spent": bool}` and burns nothing. A token that is not the service's
(forged, of another service, or of a closed window) is `400` with the
reason.

## Between ships

The owner drives the holder side from the dashboard's Wallet tab or its API
(below). Apps on the ship drive it with pokes: mark `%tessera-action`,
answered with a `%tessera-answer` poke `[rid answer]` to the asking agent.
`rid` is the asker's own id for the request.

| Action (from this ship) | |
|---|---|
| `[%get rid issuer svc n]` | ask `issuer` for n tokens (1..10). They arrive blinded, their DLEQ proofs are checked, and they are stored |
| `[%use rid issuer svc to]` | present one token. `to` is `~`, or `` `[agent data] ``: on a good token the issuer pokes that agent of its own with `data` (see below) |
| `[%ask rid issuer svc token burn]` | as a verifier ship: check, or burn, a token someone showed this ship |
| `[%give rid to issuer svc n]` | hand n tokens to another ship. They wait there as an offer |
| `[%accept rid from issuer svc]` | take the offer from `from`: a refresh at the issuer makes the tokens this ship's, so the giver can't spend them too |
| `[%decline rid from issuer svc]` | drop that offer |

| Answer | |
|---|---|
| `[%done n]` | a get or an accept stored n tokens, a give handed them over, or a decline dropped them |
| `[%valid fresh]` | a use or an ask: fresh means unspent until now (and, for a use, delivered) |
| `[%refused why]` | e.g. `not-allowed`, `quota-exceeded`, `no-tokens`, `not-a-verifier`, `service-inactive`, `agent-not-allowed`, `agent-not-running`, `forward-refused`, `no-offer`, `nacked` |

A refused use puts the token back, unless the token itself was bad. Only the
ship a request went to can answer it; a give is settled by the receiver's
ack alone.

Tokens handed to this ship wait as an offer until the owner accepts or
declines them, so another ship can't spend this one's CPU (an accept is a
refresh at the issuer) or fill its wallet. At most 100 offers wait at once,
each up to 10 tokens; a refused hand-over nacks, and the giver gets its
tokens back. `.^((map [ship @t] @ud) %gx
/=tessera=/wallet/noun)` counts the tokens held.

## Gating an app

The issuer delivers a presented token's action to one of its own agents:
the agent never handles tokens. The agent must be in the service's
`agents`, and running, or the present is refused before the token is
touched; `data` is at most 16 KiB jammed. The agent gets a poke with mark
`%tessera-granted` and `[svc=@t who=ship data=*]`, and must trust it only
from `%tessera` on its own ship:

```hoon
    %tessera-granted
  ?>  &(=(our src):bowl =(/gall/tessera sap.bowl))
  =+  !<([svc=@t who=ship data=*] vase)
  ?>  =('guestbook' svc)
  ...  ::  who presented a good token of svc: do what it asked (data)
```

`app/tessera-demo.hoon` is the whole example: a guestbook that takes a post
only with a `guestbook` token (a service named `guestbook`, with `agents:
["tessera-demo"]`).

1. The holder's app pokes its `%tessera` with `[%use rid ~issuer 'guestbook'
   `[%tessera-demo [%o ...]]]`.
2. The issuer burns the token and pokes `%tessera-demo` with it.
3. If the agent nacks (here: an empty post), the token is not spent after
   all, and the holder gets it back.

For a resource on a third ship, the holder shows the token to that ship's
app, and the app asks its own `%tessera` (`%ask`). That ship must be one of
the service's `verifiers`.

## Admin API

Base path `/apps/tessera/api`. It needs your ship's session cookie, and a
write must come from your own page (or send no `Origin`/`Referer`).

| Route | |
|---|---|
| `GET /services` | every service, with its policy, counters and keyset |
| `POST /services/create` | `{name, title, ...fields}`. `name` is 1..64 of `a-z 0-9 _ -` |
| `POST /services/update` | `{name, ...fields}`: absent fields are left alone; `null` clears an optional one |
| `POST /services/activate`, `/deactivate` | `{name}` |
| `POST /services/delete` | `{name}`: only an inactive service that never issued |
| `POST /services/batch` | `{name, n}` → `{tokens}`: n ≤ 100 tokens made here, as `authA` strings to hand out off-ship (tickets, invites). They count toward the cap |
| `GET /overview` | counts: spent kept, quota counts, tokens held, requests out, next prune |
| `POST /prune` | drop spent sets of closed keysets and quota counts of past windows now (a timer does it hourly) |
| `GET /wallet` | tokens held, by issuer and service |
| `POST /wallet/get` | `{issuer, service, n}` → `{done}` when the issuer answers |
| `POST /wallet/use` | `{issuer, service, agent?, data?}` → `{fresh}` |
| `POST /wallet/take` | `{issuer, service}` → `{token}`: one token out, to give a web client or anyone |
| `POST /wallet/give` | `{to, issuer, service, n}` → `{done}` |
| `POST /wallet/accept`, `/wallet/decline` | `{from, issuer, service}` → `{done}`: an offer (listed under `offers` in `GET /wallet`) |
| `POST /wallet/ask` | `{issuer, service, token, burn}` → `{fresh}` |

The wallet calls answer when the other ship does. If it is offline, the
request waits.

## Limits and costs

- Signing costs about 90 ms per token, so a mint or refresh takes at most 10
  (about a second) and a batch at most 100. Checking a token costs less.
  Keep quotas on open services, and rate-limit `/tessera` at your proxy.
- Verification is online: the issuer must be up for every use.
- Spent sets keep `sha256(secret)` per keyset. A windowed service's sets go
  with their windows; a service without a window keeps its set for good.
- Over Ames, anyone can present or refresh tokens, which costs the issuer a
  little EC work each. Policies gate issuance only.
- Per-ship quotas don't bound an `open` or `rank: comet` service over Ames:
  comets are free. Prefer `rank: planet`, and a `max_issuance`. Over HTTP,
  all open clients share one quota count, so one client can use it up.
- A ship you give tokens to could copy them and then nack the give. You get
  them back, but it may already have spent them. Give to ships you trust.
- Holder requests (get, use, ask, give) to a ship that doesn't answer (it
  doesn't run `%tessera`, say) wait for good, and so does the admin call.
- As with any eyre app, any ship can open a subscription to
  `/http-response/…`. That can't be told apart from eyre's own, so each one
  stays in the agent's subscriber list.

## Testing

`test-tessera.mjs` (one ship, in `run-tests`) drives the HTTP surface with a
real `AuthManager`. `test-tessera-ships.mjs` needs three ships, each running
`%tessera`, with `%tessera-demo` on the issuer:

```bash
SHIP_URL=… URBAUTH_COOKIE=…  HOLDER_URL=… HOLDER_COOKIE=…  THIRD_URL=… THIRD_COOKIE=… \
  npm run test:tessera-ships
```

The rules are unit-tested in `tests/lib/tessera-rules.hoon`. See
[`hoon-testing.md`](hoon-testing.md).
