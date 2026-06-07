# ecash Phase 1 — Stop the Bleeding (Security) Implementation Plan

**Goal:** Close the two money-losing holes in the `%ecash` mint — unauthenticated admin and free minting — and harden request parsing, leaving the agent safe to run.

**Architecture:** Single-agent edits to `desk/app/ecash.hoon`: add an admin auth gate in `handle-http`, require the operator on the config poke, remove the legacy free-sign endpoints, make number parsing total, and add a persisted `self-method-enabled` flag (default off, state v9→v10 migration) gating every `self` mint/melt path. New JS e2e tests assert the security behavior; the value-token regression suites gain a login helper so they can re-enable `self` through the authenticated admin API.

**Tech Stack:** Hoon (Gall agent, zuse kelvin 409), Node.js e2e tests (`@noble/*`), a running fake `~zod` dev ship.

---

## Prerequisites & Test Loop

This plan assumes a local dev ship:

- A fake `~zod` running with its web interface on `http://localhost:8080`.
- The `%ecash` desk installed and **mounted**: in dojo `|mount %ecash` (so it lives at `./zod/ecash/`).
- `npm install` already run (provides `@noble/secp256k1`, `@noble/curves`, `@noble/hashes`).
- The web login code: in dojo run `+code` and export it as `SHIP_CODE` for tests that touch admin endpoints, e.g. `export SHIP_CODE=lidlut-tabwed-pillex-ridrup`.

**The edit→test loop used by every task below:**

1. Edit files under `desk/` in the repo.
2. **Sync to the ship:** `cp -r desk/* zod/ecash/`
3. **Commit on the ship:** in dojo run `|commit %ecash` (watch for build errors).
4. **Run the test:**
   - Hoon unit tests: in dojo `-test /=ecash=/tests/test/hoon`
   - JS e2e: `node test-<name>.mjs` (prefix `SHIP_CODE=… ` when the test hits admin)

Where a step says "rebuild + commit," it means steps 2–3 above.

Commit messages follow the repo style: short, lower-case, no co-author trailer.

---

## File Structure

- `desk/app/ecash.hoon` — all agent changes (auth gate, poke guard, legacy removal, `parse-ud`, state v10 + `self` flag + gating, admin settings).
- `desk/tests/test.hoon` — add `parse-ud` fail-soft unit tests.
- `test-helpers.mjs` — **new**: shared login + authenticated-fetch helper for JS tests.
- `test-admin-auth.mjs` — **new**: admin endpoints require auth; public endpoints stay open.
- `test-legacy-removed.mjs` — **new**: legacy free-sign routes return 404.
- `test-parse-robustness.mjs` — **new**: malformed numbers yield 400, not a crashed event.
- `test-self-method.mjs` — **new**: `self` disabled by default; enable→use→disable via admin.
- `test-e2e.mjs`, `test-p2pk.mjs` — **modify**: enable `self` via admin at startup.
- `test-cred.mjs`, `test-services.mjs` — **modify**: route admin setup calls through the auth helper.
- `package.json`, `Makefile`, `README.md` — **modify**: wire new tests, document the auth + `self`-off changes.

---

## Task 1: Login helper for JS tests

**Files:**
- Create: `test-helpers.mjs`
- Create: `test-login.mjs` (smoke test)

- [ ] **Step 1: Write the helper**

Create `test-helpers.mjs`:

```js
// Shared helpers for authenticated test calls against a dev ship.
// SHIP_URL defaults to the fake-zod web port; SHIP_CODE is the `+code` login code.
export const SHIP_URL = process.env.SHIP_URL || 'http://localhost:8080';
const SHIP_CODE = process.env.SHIP_CODE || '';

export function hasCode() { return !!SHIP_CODE; }

let cookie = null;
export async function login() {
  if (cookie) return cookie;
  if (!SHIP_CODE) throw new Error('SHIP_CODE not set — cannot authenticate to admin endpoints');
  const res = await fetch(`${SHIP_URL}/~/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: `password=${encodeURIComponent(SHIP_CODE)}`,
    redirect: 'manual',
  });
  if (![200, 204, 302].includes(res.status)) throw new Error(`login failed: ${res.status}`);
  const raw = res.headers.getSetCookie ? res.headers.getSetCookie() : [res.headers.get('set-cookie')];
  const auth = raw.filter(Boolean).map(c => c.split(';')[0]).find(c => c.startsWith('urbauth-'));
  if (!auth) throw new Error('no urbauth cookie in login response');
  cookie = auth;
  return cookie;
}

export async function adminFetch(path, opts = {}) {
  const c = await login();
  return fetch(`${SHIP_URL}${path}`, { ...opts, headers: { ...(opts.headers || {}), cookie: c } });
}
```

- [ ] **Step 2: Write the smoke test**

Create `test-login.mjs`:

```js
import { hasCode, login, SHIP_URL } from './test-helpers.mjs';
if (!hasCode()) { console.log('SKIP test-login (set SHIP_CODE to run)'); process.exit(0); }
const c = await login();
const ok = c.startsWith('urbauth-');
console.log(ok ? 'PASS login returns urbauth cookie' : 'FAIL no cookie', `(${SHIP_URL})`);
process.exit(ok ? 0 : 1);
```

- [ ] **Step 3: Run the smoke test**

Run: `SHIP_CODE=$SHIP_CODE node test-login.mjs`
Expected: `PASS login returns urbauth cookie` (or `SKIP` if `SHIP_CODE` unset).

- [ ] **Step 4: Commit**

```bash
git add test-helpers.mjs test-login.mjs
git commit -m "add login helper for authenticated tests"
```

---

## Task 2: Authenticate the admin API (finding C1)

**Files:**
- Modify: `desk/app/ecash.hoon` (`handle-http`, top of the routing core)
- Create: `test-admin-auth.mjs`

- [ ] **Step 1: Write the failing test**

Create `test-admin-auth.mjs`:

```js
import { hasCode, adminFetch, SHIP_URL } from './test-helpers.mjs';
let pass = 0, fail = 0;
const check = (n, c) => { c ? (pass++, console.log('PASS', n)) : (fail++, console.log('FAIL', n)); };

// Unauthenticated admin read must be rejected.
check('unauth admin overview -> 401',
  (await fetch(`${SHIP_URL}/apps/ecash/admin/api/overview`)).status === 401);

// Unauthenticated admin write must be rejected.
check('unauth admin ln-configure -> 401',
  (await fetch(`${SHIP_URL}/apps/ecash/admin/api/lightning/configure`,
    { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"type":"none"}' })).status === 401);

// Unauthenticated dashboard must be rejected.
check('unauth admin dashboard -> 401',
  (await fetch(`${SHIP_URL}/apps/ecash/admin`)).status === 401);

// Public Cashu endpoint must stay open.
check('public /v1/keys -> 200',
  (await fetch(`${SHIP_URL}/v1/keys`)).status === 200);

// Authenticated admin must succeed (requires SHIP_CODE).
if (hasCode()) {
  check('auth admin overview -> 200', (await adminFetch('/apps/ecash/admin/api/overview')).status === 200);
} else {
  console.log('SKIP auth admin overview (set SHIP_CODE)');
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
```

- [ ] **Step 2: Run it to confirm it fails**

rebuild + commit, then run: `SHIP_CODE=$SHIP_CODE node test-admin-auth.mjs`
Expected: the three `-> 401` checks FAIL (current code returns 200 for unauthenticated admin).

- [ ] **Step 3: Add the auth gate**

In `desk/app/ecash.hoon`, find the head of `++  handle-http`:

```hoon
    =/  req-body            body.request.req
    =/  route=(list @t)     [method.request.req (parse-request-path url.request.req)]
    ?+  route  :_  st  (give-err eyre-id 404 'not-found')
```

Replace it with (adds the admin gate before dispatch):

```hoon
    =/  req-body            body.request.req
    =/  segs=(list @t)      (parse-request-path url.request.req)
    =/  route=(list @t)     [method.request.req segs]
    ::  Admin surface requires a valid ship session; Cashu /v1, /cred, /services
    ::  stay public by protocol design.
    ?:  ?&  ?=([%apps %ecash %admin *] segs)
            !authenticated.req
        ==
      :_  st  (give-err eyre-id 401 'unauthorized')
    ?+  route  :_  st  (give-err eyre-id 404 'not-found')
```

- [ ] **Step 4: Run it to confirm it passes**

rebuild + commit, then run: `SHIP_CODE=$SHIP_CODE node test-admin-auth.mjs`
Expected: all checks PASS (the auth one SKIPs without `SHIP_CODE`).

- [ ] **Step 5: Keep extension tests green under auth**

`test-cred.mjs` and `test-services.mjs` perform admin setup (keyset generate / service create) that is now authenticated. At the top of each, import the helper and replace their admin `fetch(...)` setup calls with `adminFetch(...)`:

In `test-cred.mjs`, add after the existing imports:

```js
import { adminFetch, hasCode } from './test-helpers.mjs';
if (!hasCode()) { console.log('SKIP test-cred (admin setup needs SHIP_CODE)'); process.exit(0); }
```

Then change each admin call (paths under `/apps/ecash/admin/api/...`) from
`fetch('http://localhost:8080/apps/ecash/admin/api/...', opts)` to
`adminFetch('/apps/ecash/admin/api/...', opts)`. Apply the same two-line guard + `adminFetch`
substitution in `test-services.mjs`.

- [ ] **Step 6: Run the extension suites**

Run: `SHIP_CODE=$SHIP_CODE node test-cred.mjs && SHIP_CODE=$SHIP_CODE node test-services.mjs`
Expected: both suites PASS (or SKIP without `SHIP_CODE`).

- [ ] **Step 7: Commit**

```bash
git add desk/app/ecash.hoon test-admin-auth.mjs test-cred.mjs test-services.mjs
git commit -m "require ship auth on admin endpoints"
```

---

## Task 3: Require the operator on the config poke (finding C1, poke surface)

**Files:**
- Modify: `desk/app/ecash.hoon` (`on-poke`, `%noun` arm)

The `%noun` poke sets the Lightning backend and currently accepts pokes from **any** ship. Restrict it to the host.

- [ ] **Step 1: Add the source guard**

In `desk/app/ecash.hoon`, find the `%noun` poke arm:

```hoon
      %noun
    =/  cmd  !<(ln-backend vase)
    `this(ln-config.state cmd)
  ==
```

Replace with:

```hoon
      %noun
    ?>  =(src.bowl our.bowl)
    =/  cmd  !<(ln-backend vase)
    `this(ln-config.state cmd)
  ==
```

- [ ] **Step 2: Verify it compiles and the operator path still works**

rebuild + commit. In dojo run: `:ecash [%none ~]`
Expected: `|commit` succeeds; the poke is accepted from your own ship (no crash). A poke from a foreign ship would now crash on the `?>` (operator-only), which is the intent.

- [ ] **Step 3: Commit**

```bash
git add desk/app/ecash.hoon
git commit -m "restrict config poke to host ship"
```

---

## Task 4: Remove legacy free-sign endpoints (finding C2a)

**Files:**
- Modify: `desk/app/ecash.hoon` (routing table + two handler arms)
- Create: `test-legacy-removed.mjs`

`post-mint-legacy` signs arbitrary outputs with no quote; `post-melt-legacy` consumes proofs and fakes a paid response. Both are unauthenticated free-value paths. Remove them.

- [ ] **Step 1: Write the failing test**

Create `test-legacy-removed.mjs`:

```js
const BASE = process.env.SHIP_URL || 'http://localhost:8080';
let pass = 0, fail = 0;
const check = (n, c) => { c ? (pass++, console.log('PASS', n)) : (fail++, console.log('FAIL', n)); };
const post = (p) => fetch(`${BASE}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"outputs":[]}' });

check('legacy POST /apps/ecash/mint -> 404', (await post('/apps/ecash/mint')).status === 404);
check('legacy POST /apps/ecash/melt -> 404', (await post('/apps/ecash/melt')).status === 404);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
```

- [ ] **Step 2: Run it to confirm it fails**

rebuild + commit, then run: `node test-legacy-removed.mjs`
Expected: both FAIL (current code returns 200 from the legacy handlers).

- [ ] **Step 3: Remove the two route arms**

In `++  handle-http`, find:

```hoon
        [%'GET' %apps %ecash %info ~]
      :_  st  (get-info eyre-id)
        [%'POST' %apps %ecash %mint ~]
      (post-mint-legacy eyre-id req-body)
        [%'POST' %apps %ecash %melt ~]
      (post-melt-legacy eyre-id req-body)
```

Replace with (keep the info alias, drop the two POSTs):

```hoon
        [%'GET' %apps %ecash %info ~]
      :_  st  (get-info eyre-id)
```

- [ ] **Step 4: Remove the two handler arms**

Delete the `post-mint-legacy` and `post-melt-legacy` arms in full, including the
`::  -- Legacy endpoint handlers (preserved for backward compat) --` comment banner directly
above them. The span starts at that comment and ends at the blank `::` line immediately before
`++  admin-overview`'s `:: ====` banner. The two arms to remove begin:

```hoon
  ++  post-mint-legacy
    |=  [eyre-id=@ta req-body=(unit octs)]
    ^-  (quip card state-9)
    ...
  ++  post-melt-legacy
    |=  [eyre-id=@ta req-body=(unit octs)]
    ^-  (quip card state-9)
    ...
```

After deletion, the `::  Convert a tape …` / `split-tape` helper above and the
`::  ====  Admin API handlers …` banner below should sit adjacent with no dangling references.

- [ ] **Step 5: Run it to confirm it passes**

rebuild + commit, then run: `node test-legacy-removed.mjs`
Expected: both PASS.

- [ ] **Step 6: Commit**

```bash
git add desk/app/ecash.hoon test-legacy-removed.mjs
git commit -m "remove legacy free-sign mint/melt endpoints"
```

---

## Task 5: Make number parsing total (finding S3)

**Files:**
- Modify: `desk/app/ecash.hoon` (`parse-ud`)
- Modify: `desk/tests/test.hoon`
- Create: `test-parse-robustness.mjs`

`parse-ud` uses `scan`, which crashes the whole event on any non-integer JSON number. Switch to `rust` (soft parse) so malformed input degrades to `0`, which existing per-field validation already rejects with a 400.

- [ ] **Step 1: Write the failing Hoon unit tests**

In `desk/tests/test.hoon`, the test core imports are `/+  *test, *bdhke, *curve`. `parse-ud` lives in the agent, not a library, so test the underlying parser behavior directly. Add these arms before the closing `--`:

```hoon
++  test-parse-ud-integer
  ^-  tang
  %+  expect-eq
    !>(`@ud`100)
  !>(`@ud`=/(r (rust "100" (bass 10 (plus dit))) ?~(r 0 u.r)))
++  test-parse-ud-decimal-is-zero
  ^-  tang
  %+  expect-eq
    !>(`@ud`0)
  !>(`@ud`=/(r (rust "1.5" (bass 10 (plus dit))) ?~(r 0 u.r)))
```

> `bass` and `dit` are bare standard-library symbols (always in scope in a Hoon file). These two
> arms mirror the production `parse-ud` body below exactly, so green here proves the production
> change. The `` `@ud` `` casts keep both sides of `expect-eq` the same type.

- [ ] **Step 2: Run them to confirm they fail**

rebuild + commit, then in dojo: `-test /=ecash=/tests/test/hoon`
Expected: the two new arms are present; `test-parse-ud-decimal-is-zero` is the behavior we are
locking in. (If you instead inline the *current* `scan` body it crashes — confirming the bug.)

- [ ] **Step 3: Fix `parse-ud`**

In `desk/app/ecash.hoon`, find:

```hoon
  ++  parse-ud
    |=  t=@t  ^-  @ud
    (scan (trip t) (bass 10 (plus dit)))
```

Replace with:

```hoon
  ++  parse-ud
    |=  t=@t  ^-  @ud
    =/  res  (rust (trip t) (bass 10 (plus dit)))
    ?~(res 0 u.res)
```

- [ ] **Step 4: Write the HTTP robustness test**

Create `test-parse-robustness.mjs`:

```js
const BASE = process.env.SHIP_URL || 'http://localhost:8080';
let pass = 0, fail = 0;
const check = (n, c) => { c ? (pass++, console.log('PASS', n)) : (fail++, console.log('FAIL', n)); };

// A non-integer amount must yield a clean 400, not a crashed event (500/closed).
const r = await fetch(`${BASE}/v1/mint/quote/bolt11`, {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"amount":1.5}',
});
check('amount 1.5 -> 400 invalid-amount', r.status === 400);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
```

> `bolt11` is used because its amount is parsed before any Lightning-backend check, so this test
> needs no LN backend and is independent of the `self` flag.

- [ ] **Step 5: Run both to confirm they pass**

rebuild + commit, then:
- `-test /=ecash=/tests/test/hoon` → the `parse-ud` arms PASS.
- `node test-parse-robustness.mjs` → PASS.

- [ ] **Step 6: Commit**

```bash
git add desk/app/ecash.hoon desk/tests/test.hoon test-parse-robustness.mjs
git commit -m "make parse-ud total so bad numbers 400 instead of crashing"
```

---

## Task 6: Add the `self-method-enabled` flag (state v9→v10)

**Files:**
- Modify: `desk/app/ecash.hoon` (state defs, `versioned-state`, `=|`, helper core `st=`, `on-load`, `init`, admin settings)

Adds a persisted flag (default **off**). No `self` gating yet — that is Task 7. The bunt of `?` is `%.y` (true), so the default **must** be set explicitly in both the migration and `init`.

- [ ] **Step 1: Add the `state-10` type**

In `desk/app/ecash.hoon`, directly after the `+$  state-9  $:  %9 … ==` block, add:

```hoon
+$  state-10
  $:  %10
      keysets=(map @t keyset)
      active-keyset=@t
      spent=(set @t)
      spent-ys=(set @t)
      counter=@ud
      mint-quotes=(map @t mint-quote)
      melt-quotes=(map @t melt-quote)
      ln-config=ln-backend
      pending=(map @ta pending-req)
      total-issued-sats=@ud
      total-redeemed-sats=@ud
      mint-name=@t
      mint-description=@t
      fee-reserve-pct=@ud
      fee-reserve-min=@ud
      quote-ttl-secs=@ud
      cred-keysets=(map @t cred-keyset)
      cred-spent=(set @t)
      cred-counter=@ud
      melt-change=(map @t (list json))
      services=(map @t service)
      self-method-enabled=?
  ==
```

- [ ] **Step 2: Extend `versioned-state`**

Find:

```hoon
+$  versioned-state  $%(state-6 state-7 state-8 state-9)
```

Replace with:

```hoon
+$  versioned-state  $%(state-6 state-7 state-8 state-9 state-10)
```

- [ ] **Step 3: Point the agent at `state-10`**

Find `=|  state-9` (the line just below `^- agent:gall` / `=<`) and replace with `=|  state-10`.

Find the helper-core line `  |_  [=bowl:gall st=state-9]` and replace with `  |_  [=bowl:gall st=state-10]`.

- [ ] **Step 4: Retarget every handler return type**

Replace **all** occurrences of the literal `(quip card state-9)` with `(quip card state-10)`
(≈39 occurrences — the return annotations and one comment). This is a whole-file find/replace of
that exact string. Do **not** touch `+$  state-9`, the `state-8-to-9` migration, or
`^-  state-9` inside it.

- [ ] **Step 5: Add the migration and bump the assert**

In `++  on-load`, find:

```hoon
      =?  prev  ?=(%8 -.prev)  (state-8-to-9 prev)
      ?>  ?=(%9 -.prev)
```

Replace with:

```hoon
      =?  prev  ?=(%8 -.prev)  (state-8-to-9 prev)
      =?  prev  ?=(%9 -.prev)  (state-9-to-10 prev)
      ?>  ?=(%10 -.prev)
```

Then add the migration arm. Find the end of `++  state-8-to-9` (its closing `==` then the `--`
that closes the `|^`) and insert this arm just before that `--`:

```hoon
  ::
  ::  state-9 → state-10: add self-method-enabled, default off (public mint).
  ::
  ++  state-9-to-10
    |=  prev=state-9
    ^-  state-10
    :*  %10
        keysets.prev
        active-keyset.prev
        spent.prev
        spent-ys.prev
        counter.prev
        mint-quotes.prev
        melt-quotes.prev
        ln-config.prev
        pending.prev
        total-issued-sats.prev
        total-redeemed-sats.prev
        mint-name.prev
        mint-description.prev
        fee-reserve-pct.prev
        fee-reserve-min.prev
        quote-ttl-secs.prev
        cred-keysets.prev
        cred-spent.prev
        cred-counter.prev
        melt-change.prev
        services.prev
        %.n
    ==
```

- [ ] **Step 6: Set the default on fresh install**

In `++  init`, find the config defaults block:

```hoon
    =.  fee-reserve-min.st   10
    =.  quote-ttl-secs.st    3.600
```

Replace with (add the explicit `%.n` — the `?` bunt would otherwise be `%.y`):

```hoon
    =.  fee-reserve-min.st       10
    =.  quote-ttl-secs.st        3.600
    =.  self-method-enabled.st   %.n
```

- [ ] **Step 7: Expose the flag in admin settings**

In `++  admin-get-settings`, find:

```hoon
    :~  ['fee_reserve_pct' (numb:enjs:format fee-reserve-pct.st)]
        ['fee_reserve_min' (numb:enjs:format fee-reserve-min.st)]
        ['quote_ttl_secs' (numb:enjs:format quote-ttl-secs.st)]
    ==
```

Replace with:

```hoon
    :~  ['fee_reserve_pct' (numb:enjs:format fee-reserve-pct.st)]
        ['fee_reserve_min' (numb:enjs:format fee-reserve-min.st)]
        ['quote_ttl_secs' (numb:enjs:format quote-ttl-secs.st)]
        ['self_method_enabled' b+self-method-enabled.st]
    ==
```

In `++  admin-update-settings`, find:

```hoon
    =?  quote-ttl-secs.st   (has-key p.jon 'quote_ttl_secs')   (get-num p.jon 'quote_ttl_secs')
    :_  st
```

Replace with:

```hoon
    =?  quote-ttl-secs.st   (has-key p.jon 'quote_ttl_secs')   (get-num p.jon 'quote_ttl_secs')
    =?  self-method-enabled.st  (has-key p.jon 'self_method_enabled')
      (get-bool p.jon 'self_method_enabled')
    :_  st
```

Also add the field to the response object in `admin-update-settings` (the `pairs` list mirrors
`admin-get-settings`): add `['self_method_enabled' b+self-method-enabled.st]` as the final pair.

- [ ] **Step 8: Verify migration + settings round-trip**

rebuild + commit (an existing v9 ship migrates to v10 on load; watch dojo for a clean `|commit`
with no migration crash). Then:

```bash
SHIP_CODE=$SHIP_CODE node -e '
import("./test-helpers.mjs").then(async ({adminFetch}) => {
  const r = await adminFetch("/apps/ecash/admin/api/settings");
  const j = await r.json();
  console.log(j.self_method_enabled === false ? "PASS default off" : "FAIL", j);
  process.exit(j.self_method_enabled === false ? 0 : 1);
});'
```

Expected: `PASS default off`.

- [ ] **Step 9: Confirm no regressions**

Run the existing crypto unit tests: `-test /=ecash=/tests/test/hoon` → all PASS.

- [ ] **Step 10: Commit**

```bash
git add desk/app/ecash.hoon
git commit -m "add self-method-enabled flag, default off (state v10)"
```

---

## Task 7: Gate the `self` method (finding C2b)

**Files:**
- Modify: `desk/app/ecash.hoon` (four POST handlers)
- Create: `test-self-method.mjs`
- Modify: `test-e2e.mjs`, `test-p2pk.mjs` (enable `self` at startup)

- [ ] **Step 1: Write the failing test**

Create `test-self-method.mjs`:

```js
import { hasCode, adminFetch, SHIP_URL } from './test-helpers.mjs';
let pass = 0, fail = 0;
const check = (n, c) => { c ? (pass++, console.log('PASS', n)) : (fail++, console.log('FAIL', n)); };
const setSelf = (on) => adminFetch('/apps/ecash/admin/api/settings',
  { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ self_method_enabled: on }) });
const selfQuote = () => fetch(`${SHIP_URL}/v1/mint/quote/self`,
  { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"amount":4}' });

if (hasCode()) await setSelf(false);
check('self disabled -> 400', (await selfQuote()).status === 400);

if (hasCode()) {
  await setSelf(true);
  check('self enabled -> 200', (await selfQuote()).status === 200);
  await setSelf(false); // restore safe default
} else {
  console.log('SKIP enable/disable round-trip (set SHIP_CODE)');
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
```

- [ ] **Step 2: Run it to confirm it fails**

rebuild + commit, then run: `SHIP_CODE=$SHIP_CODE node test-self-method.mjs`
Expected: `self disabled -> 400` FAILS (the method still works — returns 200).

- [ ] **Step 3: Gate `post-mint-quote`**

In `desk/app/ecash.hoon`, find (in `++  post-mint-quote`):

```hoon
    ?.  |(=('self' method) =('bolt11' method))
      :_  st  (give-err eyre-id 400 'unsupported-method')
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_  st  (give-err eyre-id 400 p.parsed)
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    =/  amount=@ud  (get-num p.jon 'amount')
```

Replace with:

```hoon
    ?.  |(=('self' method) =('bolt11' method))
      :_  st  (give-err eyre-id 400 'unsupported-method')
    ?:  &(=('self' method) !self-method-enabled.st)
      :_  st  (give-err eyre-id 400 'self-method-disabled')
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_  st  (give-err eyre-id 400 p.parsed)
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    =/  amount=@ud  (get-num p.jon 'amount')
```

- [ ] **Step 4: Gate `post-mint-v1`**

Find (in `++  post-mint-v1`):

```hoon
    ?.  |(=('self' method) =('bolt11' method))
      :_  st  (give-err eyre-id 400 'unsupported-method')
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_  st  (give-err eyre-id 400 p.parsed)
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    =/  qid=@t  (get-str p.jon 'quote')
    ?:  =('' qid)
      :_  st  (give-err eyre-id 400 'missing-quote')
    =/  maybe-mq  (~(get by mint-quotes.st) qid)
```

Replace with (same block plus the gate; note the `mint-quotes.st` line makes this anchor unique):

```hoon
    ?.  |(=('self' method) =('bolt11' method))
      :_  st  (give-err eyre-id 400 'unsupported-method')
    ?:  &(=('self' method) !self-method-enabled.st)
      :_  st  (give-err eyre-id 400 'self-method-disabled')
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_  st  (give-err eyre-id 400 p.parsed)
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    =/  qid=@t  (get-str p.jon 'quote')
    ?:  =('' qid)
      :_  st  (give-err eyre-id 400 'missing-quote')
    =/  maybe-mq  (~(get by mint-quotes.st) qid)
```

- [ ] **Step 5: Gate `post-melt-quote`**

Find (in `++  post-melt-quote`):

```hoon
    ?.  |(=('self' method) =('bolt11' method))
      :_  st  (give-err eyre-id 400 'unsupported-method')
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_  st  (give-err eyre-id 400 p.parsed)
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    =/  bolt11=@t  (get-str p.jon 'request')
```

Replace with:

```hoon
    ?.  |(=('self' method) =('bolt11' method))
      :_  st  (give-err eyre-id 400 'unsupported-method')
    ?:  &(=('self' method) !self-method-enabled.st)
      :_  st  (give-err eyre-id 400 'self-method-disabled')
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_  st  (give-err eyre-id 400 p.parsed)
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    =/  bolt11=@t  (get-str p.jon 'request')
```

- [ ] **Step 6: Gate `post-melt-v1`**

Find (in `++  post-melt-v1`):

```hoon
    ?.  |(=('self' method) =('bolt11' method))
      :_  st  (give-err eyre-id 400 'unsupported-method')
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_  st  (give-err eyre-id 400 p.parsed)
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    =/  qid=@t  (get-str p.jon 'quote')
    ?:  =('' qid)
      :_  st  (give-err eyre-id 400 'missing-quote')
    =/  maybe-mq  (~(get by melt-quotes.st) qid)
```

Replace with (the `melt-quotes.st` line makes this anchor unique vs `post-mint-v1`):

```hoon
    ?.  |(=('self' method) =('bolt11' method))
      :_  st  (give-err eyre-id 400 'unsupported-method')
    ?:  &(=('self' method) !self-method-enabled.st)
      :_  st  (give-err eyre-id 400 'self-method-disabled')
    =/  parsed  (parse-object-body req-body)
    ?:  ?=(%| -.parsed)  :_  st  (give-err eyre-id 400 p.parsed)
    =/  jon  p.parsed
    ?>  ?=([%o *] jon)
    =/  qid=@t  (get-str p.jon 'quote')
    ?:  =('' qid)
      :_  st  (give-err eyre-id 400 'missing-quote')
    =/  maybe-mq  (~(get by melt-quotes.st) qid)
```

- [ ] **Step 7: Run the gate test**

rebuild + commit, then run: `SHIP_CODE=$SHIP_CODE node test-self-method.mjs`
Expected: `self disabled -> 400` and (with `SHIP_CODE`) `self enabled -> 200` PASS.

- [ ] **Step 8: Keep the value-token regression suites green**

`test-e2e.mjs` and `test-p2pk.mjs` mint via `self`, so they must enable it first. At the very top
of each (after existing imports), add:

```js
import { adminFetch, hasCode } from './test-helpers.mjs';
if (!hasCode()) { console.log('SKIP (needs SHIP_CODE to enable self-mint)'); process.exit(0); }
await adminFetch('/apps/ecash/admin/api/settings',
  { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ self_method_enabled: true }) });
```

- [ ] **Step 9: Run the regression suites**

rebuild not needed (test-only change). Run:
`SHIP_CODE=$SHIP_CODE node test-e2e.mjs && SHIP_CODE=$SHIP_CODE node test-p2pk.mjs`
Expected: both PASS (they now enable `self` before minting).

- [ ] **Step 10: Commit**

```bash
git add desk/app/ecash.hoon test-self-method.mjs test-e2e.mjs test-p2pk.mjs
git commit -m "gate self mint/melt behind self-method-enabled flag"
```

---

## Task 8: Wire tests and update docs

**Files:**
- Modify: `package.json`, `Makefile`, `README.md`

- [ ] **Step 1: Add npm scripts**

In `package.json`, add to `"scripts"`:

```json
    "test:security": "node test-admin-auth.mjs && node test-legacy-removed.mjs && node test-parse-robustness.mjs && node test-self-method.mjs",
    "test:login": "node test-login.mjs"
```

- [ ] **Step 2: Add a Make target**

In `Makefile`, add `test-security` to `.PHONY` and add the target:

```make
# Phase 1 security regression (set SHIP_CODE for the authenticated paths)
test-security:
	node test-admin-auth.mjs
	node test-legacy-removed.mjs
	node test-parse-robustness.mjs
	node test-self-method.mjs
```

- [ ] **Step 3: Update the README**

In `README.md`:
- In the State section, change "version 9" to "version 10" and add a `self_method_enabled`
  row: `| self-method-enabled | ? | Whether the no-payment 'self' mint/melt method is enabled (default off) |`.
- In the Mint Methods section, note: "`self` is **disabled by default** on a value-bearing mint.
  Enable it for testing via the admin dashboard (Settings) or
  `POST /apps/ecash/admin/api/settings {"self_method_enabled": true}` (authenticated)."
- Add a line to the Admin section: "All `/apps/ecash/admin/*` routes require a valid ship
  session; unauthenticated requests receive 401."
- Note that the legacy `POST /apps/ecash/mint` and `/apps/ecash/melt` endpoints have been removed.

- [ ] **Step 4: Run the full security suite**

Run: `SHIP_CODE=$SHIP_CODE npm run test:security`
Expected: all four suites PASS.

- [ ] **Step 5: Commit**

```bash
git add package.json Makefile README.md
git commit -m "wire phase 1 security tests and update docs"
```

---

## Acceptance criteria (Phase 1 done)

- Unauthenticated `/apps/ecash/admin/*` → 401; authenticated → 200.
- The config poke is rejected from any ship but the host.
- `POST /apps/ecash/mint` and `/apps/ecash/melt` → 404.
- `{"amount":1.5}` → 400, no crashed event; `parse-ud` unit tests pass.
- `self` mint/melt → 400 when disabled (the default); works only after an authenticated enable.
- A v9 ship migrates to v10 cleanly; existing crypto unit tests and (with `SHIP_CODE`) the e2e,
  p2pk, cred, and services suites pass.

## Self-review notes

- **Spec coverage:** C1 → Tasks 2–3; C2a → Task 4; C2b → Tasks 6–7; S3 → Task 5. The Phase 1
  acceptance criteria in the spec are all covered.
- **Deferred to later phases (intentionally):** `/v1/info` still advertises `self` even when
  disabled — corrected in Phase 2 (conformance), since `info` shape is being audited there
  anyway. S1/S4/S5 are Phase 4. The extension split is Phase 3.
- **Type consistency:** the flag is `self-method-enabled=?` in Hoon and `self_method_enabled`
  (boolean) in JSON everywhere; the state type is `state-10` consistently after Task 6.
