# Operator Dashboards Implementation Plan

**Goal:** Two full-featured, single-file operator dashboards — one per agent (`%ecash` value mint, `%ecash-services` access control) — sharing a design language, with auto-refresh on Overview.

**Architecture:** Each dashboard is a self-contained HTML+CSS+JS file in a `.txt`, imported into its agent via `/*` and served at the agent's auth-gated `/apps/<agent>/admin` route. The services dashboard is built fresh by copying the proven design system (CSS + `req()`/tab/toast helpers) from the existing `%ecash` dashboard and retheming orange→teal; the `%ecash` dashboard is edited in place (remove dead Services tab, add the `self` kill-switch + liability Overview + auto-refresh). No new backend endpoints except one HTML route on `%ecash-services`.

**Tech Stack:** Vanilla HTML/CSS/JS (no build, no deps); Hoon Gall agents; Node smoke tests; the live `~zod` dev ship.

---

## Prerequisites & loop

- Reference file (design conventions, CSS, `req()`, tabs, toasts, table/card rendering): `desk/app/dashboard.txt`. READ IT before building the services dashboard — copy its patterns.
- Spec: `docs/design/specs/2026-06-05-operator-dashboards-design.md` (tab → endpoint map).
- Deploy via the project's mount + commit workflow (see README); committing auto-reloads.
- Cookie: `URBAUTH_COOKIE='urbauth-~zod=0v...'` (your ship's admin session cookie).
- These dashboards are HTML; automated tests are **route smoke tests** (200 with cookie / 401 without / `text/html`) plus **manual** tab verification in a browser logged into the ship. No DOM testing (per spec non-goals).

## File structure

- `desk-services/app/dashboard.txt` — **new** services dashboard (Overview/Services/Credentials).
- `desk-services/app/ecash-services.hoon` — **modify**: add `/*` import + `GET /apps/ecash-services/admin` route.
- `desk/app/dashboard.txt` — **modify**: remove Services tab, add `self` toggle + liability Overview + auto-refresh.
- `test-dashboards.mjs` — **new** smoke test for both dashboard routes.
- `package.json` — **modify**: add `test:dashboards`.

---

## Task 1: Smoke test for dashboard routes (write first; drives Tasks 2 + 6)

**Files:** Create `test-dashboards.mjs`

- [ ] **Step 1: Write the smoke test**

```js
import { adminFetch, hasAuth, SHIP_URL } from './test-helpers.mjs';
let pass = 0, fail = 0;
const check = (n, c) => { c ? (pass++, console.log('PASS', n)) : (fail++, console.log('FAIL', n)); };

// %ecash dashboard (already routed) — must stay served + gated.
check('GET /apps/ecash/admin unauth -> 401',
  (await fetch(`${SHIP_URL}/apps/ecash/admin`)).status === 401);
if (hasAuth()) {
  const r = await adminFetch('/apps/ecash/admin');
  check('GET /apps/ecash/admin auth -> 200 html',
    r.status === 200 && (r.headers.get('content-type') || '').includes('text/html'));
}

// %ecash-services dashboard (new route in Task 2).
check('GET /apps/ecash-services/admin unauth -> 401',
  (await fetch(`${SHIP_URL}/apps/ecash-services/admin`)).status === 401);
if (hasAuth()) {
  const r = await adminFetch('/apps/ecash-services/admin');
  check('GET /apps/ecash-services/admin auth -> 200 html',
    r.status === 200 && (r.headers.get('content-type') || '').includes('text/html'));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
```

- [ ] **Step 2: Run it (services route fails, ecash passes)**

Run: `URBAUTH_COOKIE=$URBAUTH_COOKIE node test-dashboards.mjs`
Expected: the two `/apps/ecash/admin` checks PASS; the `/apps/ecash-services/admin auth -> 200` check FAILS (route doesn't exist yet → currently 404, not 200). The unauth services check passes (the admin gate returns 401 for any `/apps/ecash-services/admin*`).

- [ ] **Step 3: Commit**

```bash
git add test-dashboards.mjs
git commit -m "add dashboard route smoke test"
```

---

## Task 2: Serve a placeholder services dashboard (route + import)

**Files:** Modify `desk-services/app/ecash-services.hoon`; Create `desk-services/app/dashboard.txt`

- [ ] **Step 1: Create a minimal placeholder `desk-services/app/dashboard.txt`**

```html
<!doctype html><html><head><meta charset="utf-8"><title>ecash-services admin</title></head>
<body style="background:#0b0e11;color:#e5e7eb;font-family:system-ui"><h1>ecash-services admin</h1>
<p>dashboard placeholder</p></body></html>
```

- [ ] **Step 2: Add the `/*` import at the top of `desk-services/app/ecash-services.hoon`**

Find the import block near the top:
```hoon
/-  *ecash-services
/+  default-agent, dbug, *bdhke
```
Change it to add the dashboard import (so `dashboard-lines` is in scope):
```hoon
/-  *ecash-services
/+  default-agent, dbug, *bdhke
/*  dashboard-lines  %txt  /app/dashboard/txt
```

- [ ] **Step 3: Add the HTML route in `++ handle-http`**

In `desk-services/app/ecash-services.hoon`, the `handle-http` routing table begins `?+ route :_ st (give-err eyre-id 404 'not-found')`. Add this arm immediately after that line (it is under the admin prefix, so the existing `?: ?&(?=([%apps %ecash-services %admin *] segs) !authenticated.req)` gate already protects it):
```hoon
        [%'GET' %apps %ecash-services %admin ~]
      :_  st
      (give-http eyre-id 200 [['content-type' 'text/html'] ~] `(as-octs:mimes:html (rap 3 (join `@t`10 `wain`dashboard-lines))))
```

- [ ] **Step 4: Deploy and confirm the smoke test passes**

Run: `/tmp/ecash-services-deploy.sh` → `commit: Commit successful!`
Run: `URBAUTH_COOKIE=$URBAUTH_COOKIE node test-dashboards.mjs`
Expected: `4 passed, 0 failed` (the services route now returns 200 html with cookie, 401 without).

- [ ] **Step 5: Commit**

```bash
git add desk-services/app/ecash-services.hoon desk-services/app/dashboard.txt
git commit -m "serve %ecash-services admin dashboard route (placeholder)"
```

---

## Task 3: Services dashboard shell (design system, copied + rethemed)

**Files:** Modify `desk-services/app/dashboard.txt`

- [ ] **Step 1: Build the shell by copying the proven design system**

Read `desk/app/dashboard.txt`. Copy into `desk-services/app/dashboard.txt`: the `<head>`/`<style>` block (CSS), the `req(path, opts)` fetch helper, the tab-switching JS, the toast/error banner, and `copyText()`. Then adapt:
- Title → "ecash-services admin"; `<h1>` → "Ecash Services".
- Accent: change the orange `#f7931a` accent to teal `#14b8a6` throughout the CSS (the `.tab.on`, buttons, badges, headers). Keep the dark background.
- `req()` base path → `/apps/ecash-services/admin/api` (the ecash one uses `/apps/ecash/admin/api`).
- Tab bar with three tabs only: `<button class="tab on" data-tab="ov">Overview</button>`, `<button class="tab" data-tab="sv">Services</button>`, `<button class="tab" data-tab="cr">Credentials</button>`, and three matching `<div class="panel">` containers with ids `ov`/`sv`/`cr`.
- Wire tab switching so entering a tab calls its loader (`loadOverview`/`loadServices`/`loadCreds`) and leaving Overview stops auto-refresh (Task 4 adds the helper).

- [ ] **Step 2: Add the shared auto-refresh helper (used by Overview here and in `%ecash`)**

Add this JS (it is the one genuinely new reusable piece — identical in both dashboards):
```js
let _ar = null, _arAt = 0;
function startAuto(loader, sec) {
  stopAuto();
  if (!document.getElementById('autorefresh')?.checked) return;
  _ar = setInterval(() => loader(true), (sec || 10) * 1000);
}
function stopAuto() { if (_ar) { clearInterval(_ar); _ar = null; } }
function stampUpdated() {
  _arAt = Date.now();
  const el = document.getElementById('updated'); if (el) el.textContent = 'updated just now';
}
setInterval(() => {
  const el = document.getElementById('updated');
  if (el && _arAt) { const s = Math.round((Date.now() - _arAt) / 1000); el.textContent = `updated ${s}s ago`; }
}, 1000);
```
The Overview panel's header includes `<label><input type="checkbox" id="autorefresh" checked> auto-refresh</label> <span id="updated"></span>`, and toggling the checkbox calls `startAuto(loadOverview)`/`stopAuto()`.

- [ ] **Step 3: Deploy + verify it loads**

Run: `/tmp/ecash-services-deploy.sh`; then load `http://localhost:8080/apps/ecash-services/admin` in a browser logged into the ship — confirm the teal-themed shell renders with three tabs and no console errors (tabs may be empty until Tasks 4-6).
Run the smoke test again: `URBAUTH_COOKIE=$URBAUTH_COOKIE node test-dashboards.mjs` → 4 passed.

- [ ] **Step 4: Commit**

```bash
git add desk-services/app/dashboard.txt
git commit -m "services dashboard shell (teal design system + auto-refresh helper)"
```

---

## Task 4: Services dashboard — Overview tab (+ auto-refresh)

**Files:** Modify `desk-services/app/dashboard.txt`

- [ ] **Step 1: Implement `loadOverview(silent)`**

Fetch in parallel and render summary cards (follow `desk/app/dashboard.txt`'s `loadOverview` card markup):
```js
async function loadOverview(silent) {
  try {
    const [cred, svcs] = await Promise.all([
      req('/cred/overview'), req('/services'),
    ]);
    const services = svcs.services || [];
    const active = services.filter(s => s.active).length;
    const issued = services.reduce((a, s) => a + (s.issued || 0), 0);
    const redeemed = services.reduce((a, s) => a + (s.redeemed || 0), 0);
    // render cards: services active/${services.length}, cred keysets ${cred.cred_keysets},
    // credentials issued ${cred.cred_issued}, spent ${cred.cred_spent}, issued ${issued}, redeemed ${redeemed}
    // and a per-service issuance gauge list (issued / max_issuance when set).
    stampUpdated();
  } catch (e) { if (!silent) toast(e.message); }
}
```
On entering Overview: call `loadOverview()` then `startAuto(loadOverview)`. The `/cred/overview` response has `cred_keysets`, `cred_issued`, `cred_spent`; `/services` returns `{services:[{name,title,active,issued,redeemed,max_issuance,expires,allowlist_count,...}]}`.

- [ ] **Step 2: Deploy + verify**

`/tmp/ecash-services-deploy.sh`; load the dashboard, confirm Overview shows the stats and the "updated Ns ago" label ticks; untick auto-refresh → it stops.

- [ ] **Step 3: Commit**

```bash
git add desk-services/app/dashboard.txt
git commit -m "services dashboard: Overview tab with auto-refresh"
```

---

## Task 5: Services dashboard — Services tab (CRUD + allowlist)

**Files:** Modify `desk-services/app/dashboard.txt`

- [ ] **Step 1: Implement the Services tab**

`loadServices()` → `req('/services')`, render one card per service (follow the existing dashboard's service-card markup), each showing: name, title/description, active/inactive + expired badges, issuance gauge (`issued`/`max_issuance`), `allowlist_count` + required badge, and buttons. Provide a "Create service" form and these actions (each `POST` via `req(path,{method:'POST',body:JSON.stringify(payload)})`, then reload):
```js
const createService = () => req('/services/create', {method:'POST', body: JSON.stringify({
  name: val('svc-name'), title: val('svc-title'), description: val('svc-desc'),
  ...(val('svc-expires') ? {expires: Number(val('svc-expires'))} : {}),
  ...(val('svc-max') ? {max_issuance: Number(val('svc-max'))} : {}),
})}).then(loadServices).catch(e=>toast(e.message));
const updateService = (name, patch) => req('/services/update', {method:'POST', body: JSON.stringify({name, ...patch})}).then(loadServices);
const activateService   = name => req('/services/activate',   {method:'POST', body: JSON.stringify({name})}).then(loadServices);
const deactivateService = name => guard(`Deactivate "${name}"?`, () => req('/services/deactivate', {method:'POST', body: JSON.stringify({name})}).then(loadServices));
const deleteService     = name => guard(`Delete "${name}"? (only if inactive & never issued)`, () => req('/services/delete', {method:'POST', body: JSON.stringify({name})}).then(loadServices));
const addKey    = (name, key) => req('/services/allowlist/add',    {method:'POST', body: JSON.stringify({name, key})}).then(loadServices);
const removeKey = (name, key) => guard('Revoke this access key?', () => req('/services/allowlist/remove', {method:'POST', body: JSON.stringify({name, key})}).then(loadServices));
```
where `val(id)` reads an input, and `guard(msg, fn)` is `if (confirm(msg)) fn()`. The admin `/services` list returns the plaintext `allowlist` array per service — render each key with a copy + revoke button (admin-only view).

- [ ] **Step 2: Deploy + manual verify the full lifecycle**

`/tmp/ecash-services-deploy.sh`; in the browser: create a service, add an allowlist key (copy it), deactivate, delete; confirm the guards prompt and the list refreshes. Then run the services regression to confirm nothing broke:
`URBAUTH_COOKIE=$URBAUTH_COOKIE node test-services.mjs` → 34 passed.

- [ ] **Step 3: Commit**

```bash
git add desk-services/app/dashboard.txt
git commit -m "services dashboard: Services tab (CRUD + allowlist management)"
```

---

## Task 6: Services dashboard — Credentials tab

**Files:** Modify `desk-services/app/dashboard.txt`

- [ ] **Step 1: Implement the Credentials tab**

`loadCreds()` → `req('/cred/overview')` → render the keyset list (`keysets:[{id,active}]`) with a Generate button and per-keyset Activate/Deactivate:
```js
const genCredKs   = ()   => req('/cred/keysets/generate',   {method:'POST'}).then(loadCreds).catch(e=>toast(e.message));
const actCredKs   = id   => req('/cred/keysets/activate',   {method:'POST', body: JSON.stringify({id})}).then(loadCreds);
const deactCredKs = id   => req('/cred/keysets/deactivate', {method:'POST', body: JSON.stringify({id})}).then(loadCreds);
```
Show `cred_issued`/`cred_spent` totals at the top.

- [ ] **Step 2: Deploy + verify**

`/tmp/ecash-services-deploy.sh`; generate a cred keyset, toggle active; confirm. `node test-cred.mjs` (with cookie) → 28 passed (cred suite still green).

- [ ] **Step 3: Commit**

```bash
git add desk-services/app/dashboard.txt
git commit -m "services dashboard: Credentials tab"
```

---

## Task 7: `%ecash` dashboard — remove the dead Services tab

**Files:** Modify `desk/app/dashboard.txt`

- [ ] **Step 1: Remove the Services tab + its code**

In `desk/app/dashboard.txt`: delete the `<button class="tab tab-svc" data-tab="sv">Services</button>` tab button, the entire `<div ...id="sv">` Services panel (the create-service form + list), the `loadServices()` / `createService()` / service-action JS functions, the services summary card on Overview, and any `tab-svc`/`rbtn-svc`/`btn-svc` CSS that's now unused. Grep to confirm nothing references the removed functions: `grep -n "loadServices\|createService\|tab-svc\|/services\|/admin/api/services" desk/app/dashboard.txt` → no live references remain.

- [ ] **Step 2: Deploy + verify**

`/tmp/ecash-deploy.sh`; load `http://localhost:8080/apps/ecash/admin` — confirm six tabs (Overview, Keysets, Quotes, Tokens, Lightning, Info), no Services, no console errors. Smoke test still green: `URBAUTH_COOKIE=$URBAUTH_COOKIE node test-dashboards.mjs`.

- [ ] **Step 3: Commit**

```bash
git add desk/app/dashboard.txt
git commit -m "ecash dashboard: remove dead Services tab (moved to %ecash-services)"
```

---

## Task 8: `%ecash` dashboard — self kill-switch in Settings

**Files:** Modify `desk/app/dashboard.txt`

- [ ] **Step 1: Add the toggle to the Settings form**

The Settings form (Overview/Settings area) reads/writes via `GET`/`POST /settings`. The response now includes `self_method_enabled` (boolean). In the Settings render, after the quote-TTL field, add:
```html
<div class="srow danger">
  <label><input type="checkbox" id="self-enabled"> Enable <code>self</code> mint/melt</label>
  <span class="warn">⚠ lets anyone mint tokens with no payment — testing only; leave OFF in production</span>
</div>
```
In `loadSettings()`, set `document.getElementById('self-enabled').checked = !!s.self_method_enabled;`. In `updateSettings()`, include it in the POST body, guarded when turning it ON:
```js
const selfOn = document.getElementById('self-enabled').checked;
if (selfOn && !confirm('Enable self-mint? Anyone can then mint tokens for free. Testing only.')) return;
const body = { fee_reserve_pct: ..., fee_reserve_min: ..., quote_ttl_secs: ..., self_method_enabled: selfOn };
await req('/settings', {method:'POST', body: JSON.stringify(body)});
```
Add a `.danger`/`.warn` CSS rule (red-tinted) if not present.

- [ ] **Step 2: Deploy + verify the round-trip**

`/tmp/ecash-deploy.sh`; in the browser toggle self on (confirm prompt) → Save → reload → it persists; toggle off → Save. Then verify the flag is OFF at the API and self-mint refused:
```bash
URBAUTH_COOKIE=$URBAUTH_COOKIE node -e "import('./test-helpers.mjs').then(async({adminFetch})=>{await adminFetch('/apps/ecash/admin/api/settings',{method:'POST',headers:{'content-type':'application/json'},body:'{\"self_method_enabled\":false}'});const j=await(await adminFetch('/apps/ecash/admin/api/settings')).json();console.log('self off:',j.self_method_enabled===false)})"
URBAUTH_COOKIE=$URBAUTH_COOKIE node test-self-method.mjs | tail -1
```
Expected: `self off: true`; `test-self-method` → 3 passed (it sets the flag via the same endpoint the dashboard uses).

- [ ] **Step 3: Commit**

```bash
git add desk/app/dashboard.txt
git commit -m "ecash dashboard: self-method kill-switch in Settings"
```

---

## Task 9: `%ecash` dashboard — liability Overview + auto-refresh

**Files:** Modify `desk/app/dashboard.txt`

- [ ] **Step 1: Add the auto-refresh helper (same as Task 3 Step 2)**

Copy the identical `startAuto`/`stopAuto`/`stampUpdated` block (and the 1s "updated Ns ago" ticker) from Task 3 Step 2 into `desk/app/dashboard.txt`. Add `<label><input type="checkbox" id="autorefresh" checked> auto-refresh</label> <span id="updated"></span>` to the Overview header.

- [ ] **Step 2: Beef up `loadOverview()`**

`/overview` already returns `total_issued_sats`, `total_redeemed_sats`, `counter` (tokens issued), `spent_count`, `spent_ys_count`, `keyset_count`, `active_keyset`, `pending_requests`, `mint_quotes`/`melt_quotes` tallies, `ln_backend`. Add a prominent **liability** card: `outstanding = total_issued_sats − total_redeemed_sats`, shown with issued/redeemed; keep the existing cards. At the end of `loadOverview` call `stampUpdated()`. On entering Overview: `loadOverview(); startAuto(loadOverview);`; on leaving Overview or unticking: `stopAuto()`.

- [ ] **Step 3: Deploy + verify**

`/tmp/ecash-deploy.sh`; load Overview — confirm the outstanding/liability figure, the "updated Ns ago" ticking, and that switching to another tab stops the polling (watch the network tab or the ticker freezing).

- [ ] **Step 4: Commit**

```bash
git add desk/app/dashboard.txt
git commit -m "ecash dashboard: liability Overview + auto-refresh"
```

---

## Task 10: Wire the smoke test + final pass

**Files:** Modify `package.json`

- [ ] **Step 1: Add the npm script**

In `package.json` `"scripts"`, add: `"test:dashboards": "node test-dashboards.mjs"`.

- [ ] **Step 2: Full verification**

```bash
URBAUTH_COOKIE=$URBAUTH_COOKIE npm run test:dashboards   # 4 passed
URBAUTH_COOKIE=$URBAUTH_COOKIE node test-services.mjs | tail -1   # 34 passed
URBAUTH_COOKIE=$URBAUTH_COOKIE node test-cred.mjs | tail -1       # 28 passed
URBAUTH_COOKIE=$URBAUTH_COOKIE node test-self-method.mjs | tail -1 # 3 passed
```
Manual: open both dashboards in a browser logged into the ship; click every tab; do one write per tab; confirm auto-refresh ticks on Overview and pauses off-tab; confirm the `self` toggle and destructive-action confirms work.

- [ ] **Step 3: Commit**

```bash
git add package.json
git commit -m "wire dashboards smoke test"
```

---

## Acceptance criteria

- `GET /apps/ecash/admin` and `GET /apps/ecash-services/admin` → 200 `text/html` with the ship cookie, 401 without.
- `%ecash` dashboard: six tabs, no Services; Settings has the `self` kill-switch (guarded, persists); Overview shows outstanding/liability and auto-refreshes (pausing off-tab).
- `%ecash-services` dashboard (teal): Overview (stats + auto-refresh), Services (create/edit/activate/deactivate/delete + allowlist add/remove/copy, guarded), Credentials (keyset generate/activate/deactivate).
- All existing suites stay green (services 34, cred 28, self-method 3); `npm run test:dashboards` passes.

## Self-review notes

- **Spec coverage:** two dashboards (Tasks 2-6 services, 7-9 ecash); shared design language (Task 3 copies it); auto-refresh on Overview (Tasks 4, 9); self kill-switch (Task 8); liability Overview (Task 9); allowlist mgmt (Task 5); new HTML route only (Task 2); smoke tests (Tasks 1, 10). All spec sections map to tasks.
- **No new backend endpoints** beyond the one services HTML route — every dashboard action uses an existing admin endpoint (verified against the spec's tab→endpoint map).
- **Consistency:** the `startAuto/stopAuto/stampUpdated` helper and `req()`/tab/toast patterns are identical across both files by copying; accent differs (orange vs teal).
