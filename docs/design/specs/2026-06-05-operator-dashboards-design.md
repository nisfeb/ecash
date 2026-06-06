# Operator Dashboards — Design

- **Date:** 2026-06-05
- **Status:** Draft for review
- **Scope:** Full-featured operator admin dashboards for the two-agent ecash mint.

## Decisions (locked)

1. **Two separate dashboards**, one per agent — each scoped to and served by its own agent,
   authenticated by the ship cookie (the admin routes are already auth-gated).
2. **Vanilla single-file** per dashboard (HTML+CSS+JS in a `.txt` imported via `/*`). No build
   step, no external deps, no CDN fetches. Matches the existing dashboard.
3. **Approach A:** extend the existing `%ecash` dashboard in place (it works); build the
   `%ecash-services` dashboard fresh against the same design language.
4. **Auto-refresh on the Overview tab** of both dashboards (toggle + "last updated"; polls only
   while Overview is active).

## Context

- `desk/app/dashboard.txt` (1,235 lines) is the existing `%ecash` dashboard, imported via
  `/*  dashboard-lines  %txt  /app/dashboard/txt` and served at `GET /apps/ecash/admin`. Tabs:
  Overview, Keysets, Quotes, Tokens, Lightning, **Services** (now broken), Info.
- Phase 3 moved credentials + services to the `%ecash-services` agent, so the dashboard's
  Services tab calls `/apps/ecash/admin/api/services`, which no longer exists. `%ecash-services`
  has no dashboard at all.
- Both agents' admin APIs already exist and are auth-gated; **no new backend endpoints are
  needed** beyond one HTML-serving route on `%ecash-services`.

## Shared design language (kept identical by convention across the two files)

- Dark theme; small inlined CSS; a `req(path, opts)` fetch helper that sends the cookie and
  parses JSON, surfacing non-200 `detail` as a toast.
- Tab system (buttons switch panels; only the active tab's loader runs).
- Toast/error banner, copy-to-clipboard, confirm-guard helper for destructive actions.
- Accent: **orange `#f7931a`** for `%ecash` (value-bearing), **teal `#14b8a6`** for
  `%ecash-services` (access). Headers/badges use the agent's accent.
- Auto-refresh helper: `setInterval` started when Overview is shown, cleared on tab switch or
  when the toggle is off; default interval 10s; shows a relative "updated Ns ago".

## Dashboard 1 — `%ecash` (value mint)

File `desk/app/dashboard.txt`, route `GET /apps/ecash/admin` (unchanged). Orange theme.

| Tab | Data source (admin API) | Actions |
|---|---|---|
| **Overview** | `GET /overview`, `GET /settings` | read-only; **auto-refresh**. Surfaces: outstanding sats = `total_issued_sats − total_redeemed_sats` (liability), issued/redeemed, tokens issued (`counter`), spent counts, active keyset, keyset count, LN backend, pending requests, mint/melt quote tallies, `self` enabled badge. |
| **Keysets** | `GET /keysets`, `GET /keysets/{id}` | `POST /keysets/generate`, `/activate`, `/deactivate`, `/set-fee` |
| **Quotes** | `GET /quotes` | `POST /quotes/delete`; client-side filter (all/mint/melt/unpaid/paid/issued) |
| **Tokens** | `GET /spent` | `POST /spent/check` (secret or Y) |
| **Lightning** | `GET /lightning` | `POST /lightning/configure` (lnbits/lnd/none), `/lightning/test` |
| **Settings** | `GET /settings` | `POST /settings` — fee_reserve_pct, fee_reserve_min, quote_ttl_secs, **`self_method_enabled`** (the security kill-switch: prominent, default-off, with a "lets anyone mint for free — testing only" warning) |
| **Info** | `GET /info` | `POST /info/update` (name, description); shows supported NUTs |

Changes vs. the existing file: remove the **Services** tab and its loaders; add the
`self_method_enabled` toggle to Settings; beef up Overview (liability framing + auto-refresh).
All endpoint paths are under `/apps/ecash/admin/api`.

## Dashboard 2 — `%ecash-services` (access control)

File `desk-services/app/dashboard.txt` (**new**), served at a **new** `GET /apps/ecash-services/admin`
route (add `/*  dashboard-lines  %txt  /app/dashboard/txt` import + the route arm to the agent).
Teal theme.

| Tab | Data source (`/apps/ecash-services/admin/api`) | Actions |
|---|---|---|
| **Overview** | `GET /cred/overview`, `GET /services` | read-only; **auto-refresh**. Services active/inactive, cred keyset count, credentials issued/spent, per-service issuance gauges (issued / max_issuance). |
| **Services** | `GET /services`, `GET /services/{name}` | `POST /services/create` (name, title, description, expires?, max_issuance?), `/services/update`, `/services/activate`, `/services/deactivate`, `/services/delete` (guarded: only when inactive + never issued), `/services/allowlist/add`, `/services/allowlist/remove`. Per-service card shows active/expired badges, issuance gauge, and an inline allowlist panel (paste/copy/revoke plaintext keys — admin-only view). |
| **Credentials** | `GET /cred/overview` | `POST /cred/keysets/generate`, `/cred/keysets/activate`, `/cred/keysets/deactivate`. Raw cred-keyset management for power users. |

## Auto-refresh behavior

- A checkbox on the Overview tab (default **on**) and a "updated Ns ago" label.
- `setInterval(loadOverview, 10000)` started on entering Overview; cleared on leaving Overview
  or unchecking. No polling on other tabs. Survives transient fetch errors (logs a toast, keeps
  polling).

## Error handling

- `req()` centralizes: network error → toast "network error"; non-200 → toast with the JSON
  `detail`; 401 → toast "session expired — reload and log in to the ship".
- Destructive actions (keyset deactivate, quote delete, service delete, allowlist remove,
  setting `self_method_enabled` on) go through a `confirm()` guard with a specific message.

## Non-goals

- No charts/graphs library (numbers + simple gauges only).
- No build pipeline, framework, or external assets.
- No mobile-specific layout (responsive-enough, but desktop-first operator tool).
- No new backend endpoints beyond the one `%ecash-services` HTML route.
- The two files are kept consistent by convention, not a runtime-shared asset.

## Testing

- **Smoke (automated):** a JS test that `GET /apps/ecash/admin` and `GET /apps/ecash-services/admin`
  return `200 text/html` (with cookie), `401` without; and that each admin data endpoint the
  dashboards call returns the expected JSON shape. (No DOM testing.)
- **Manual:** load each dashboard in a browser logged into the ship; exercise each tab's
  read + one representative write; confirm auto-refresh ticks and pauses off-tab.

## Build / deploy

- `%ecash`: edit `desk/app/dashboard.txt` (already imported + routed).
- `%ecash-services`: add `desk-services/app/dashboard.txt`, the `/*` import, and the
  `GET /apps/ecash-services/admin` route arm; deploy via the existing helper.
