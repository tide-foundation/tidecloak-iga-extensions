# IGA E2E Harness (Playwright API tests)

Reusable Playwright **API-test** harness for the Tidecloak IGA approval
workflow. These are API tests (Playwright's `APIRequestContext`), **not**
browser UI tests — the IGA capture is enforced at the model layer, so raw
Admin REST exercises the exact production path any caller hits, deterministically.

## One-line run

```
cd /home/sasha/project/tidecloak-iga-extensions/e2e && npx playwright test
```

(First time only: `npm i` and `npx playwright install chromium`.)

## What it does

- `tests/phase1-role-governance.spec.ts` — Phase 1: governed realm + client
  role create (with composites) → 202 + `Location` → CR `PENDING` →
  authorize + commit → post-commit fidelity (description, attributes,
  realm + client composites) for both `r-parent` and `acme:c-parent`.
  Uses a self-contained scratch realm `iga-phase1-e2e` (delete-if-exists,
  re-runnable; torn down in `afterAll` even on failure).

## Precondition gate

Every scenario first runs `lib/precondition.ts`, which stands up a throwaway
IGA realm and performs a governed composite create. It distinguishes:

- `UNREACHABLE` — Keycloak/token unavailable
- `IGA_NOT_ENABLED` — probe realm/toggle setup failed
- `PHASE1_NOT_LOADED` — governed create didn't 202 (e.g. 500 from a broken
  provider jar, 201 bare-create slip-through, missing Location, or dropped
  composites)
- `OK` — Phase 1 is live

On a non-`OK` verdict the test fails fast with the exact restart-and-rerun
command. This is **not** a scenario failure — it means the running container
isn't serving a working Phase 1 build.

## Config / env overrides

- `KC_BASE_URL` (default `http://localhost:8080`)
- `KC_ADMIN_USER` / `KC_ADMIN_PASSWORD` (default: read from the localtest
  `docker-compose.yml` `KC_BOOTSTRAP_ADMIN_*`)
- `KC_COMPOSE_FILE` (default localtest compose path)

The admin password is never logged.

## Reusable helpers (`lib/kc.ts`)

`adminToken`, `kcFetch`, `safeJson`, `createScratchRealm`, `deleteRealm`,
`realmExists`, `enableIga`, `igaStatus`, `createRole`, `createClientRole`,
`createClient`, `clientUuid`, `getRole`, `getClientRole`, `getRoleComposites`,
`getClientRoleComposites`, `findChangeRequest`, `getChangeRequest`,
`authorizeAndCommit`, `locationHeader`. Phase 2/3/4 specs should reuse these.
