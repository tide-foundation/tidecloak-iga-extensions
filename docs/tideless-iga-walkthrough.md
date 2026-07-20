# TideCloak IGA — Developer Walkthrough

A click-by-click walkthrough of **tideless IGA** (the capture-then-veto governance
layer for Keycloak admin actions). Each section has a screenshot with a thin red
outline pointing at what to look at, plus exact **Click** / **Type** instructions.

Companion docs:
- [`IGA.md`](IGA.md) — concepts + design
- [`EXTENDING-IGA.md`](EXTENDING-IGA.md) — extending the pipeline
- [`iga-tve-producer-design.md`](iga-tve-producer-design.md) — the IGA→TVE producer

## Prerequisites

A running TideCloak with the IGA jar deployed. The screenshots were captured
against a realm `iga-demo-cloned` set up with:

- `organizationsEnabled = true`
- Realm attributes: `iga.threshold = 2`, `iga.approverRole = iga-approver-x`, `iga.scopeMode = any`
- Realm roles: `iga-approver-x`, `iga-approver-y`
- Group `governed-team` with attributes `iga.approverRole = iga-approver-x`, `iga.threshold = 2`
- Users:
  - `alice` and `bob` — granted realm role `iga-approver-x` + client role `realm-management/realm-admin`
  - `carol` — granted realm role `iga-approver-y` (wrong approver role) + `realm-admin`

IGA is then toggled on via `POST /admin/realms/{realm}/tide-admin/toggle-iga`. The
toggle-on scan creates `ADOPT_*` change requests for any pre-existing entities; drain
them (authorize+commit) before continuing — they bypass approver-role enforcement by design.

---

## 1. The keycloak-IGA admin console

Sign in as alice at `/admin/{realm}/console`. The IGA-aware fork adds
**Change Requests** to the left navigation — that's where every governed action ends up.

![Console landing](images/tideless-iga-walkthrough/01_console_landing.png)

---

## 2. Enabling IGA + setting policy

**Click:** *Realm settings* in the left nav.

![Realm Settings — top](images/tideless-iga-walkthrough/02_realm_settings_top.png)

Scroll to the **Identity Governance and Administration** section. Four knobs:

- **IGA enabled** — master switch (`isIGAEnabled` realm attribute).
- **IGA approval threshold** — number of distinct admin signatures needed to commit.
- **IGA approver role** — required role for the signer (realm-level default).
- **IGA scope mode** — `any` (signer holds ≥1 required role) or `all` (signer holds every required role).

![IGA toggle + threshold + approver role + scope mode](images/tideless-iga-walkthrough/03_realm_settings_iga_config.png)

---

## 3. Capture-then-veto (the heart of IGA)

When IGA is on, privileged admin actions don't apply immediately — they're
**captured** as a PENDING change request and the request is rolled back.

**Click:** *Realm roles* → **Create role**.

![Realm Roles list — Create role](images/tideless-iga-walkthrough/04_realm_roles_list_before.png)

**Type:** Role name `marketing-admin`.

![Role name typed](images/tideless-iga-walkthrough/05_create_role_form_typed.png)

**Click:** **Save**.

The server returns **HTTP 202 Accepted** (not 201) and the UI shows a toast saying
the change request was created. The role does **not** appear in the Realm Roles
list yet.

![202 — Change request created](images/tideless-iga-walkthrough/06_create_role_after_save_toast.png)

---

## 4. Reviewing change requests

**Click:** *Change Requests* in the left nav.

The list shows pending CRs with action type, entity, authorization count vs threshold,
and the required approver roles.

![CR list — Pending](images/tideless-iga-walkthrough/07_change_requests_list.png)

**Click:** the row's kebab (⋮) menu. Each row gives you **Open** / **Authorize**
/ **Commit** / **Deny**.

![CR row kebab menu](images/tideless-iga-walkthrough/08_cr_row_kebab_menu.png)

**Click:** **Open** to view the full captured payload + comments thread.

![CR detail](images/tideless-iga-walkthrough/09_cr_detail_view.png)

---

## 5. Threshold enforcement (and the 412 round-trip)

Threshold = **2**. As alice, open the CR's kebab and click **Authorize**. The row
now shows **1 / 2** — under threshold; Commit stays disabled.

![1 of 2 — under threshold](images/tideless-iga-walkthrough/10_cr_after_alice_authorize_1_of_2.png)

Hovering the disabled Commit menuitem shows it's gated. The server enforces the
same rule as **HTTP 412 Precondition Failed** with body
`{error: "Need 1 more signature(s)", threshold: 2, authCount: 1}`.

![Commit disabled — under threshold](images/tideless-iga-walkthrough/11_cr_commit_disabled_tooltip.png)

Sign out, sign in as **bob**, open the same row, click **Authorize**. Now it's
**2 / 2** and Commit is enabled.

![2 of 2 — threshold met](images/tideless-iga-walkthrough/12_cr_after_bob_authorize_2_of_2.png)

**Click:** the kebab → **Commit**. The change applies — and the entity row's
`ATTESTATION` column is stamped.

![Committed](images/tideless-iga-walkthrough/13_cr_after_commit.png)

The `marketing-admin` role now appears in Realm Roles for real.

![marketing-admin in Realm Roles](images/tideless-iga-walkthrough/14_realm_roles_after_commit.png)

---

## 6. Approver-role enforcement (and the 403 round-trip)

Alice puts bob into the `governed-team` group. That `JOIN_GROUPS` request is
captured into a CR whose **required approver roles = `[iga-approver-x]`** (the
group carries `iga.approverRole = iga-approver-x` on its own attributes).

Sign in as **carol** (who has `iga-approver-y`, not `-x`) and open Change Requests:

![Carol sees the JOIN_GROUPS CR — required role is iga-approver-x](images/tideless-iga-walkthrough/15_carol_cr_view.png)

Open the CR's detail view. The UI's `canApprove(cr, userRoles)` check
(`canApprove.ts`) is gated against the user's roles; carol fails it, so the
**Authorize** button in the detail view is disabled.

![Authorize disabled for Carol — wrong approver role](images/tideless-iga-walkthrough/16_carol_authorize_disabled_in_detail.png)

> **Server side:** if carol bypasses the UI and POSTs `/iga/change-requests/{id}/authorize`
> directly, the server returns **HTTP 403** with `Approver role required: [iga-approver-x] (mode=any)`.
> (Source: `IgaScopeResolver.requireApprover` → `ForbiddenException`.)

---

## 7. Deny a change request

**Click:** the kebab on a PENDING row → **Deny**.

![Deny dialog](images/tideless-iga-walkthrough/17_cr_deny_dialog.png)

**Type:** a reason explaining the rejection.

![Reason typed](images/tideless-iga-walkthrough/18_cr_deny_dialog_reason_typed.png)

**Click:** **Deny** in the dialog. The CR's status flips to `DENIED`; the
**Denied** tab retains the audit trail.

![Denied tab — audit trail](images/tideless-iga-walkthrough/19_cr_denied_tab.png)

---

## 8. Bulk authorize + Bulk commit

Useful when an ADOPT scan creates many CRs, or to drain a backlog as a batch.

Create a couple of pending CRs first (`bulk-role-1`, `bulk-role-2`). Both show
up in the CR list.

![Multiple pending CRs](images/tideless-iga-walkthrough/20_cr_list_with_bulk_targets.png)

**Click:** the table-header checkbox to select all. The **Bulk Authorize** button
surfaces (showing the count of authorizable selections).

![Selected — Bulk Authorize button](images/tideless-iga-walkthrough/21_cr_multi_selected.png)

**Click:** **Bulk Authorize** → **Authorize** in the confirm dialog.

![Confirm bulk authorize](images/tideless-iga-walkthrough/22_cr_bulk_authorize_dialog.png)

After Alice's bulk authorize, each selected CR is now at **1 / 2** — still under
threshold.

![Alice bulk-authorized — each CR 1/2](images/tideless-iga-walkthrough/23_cr_after_alice_bulk_authorize.png)

Sign out, sign in as **bob**, and repeat the bulk authorize. Each CR is now
**2 / 2** — threshold met, and a **Bulk Commit** button surfaces (with the
committable count).

![Bob bulk-authorized — Bulk Commit button now surfaces](images/tideless-iga-walkthrough/24_cr_after_bob_bulk_authorize.png)

**Click:** **Bulk Commit** → **Commit** in the confirm dialog.

![Confirm bulk commit](images/tideless-iga-walkthrough/25_cr_bulk_commit_dialog.png)

All selected CRs commit and flip to APPROVED — the bulk equivalent of clicking
Commit on each row.

![After bulk commit — all applied](images/tideless-iga-walkthrough/26_cr_after_bulk_commit.png)

> Implementation note: the server has only `POST /iga/change-requests/bulk-authorize`.
> "Bulk Commit" is a client-side loop calling the per-CR `/commit` endpoint —
> see `ChangeRequestsSection.tsx:445-477`.

---

## 9. Organization attestation

With IGA on, organizations are now part of the attested set. **Click:**
*Organizations* in the left nav.

![Organizations (empty)](images/tideless-iga-walkthrough/27_organizations_empty.png)

**Click:** **Create organization**. **Type:** name=`acme`, alias=`acme`,
domain=`acme.com`.

![Org create form](images/tideless-iga-walkthrough/28_org_create_form_typed.png)

**Click:** **Save**. As with role creation, the server returns 202 — a
`CREATE_ORGANIZATION` change request is captured.

![Org capture toast](images/tideless-iga-walkthrough/29_org_after_save_toast.png)

Head to *Change Requests* — the new `CREATE_ORGANIZATION` row is pending.

![CR list with org CR](images/tideless-iga-walkthrough/30_cr_list_with_org_cr.png)

Authorize as alice, sign out, sign in as bob, authorize again, then commit. The
org appears in Organizations — **and** its row in the `ORG` DB table now has a
non-null `ATTESTATION` value:

```sql
SELECT id, alias, attestation FROM ORG WHERE alias = 'acme';
-- id=…  alias=acme  attestation=[{"by":"alice","at":…},{"by":"bob","at":…}]
```

![acme — committed + ORG.ATTESTATION stamped](images/tideless-iga-walkthrough/31_organizations_after_commit.png)

---

## Server-side enforcement summary

The UI gates are convenient; the server is the source of truth. Every gate has
a matching HTTP failure mode you can verify with curl:

| Trigger | HTTP | Body / signal |
|---|---|---|
| Action captured | **202** | `Location` → CR get endpoint |
| Authorize/commit by user lacking required approver role | **403** | `"Approver role required: [...] (mode=any\|all)"` |
| Commit with `authCount < threshold` | **412** | `{error:"Need N more signature(s)", threshold, authCount}` |
| CR not in PENDING state | **409** | `"...not in PENDING state"` |
| Same admin signing the same CR twice | **409** | `"Caller has already signed this change request"` |
| Bulk-authorize lost the per-realm cluster lock | **429** | — |
| ADOPT target deleted out-of-band | **404** | `{error:"ENTITY_VANISHED", entityType, entityId, realmId}` |

All authoritative in `IgaAdminResource.java` and `IgaScopeResolver.java` in the
`iga-core` module.

---

## Further reading

- [`IGA.md`](IGA.md) — full concepts (capture seams, replay dispatcher, scanner, attestor SPI).
- [`EXTENDING-IGA.md`](EXTENDING-IGA.md) — extending IGA with new entity types or attestors.
- [`iga-tve-producer-design.md`](iga-tve-producer-design.md) — IGA→TVE bundle producer design.
- [`.claude/skills/tidecloak-iga/SKILL.md`](../.claude/skills/tidecloak-iga/SKILL.md) — operator/diagnose skill for AI agents.
