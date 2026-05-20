# Identity Governance and Administration (IGA)

> **Last updated:** 2026-05-20. Reflects Phases 1–5 as of commit `5276c40`
> (branch `iga-approval-workflow`). This guide is the operator/administrator
> reference. Developers extending IGA should start at
> [`EXTENDING-IGA.md`](EXTENDING-IGA.md).

## TL;DR

- **What IGA does.** Turns privileged Keycloak admin writes into **change
  requests** that must be authorized (signed) and then committed (replayed)
  before they actually take effect. The HTTP response on the original write
  is **`202 Accepted`** with a CR id; the original entity is **not** written
  until commit.
- **Mode implemented in this codebase: Tideless.** The commit-time gate is
  attribute-based (`iga.threshold`, `iga.approverRole`, `iga.scopeMode` on
  Keycloak entities). No Tide IdP / cryptographic threshold is required.
- **Mode coexisting in the schema: Tide.** The `IGA_ROLE_POLICY` table /
  `IgaRolePolicyEntity` and the role-policy REST surface are scaffolding for
  a future cryptographic gate (Midgard `signClaims()`); they are **not**
  consulted by the enforced commit gate today. Tideless and Tide are intended
  as two coexisting first-class modes — not interim → permanent — so the
  Tideless gate is not going away when Tide ships.
- **What you get out of the box with zero configuration.** With IGA on and
  no `iga.threshold` / `iga.approverRole` set anywhere, a single admin
  holding `manage-realm` can self-authorize **and** self-commit any CR with
  one signature. That is by design for bootstrap; harden it before relying on
  IGA as a real gate (see
  [Default behavior](#default-behavior-when-nothing-is-configured) and
  [Ordering](#ordering-configure-governance-before-enabling-iga)).
- **Where to harden.** Set the realm `iga.threshold` ≥ 2, set
  `iga.approverRole` on every sensitive scope **paired with** an
  `iga.threshold` on the *same* entity (see the
  [coupling rule](#warning-the-approver-role--threshold-coupling-rule)), and
  decide `iga.scopeMode`. Do all of this **before** enabling IGA on the
  realm.

> **Note**
> Throughout this guide, "admin console path" refers to the Keycloak
> administration console. The exact menu labels can differ slightly between
> Keycloak releases and between the legacy and new admin themes. Where a
> label may differ in your build, the path is described generically and the
> equivalent Admin REST call — which is stable — is given alongside. Treat
> the REST representation field as the authoritative source if a console
> label does not match.

## Table of contents

1. [Overview](#overview)
2. [Modes: Tideless vs Tide](#modes-tideless-vs-tide)
3. [Concepts and attributes](#concepts-and-attributes)
4. [Enabling and disabling IGA](#enabling-and-disabling-iga)
5. [Configuring thresholds](#configuring-thresholds)
6. [Restricting who can approve](#restricting-who-can-approve)
7. [Ordering: configure governance before enabling IGA](#ordering-configure-governance-before-enabling-iga)
8. [The approval workflow: authorize then commit](#the-approval-workflow-authorize-then-commit)
9. [What gets captured (per entity type)](#what-gets-captured-per-entity-type)
10. [Multi-entity governance: `partialImport`](#multi-entity-governance-partialimport)
11. [Failure responses an operator will see](#failure-responses-an-operator-will-see)
12. [Default behavior when nothing is configured](#default-behavior-when-nothing-is-configured)
13. [Governing Keycloak Organizations](#governing-keycloak-organizations)
14. [Operator runbook](#operator-runbook)
15. [Known limitations](#known-limitations)
16. [Internals](#internals)

## Overview

IGA turns privileged Keycloak administration writes into **change requests**
that must be approved before they take effect.

The lifecycle is:

1. **Intercept.** When IGA is enabled for a realm, the IGA model providers
   intercept privileged writes (create client/user/role/group/client-scope,
   role grants, group membership, composites, scope assignments, protocol
   mappers, attribute writes, realm-config setters, organization mutations,
   `partialImport`, etc.) instead of applying them.
2. **Record and return 202.** The interceptor persists a `PENDING` change
   request in a separate transaction (so it survives the rollback of the
   interrupted write) and throws `IgaPendingApprovalException`, which is
   mapped to **HTTP 202 Accepted** with a JSON body such as:

   ```json
   {
     "status": "PENDING",
     "changeRequestId": "<uuid>",
     "entityType": "CLIENT",
     "actionType": "CREATE_CLIENT",
     "message": "Change request created — awaiting approval"
   }
   ```

   The response also carries a `Location:
   /admin/realms/{realm}/iga/change-requests/{id}` header so automation can
   poll the CR. The original entity is **not** written. Callers and UIs must
   treat a 202 as "queued for approval", not "done".
3. **Authorize (sign).** One or more admins sign the change request via
   `POST /admin/realms/{realm}/iga/change-requests/{id}/authorize`. This only
   records a signature; it does not apply the change even if the threshold
   is already met.
4. **Commit (apply).** Once the signature count meets the threshold, an
   admin calls
   `POST /admin/realms/{realm}/iga/change-requests/{id}/commit`. This replays
   the recorded operation against the real Keycloak model and sets the
   change request to `APPROVED`.

A change request can hold the statuses `PENDING`, `APPROVED` (after a
successful commit/replay), and `DENIED` (via
`POST .../iga/change-requests/{id}/deny`). All `iga/*` endpoints are mounted
under the realm admin base, that is `/admin/realms/{realm}/iga/...`.

## Modes: Tideless vs Tide

IGA is designed around **two first-class modes** that share the same
capture-then-veto pipeline. Only the commit-time gate differs.

| Aspect | Tideless (this codebase) | Tide (future) |
|--------|--------------------------|---------------|
| Identity-provider requirement | Stock Keycloak; no Tide IdP needed. | Tide IdP wired via Midgard. |
| Commit gate | Attribute-based: count distinct signatures, compare against `iga.threshold`, enforce `iga.approverRole` per scope. | Cryptographic: Midgard `signClaims()` on the resolved CR payload; threshold encoded in the policy. |
| Configuration surface | `iga.threshold`, `iga.approverRole`, `iga.scopeMode` on realm and on group/role/client/organization. | `IGA_ROLE_POLICY` rows (table + `/iga/role-policies` REST). |
| Status in this codebase | **Enforced.** All authorize/commit gating runs through `IgaScopeResolver.requireApprover` and `resolveThreshold`. | **Scaffolding only.** Table and endpoints exist; `THRESHOLD` is echoed back but never consulted by the gate. |

> **Important**
> Tideless and Tide are **not** an interim-vs-permanent pair. They are
> intended to coexist. Tideless targets deployments that do not run a Tide
> IdP and need a self-contained Keycloak governance layer; Tide will harden
> the same workflow for deployments that do. The capture/replay machinery
> is identical for both — only the gate at commit time changes.

## Concepts and attributes

| Term | Meaning |
|------|---------|
| Change request (CR) | A recorded, pending privileged write awaiting approval. |
| Authorize | Record one admin signature on a CR. Does not apply the change. |
| Commit | Apply (replay) a CR once enough signatures exist. |
| Threshold | Number of **distinct** admin signatures required before a CR can be committed. |
| Approver role | A Keycloak role that an admin must hold to authorize/commit a scoped CR. |
| Scope mode | Realm-level switch deciding whether an approver needs *any* or *all* required roles. |
| Scope entity | A group, role, client, or organization carrying `iga.approverRole` / `iga.threshold`. |

The relevant attribute keys are constants in the code
(`IgaScopeResolver.java:44-46`):

| Attribute key | Where it is set | Effect |
|---------------|-----------------|--------|
| `isIGAEnabled` | Realm attribute | `"true"` (exact, case-sensitive) enables IGA for the realm. |
| `iga.threshold` | Realm attribute, or a group/role/client/organization attribute | Required signature count. |
| `iga.approverRole` | A group/role/client/organization attribute | Restricts who may approve CRs affecting that entity. |
| `iga.scopeMode` | **Realm attribute only.** | `all` (case-insensitive) = approver must hold every required role; anything else / unset = `any`. There is no per-entity `iga.scopeMode`. |

## Enabling and disabling IGA

IGA is controlled by the **case-sensitive** realm attribute `isIGAEnabled`.
It is enabled only when the attribute string is exactly `"true"`
(`IgaChangeRequestService.isIgaEnabled`,
`IgaChangeRequestService.java:36-39`). Any other value, including `"True"`,
leaves IGA off.

> **Important**
> The `master` realm is always exempt. `isIgaEnabled` returns `false`
> unconditionally when the realm name is `master`
> (`IgaChangeRequestService.java:37`). IGA cannot be enforced on the
> `master` realm, and administration there is never intercepted. This is
> the operational escape hatch if a realm's governance becomes self-locked.

### Procedure: enable IGA for a realm

**Prerequisites**

- You hold `manage-realm` for the target realm (not `master`).
- Thresholds and approver roles are already configured — see
  [Ordering](#ordering-configure-governance-before-enabling-iga). Configure
  governance **first**.

**Procedure**

1. Call the toggle endpoint:
   `POST /admin/realms/{realm}/tide-admin/toggle-iga`
   (`TideAdminCompatResource.java:38-48`). It flips `isIGAEnabled` between
   `"true"` and `"false"` and requires `manage-realm`. Equivalently, set
   the realm attribute `isIGAEnabled = "true"` directly while IGA is still
   off.
2. Verify with `GET /admin/realms/{realm}/tide-admin/iga-status` (requires
   `view-realm`).

**Verification**

```bash
curl -fsS -H "Authorization: Bearer $TOKEN" \
  "$KC_URL/admin/realms/$REALM/tide-admin/iga-status"
# → {"enabled":true}
```

> **Note**
> Enabling is applied directly and is **not** itself governed. When IGA is
> OFF and an admin sets `isIGAEnabled = true`, `isIgaActive()`
> (`IgaRealmAdapter.java:63-71`) reads the attribute *currently being
> written*, which is still `false` at that instant, so the write passes
> through immediately. IGA only engages on the *next* privileged write.
> Plan the enable as a deliberate, trusted operation.

### Procedure: disable IGA

Once IGA is ON, disabling it is itself a governed action.

1. Set `isIGAEnabled = false` (or call the toggle endpoint). This is
   intercepted as a `SET_REALM_ATTRIBUTE` change request
   (`IgaRealmAdapter.java:73-88`).
2. The change request must be authorized and committed like any other
   privileged realm-attribute write before IGA actually turns off.

> **Warning**
> You cannot unilaterally disable governance once it is active — it
> requires the same approvals as any other change. While a realm-attribute
> or realm-config change request is pending, any other attempt to set or
> remove a realm attribute/config on the same realm fails with **HTTP 409**
> (`IgaRealmAdapter.checkNoPendingCr`, `IgaRealmAdapter.java:106-111`).
> Resolve (approve or deny) the existing change request first.

## Configuring thresholds

The threshold is the number of distinct admin signatures required before a
change request can be committed. It is resolved at commit time by
`IgaScopeResolver.resolveThreshold` (`IgaScopeResolver.java:211-230`).

**Precedence (highest to lowest):**

1. **Per-scope-entity `iga.threshold`** — if any group, role, client, or
   organization *affected by this change request* carries an
   `iga.threshold` attribute, the **maximum** of all such positive integer
   values is used (`IgaScopeResolver.java:213-214`; `addThreshold`,
   `IgaScopeResolver.java:361-368`, only accepts values that parse as an
   integer **greater than 0**).
2. **Realm attribute `iga.threshold`** — if no scoped threshold applies,
   the realm attribute `iga.threshold` is parsed as an integer and used,
   but only when it is a valid integer `>= 1` (`IgaScopeResolver.java:
   216-225`); a non-integer or `< 1` value is ignored.
3. **Hardcoded default `1`** — if neither is set, or the realm value is
   not a valid integer `>= 1`, the threshold is **`1`**.
   `resolveThreshold` also applies a defensive final clamp
   (`Math.max(1, resolved)`, `IgaScopeResolver.java:229`), so it can never
   return a value below `1` regardless of the source.

> **Note — the realm-level value is enforced.** The realm `iga.threshold`
> is subject to the same positivity rule as the per-entity path. A
> non-integer value (for example `"two"`) **or** a value `< 1` (for
> example `"0"` or `"-1"`) is **ignored and treated as `1`** — it never
> lowers the gate. In addition, `resolveThreshold` applies a defensive
> final clamp so it can **never** return a value below `1` regardless of
> the source. The commit gate therefore cannot be disabled by a bad realm
> value: a change request always requires at least one signature. Set the
> realm `iga.threshold` to the positive integer you actually want (for
> example `"2"`); a `"0"` or negative value simply behaves as `1`.

### <a id="warning-the-approver-role--threshold-coupling-rule"></a> Warning: the approver-role / threshold coupling rule

> **Warning**
> A per-scope-entity `iga.threshold` is **silently ignored** unless the
> same entity also carries an `iga.approverRole`. If you set
> `iga.threshold` alone on a group, role, client, or organization, it has
> no effect — the resolved threshold falls back to the realm value (or
> `1`).

The reason is in the scope collectors. `addThreshold(...)` is only called
under the `iga.approverRole != null && !isBlank()` branch in every
collector:

- Roles — `IgaScopeResolver.collectRoleScope` lines `345-351`.
- Clients — `IgaScopeResolver.collectClientScope` lines `353-359`.
- Groups (incl. ancestor walk) — `IgaScopeResolver.walkGroupAncestors`
  lines `333-343`.
- Organizations — `IgaScopeResolver.collectOrganizationScope` lines
  `312-321`.

Practical rule: **set both attributes together on the same scope entity, or
neither**. UI and automation should warn if `iga.threshold` is set
without an `iga.approverRole` on the same entity. The contributor docs
mirror this from the implementer's side — see step 9 of
[`EXTENDING-IGA.md`](EXTENDING-IGA.md#recipe-add-a-new-governed-entity-type)
when adding a new scoped type.

### Procedure: set the realm-wide default threshold

**Prerequisites**

- You hold `manage-realm` for the realm.
- Preferably IGA is still OFF (see
  [Ordering](#ordering-configure-governance-before-enabling-iga));
  otherwise this change is itself a governed `SET_REALM_ATTRIBUTE` change
  request.

**Procedure**

1. Admin console: go to **Realm settings → General** and locate the
   **"Identity Governance and Administration (IGA)"** section. Set the
   **"IGA approval threshold"** numeric field to `2` and save. This
   persists the `iga.threshold` realm attribute.
2. Admin REST equivalent: update the realm representation `attributes`
   map via `PUT /admin/realms/{realm}`, including:

   ```json
   { "attributes": { "iga.threshold": "2" } }
   ```

   (Send the full realm representation as Keycloak's realm-update endpoint
   expects; the relevant addition is the `attributes` entry above.)
3. Result: any change request that does not resolve a higher per-entity
   threshold now requires **2** distinct admin signatures before it can be
   committed.

### Procedure: set a per-entity threshold

**Prerequisites**

- You hold `manage-realm` for the realm.
- The target group, role, client, or organization exists.
- You will set **both** `iga.threshold` and `iga.approverRole` on the
  same entity (see the
  [coupling rule](#warning-the-approver-role--threshold-coupling-rule)).

**Procedure**

1. Admin console: open the entity and select its **Attributes** tab:
   - Group: **Groups → (group) → Attributes**.
   - Realm role: **Realm roles → (role) → Attributes**. Client role:
     **Clients → (client) → Roles → (role) → Attributes**.
   - Client: **Clients → (client) → Attributes**.
   - Organization: **Organizations → (organization) → Attributes**.

   Add the key `iga.threshold` with a positive integer value, for example
   `3`. **In the same step**, add `iga.approverRole = <role-name>` on
   the same entity — without it, the threshold is silently ignored.
2. Admin REST equivalent — add **both** attributes to the entity's
   representation:
   - Group: `PUT /admin/realms/{realm}/groups/{id}` with
     ```json
     { "attributes": { "iga.threshold": ["3"], "iga.approverRole": ["hr-approver"] } }
     ```
   - Role: `PUT /admin/realms/{realm}/roles-by-id/{role-id}` with
     ```json
     { "attributes": { "iga.threshold": ["3"], "iga.approverRole": ["hr-approver"] } }
     ```
   - Client: `PUT /admin/realms/{realm}/clients/{id}` with
     ```json
     { "attributes": { "iga.threshold": "3", "iga.approverRole": "hr-approver" } }
     ```
   - Organization: `PUT /admin/realms/{realm}/organizations/{org-id}` with
     ```json
     { "attributes": { "iga.threshold": ["3"], "iga.approverRole": ["hr-approver"] } }
     ```
3. Result: any change request affecting that entity requires at least
   **3** distinct signatures from `hr-approver` holders. If multiple
   affected entities declare a threshold, the **maximum** wins.
   Per-entity thresholds always override the realm default.

## Restricting who can approve

By default, **any admin with `manage-realm` can authorize and commit any
change request** (see
[Default behavior](#default-behavior-when-nothing-is-configured)). To
restrict approval to specific people, mark the affected Keycloak entities
with the attribute `iga.approverRole`.

### How scope is resolved

For a given change request, `IgaScopeResolver.resolve(...)` walks the
change request's `rows_json` based on its `actionType` and collects the
union of `iga.approverRole` values from the affected entities
(`IgaScopeResolver.java:62-173`):

- **User-targeting actions** (`GRANT_ROLES`, `REVOKE_ROLES`,
  `JOIN_GROUPS`, `LEAVE_GROUPS`, `SET_USER_ATTRIBUTE`,
  `REMOVE_USER_ATTRIBUTE`): every **group the user belongs to** and each
  group's **ancestor groups** are walked (`collectUserGroupScopes`,
  `walkGroupAncestors`, `IgaScopeResolver.java:329-343`).
- **Role-targeting actions**: the role's `iga.approverRole` is read
  (`collectRoleScope`, `IgaScopeResolver.java:345-351`).
- **Group-targeting actions**: the group and its ancestors are walked.
- **Client-targeting actions**: the client's `iga.approverRole` is read
  (`collectClientScope`, `IgaScopeResolver.java:353-359`).
- **Organization-targeting actions** (`UPDATE_ORGANIZATION`,
  `DELETE_ORGANIZATION`, `ADD_ORG_MEMBER`, `REMOVE_ORG_MEMBER`,
  `ORG_INVITE_MEMBER`, `ORG_ADD_IDP`, `ORG_REMOVE_IDP`): the
  organization's `iga.approverRole` is read (`collectOrganizationScope`,
  `IgaScopeResolver.java:312-321`).
- **Realm-wide / top-level-create actions** (`CREATE_USER`,
  `CREATE_ROLE`, `CREATE_GROUP`, `CREATE_CLIENT`, `CREATE_CLIENT_SCOPE`,
  `CREATE_ORGANIZATION`, `SET_REALM_*`, `BASELINE_APPROVAL`, license
  and server-cert actions, and the `BATCH / PARTIAL_IMPORT` aggregate
  CR) yield an **empty scope** — no approver-role requirement is derived;
  only the baseline `manage-realm` gate applies.

> **Important**
> Creating top-level entities (users, roles, groups, clients, client
> scopes, organizations) and realm-wide writes are **not** approver-role
> scoped. They are governed only by `manage-realm` plus the threshold.
> Restrict who holds `manage-realm` accordingly, and use a realm-wide
> `iga.threshold` so even unscoped creates need multiple signatures.

### Procedure: restrict approval of a scope to a dedicated role

**Prerequisites**

- You hold `manage-realm` for the realm.
- Preferably IGA is still OFF (see
  [Ordering](#ordering-configure-governance-before-enabling-iga)).

**Procedure**

1. **Create the approver Keycloak role.** Admin console:
   **Realm roles → Create role**, name it for example `hr-approver`.
   Admin REST: `POST /admin/realms/{realm}/roles` with
   `{ "name": "hr-approver" }`.
2. **Assign the role** only to the admins who should approve this scope.
   They must *also* hold `manage-realm`. Admin console:
   **Users → (user) → Role mapping → Assign role**. Admin REST:
   `POST /admin/realms/{realm}/users/{user-id}/role-mappings/realm` with
   the role representation.
3. **Mark the scope entity.** On the group/role/client/organization that
   the change affects, set `iga.approverRole = hr-approver` via the
   **Attributes** tab (console) or by adding `iga.approverRole` to that
   entity's representation `attributes` (REST). **If you also want a
   per-entity threshold, set `iga.threshold` on the same entity in the
   same call** — see the
   [coupling rule](#warning-the-approver-role--threshold-coupling-rule).
4. **Choose the scope mode** (see next procedure). The default (`any`)
   means an approver needs at least one of the required roles.

### Procedure: set the realm scope mode

The scope mode is read from the **realm attribute** `iga.scopeMode`
(`IgaScopeResolver.ATTR_SCOPE_MODE`, gate logic
`IgaScopeResolver.requireApprover`, `IgaScopeResolver.java:182-196`):

- `iga.scopeMode = all` (case-insensitive): strict. The approving admin
  must hold **every** role in the resolved required set
  (`containsAll`, `IgaScopeResolver.java:190`).
- Any other value, or unset: **`any`** (default). The admin needs **at
  least one** of the required roles (`anyMatch`,
  `IgaScopeResolver.java:191`).

`scopeMode` is **realm-level only**; there is no per-entity scope-mode
attribute.

**Procedure**

1. Admin console: **Realm settings → General**, in the **"Identity
   Governance and Administration (IGA)"** section set the **"IGA scope
   mode"** select to `all` (or leave it at `any` for the default). This
   persists the `iga.scopeMode` realm attribute.
2. Admin REST: include `"iga.scopeMode": "all"` in the realm
   representation `attributes` map via `PUT /admin/realms/{realm}`.

> **Note**
> If the resolved required-roles set is empty, `requireApprover` is a
> no-op (`IgaScopeResolver.java:183`) and the only gate is `manage-realm`.
> Scope mode has no effect when nothing is scoped.

### Worked example: only HR can approve changes to the HR group

**Prerequisites**

- You hold `manage-realm`. IGA is still OFF (configure before enabling).
- A Keycloak group `hr` exists.

**Procedure**

1. Create the realm role `hr-approver`
   (`POST /admin/realms/{realm}/roles` with `{ "name": "hr-approver" }`).
2. Assign `hr-approver` to the HR approvers (who also hold
   `manage-realm`).
3. On the `hr` group's **Attributes** tab, set **both**:
   - `iga.approverRole = hr-approver`
   - `iga.threshold = 2` (requires two HR approvers)

   REST: `PUT /admin/realms/{realm}/groups/{hr-group-id}` with
   ```json
   { "attributes": { "iga.approverRole": ["hr-approver"], "iga.threshold": ["2"] } }
   ```
4. Leave `iga.scopeMode` unset (default `any`).
5. Enable IGA (now that governance is configured).

**Verification**

Any change request that adds/removes members of the `hr` group, or grants
the `hr` group roles, resolves the required role set `{hr-approver}` and
the threshold `2`. With scope mode `any`, authorize and commit succeed
only for admins who (a) hold `manage-realm` and (b) hold `hr-approver`.
Other realm admins receive **HTTP 403** "Approver role required:
[hr-approver] (mode=any)" (`IgaScopeResolver.java:193-194`).

## Ordering: configure governance before enabling IGA

> **Important**
> Set thresholds and approver roles **before** enabling IGA. Once IGA is
> on, changing the realm `iga.threshold` (or any realm attribute) is
> itself a governed `SET_REALM_ATTRIBUTE` change request that must be
> authorized and committed.
>
> This is a direct consequence of the interception logic:
> `IgaRealmAdapter.setAttribute` (`IgaRealmAdapter.java:73-88`) checks
> `isIgaActive()` (`IgaRealmAdapter.java:63-71`); when IGA is already
> active, a write to `iga.threshold`, `iga.scopeMode`, or any other realm
> attribute is recorded as a `SET_REALM_ATTRIBUTE` change request instead
> of being applied. Per-entity attributes on groups/roles/clients are
> likewise intercepted as `SET_GROUP_ATTRIBUTE` / `SET_ROLE_ATTRIBUTE` /
> `SET_CLIENT_ATTRIBUTE` change requests once IGA is on. If you raise the
> threshold or add approver roles only *after* enabling, those very
> governance changes are blocked behind the (possibly weak or empty)
> policy that was in force at enable time, and you may need several
> approvals just to tighten the policy.
>
> If a realm's governance becomes self-locked, the only escape hatch is
> the permanently exempt `master` realm — IGA is never enforced there
> (`IgaChangeRequestService.java:37`), so a `master` realm administrator
> can still administer other realms' Keycloak objects through
> master-scoped admin APIs. There is no per-realm override.

**Recommended order**

1. Decide the realm-wide `iga.threshold` (e.g. `2`) and set it.
2. Decide `iga.scopeMode` and set it.
3. Create approver roles and assign them.
4. Set `iga.approverRole` **and** `iga.threshold` together on every
   sensitive group/role/client/organization (see the
   [coupling rule](#warning-the-approver-role--threshold-coupling-rule)).
5. Enable IGA last.

## The approval workflow: authorize then commit

Approval is **two explicit steps**. Collecting signatures is deliberately
separate from applying the change.

### Step 1: authorize (sign)

`POST /admin/realms/{realm}/iga/change-requests/{id}/authorize`
(`IgaAdminResource.java:194-252`)

- Requires `manage-realm` (`auth.realm().requireManageRealm()`,
  `IgaAdminResource.java:198`).
- The change request must be `PENDING` (else **HTTP 409**).
- **One signature per admin.** A second authorize from the same admin is
  rejected with **HTTP 409** `{"error": "Caller has already signed this
  change request"}` (`IgaAdminResource.java:226-238`).
- The approver-role gate is enforced **before** the row is persisted —
  `SimpleNameAttestor.record` calls
  `IgaScopeResolver.requireApprover(...)` (line 52) **before**
  `em.persist(auth)` (line 62), so a rejected authorize leaves
  `authCount = 0` on the CR (no half-recorded signature).
- **Authorize never applies the change**, even if the threshold is now
  met (`IgaAdminResource.java:245-247`). It only records the signature.

### Step 2: commit (apply)

`POST /admin/realms/{realm}/iga/change-requests/{id}/commit`
(`IgaAdminResource.java:261-311`)

- Requires `manage-realm` (`IgaAdminResource.java:262`).
- The change request must be `PENDING`.
- Re-checks the same approver-role gate
  (`IgaScopeResolver.resolve` + `requireApprover`,
  `IgaAdminResource.java:284-285`).
- Counts recorded signatures; if `authCount < threshold` it returns
  **HTTP 412 Precondition Failed** with body
  `{error: "Need N more signature(s)", threshold: <int>, authCount:
  <int>}` (`IgaAdminResource.java:292-301`).
- When the threshold is met it combines the final attestation and calls
  `IgaReplayDispatcher.replay(...)`, which performs the real Keycloak
  write and sets the change request to `APPROVED`
  (`IgaAdminResource.java:303-310`).

**Who can commit:** any admin who passes `manage-realm` *and* the
approver-role gate for that change request. The committer does not have
to be one of the signers, but the threshold must already be satisfied by
recorded signatures. There is no separate "committer" role.

Other change-request operations: `PUT .../change-requests/{id}` edits the
rows and **wipes all existing authorizations**; each change request also
supports comments under `.../change-requests/{id}/comments`. Pending
change requests are listed via `GET .../iga/change-requests` (defaults to
`status=PENDING`). `deny` and comment deletion additionally allow the
original author in addition to `manage-realm` holders.

## What gets captured (per entity type)

Each captured entity type writes a `CREATE_*` change request whose
`rowsJson` carries the **full Keycloak representation** of the
to-be-created entity as `REP_JSON`, *except* for users. Replay rebuilds
the entity from this representation through Keycloak's own builders.

| Entity type | What is in `REP_JSON` | Source |
|-------------|-----------------------|--------|
| Role | Full `RoleRepresentation` (incl. attributes; composites merged in at capture time because `ModelToRepresentation` drops them). | `IgaRoleAdapter`, `IgaReplayDispatcher.replayCreateRole` |
| Client scope | Full `ClientScopeRepresentation` (incl. attributes, protocol mappers, default-scope flag). | `IgaClientScopeAdapter`, `IgaReplayDispatcher.replayCreateClientScope` |
| Group | Full `GroupRepresentation` (incl. attributes, parent-group linkage). | `IgaGroupAdapter`, `IgaReplayDispatcher.replayCreateGroup` |
| Client | Full `ClientRepresentation` (incl. attributes, protocol mappers, scopes, redirect URIs, all `updateClientProperties` fields). | `IgaClientAdapter.updateClient()`, `IgaReplayDispatcher.replayCreateClient` |
| User | **ONLY the 8 token-affecting fields:** `username`, `enabled`, `email`, `emailVerified`, `firstName`, `lastName`, `attributes`, `groups`. | `IgaUserAdapter.buildCapturedUserRow` (`IgaUserAdapter.java:603-697`) |

For users, the following are **explicitly NOT** governed (the capture
sets them to `null` on the `UserRepresentation` so they cannot ride
along into the CR):

- `credentials` — the user sets their own password after approval.
- `realmRoles` / `clientRoles` — roles are assigned through the separate
  `POST /users/{id}/role-mappings/*` endpoint, which IGA already governs
  as a standalone `GRANT_ROLES` change request.
- `requiredActions`, `federatedIdentities`, `createdTimestamp`,
  `federationLink` — not part of the issued token; intentionally out of
  scope.

> **Note**
> Keycloak's **declarative UserProfile** drops any custom user attribute
> that is not declared in the realm user-profile configuration. If you
> rely on a custom attribute (`x`, `department`, ...), declare it in the
> realm user-profile first; otherwise KC silently strips it on create and
> the captured `UserRepresentation.attributes` will not contain it. The
> E2E suite uses
> `e2e/lib/kc.ts:declareUserProfileAttribute` to set this up before
> creating users; operators should do the same in any automated user
> provisioning.

## Multi-entity governance: `partialImport`

Keycloak's bulk `POST /admin/realms/{realm}/partialImport` endpoint is
governed by **Phase 4** batch capture
(`IgaImportMode.java`,
`IgaImportMode.BatchEmitTransaction.commit`).

### How it appears to an operator

- Submit a `partialImport` payload containing any governed entity types
  (clients, roles, groups, users — and client scopes once a future KC
  version registers them; see the note below).
- IGA returns **`202 Accepted`** with a single batch envelope:

  ```json
  {
    "status": "PENDING",
    "changeRequestId": "<uuid of the first per-type CR in the batch>",
    "entityType": "BATCH",
    "actionType": "PARTIAL_IMPORT",
    "message": "Change request created — awaiting approval"
  }
  ```
- The `Location` header points at the first per-type CR
  (`/admin/realms/{realm}/iga/change-requests/{id}`).
- **Nothing in the import is persisted at draft time.** Internally, IGA
  enlists a `BatchEmitTransaction` on the partialImport's nested session
  via `enlistPrepare`. That transaction harvests every accumulated entity
  into one batch of per-type CRs (each with the SAME row contract that
  the single-entity seam would have written), writes them in one
  independent `runJobInTransaction`, then throws — which rolls back the
  whole nested import scratch and discards every entity atomically.
- On approval, each per-type CR is committed individually through the
  normal `IgaReplayDispatcher` (no batch-specific replay path; the
  dispatcher is byte-unchanged since `742f944`).

### Required payload shape

> **Important**
> Keycloak 26.5.5 requires `groupRep.path` on every group representation
> in a `partialImport` payload. This is a vanilla KC constraint — not an
> IGA one. `GroupsPartialImport.getModelId` calls
> `findGroupModel(realm, groupRep).getId()`; the inner helper guards
> `if (path == null) return null;` and KC then dereferences the null →
> `NullPointerException` → HTTP 500. To confirm it is a KC issue rather
> than IGA, send the same payload to an **IGA-disabled** realm — if it
> still 500s with an NPE in `GroupsPartialImport.java:53`, it is the KC
> contract. Always populate `path` on every group rep in the payload.

```json
{
  "groups": [
    { "name": "hr", "path": "/hr" }
  ]
}
```

The E2E suite encodes this expectation in
`e2e/tests/phase4-multientity-governance.spec.ts` (the `path` field on
line 148 is explicitly set with the same rationale).

### What is NOT captured today

> **Note**
> Client scopes inside a `partialImport` payload are **not** produced as
> `CREATE_CLIENT_SCOPE` rows by KC 26.5.5, because KC's
> `PartialImportManager` does not register a `ClientScopesPartialImport`
> handler (the registered handlers are
> Clients/Roles/IdPs/IdP-mappers/Groups/Users). The IGA import branch
> for `addClientScope` is **defensive parity** wiring — symmetrical with
> `addClient`, with the same accumulate-then-emit contract — so it will
> auto-activate if a future KC version adds the handler. Today, a
> `partialImport` carrying `clientScopes` simply leaves them out of the
> batch.

### Authorizing and committing the batch

The batch creates **N per-type CRs**, not one combined CR. To approve the
whole import, authorize **each** CR and then commit each. There is no
"approve the batch" shortcut — every per-type CR is gated independently
on its own scope/threshold rules. In practice, configure your scopes so
the same approver role covers every per-type CR in a typical import.

## Failure responses an operator will see

| Trigger | Status | Body | Source |
|---------|--------|------|--------|
| Caller missing `manage-realm` on authorize/commit/list/get/deny. | **403** | `ForbiddenException` (Keycloak's default body). No custom mapper. | `IgaAdminResource.java:198, :262, :143, :179, :375` (`auth.realm().requireManageRealm()`) |
| Approver lacks the required role (`iga.approverRole`). | **403** | `Approver role required: [<role-list>] (mode=any|all)` | `IgaScopeResolver.java:193-194` (raised inside `SimpleNameAttestor.record` and again in `commit`) |
| Commit with `authCount < threshold`. | **412 Precondition Failed** | `{"error":"Need N more signature(s)", "threshold": <int>, "authCount": <int>}` | `IgaAdminResource.java:292-301` |
| Authorize twice from the same admin. | **409 Conflict** | `{"error":"Caller has already signed this change request"}` | `IgaAdminResource.java:226-238` (matches on username OR `authorized_by` id) |
| Authorize/commit a CR that is not `PENDING`. | **409 Conflict** | `{"error":"Change request is not in PENDING state (current=<status>)"}` | `IgaAdminResource.java:269-273` |
| Setting a second realm/realm-config attribute while one is already pending. | **409 Conflict** | (Keycloak default body for the underlying `BadRequestException`.) | `IgaRealmAdapter.checkNoPendingCr`, `IgaRealmAdapter.java:106-111` |
| Group payload missing `path` on `partialImport`. | **500** | KC `KC-SERVICES0037` (vanilla KC NPE — not IGA-specific). | KC `GroupsPartialImport.java:53` |

> **Note**
> A **rejected** authorize attempt (no required role) leaves
> `authCount = 0`. `SimpleNameAttestor.record` calls
> `IgaScopeResolver.requireApprover` (which throws
> `ForbiddenException`) **before** `em.persist(auth)`
> (`SimpleNameAttestor.java:52` vs `:62`), so no partial signature row
> ever exists.

## Default behavior when nothing is configured

**When IGA is freshly enabled and nothing has `iga.approverRole` or
`iga.threshold` configured, which admin is allowed to sign?**

**Any admin with the realm `manage-realm` permission can authorize *and*
commit *any* change request — there is no narrower built-in "first
approver" role.** Why, from the code:

- Every approval endpoint (`authorize`, `commit`, `list`, `get`, `deny`)
  starts with `auth.realm().requireManageRealm()`
  (`IgaAdminResource.java:198`, `:262`, `:143`, `:179`, `:375`).
- The only additional gate is
  `IgaScopeResolver.requireApprover(...)`, which **returns immediately
  when the required-roles set is empty**
  (`IgaScopeResolver.java:182-196`, early return at line 183).
- With zero `iga.approverRole` attributes anywhere, every change request
  resolves to an empty scope, so `requireApprover` never blocks.
- With no `iga.threshold` set anywhere, the threshold defaults to
  **`1`** (`IgaScopeResolver.java:212`, defensive clamp at `:229`).

> **Warning — bootstrap is by design.** With zero configuration, a single
> admin holding `manage-realm` can self-approve and commit any change
> with **one** signature. This is not meaningful four-eyes governance
> until you harden it (raise the threshold, set approver roles on
> sensitive scopes, decide scope mode), and you must do that hardening
> **before** enabling IGA (see
> [Ordering](#ordering-configure-governance-before-enabling-iga)). The
> `master` realm admin is also exempt entirely.

## Governing Keycloak Organizations

IGA governs Keycloak Organizations (KC 26.5.5 organization SPI). The
`IgaOrganizationProvider` extends `JpaOrganizationProvider` and
intercepts organization mutations exactly the way `IgaRealmProvider`
intercepts client/group/role creation
(`iga-core/.../providers/IgaOrganizationProvider.java`).

### Covered actions

| Action type | Triggering admin operation | Scope |
|-------------|---------------------------|-------|
| `CREATE_ORGANIZATION` | `POST {realm}/organizations` | Realm-wide (empty scope), like other top-level creates |
| `UPDATE_ORGANIZATION` | `PUT {realm}/organizations/{id}` (includes domain changes) | The organization |
| `DELETE_ORGANIZATION` | `DELETE {realm}/organizations/{id}` | The organization |
| `ADD_ORG_MEMBER` | `POST {realm}/organizations/{id}/members` | The organization |
| `REMOVE_ORG_MEMBER` | `DELETE {realm}/organizations/{id}/members/{member-id}` | The organization |
| `ORG_INVITE_MEMBER` | `POST {realm}/organizations/{id}/members/invite-user` and `.../invite-existing-user` | The organization |
| `ORG_ADD_IDP` | `POST {realm}/organizations/{id}/identity-providers` | The organization |
| `ORG_REMOVE_IDP` | `DELETE {realm}/organizations/{id}/identity-providers/{alias}` | The organization |

> **Note**
> Organization **domains** are not a separate governed action. KC 26.5.5
> has no standalone domain endpoint; domains are part of the organization
> representation and are changed through `UPDATE_ORGANIZATION` (or set
> at `CREATE_ORGANIZATION`). They are governed via the create/update
> change request, which carries the full `OrganizationRepresentation` as
> `REP_JSON` so replay rebuilds attributes and domains through
> Keycloak's own `RepresentationToModel.toModel`
> (`IgaOrganizationProvider.java:42-48`,
> `IgaReplayDispatcher.java:545-570`).

### How organization actions are scoped

`OrganizationModel` supports attributes, so an organization can carry
`iga.approverRole` and `iga.threshold` just like a group, role, or
client. For `UPDATE_ORGANIZATION`, `DELETE_ORGANIZATION`,
`ADD_ORG_MEMBER`, `REMOVE_ORG_MEMBER`, `ORG_INVITE_MEMBER`,
`ORG_ADD_IDP`, and `ORG_REMOVE_IDP`, `IgaScopeResolver` resolves the
scope from the organization itself via `collectOrganizationScope`
(`IgaScopeResolver.java:156-164`, `:312-321`). Set these attributes on
the organization through **Organizations → (organization) →
Attributes** in the console, or by adding them to the organization
representation `attributes` map via
`PUT /admin/realms/{realm}/organizations/{org-id}`. Remember the
[coupling rule](#warning-the-approver-role--threshold-coupling-rule):
set both `iga.approverRole` and `iga.threshold` together, or the
threshold will be silently ignored.

`CREATE_ORGANIZATION` is realm-wide: no organization exists yet, so the
scope is empty and the only gate is `manage-realm` plus the threshold,
exactly like other top-level creates (`IgaScopeResolver.java:165-170`,
`IgaOrganizationProvider.java:117-144`).

### Invitations

> **Note**
> When IGA is active, inviting a member creates a change request and
> **no invitation e-mail or action token is produced until the change
> request is committed**. The interception happens at the
> `InvitationManager.create` SPI seam, strictly *before* the invitation
> entity is persisted and therefore before the action token is
> serialized and before the e-mail is sent
> (`IgaInvitationManager.java:86-100`,
> `IgaOrganizationProvider.java:248-272`). Denying the change request
> means no invitation, no token, and no e-mail is ever produced — there
> is nothing to undo. On commit, replay re-runs Keycloak's own
> invitation logic now: the invitation is persisted, a fresh
> `InviteOrgActionToken` is minted, and the e-mail is sent at that
> moment. **Token/invitation validity therefore starts at commit
> (approval) time**, because `expiresAt` is computed inside Keycloak's
> `create()` as
> `Time.currentTime() + realm.getActionTokenGeneratedByAdminLifespan()`
> (`IgaReplayDispatcher.java:618-689`). Replay runs at most once per
> change request, so exactly one invitation/token/e-mail is produced —
> never a duplicate.

## Operator runbook

Quick references for the most common operations. All requests assume
`TOKEN` is a `manage-realm` bearer for the target realm.

### Enable IGA on a realm

```bash
# 1. Configure governance FIRST (see the procedure sections above).
# 2. Toggle IGA on.
curl -fsS -X POST -H "Authorization: Bearer $TOKEN" \
  "$KC_URL/admin/realms/$REALM/tide-admin/toggle-iga"
# 3. Verify.
curl -fsS -H "Authorization: Bearer $TOKEN" \
  "$KC_URL/admin/realms/$REALM/tide-admin/iga-status"
# → {"enabled":true}
```

### Set thresholds and approver roles (paired)

```bash
# Realm-wide default threshold:
curl -fsS -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"attributes":{"iga.threshold":"2","iga.scopeMode":"any"}}' \
  "$KC_URL/admin/realms/$REALM"

# Per-entity (group) — BOTH attributes together (coupling rule):
curl -fsS -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"attributes":{"iga.approverRole":["hr-approver"],"iga.threshold":["3"]}}' \
  "$KC_URL/admin/realms/$REALM/groups/$GROUP_ID"
```

### Create a governed change request

Any privileged write while IGA is on creates a CR. Example — create a
client:

```bash
curl -i -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"clientId":"my-app","enabled":true,"publicClient":true}' \
  "$KC_URL/admin/realms/$REALM/clients"
# → HTTP/1.1 202 Accepted
# → Location: /admin/realms/$REALM/iga/change-requests/<uuid>
# → {"status":"PENDING","changeRequestId":"<uuid>","entityType":"CLIENT","actionType":"CREATE_CLIENT", ...}
```

### Authorize and commit a CR

```bash
# Authorize (records ONE signature for the calling admin).
curl -fsS -X POST -H "Authorization: Bearer $TOKEN" \
  "$KC_URL/admin/realms/$REALM/iga/change-requests/$CR_ID/authorize"

# Commit (replays the change against Keycloak's real model).
curl -fsS -X POST -H "Authorization: Bearer $TOKEN" \
  "$KC_URL/admin/realms/$REALM/iga/change-requests/$CR_ID/commit"
# 412 here means the threshold isn't met yet: collect more authorize calls
# from distinct admins and try commit again.
```

### Revoke (deny) a CR

```bash
curl -fsS -X POST -H "Authorization: Bearer $TOKEN" \
  "$KC_URL/admin/realms/$REALM/iga/change-requests/$CR_ID/deny"
```

### List pending CRs

```bash
curl -fsS -H "Authorization: Bearer $TOKEN" \
  "$KC_URL/admin/realms/$REALM/iga/change-requests"
# Defaults to status=PENDING. Pass ?status=APPROVED or ?status=DENIED to list those.
```

## Known limitations

- **Native organization-membership admin event is not emitted for
  IGA-approved invitations.** When `ORG_INVITE_MEMBER` is committed,
  replay faithfully reproduces Keycloak's
  `OrganizationInvitationResource.sendInvitation` mechanics (invitation,
  token, e-mail) but intentionally does **not** fire the trailing
  `adminEvent...success()` audit event — the replay dispatcher has no
  `AdminEventBuilder`, exactly like every other replay action. The
  **approved IGA change request is the authoritative audit record** for
  the invitation (`IgaReplayDispatcher.java:618-651`). Do not rely on a
  native `ORGANIZATION_MEMBERSHIP`-style admin event for IGA-approved
  invitations; audit through the change-request history instead.
- **Role policies do not drive enforcement (yet).** The
  `IGA_ROLE_POLICY` table / `IgaRolePolicyEntity` has a `THRESHOLD`
  column and there are `/iga/role-policies` endpoints, but that
  `THRESHOLD` is **not** consulted by the authorize/commit threshold
  gate. It is read only by the non-cryptographic
  `IgaFirstAdminSignPreviewService` preview/prototype and echoed back
  through the role-policy REST representation. To control the *enforced*
  threshold today, use the realm or per-entity `iga.threshold`
  attribute — not a role-policy row. This is the Tide-mode scaffolding
  referenced in [Modes](#modes-tideless-vs-tide).
- **Composite-role links across separate pending change requests are
  skipped.** During `CREATE_ROLE` replay, if a composite-target role
  does not yet exist (e.g. it is itself sitting in a different pending
  change request), that single composite link is skipped and
  warn-logged rather than failing the whole replay
  (`IgaReplayDispatcher.java:294-304` for realm composites, `:311-317`
  for client composites). Re-establish the link after the other change
  request is committed.
- **Old pre-`REP_JSON` pending change requests are identity-only.**
  Change requests created before the full-representation capture change
  lack the captured representation. On replay they get at most a bare
  identity-only create (no attributes/mappers/full config); there is no
  old-format compatibility (`IgaReplayDispatcher.java:50-66`). Recreate
  such change requests after upgrading rather than relying on replay.
- **`isIGAEnabled` is case-sensitive and exact.** Only the literal
  string `"true"` enables IGA. Any other value, including `"True"`,
  leaves it off.
- **The first write after enable is not governed.** Because the enable
  check reads the attribute being mutated, the act of enabling IGA is
  itself not governed by design. Plan the enable as a deliberate,
  trusted operation, and configure governance beforehand.
- **A non-positive realm `iga.threshold` is ignored, not honored.** A
  value of `"0"`, a negative number, or a non-integer is treated as
  `1` (the same positivity rule as the per-entity path), and
  `resolveThreshold` applies a defensive final clamp so it can never
  return below `1`. A bad realm value therefore cannot disable the
  commit gate — it simply behaves as `1`. Set `iga.threshold` to the
  positive integer you actually want.
- **Per-entity `iga.threshold` requires a paired `iga.approverRole`.**
  See the
  [coupling rule](#warning-the-approver-role--threshold-coupling-rule).
- **No `ClientScopesPartialImport` in KC 26.5.5.** Client scopes inside
  a `partialImport` payload are not produced as `CREATE_CLIENT_SCOPE`
  rows. The IGA import branch is defensive parity for forward
  compatibility.
- **User CR omits non-token fields.** Credentials, role mappings,
  required actions, federated identities, `createdTimestamp` and
  `federationLink` are intentionally NOT in the captured
  `UserRepresentation`. See [What gets captured](#what-gets-captured-per-entity-type).

## Internals

(For developers.) To add a new captured entity type or action, see the
contributor guide: [Extending IGA](EXTENDING-IGA.md).

- **`IgaRealmProvider`** (`providers/`) — `JpaRealmProvider` subclass;
  wraps the realm in `IgaRealmAdapter` and overrides `add*`
  (client/role/group/client-scope) to intercept creates; persists the
  change request in a separate transaction and throws
  `IgaPendingApprovalException`. Each branch also has an
  `IgaImportMode.isImportMode(...)` short-circuit that registers the
  capture-mode adapter with the batch accumulator instead of
  per-entity throw.
- **`IgaUserProvider`** (`providers/`) — `UserProvider` decorator;
  intercepts both the 1-arg
  `UsersResource.createUser` model seam (single-entity) and the 5-arg
  local-storage `addUser` seam (used by
  `DefaultExportImportManager.createUser` on `partialImport`).
- **`IgaRealmAdapter` / `Iga*Adapter`** — wrap Keycloak model adapters
  and intercept attribute/relationship/config writes into change
  requests; gated by `isIgaActive()` (enabled and not currently
  replaying).
- **`IgaImportMode`** (`providers/`) — Phase 4 multi-entity (batch)
  governance for `partialImport`. Detects the `partialImport` stack
  frame, enlists a `BatchEmitTransaction` on the nested import session,
  accumulates per-type CRs, and emits them in one independent
  transaction before throwing to roll back the scratch import. Replay
  contract is byte-identical to single-entity capture — no changes to
  `IgaReplayDispatcher`.
- **`IgaClientAdapter.updateClient()`** — Phase 4 **eager-harvest**
  client seam. Harvests `CREATE_CLIENT` at the end of
  `RepresentationToModel.createClient` (KC 26.5.5
  `RepresentationToModel.java:404`), avoiding a ConcurrentModification
  during `BatchEmitTransaction.commit` (see
  [`EXTENDING-IGA.md`](EXTENDING-IGA.md#lessons-learned-with-receipts)
  for the full story).
- **`IgaOrganizationProvider`** (`providers/`) —
  `JpaOrganizationProvider` subclass; intercepts
  create/update/delete/member/idp organization mutations; returns an
  `IgaInvitationManager` from `getInvitationManager()` so invitations
  are intercepted at the SPI seam before any token/e-mail.
- **`IgaInvitationManager`** (`providers/`) — decorating
  `InvitationManager` whose `create(...)` records an
  `ORG_INVITE_MEMBER` change request and throws before the invitation
  entity is persisted; all reads/removes delegate straight to the
  wrapped manager.
- **`IgaPendingApprovalExceptionMapper`** (`rest/`) — maps the
  interception exception to HTTP 202 with the `{status:"PENDING",
  changeRequestId, ...}` body.
- **`IgaScopeResolver`** (`attestors/`) — walks a change request's
  `rows_json` to derive required approver roles and scoped thresholds;
  enforces the approver gate (`requireApprover`) and computes the
  effective threshold (`resolveThreshold`). Holds the attribute key
  constants. **Approver-role / threshold coupling is enforced here**
  (`addThreshold` only fires under
  `iga.approverRole != null && !isBlank()`).
- **`SimpleNameAttestor`** (`attestors/`) — default attestor (no
  cryptography): records the approving admin's username as the
  signature, enforces the scope gate on `record` **before**
  `em.persist`, combines signatures into a JSON array on
  `combineFinal`, and delegates `getThreshold` to `IgaScopeResolver`.
- **`IgaReplayDispatcher`** (`replay/`) — on commit, sets
  `IGA_REPLAY_ACTIVE=true`, replays the recorded operation against the
  real Keycloak model (rebuilding full config from `REP_JSON` for
  creates, replaying relationship/attribute rows, and re-running
  Keycloak's own organization/invitation logic for org actions), writes
  the final attestation, and marks the change request `APPROVED`.
  **Byte-unchanged from commit `742f944`.**
- **`IgaAdminResource`** (`rest/`, `@Path("iga")`) — all operator
  endpoints: `change-requests`
  (list/get/update/authorize/commit/deny/comments), `role-policies`,
  `authorizers`, `forseti-contracts`, `server-certs`, `licensing`,
  `baseline-review`. Every endpoint requires `manage-realm` (deny /
  comment-delete additionally allow the original author).
- **`TideAdminCompatResource`** (`rest/`, `@Path("tide-admin")`) —
  backwards-compatible `toggle-iga` / `iga-status` endpoints driving
  the `isIGAEnabled` realm attribute.
