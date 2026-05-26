# Identity Governance and Administration (IGA)

> **Last updated:** 2026-05-21. Reflects Phases 1–7 as of commit `742c9eb`
> (branch `iga-approval-workflow`; Phase 7e docs refresh on top of Phase 7d
> backend HEAD). This guide is the operator/administrator reference.
> Developers extending IGA should start at
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
2. [Governance scope (what IGA does NOT govern)](#governance-scope-what-iga-does-not-govern)
3. [Modes: Tideless vs Tide](#modes-tideless-vs-tide)
4. [Concepts and attributes](#concepts-and-attributes)
5. [Enabling and disabling IGA](#enabling-and-disabling-iga)
6. [Configuring thresholds](#configuring-thresholds)
7. [Restricting who can approve](#restricting-who-can-approve)
8. [Ordering: configure governance before enabling IGA](#ordering-configure-governance-before-enabling-iga)
9. [The approval workflow: authorize then commit](#the-approval-workflow-authorize-then-commit)
10. [What gets captured (per entity type)](#what-gets-captured-per-entity-type)
11. [Multi-entity governance: `partialImport`](#multi-entity-governance-partialimport)
12. [Failure responses an operator will see](#failure-responses-an-operator-will-see)
13. [Default behavior when nothing is configured](#default-behavior-when-nothing-is-configured)
14. [Governing Keycloak Organizations](#governing-keycloak-organizations)
    - [Bootstrap: retroactive ADOPT_ORGANIZATION on IGA toggle (Phase 7b)](#bootstrap-retroactive-adopt_organization-on-iga-toggle-phase-7b)
    - [Quarantine: the org `isEnabled` override and its cascade (Phase 7c)](#quarantine-the-org-isenabled-override-and-its-cascade-phase-7c)
    - [IdP-aware scope for ORG_ADD_IDP / ORG_REMOVE_IDP (Phase 7d)](#idp-aware-scope-for-org_add_idp--org_remove_idp-phase-7d)
    - [Bootstrap-safety and escape hatches (organizations)](#bootstrap-safety-and-escape-hatches-organizations)
    - [SMTP-tolerance on invitation replay](#smtp-tolerance-on-invitation-replay)
    - [Known gaps and follow-ups (organizations)](#known-gaps-and-follow-ups-organizations)
15. [Phase 6: retroactive ADOPT and quarantine on IGA toggle](#phase-6-retroactive-adopt-and-quarantine-on-iga-toggle)
16. [Bulk-authorizing pending change requests](#bulk-authorizing-pending-change-requests)
17. [Known limitations](#known-limitations)
18. [Internals](#internals)

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

## Governance scope (what IGA does NOT govern)

IGA's surface is deliberately bounded to the **token-shaping** Keycloak
objects — the entities and relationships that decide what lands in an issued
OIDC token. Several Keycloak surfaces are **intentionally out of scope**.
Each exclusion below is a deliberate design decision, not an oversight; the
rationale and any caveat are recorded so operators know exactly what is — and
is not — behind the approval gate.

- **Federated-storage users are NOT governed.** Users backed by a user
  storage provider (LDAP / Kerberos federation) live in the `fed_user_*`
  tables and carry ids of the form `f:<provider-id>:<external-id>`. The
  quarantine and the toggle-on ADOPT scan key on `user_entity` **only**, so a
  federated user is never seen as unsigned — it is treated as
  not-unsigned (**fail-open**). *By design:* Tide realms use Tide-native
  identities, not LDAP/Kerberos federation, so there is nothing to govern in
  practice. **If federation is ever enabled on a realm, this must be
  revisited — it would become a security hole** (a federated user would
  bypass the quarantine entirely). Note that `FED_USER_ATTRIBUTE.attestation`
  exists as a column but is **unused/dead** today; it is not read or written
  by any IGA path.
- **UMA / Authorization Services are NOT governed.** The
  `resource_server`, `resource_server_resource`, `resource_server_scope`,
  `resource_server_policy`, and related tables are not intercepted. *Rationale:*
  authorization-services policies are evaluated at the **UMA permission
  endpoint**, not in the OIDC token-construction pipeline, so they fall
  outside IGA's token-shaping surface. **Caveat:** an admin who grants access
  by editing a `user`- or `role`-based authorization policy is therefore
  acting outside IGA governance.
- **IdP claim/role mappers are NOT governed as entities.** Rows in
  `identity_provider_mapper` are referenced only by IdP alias when an org
  adds or removes an IdP (`ORG_ADD_IDP` / `ORG_REMOVE_IDP`); they are never
  ADOPT-able entities in their own right. **Caveat:** an IdP mapper **can**
  inject claims and roles into an issued token, so this is an **ungoverned
  token-shaping surface** — flagged for a future phase (it ties to the
  "IdPs as an ADOPT-able entity" roadmap item; see
  [IdP-aware scope](#idp-aware-scope-for-org_add_idp--org_remove_idp-phase-7d)).
- **Authentication flows are NOT governed.** The `authentication_flow`,
  `authentication_execution`, and `authenticator_config` tables are not
  intercepted. *Rationale:* authentication flows are a security-relevant
  admin surface, but they shape **how a user authenticates**, not the
  **claims placed in the issued token**, so they are outside IGA's
  token-claim-shaping scope.

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
  `CREATE_ORGANIZATION`, `SET_REALM_*`, `ADOPT_*` (toggle-on adoption,
  Phase 6), license
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
| `ORG_RESEND_INVITE` | `POST {realm}/organizations/{id}/invitations/{inv-id}/resend` | The organization |
| `ORG_ADD_IDP` | `POST {realm}/organizations/{id}/identity-providers` | The organization (+ the linked IdP — see [IdP-aware scope](#idp-aware-scope-for-org_add_idp--org_remove_idp-phase-7d)) |
| `ORG_REMOVE_IDP` | `DELETE {realm}/organizations/{id}/identity-providers/{alias}` | The organization (+ the linked IdP — see [IdP-aware scope](#idp-aware-scope-for-org_add_idp--org_remove_idp-phase-7d)) |

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

### Bootstrap: retroactive ADOPT_ORGANIZATION on IGA toggle (Phase 7b)

The Phase 6b OFF→ON adopt scan
([Phase 6: retroactive ADOPT and quarantine](#phase-6-retroactive-adopt-and-quarantine-on-iga-toggle))
was extended in Phase 7b to cover organizations. When
`POST /admin/realms/{realm}/tide-admin/toggle-iga` flips `isIGAEnabled`
from `false` → `true`, the toggle handler now also walks every existing
`OrganizationEntity` in the realm and emits one PENDING
`ADOPT_ORGANIZATION` change request per row, plus a matching
`IGA_UNSIGNED_ENTITY` sidecar row keyed on
`(realmId, entityType='ORGANIZATION', entityId=orgId)`. The scan response
JSON exposes the count under `scan.adoptCrsCreated.ORGANIZATION` alongside
the existing USER / ROLE / GROUP / CLIENT / CLIENT_SCOPE counts (see
[Toggle response shape](#toggle-response-shape) for the full body).

> **Note**
> The `OrganizationEntity` table has **no `attestation` column**. This is
> a deliberate departure from the Phase 6 storage-on-the-entity pattern:
> orgs are sidecar-only. The signed/unsigned state lives entirely in
> `IGA_UNSIGNED_ENTITY` plus the CR row's `status=APPROVED` — there is no
> per-org attestation byte. This avoided a schema migration on the stock
> KC organization table and keeps the IGA provider a pure wrapper around
> `JpaOrganizationProvider`
> (`IgaReplayDispatcher.java:483-497`,
> `IgaOrganizationProvider.java`).

The ADOPT_* gate bypass from Phase 6c
([ADOPT gate bypass: threshold + approver-role](#adopt-gate-bypass-threshold--approver-role))
applies unchanged to `ADOPT_ORGANIZATION`: threshold is forced to 1 and
no `iga.approverRole` check fires, so any admin with `manage-realm`
can self-authorize + self-commit a freshly-emitted ADOPT_ORGANIZATION CR
on the toggled realm. This is what keeps the toggle-on event a single
maintenance window rather than a multi-admin coordination problem.

### Quarantine: the org `isEnabled` override and its cascade (Phase 7c)

While a PENDING `ADOPT_ORGANIZATION` CR exists for an org (equivalently:
while the org's `IGA_UNSIGNED_ENTITY` sidecar row is present), the IGA
provider's `IgaOrganizationModel.isEnabled()` returns **`false`**
regardless of the underlying `OrganizationEntity.enabled` column. The
override is implemented at `IgaOrganizationModel.java:289-310` (defers
first to the wrapped delegate's real flag, then consults
`IgaQuarantineCache.isOrganizationUnsigned`; respects the
`IGA_REPLAY_ACTIVE` gate so the ADOPT commit's own replay can touch the
org mid-commit). Operators observe this directly on admin REST: a
`GET /admin/realms/{realm}/organizations/{orgId}` while the CR is
PENDING returns the org rep with `enabled=false`.

The override is consumed by KC's own org-aware enforcement points — the
override does not need a new IGA seam for each of them, every consumer
that reads `org.isEnabled()` observes the quarantine automatically. The
known cascade points in KC 26.5.5 are:

| KC source (line ref) | What it gates | Cascade effect while ADOPT_ORGANIZATION is PENDING |
|----------------------|---------------|----------------------------------------------------|
| `Organizations.isReadOnlyOrganizationMember:288-291` | `UserCacheSession.getUserById:384` wraps managed members in `ReadOnlyUserModelDelegate` | Managed org members become read-only on admin REST: `PUT {realm}/users/{userId}` setters throw `ReadOnlyException` → `400 Bad Request "User is read only!"` (`UserResource.java:249-251`). Unmanaged members are unaffected. |
| `OrganizationAuthenticator.authenticate:215` | Org-aware browser auth flow (the post-username-form branch that picks an org by domain) | Org-scoped browser logins are refused. The user sees the standard authenticator failure page; KC does not reveal `enabled=false` to the end-user. |
| `IdpAddOrganizationMemberAuthenticator.configuredFor:82` | The IdP-broker authenticator that calls `provider.addManagedMember(...)` at completion | IdP-brokered users who would have been auto-added to the org as managed members are NOT added; the authenticator's `configuredFor` returns false and the auth step is `attempted()` (advances to the next step) rather than succeeding. |
| `RegistrationPage.render:69` | The invitation-flow registration form's pre-render gate | Registration via an `InviteOrgActionToken` for the quarantined org is rejected with `BAD_REQUEST` + `EXPIRED_ACTION` message. (Existing minted tokens still bind to the org id; they just can't complete until the org is un-quarantined.) |
| `OrganizationScope.resolveOrganizations:196` + `OrganizationMembershipMapper.resolveValue:159` | The OIDC `organization` claim mapper attached to the stock `organization` client-scope | Tokens issued via direct-grant / authorization-code while the org is quarantined OMIT the org from the `organization` claim. This is the cascade point Phase 7e exercises end-to-end (`e2e/tests/phase7e-org-cascade.spec.ts`). |

> **Note**
> The fifth row (the OIDC claim mapper) is what the Phase 7e
> cascading-enforcement E2E asserts: it lifts user + client quarantine
> via ADOPT_USER + ADOPT_CLIENT commits, leaves ADOPT_ORGANIZATION
> PENDING, then issues a `scope=openid organization` direct-grant token
> and observes the `organization` claim is absent until
> ADOPT_ORGANIZATION commits and the cascade lifts.

> **Important**
> The managed-member-read-only branch
> (`Organizations.isReadOnlyOrganizationMember:290`) only fires for
> members whose `UserGroupMembership.MembershipType` is `MANAGED`. KC
> 26.5.5 exposes no admin-REST endpoint that creates a managed
> membership — `POST {realm}/organizations/{id}/members` always creates
> UNMANAGED. Managed status is set exclusively by
> `IdpAddOrganizationMemberAuthenticator.authenticate:63` during an
> IdP-broker login. If your deployment has no IdP-broker traffic for an
> org, no members of that org are managed, and the read-only cascade is
> latent (visible if/when an IdP-broker login first runs).

The lift path is symmetric: once `ADOPT_ORGANIZATION` commits, the IGA
replay clears the sidecar row, evicts the per-org `CachedOrganization`
entry via the public `CacheRealmProvider.registerInvalidation(orgId)`
primitive (`TideAdminCompatResource.java:627-659`), and the next
`getById` / `getByMember` lookup re-runs through the IGA provider chain
and observes the sidecar absence — `isEnabled()` returns `true` again,
and every cascade point above reverts to the pre-quarantine path.

### IdP-aware scope for ORG_ADD_IDP / ORG_REMOVE_IDP (Phase 7d)

`ORG_ADD_IDP` and `ORG_REMOVE_IDP` are **two-entity** actions: each binds
both the organization and the linked identity provider. Phase 7d
extended `IgaScopeResolver` so the commit-time gate merges scope
contributions from BOTH the org AND the IdP, not just the org.

For these two action types, `IgaScopeResolver.resolve`
(`IgaScopeResolver.java:174-189`) calls
`resolveOrganizationScopesFromRows` AND `resolveIdpScopesFromRows`,
keyed off the captured `ORG_ID` and `IDP_ALIAS` rows respectively. The
IdP-side helper (`collectIdpScope` at `IgaScopeResolver.java:444-457`)
reads `iga.approverRole` and `iga.threshold` off
`IdentityProviderModel.getConfig()` (the stock KC IdP-config map at
`server-spi:208`), conditional on `iga.approverRole` being set on the
IdP — same coupling rule as everywhere else
([the approver-role / threshold coupling rule](#warning-the-approver-role--threshold-coupling-rule)).

Merge semantics (shared `ResolvedScope` across both helpers):

- **`requiredApproverRoles`**: UNION of the org's + the IdP's approver
  roles. In default scope mode (`any`) a single match by ANY signer
  satisfies the gate; in `all` mode every contributed role must be
  matched at least once across the set of signers.
- **`thresholds`**: MAX across all collected thresholds
  (`resolveThresholdInternal:280-298` takes the max across
  `scope.thresholds`; the realm-level `iga.threshold` is only the
  fallback when `scope.thresholds` is empty).

> **Note**
> Setting `iga.threshold` / `iga.approverRole` on an IdP is identical to
> setting them on an org or a role: edit the IdP's config map via
> `PUT /admin/realms/{realm}/identity-provider/instances/{alias}`
> carrying `config: { "iga.threshold": "3", "iga.approverRole": "idp-approver", ... }`.
> The coupling rule still applies — set both or the threshold is
> silently ignored. Same gotcha as everywhere else, just on a different
> entity surface.

> **Warning**
> IdPs are **not in the toggle-on ADOPT scan**. Identity providers are
> configuration objects rather than user-data, and the Phase 7b scan
> deliberately scans only the five user-data tables plus
> `OrganizationEntity`. IdPs are pulled into governance only when they
> participate as a scope contributor for `ORG_ADD_IDP` / `ORG_REMOVE_IDP`
> CRs, not as ADOPT subjects in their own right.

### Bootstrap-safety and escape hatches (organizations)

The general bootstrap-safety guarantees from Phase 6
([Bootstrap-safety and escape hatches](#bootstrap-safety-and-escape-hatches))
apply unchanged to organizations:

- **Master-realm admin is the unconditional escape.** The master realm
  is system-skipped: no IGA capture fires on master-realm operations,
  so a master-realm admin can always disable IGA on a non-master realm
  via `POST /admin/realms/{realm}/tide-admin/toggle-iga` even if every
  org in that realm is quarantined.
- **`ADOPT_ORGANIZATION` reuses the ADOPT_* gate bypass.** Threshold is
  forced to 1; no `iga.approverRole` check fires. A single admin with
  `manage-realm` can always sign + commit. This is what makes the
  toggle-on adopt scan recoverable: even if `iga.approverRole` is
  mis-configured on the realm or on individual orgs, the ADOPT family
  is still committable by any admin holding the base management role.

### SMTP-tolerance on invitation replay

The `ORG_INVITE_MEMBER` and `ORG_RESEND_INVITE` replay paths (both
handled by the same `replayOrgInviteMember` method at
`IgaReplayDispatcher.java:618-744`) **tolerate SMTP failure**: the
invitation row is persisted by `invitationManager.create(...)` BEFORE
the e-mail send is attempted, and a `try/catch (EmailException)` wraps
the e-mail send so a misconfigured / down SMTP server emits a WARN log
line and the commit still returns 200. The CR is marked APPROVED and
the invitation persists.

> **Warning**
> If your deployment relies on the invitation e-mail actually being
> delivered (rather than the action token being communicated
> out-of-band), monitor the IGA replay logs for the line:
>
> ```
> IGA replay ORG_INVITE_MEMBER: invitation persisted but e-mail send failed
> ```
>
> Recovery: the same invitation can be re-triggered via the standard
> `POST {realm}/organizations/{id}/invitations/{inv-id}/resend`
> endpoint (which itself flows through `ORG_RESEND_INVITE` governance
> and lands back in the same replay path) once SMTP is restored.
> Reasoning for the swallow-and-log behaviour — and why the commit must
> not fail on an infrastructure problem post-approval — is documented
> inline at `IgaReplayDispatcher.java:697-708`.

### Known gaps and follow-ups (organizations)

These are documented limitations of the Phase 7 org governance surface
as it ships at HEAD `742c9eb`. None are blockers; each is recorded so
operators know what NOT to rely on.

- **`ORG_RESEND_INVITE` removes the original invitation BEFORE the IGA
  capture seam fires.** KC's
  `OrganizationInvitationResource.resendInvitation:322-333` calls
  `invitationManager.remove(id)` and only *then* delegates to
  `inviteUser(...)` — that delegation is where IGA intercepts. So even
  if approval is later denied, the original invitation row is already
  gone. The user-facing effect: a denied resend leaves the org with no
  pending invitation for that email (whereas a denied initial invite
  leaves the original — there was no original to begin with). This is
  a KC ordering quirk, not an IGA bug; IGA-side this could be papered
  over by deferring the remove to commit time, but doing so would
  require shadowing more of KC's invitation lifecycle than the current
  design accepts.
- **Cache-coherence with the Infinispan organization layer.** The IGA
  org provider extends `JpaOrganizationProvider` directly rather than
  wrapping `InfinispanOrganizationProvider`. The Infinispan layer's
  IdP-removed / user-removed event listeners still register (because
  `postInit` runs on every factory regardless of which one is selected
  as the default — see
  [Wire-up lessons](EXTENDING-IGA.md#wire-up-lessons-the-phase-7a-discoveries))
  but cache invalidations for IGA-mediated org mutations don't
  automatically fire through the Infinispan cache path. The IGA toggle
  + ADOPT replay both invoke `CacheRealmProvider.registerInvalidation`
  for affected org ids
  (`TideAdminCompatResource.java:627-659`,
  `IgaReplayExtension.evictCacheForAdopt`), so authoritative reads are
  fine. The observable side-effect: operators who rely on reading
  `OrganizationModel.getIdentityProviders()` immediately after an
  IGA-mediated `ORG_ADD_IDP` / `ORG_REMOVE_IDP` commit may see a brief
  stale broker list until the next per-request session loads the
  evicted entry. The E2E harness sidesteps this by reading
  authoritative DB-backed fields rather than re-resolving cache
  entries.
- **IdPs are not toggle-on ADOPT subjects.** As noted under
  [IdP-aware scope](#idp-aware-scope-for-org_add_idp--org_remove_idp-phase-7d):
  identity providers participate in governance only via the
  ORG_ADD_IDP / ORG_REMOVE_IDP scope merge, never as adoption targets
  in their own right. If a future phase decides per-IdP attestation
  matters (e.g. to govern raw `PUT /admin/realms/{r}/identity-provider/instances/{alias}`
  edits) the scan would need a sixth pass over the IdP table.
- **Phase 7e cascade coverage is exemplary, not exhaustive.** Of the
  five `org.isEnabled()` cascade points enumerated in the
  [quarantine cascade table](#quarantine-the-org-isenabled-override-and-its-cascade-phase-7c),
  Phase 7e exercises one end-to-end (the OIDC `organization` claim
  mapper at `OrganizationMembershipMapper.resolveValue:159`). The
  other four — managed-member read-only, org-aware browser auth, IdP-
  broker membership block, registration-flow block — are verified by
  KC source inspection at the cited line refs. End-to-end exercise of
  those four requires either a UI driver (browser auth + registration
  flow) or a federated IdP server (managed-member and IdP-broker
  branches), both out of scope for the REST-only harness. The single
  `IgaOrganizationModel.isEnabled` override is the one primitive every
  cited cascade point reads, so a Phase 7c-style change to that
  primitive would propagate to all five.

## Phase 6: retroactive ADOPT and quarantine on IGA toggle

Phases 1–5 govern the *next* admin write. **Phase 6 retroactively brings
every entity that already exists in a realm under governance** when IGA
is toggled OFF→ON, and **quarantines** those entities until an admin
signs them off. This solves the bootstrap gap: a realm imported pre-IGA,
or operated for a while with IGA off, contains users / roles / groups /
clients / client-scopes that nothing in Phases 1–5 ever attested.

> **Important**
> Read the [Ordering](#ordering-configure-governance-before-enabling-iga)
> section first. The Phase 6 OFF→ON path is **strictly more disruptive**
> than the pre-Phase-6 flip: turning IGA on for a non-empty realm will
> quarantine every pre-existing user, client, role, group and
> operator-authored client-scope until each one's ADOPT change request is
> committed. Plan the toggle as a maintenance event.

### Bootstrap onramp: the OFF→ON ADOPT scan

When `POST /admin/realms/{realm}/tide-admin/toggle-iga` flips
`isIGAEnabled` from `false` → `true`, the toggle handler runs the **Phase
6b adopt scan** in its own transaction
(`TideAdminCompatResource.toggleIga`,
`TideAdminCompatResource.java:91-210`):

- The scan walks `USER_ENTITY`, `KEYCLOAK_ROLE`, `KEYCLOAK_GROUP`,
  `CLIENT`, and `CLIENT_SCOPE`, projecting every row whose `attestation`
  column is still `NULL` (`IgaUnsignedRowScanner.usersWithNames` etc.).
- For each surviving row it emits a per-entity
  `ADOPT_USER` / `ADOPT_ROLE` / `ADOPT_GROUP` / `ADOPT_CLIENT` /
  `ADOPT_CLIENT_SCOPE` change request via
  `IgaChangeRequestService.createAdoptCr`, and inserts a sidecar row in
  `IGA_UNSIGNED_ENTITY` keyed on `(realmId, entityType, entityId)` that
  points back at the ADOPT CR.
- Three pre-existing skip lanes apply (see
  [System-entity filter](#system-entity-filter-which-pre-existing-entities-are-skipped)):
  the system-entity filter, an already-committed-ADOPT skip (so a
  re-toggle is a no-op), and a pending-`CREATE_*` race skip (the entity
  is mid-flight under Phase 1–4 governance and must not be ADOPTed
  concurrently).

After the scan, the toggle handler:

1. Invalidates every live user session on the realm
   (`session.sessions().removeUserSessions(realm)`,
   `TideAdminCompatResource.java:160`) so a user newly quarantined by
   the scan cannot ride an existing cookie or refresh token past the
   transition.
2. Evicts the realm's user cache
   (`UserStorageUtil.userCache(session).evict(realm)`) — Keycloak's
   `UserCacheSession` snapshots `isEnabled` at cache-load time and would
   otherwise keep returning the pre-toggle `enabled=true` until the
   entry expires.
3. Evicts the realm's client/role/group/scope cache via
   `evictRealmCache`
   (`TideAdminCompatResource.java:514-626`) — Keycloak's
   `RealmCacheSession` likewise caches client/role/group/scope adapters,
   so the OFF→ON transition must invalidate per-entity entries before
   the next read so the quarantine override fires.

### Quarantine semantics per entity type

Until each pre-existing entity's ADOPT CR commits, the entity is
**quarantined** by the Phase 6c hooks. Quarantine semantics are
deliberately different per entity type — hard refusal for user/client
(operationally inert), silent strip for group/client-scope (token shape
diverges, but the request still succeeds).

| Entity | Hook | Semantic | Operator-observed behaviour |
|--------|------|----------|-----------------------------|
| User | `IgaUserAdapter.isEnabled() → false` (`IgaUserAdapter.java:1184-1203`) | **Hard refuse.** | Direct-grant returns `400`/`401 invalid_grant`. Browser flow rejects login. |
| Role held by a user | `IgaUserAdapter.isEnabled() → false` via the role fan-out in `IgaQuarantineCache.isUserUnsignedWithRoles` (`IgaQuarantineCache.java:134-227`) | **Hard refuse on the user.** | Any user that holds an unsigned realm-role or client-role is treated as not-enabled. Not a silent role-strip — explicit refusal at the token endpoint. |
| Client | `IgaClientAdapter.isEnabled() → false` (`IgaClientAdapter.java:634-649`) | **Hard refuse.** | `client_credentials`, `client_secret_basic`/`_post`, JWT client-auth, and token introspection all refuse. |
| Group | `IgaUserAdapter.getGroupsStream()` filters unsigned groups out (`IgaUserAdapter.java:1234-1263`) | **Silent strip from token mapping.** | The user can still log in; group claims and roles-via-the-group are absent from the issued token. **Admin REST reads still see the group** — the StackWalker bypass keeps the group visible so operators can ADOPT it. |
| Client scope | `IgaClientScopeAdapter.getProtocolMappersStream() → Stream.empty()` (`IgaClientScopeAdapter.java:724-743`) | **Silent strip from token mapping.** | The scope's mappers don't fire; any claim the scope would have added is absent. Token still issues. |

> **Note**
> Every quarantine check is bypassed when the session attribute
> `IGA_REPLAY_ACTIVE` is `"true"` — that is the gate that lets an ADOPT
> commit *replay* against the very entity it is about to attest. Without
> it the replay would be refused by the quarantine on its target. The
> attribute is set by `IgaReplayExtension.tryReplay` and by the toggle
> handler around its own attribute write (so the toggle's
> `isIGAEnabled` write is not itself captured as a CR — see
> [Bootstrap-safety + escape hatches](#bootstrap-safety-and-escape-hatches)).

### Toggle response shape

The toggle endpoint returns a JSON body describing what the scan / cancel
did. Use the body to feed your runbook (e.g. seed the bulk-authorize
call below).

**OFF→ON example** (newly-toggled realm with 5 users, 10 roles, 10
groups, and 0 operator-authored client-scopes):

```json
{
  "enabled": true,
  "scan": {
    "realmId": "f7c0e1e0-...",
    "durationMs": 312,
    "totalEntitiesScanned": 47,
    "adoptCrsCreated": {
      "USER": 5,
      "ROLE": 10,
      "GROUP": 10,
      "CLIENT": 0,
      "CLIENT_SCOPE": 0
    },
    "skipped": {
      "systemFilter": 22,
      "alreadyCommittedAdopt": 0,
      "pendingCreateCr": 0,
      "alreadyAttested": 0
    },
    "errors": 0,
    "sessionsInvalidated": 3
  },
  "warning": "Fewer than 2 distinct admin holders detected for realm 'test-realm' (manage-realm + iga.approverRole candidates: 1). Phase 6c will enforce ADOPT approval before admin actions — provision a second manage-realm admin (or configure iga.approverRole) NOW. Recovery path if locked out: the master-realm admin can always disable IGA on this realm via the master realm (escape hatch) — there is no other recovery."
}
```

The optional `warning` (`buildAdminCoverageWarning`,
`TideAdminCompatResource.java:657-698`) appears when the realm has fewer
than two distinct `manage-realm` or `iga.approverRole` holders — i.e.
the realm is at risk of self-lockout. The toggle still succeeds; the
warning is advisory.

**ON→OFF example**:

```json
{
  "enabled": false,
  "scanOff": {
    "realmId": "f7c0e1e0-...",
    "cancelledAdoptCrs": 17,
    "sidecarRowsCleared": 17,
    "durationMs": 28
  }
}
```

ON→OFF runs the **Phase 6d cancel** in its own transaction
(`IgaAdoptCancel.cancel`, `IgaAdoptCancel.java:93-134`): every PENDING
ADOPT_* CR for the realm is flipped to `CANCELLED` with `resolvedAt=now`,
and the entire sidecar (`IGA_UNSIGNED_ENTITY`) for the realm is
bulk-cleared. **Committed ADOPTs are preserved as audit history** and
will be the idempotent-skip set on the next OFF→ON.

### Configuration-error responses on toggle

| Trigger | HTTP | Body shape |
|---------|------|-----------|
| Sidecar would exceed the soft-cap of **100 000 rows per realm** at scan start (`IgaAdoptScan.SIDECAR_CAP_DEFAULT`, `IgaAdoptScan.java:76`). | **409 Conflict** | `{"error":"SIDECAR_CAP_EXCEEDED", "realmId":"<uuid>", "cap":100000, "current":<long>}` — the `isIGAEnabled` write is **rolled back** so IGA stays OFF. |
| Toggle-on scan itself fails (any other RuntimeException). | **200 OK** | `{"enabled":true, "scan":{"error":"<Class>", "message":"<msg>"}}` — the toggle attribute is already committed; the scan failure is surfaced in the response but **does not roll back the toggle** (a stuck toggle is worse than a partially-scanned realm). |
| Toggle-off cancel itself fails (any other RuntimeException). | **200 OK** | `{"enabled":false, "scanOff":{"error":"<Class>", "message":"<msg>"}}` — symmetric: the toggle attribute is already committed; a partial cancel is recoverable, a stuck toggle is not. |

### System-entity filter: which pre-existing entities are skipped

By default the OFF→ON scan does NOT emit ADOPT CRs for Keycloak's own
bootstrap surface — quarantining those would freeze the realm. The
filter is `IgaSystemEntityFilter.shouldSkip`
(`IgaSystemEntityFilter.java:166-225`).

**Hard-pinned skips** (always applied, regardless of opt-in):

- The realm composite role `default-roles-<realm>` (every new user is
  bound to this composite at create time).
- The bookkeeping client `default-roles-<realm>` that backs the
  composite.

**Soft skips** (lifted by setting the realm attribute
`iga.adopt.includeSystem=true`):

- Keycloak's built-in per-realm admin clients —
  `realm-management`, `account`, `account-console`,
  `security-admin-console`, `broker`, `admin-cli` — and **every
  client-role under them**
  (`IgaSystemEntityFilter.BUILTIN_CLIENT_IDS`).
- Keycloak's default client-scopes — the full set in
  `IgaSystemEntityFilter.DEFAULT_CLIENT_SCOPE_NAMES`: `profile`,
  `email`, `address`, `phone`, `offline_access`, `roles`,
  `web-origins`, `microprofile-jwt`, `acr`, `basic`, `service_account`,
  `organization`, `role_list`, `saml_organization`,
  `oid4vc_natural_person`. Operator-authored scopes are NOT in this set
  and **are** quarantined.
- Keycloak's default realm-roles `offline_access` and
  `uma_authorization`
  (`IgaSystemEntityFilter.DEFAULT_REALM_ROLE_NAMES`). The composite
  `default-roles-<realm>` is hard-pinned above.

**Opting in to govern system entities**:

```bash
# Set BEFORE toggling IGA on, otherwise this is itself a captured CR.
curl -fsS -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"attributes":{"iga.adopt.includeSystem":"true"}}' \
  "$KC_URL/admin/realms/$REALM"

# Then toggle IGA on. Built-in admin clients + their roles + KC default
# scopes + default realm-roles will all receive ADOPT_* CRs. The
# default-roles-<realm> composite remains hard-pinned regardless.
```

The toggle handler logs at WARN when scan starts with
`includeSystem=true`, surfacing that the bootstrap surface is about to
be quarantined (`IgaAdoptScan.java:217-222`).

### ADOPT gate bypass: threshold + approver-role

The ADOPT_* CRs created by the scan are a **system-bootstrap onramp**.
Applying the realm's normal governance gate to them would create a
chicken-and-egg deadlock: a high-threshold realm with pre-IGA admins
cannot bootstrap because the admins themselves are quarantined and the
ADOPTs need their signature to unlock them.

`IgaScopeResolver` therefore short-circuits the gate for ADOPT_* CRs
(`IgaScopeResolver.java:213-220` for `requireApprover`,
`IgaScopeResolver.java:270-277` for `resolveThreshold` — both via
`IgaReplayExtension.isAdoptAction(actionType)`):

- **Threshold for ADOPT_***: unconditionally `1`, regardless of realm
  `iga.threshold` or per-scope `iga.threshold`.
- **Approver-role for ADOPT_***: no check. Any caller passing the
  endpoint's `manage-realm` requirement can authorize and commit.

The bypass fires one INFO log line per (request, CR, gate) for audit:

```
IGA ADOPT gate bypass: actionType=ADOPT_USER CR=<uuid> — threshold=1, no approver-role check (system-bootstrap action) [gate=requireApprover]
```

`CREATE_*` / `UPDATE_*` / `GRANT_ROLES` / `SET_*_ATTRIBUTE` and every
other non-ADOPT action continue to enforce realm `iga.threshold` and
per-scope `iga.approverRole` exactly as in Phases 1–5.

### Bootstrap-safety and escape hatches

> **Warning — the self-locked-realm failure mode.**
> If a realm's only `manage-realm` admin is themselves quarantined by
> the OFF→ON scan (because they were a pre-IGA user adopted by the
> scan), they cannot sign their own `ADOPT_USER`. The quarantine
> hard-refuses their token request before any IGA endpoint sees them.
> The toggle-time admin-coverage warning in the response body exists to
> surface this risk before it happens.

The supported recovery path is the permanently-exempt `master` realm:

- `IgaChangeRequestService.isIgaEnabled` returns `false` unconditionally
  when the realm name is `master`
  (`IgaChangeRequestService.java:36-39`) — IGA is never enforced on
  master.
- A master-realm admin holds `manage-realm` on any realm via the
  cross-realm admin scope, is **exempt from the target realm's IGA scan
  (master is system-skipped)**, and can therefore authorize + commit any
  ADOPT_* in any realm using either the per-CR endpoints or the
  [bulk-authorize endpoint](#bulk-authorizing-pending-change-requests).

The escape hatch is single-purpose: a master-realm admin signing the
quarantined realm's ADOPTs out of the queue. There is no per-realm
override.

### Re-toggle and CANCELLED-status caveat

| Scenario | Behaviour |
|----------|-----------|
| OFF→ON → ADOPT commits → ON→OFF → OFF→ON | **Idempotent.** The second OFF→ON skips every entity whose ADOPT is already APPROVED (the scan builds the "already committed" skip set from `IDX_IGA_CR_REALM_ACTION_STATUS` at scan start). |
| OFF→ON → some ADOPTs still PENDING → ON→OFF → OFF→ON | The PENDING ADOPTs are CANCELLED on ON→OFF (sidecar cleared). On the next OFF→ON, the scan re-emits ADOPT CRs for those entities (a CANCELLED row is not in the "already committed" skip set). Per-entity history: the operator now sees both the cancelled CR and the fresh PENDING CR for the same entity. |
| Authorize / commit a CANCELLED ADOPT directly | **ADOPT_* CRs are resumable** (`IgaAdminResource.authorize`, `IgaAdminResource.java:225-243`; `IgaAdminResource.commit`, `IgaAdminResource.java:307-321`): the endpoint promotes the CR back to `PENDING` and proceeds with the normal authorize/commit flow. |
| Authorize / commit a CANCELLED CR of any other action type | **Terminal — rejected with 409.** `CREATE_*` / `UPDATE_*` / etc. CANCELLED rows are NOT resumable because the captured-entity rollback already happened; re-running the replay would attempt to recreate the rolled-back scratch entity. |

In other words: **CANCELLED is terminal for every CR family except
ADOPT_***. ADOPT_* CRs uniquely preserve the underlying entity (the
whole point of capture-then-veto is that the entity already exists), so
resuming them is meaningful.

## Bulk-authorizing pending change requests

`POST /admin/realms/{realm}/iga/change-requests/bulk-authorize`
(`IgaAdminResource.bulkAuthorize`, `IgaAdminResource.java:428-558`) is
the operator one-shot for draining a large queue of PENDING CRs in a
single call — primarily intended for the Phase 6b ADOPT_* deluge on the
first OFF→ON toggle of a non-empty realm, but usable against any action
type.

### Authority

- Requires `manage-realm` on the target realm.
- Per-realm **in-memory mutex** (`IgaBulkLock`): a second concurrent
  bulk against the same realm returns **HTTP 429** with body
  `{"error":"Another bulk-authorize is already running for this realm","realm":"<name>"}`.
- **Single-node limitation.** The lock is a per-JVM `ConcurrentHashMap`
  entry. Two bulk calls against the same realm hitting two different
  Keycloak nodes can both acquire the lock; the per-CR gate (re-run for
  every CR) is the real safety net — duplicate signatures and
  non-PENDING CRs are detected per-CR and skipped.

### Body shape

| Field | Type | Required | Default | Notes |
|-------|------|----------|---------|-------|
| `actionTypeIn` | `string[]` | yes (non-empty) | — | The CR `actionType` strings to drain (e.g. `["ADOPT_USER","ADOPT_ROLE",...]`). Blank entries are dropped. |
| `limit` | `int` | no | `100` | Hard upper-bound **`1000`**. `<=0` → 400. `>1000` → 400 with body `{"error":"limit must be <= 1000 (got <n>)", "maxLimit":1000}`. |
| `olderThan` | `long` epoch-millis | no | `null` | When set, only CRs whose `createdAt <= olderThan` are considered. |

### Response shape (HTTP 200)

```json
{
  "results": [
    {
      "crId": "...",
      "actionType": "ADOPT_USER",
      "entityType": "USER",
      "entityId": "...",
      "status": "COMMITTED"
    },
    {
      "crId": "...",
      "actionType": "CREATE_ROLE",
      "entityType": "ROLE",
      "entityId": "...",
      "status": "REJECTED",
      "error": "THRESHOLD_NOT_MET",
      "threshold": 2,
      "authCount": 1
    },
    {
      "crId": "...",
      "actionType": "ADOPT_USER",
      "entityType": "USER",
      "entityId": "...",
      "status": "SKIPPED",
      "error": "ALREADY_RESOLVED",
      "crStatus": "APPROVED"
    }
  ],
  "summary": {
    "total": 25,
    "committed": 24,
    "rejected": 0,
    "skipped": 1,
    "durationMs": 412,
    "limit": 1000,
    "defaultLimit": 100,
    "maxLimit": 1000
  }
}
```

Per-CR `status` values:

- **`COMMITTED`** — CR was authorized + replayed; now `APPROVED`.
- **`REJECTED`** — the per-CR gate refused this CR. The result row's
  `error` field gives the reason: `FORBIDDEN_APPROVER_ROLE` (`httpStatus:403`),
  `THRESHOLD_NOT_MET` (with `threshold` + `authCount` keys),
  `ENTITY_VANISHED` (with `vanishedEntityType` + `vanishedEntityId`),
  `AUTHORIZE_FAILED`, or `COMMIT_FAILED`.
- **`SKIPPED`** — CR was no longer `PENDING` by the time the bulk loop
  re-fetched it (concurrent commit/deny/cancel) — `error:
  "ALREADY_RESOLVED"` with the observed `crStatus`. Or `NOT_FOUND` if
  the CR id selected at filter time has vanished entirely.

> **Important — the per-CR gate is NOT shortcut for non-ADOPT.** Every
> CR runs the same authorize+commit gate the per-CR endpoints use,
> including `IgaScopeResolver.requireApprover` and the threshold check.
> ADOPT_* CRs short-circuit those gates (system-bootstrap bypass — see
> [ADOPT gate bypass](#adopt-gate-bypass-threshold--approver-role)).
> Non-ADOPT CRs in the same bulk call get full enforcement: a
> `CREATE_ROLE` whose realm `iga.threshold=2` will surface as
> `REJECTED THRESHOLD_NOT_MET` in the response array (the overall HTTP
> is still 200 — the bulk endpoint succeeded; per-CR outcomes ride
> inside `results`).

### Drain runbook: clear the toggle-on ADOPT queue

```bash
# Right after a OFF→ON toggle on a non-empty realm:
curl -fsS -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{
        "actionTypeIn": ["ADOPT_USER","ADOPT_ROLE","ADOPT_GROUP","ADOPT_CLIENT","ADOPT_CLIENT_SCOPE"],
        "limit": 1000
      }' \
  "$KC_URL/admin/realms/$REALM/iga/change-requests/bulk-authorize"
# → 200 OK
# → {"results":[...], "summary":{"committed": 25, "rejected": 0, "skipped": 0, ...}}
```

For queues larger than 1000, page by repeated calls — the endpoint is
idempotent (`SKIPPED ALREADY_RESOLVED` is a no-op).



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
- **Bulk-authorize lock is per-JVM, not per-cluster.** `IgaBulkLock` is
  an in-memory `ConcurrentHashMap` entry. Two simultaneous bulk calls
  for the same realm hitting two different Keycloak nodes can both
  acquire it; the per-CR gate (re-run for every CR) is the real safety
  net.
- **OFF→ON ADOPT scan is bounded by a 100 000-row sidecar soft-cap.**
  Realms whose pre-IGA `attestation IS NULL` count exceeds the cap
  refuse the toggle with **HTTP 409 SIDECAR_CAP_EXCEEDED** and roll
  `isIGAEnabled` back to `false`. Raising the cap requires editing
  `IgaAdoptScan.SIDECAR_CAP_DEFAULT` and rebuilding (not a realm
  attribute by design).
- **CANCELLED is terminal for every CR family except ADOPT_*.** Use the
  toggle-off cancel ONLY for ADOPT cleanup — `CREATE_*`/`UPDATE_*`/etc.
  PENDING CRs that need to be undone should be `deny`d, not toggled-off
  away.
- **Self-locked realm is recoverable only through the master realm.**
  If a realm's only `manage-realm` admin is themselves quarantined by
  the OFF→ON scan, they cannot sign their own ADOPT. The master-realm
  admin (always exempt from IGA) signs the queue using the per-CR or
  bulk-authorize endpoints. There is no per-realm override.

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
  (list/get/update/authorize/commit/deny/comments/**bulk-authorize**),
  `role-policies`, `authorizers`, `forseti-contracts`, `server-certs`,
  `licensing`, `adopt` (Phase 6 per-entity ADOPT seed). Every endpoint
  requires `manage-realm` (deny / comment-delete additionally allow the
  original author). The authorize/commit handlers special-case
  ADOPT_* CANCELLED → PENDING (resumable) — see
  [CANCELLED status caveat](#re-toggle-and-cancelled-status-caveat).
- **`TideAdminCompatResource`** (`rest/`, `@Path("tide-admin")`) —
  backwards-compatible `toggle-iga` / `iga-status` endpoints driving
  the `isIGAEnabled` realm attribute. The toggle handler also runs the
  Phase 6b OFF→ON adopt scan, the Phase 6d ON→OFF cancel, and the
  per-realm session + cache eviction passes that make the quarantine
  observable on the next read — see
  [Phase 6: retroactive ADOPT](#phase-6-retroactive-adopt-and-quarantine-on-iga-toggle).
- **`IgaReplayExtension`** (`replay/`) — Phase 6+ replay extension
  router for the five ADOPT_* action types
  (`USER`/`ROLE`/`GROUP`/`CLIENT`/`CLIENT_SCOPE`). `tryReplay` is
  consulted by `IgaAdminResource.commit` BEFORE `IgaReplayDispatcher`
  so the ADOPT path stays out of the dispatcher's switch (which
  remains byte-unchanged from `742f944` / `d785326`). Replay verifies
  the entity still exists (else throws `EntityVanishedException` →
  HTTP 404 `ENTITY_VANISHED`), stamps the entity row's `attestation`
  column via per-type JPQL UPDATE, deletes the matching sidecar row,
  and evicts the per-entity cache (user → `UserCache.evict`;
  client/role/group/scope → `CacheRealmProvider.register*Invalidation`;
  ADOPT_ROLE/ADOPT_GROUP also realm-wide user-cache evict to flush the
  role/group fan-out snapshot).
- **`IgaAdoptScan`** + **`IgaUnsignedRowScanner`** + **`IgaSystemEntityFilter`**
  (`services/`) — Phase 6b OFF→ON adopt scan. Walks every realm entity
  whose `attestation IS NULL`, applies the system-entity filter
  (default skips KC built-ins + default scopes/realm-roles; hard-pin
  on `default-roles-<realm>`), skips entities with already-committed
  ADOPT or pending CREATE_* CRs (via the
  `IDX_IGA_CR_REALM_ACTION_STATUS` index), and emits one `ADOPT_*` CR
  per surviving entity. Refuses when the sidecar would exceed
  `SIDECAR_CAP_DEFAULT = 100 000` rows.
- **`IgaAdoptCancel`** (`services/`) — Phase 6d ON→OFF cancel. Bulk
  UPDATE every PENDING ADOPT_* CR to CANCELLED + bulk DELETE the
  realm's sidecar rows. APPROVED ADOPTs preserved as audit history;
  DENIED untouched.
- **`IgaUnsignedEntityService`** + **`IgaUnsignedEntityEntity`**
  (`services/` + `entities/`) — sidecar table. Phase 6c quarantine
  guards do a single PK probe here; the role fan-out in
  `IgaQuarantineCache.isUserUnsignedWithRoles` is a single batched
  IN-clause query.
- **`IgaQuarantineCache`** (`services/`) — per-request, session-attribute
  memoised quarantine cache for user/client/group/scope. Bypassed when
  `IGA_REPLAY_ACTIVE=true` or when IGA is not active on the realm.
- **`IgaBulkLock`** (`rest/`) — per-realm in-memory mutex used by the
  bulk-authorize endpoint. Single-node only; see
  [Known limitations](#known-limitations).
