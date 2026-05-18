# Identity Governance and Administration (IGA)

This guide explains how to configure and operate the IGA approval workflow
provided by `tidecloak-iga-extensions`. It is written as a task-oriented
reference in the style of the Keycloak Server Administration Guide. Every
behavioral statement is derived from the implementation on the
`iga-approval-workflow` branch; where the implementation has surprising edges
or limitations, they are stated explicitly rather than smoothed over.

The audience is realm administrators and operators. A short
[Internals](#internals) section at the end is for developers.

> **Note**
> Throughout this guide, "admin console path" refers to the Keycloak account /
> administration console. The exact menu labels can differ slightly between
> Keycloak releases and between the legacy and new admin themes. Where a label
> may differ in your build, the path is described generically and the
> equivalent Admin REST call — which is stable — is given alongside. Treat the
> REST representation field as the authoritative source if a console label does
> not match.

## Table of contents

1. [Overview](#overview)
2. [Concepts](#concepts)
3. [Enabling and disabling IGA](#enabling-and-disabling-iga)
4. [Configuring thresholds](#configuring-thresholds)
5. [Restricting who can approve](#restricting-who-can-approve)
6. [Ordering: configure governance before enabling IGA](#ordering-configure-governance-before-enabling-iga)
7. [The approval workflow: authorize then commit](#the-approval-workflow-authorize-then-commit)
8. [Default behavior when nothing is configured](#default-behavior-when-nothing-is-configured)
9. [Governing Keycloak Organizations](#governing-keycloak-organizations)
10. [Known limitations](#known-limitations)
11. [Internals](#internals)

## Overview

IGA turns privileged Keycloak administration writes into **change requests**
that must be approved before they take effect.

The lifecycle is:

1. **Intercept.** When IGA is enabled for a realm, the IGA model providers
   intercept privileged writes (create client/user/role/group/client-scope,
   role grants, group membership, composites, scope assignments, protocol
   mappers, attribute writes, realm-config setters, organization mutations,
   etc.) instead of applying them.
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

   The original entity is **not** written. Callers and UIs must treat a 202
   as "queued for approval", not "done".
3. **Authorize (sign).** One or more admins sign the change request via
   `POST /admin/realms/{realm}/iga/change-requests/{id}/authorize`. This only
   records a signature; it does not apply the change even if the threshold is
   already met.
4. **Commit (apply).** Once the signature count meets the threshold, an admin
   calls `POST /admin/realms/{realm}/iga/change-requests/{id}/commit`. This
   replays the recorded operation against the real Keycloak model and sets the
   change request to `APPROVED`.

A change request can hold the statuses `PENDING`, `APPROVED` (after a
successful commit/replay), and `DENIED` (via
`POST .../iga/change-requests/{id}/deny`). All `iga/*` endpoints are mounted
under the realm admin base, that is `/admin/realms/{realm}/iga/...`.

## Concepts

| Term | Meaning |
|------|---------|
| Change request (CR) | A recorded, pending privileged write awaiting approval. |
| Authorize | Record one admin signature on a CR. Does not apply the change. |
| Commit | Apply (replay) a CR once enough signatures exist. |
| Threshold | Number of **distinct** admin signatures required before a CR can be committed. |
| Approver role | A Keycloak role that an admin must hold to authorize/commit a scoped CR. |
| Scope mode | Realm-level switch deciding whether an approver needs *any* or *all* required roles. |
| Scope entity | A group, role, client, or organization carrying `iga.approverRole` / `iga.threshold`. |

The relevant attribute keys are constants in the code:

| Attribute key | Where it is set | Effect |
|---------------|-----------------|--------|
| `isIGAEnabled` | Realm attribute | `"true"` (exact, case-sensitive) enables IGA for the realm. |
| `iga.threshold` | Realm attribute, or a group/role/client/organization attribute | Required signature count. |
| `iga.approverRole` | A group/role/client/organization attribute | Restricts who may approve CRs affecting that entity. |
| `iga.scopeMode` | Realm attribute | `all` (case-insensitive) = approver must hold every required role; anything else/unset = `any`. |

## Enabling and disabling IGA

IGA is controlled by the **case-sensitive** realm attribute `isIGAEnabled`. It
is enabled only when the attribute string is exactly `"true"`
(`IgaChangeRequestService.isIgaEnabled`,
`iga-core/.../providers/IgaChangeRequestService.java:36-39`). Any other value,
including `"True"`, leaves IGA off.

> **Important**
> The `master` realm is always exempt. `isIgaEnabled` returns `false`
> unconditionally when the realm name is `master`
> (`IgaChangeRequestService.java:37`). IGA cannot be enforced on the `master`
> realm, and administration there is never intercepted. This is the
> operational escape hatch if a realm's governance becomes self-locked.

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
   `"true"` and `"false"` and requires `manage-realm`. Equivalently, set the
   realm attribute `isIGAEnabled = "true"` directly while IGA is still off.
2. Verify with `GET /admin/realms/{realm}/tide-admin/iga-status` (requires
   `view-realm`).

> **Note**
> Enabling is applied directly and is **not** itself governed. When IGA is OFF
> and an admin sets `isIGAEnabled = true`, `isIgaActive()`
> (`IgaRealmAdapter.java:63-71`) reads the attribute *currently being written*,
> which is still `false` at that instant, so the write passes through
> immediately. IGA only engages on the *next* privileged write. Plan the
> enable as a deliberate, trusted operation.

### Procedure: disable IGA

Once IGA is ON, disabling it is itself a governed action.

1. Set `isIGAEnabled = false` (or call the toggle endpoint). This is
   intercepted as a `SET_REALM_ATTRIBUTE` change request
   (`IgaRealmAdapter.java:73-88`).
2. The change request must be authorized and committed like any other
   privileged realm-attribute write before IGA actually turns off.

> **Warning**
> You cannot unilaterally disable governance once it is active — it requires
> the same approvals as any other change. While a realm-attribute or
> realm-config change request is pending, any other attempt to set or remove a
> realm attribute/config on the same realm fails with **HTTP 409**
> (`IgaRealmAdapter.checkNoPendingCr`, `IgaRealmAdapter.java:106-111`).
> Resolve (approve or deny) the existing change request first.

## Configuring thresholds

The threshold is the number of distinct admin signatures required before a
change request can be committed. It is resolved at commit time by
`IgaScopeResolver.resolveThreshold`
(`iga-core/.../attestors/IgaScopeResolver.java:211-230`).

**Precedence (highest to lowest):**

1. **Per-scope-entity `iga.threshold`** — if any group, role, client, or
   organization *affected by this change request* carries an `iga.threshold`
   attribute, the **maximum** of all such positive integer values is used
   (`IgaScopeResolver.java:213-214`; `addThreshold`,
   `IgaScopeResolver.java:343-350`, only accepts values that parse as an
   integer **greater than 0**).
2. **Realm attribute `iga.threshold`** — if no scoped threshold applies, the
   realm attribute `iga.threshold` is parsed as an integer and used, but only
   when it is a valid integer `>= 1` (the same positivity rule as the
   per-entity path); a non-integer or `< 1` value is ignored.
3. **Hardcoded default `1`** — if neither is set, or the realm value is not a
   valid integer `>= 1`, the threshold is **`1`**. `resolveThreshold` also
   applies a defensive final clamp, so it can never return a value below `1`
   regardless of the source.

> **Note — the realm-level value is enforced.** The realm `iga.threshold` is
> subject to the same positivity rule as the per-entity path. A non-integer
> value (for example `"two"`) **or** a value `< 1` (for example `"0"` or
> `"-1"`) is **ignored and treated as `1`** — it never lowers the gate. In
> addition, `resolveThreshold` applies a defensive final clamp so it can
> **never** return a value below `1` regardless of the source. The commit
> gate therefore cannot be disabled by a bad realm value: a change request
> always requires at least one signature. Set the realm `iga.threshold` to
> the positive integer you actually want (for example `"2"`); a `"0"` or
> negative value simply behaves as `1`.

### Procedure: set the realm-wide default threshold

**Prerequisites**

- You hold `manage-realm` for the realm.
- Preferably IGA is still OFF (see
  [Ordering](#ordering-configure-governance-before-enabling-iga)); otherwise
  this change is itself a governed `SET_REALM_ATTRIBUTE` change request.

**Procedure**

1. Admin console: go to **Realm settings**, open the section that exposes the
   realm attribute map (in current Keycloak this is the **Realm settings →
   (realm) → Attributes** area; in older builds it may appear under a generic
   attributes/JSON editor). Add a key `iga.threshold` with the value `2`.
2. Admin REST equivalent: update the realm representation `attributes` map via
   `PUT /admin/realms/{realm}`, including:

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

**Procedure**

1. Admin console: open the entity and select its **Attributes** tab:
   - Group: **Groups → (group) → Attributes**.
   - Realm role: **Realm roles → (role) → Attributes**. Client role:
     **Clients → (client) → Roles → (role) → Attributes**.
   - Client: **Clients → (client) → Attributes**.
   - Organization: **Organizations → (organization) → Attributes** (this tab
     exists because `OrganizationModel` supports attributes).

   Add the key `iga.threshold` with a positive integer value, for example
   `3`.
2. Admin REST equivalent: add the attribute to that entity's representation:
   - Group: `PUT /admin/realms/{realm}/groups/{id}` with
     `{ "attributes": { "iga.threshold": ["3"] } }`.
   - Role: `PUT /admin/realms/{realm}/roles-by-id/{role-id}` with
     `{ "attributes": { "iga.threshold": ["3"] } }`.
   - Client: `PUT /admin/realms/{realm}/clients/{id}` with
     `{ "attributes": { "iga.threshold": "3" } }`.
   - Organization:
     `PUT /admin/realms/{realm}/organizations/{org-id}` with
     `{ "attributes": { "iga.threshold": ["3"] } }`.
3. Result: any change request affecting that entity requires at least **3**
   distinct signatures. If multiple affected entities declare a threshold, the
   **maximum** wins. Per-entity thresholds always override the realm default.

> **Note**
> A per-entity threshold only takes effect when the entity is *in scope* for
> the change request — that is, when the change request's action type causes
> `IgaScopeResolver` to walk that entity (see
> [Restricting who can approve](#restricting-who-can-approve) for the scoping
> rules). Typically you set `iga.threshold` and `iga.approverRole` together on
> the same entity.

## Restricting who can approve

By default, **any admin with `manage-realm` can authorize and commit any
change request** (see
[Default behavior](#default-behavior-when-nothing-is-configured)). To restrict
approval to specific people, mark the affected Keycloak entities with the
attribute `iga.approverRole`.

### How scope is resolved

For a given change request, `IgaScopeResolver.resolve(...)` walks the change
request's `rows_json` based on its `actionType` and collects the union of
`iga.approverRole` values from the affected entities
(`IgaScopeResolver.java:62-173`):

- **User-targeting actions** (`GRANT_ROLES`, `REVOKE_ROLES`, `JOIN_GROUPS`,
  `LEAVE_GROUPS`, `SET_USER_ATTRIBUTE`, `REMOVE_USER_ATTRIBUTE`): every
  **group the user belongs to** and each group's **ancestor groups** are
  walked (`collectUserGroupScopes`, `walkGroupAncestors`,
  `IgaScopeResolver.java:311-325`).
- **Role-targeting actions**: the role's `iga.approverRole` is read
  (`collectRoleScope`, `IgaScopeResolver.java:327-333`).
- **Group-targeting actions**: the group and its ancestors are walked.
- **Client-targeting actions**: the client's `iga.approverRole` is read
  (`collectClientScope`, `IgaScopeResolver.java:335-341`).
- **Organization-targeting actions** (`UPDATE_ORGANIZATION`,
  `DELETE_ORGANIZATION`, `ADD_ORG_MEMBER`, `REMOVE_ORG_MEMBER`,
  `ORG_INVITE_MEMBER`, `ORG_ADD_IDP`, `ORG_REMOVE_IDP`): the organization's
  `iga.approverRole` is read (`collectOrganizationScope`,
  `IgaScopeResolver.java:294-303`).
- **Realm-wide / top-level-create actions** (`CREATE_USER`, `CREATE_ROLE`,
  `CREATE_GROUP`, `CREATE_CLIENT`, `CREATE_CLIENT_SCOPE`,
  `CREATE_ORGANIZATION`, `SET_REALM_*`, `BASELINE_APPROVAL`, license and
  server-cert actions) yield an **empty scope** — no approver-role
  requirement is derived; only the baseline `manage-realm` gate applies.

> **Important**
> Creating top-level entities (users, roles, groups, clients, client scopes,
> organizations) and realm-wide writes are **not** approver-role scoped. They
> are governed only by `manage-realm` plus the threshold. Restrict who holds
> `manage-realm` accordingly, and use a realm-wide `iga.threshold` so even
> unscoped creates need multiple signatures.

### Procedure: restrict approval of a scope to a dedicated role

**Prerequisites**

- You hold `manage-realm` for the realm.
- Preferably IGA is still OFF (see
  [Ordering](#ordering-configure-governance-before-enabling-iga)).

**Procedure**

1. **Create the approver Keycloak role.** Admin console:
   **Realm roles → Create role**, name it for example `hr-approver`. Admin
   REST: `POST /admin/realms/{realm}/roles` with
   `{ "name": "hr-approver" }`.
2. **Assign the role** only to the admins who should approve this scope. They
   must *also* hold `manage-realm`. Admin console: **Users → (user) → Role
   mapping → Assign role**. Admin REST:
   `POST /admin/realms/{realm}/users/{user-id}/role-mappings/realm` with the
   role representation.
3. **Mark the scope entity.** On the group/role/client/organization that the
   change affects, set the attribute `iga.approverRole = hr-approver` via its
   **Attributes** tab (console) or by adding `iga.approverRole` to that
   entity's representation `attributes` (REST), exactly as in the per-entity
   threshold procedure above.
4. **Optionally set a per-entity threshold** on the same entity
   (`iga.threshold = 2`) so two `hr-approver` holders are required.
5. **Choose the scope mode** (see next procedure). The default (`any`) means
   an approver needs at least one of the required roles.

### Procedure: set the realm scope mode

The scope mode is read from the **realm attribute** `iga.scopeMode`
(`IgaScopeResolver.ATTR_SCOPE_MODE`, gate logic
`IgaScopeResolver.requireApprover`, `IgaScopeResolver.java:182-196`):

- `iga.scopeMode = all` (case-insensitive): strict. The approving admin must
  hold **every** role in the resolved required set.
- Any other value, or unset: **`any`** (default). The admin needs **at least
  one** of the required roles.

`scopeMode` is **realm-level only**; there is no per-entity scope-mode
attribute.

**Procedure**

1. Admin console: **Realm settings**, attributes area, add key
   `iga.scopeMode` with value `all` (or remove it / leave unset for `any`).
2. Admin REST: include `"iga.scopeMode": "all"` in the realm representation
   `attributes` map via `PUT /admin/realms/{realm}`.

> **Note**
> If the resolved required-roles set is empty, `requireApprover` is a no-op
> (`IgaScopeResolver.java:183`) and the only gate is `manage-realm`. Scope
> mode has no effect when nothing is scoped.

### Worked example: only HR can approve changes to the HR group

**Prerequisites**

- You hold `manage-realm`. IGA is still OFF (configure before enabling).
- A Keycloak group `hr` exists.

**Procedure**

1. Create the realm role `hr-approver`
   (`POST /admin/realms/{realm}/roles` with `{ "name": "hr-approver" }`).
2. Assign `hr-approver` to the HR approvers (who also hold `manage-realm`).
3. On the `hr` group's **Attributes** tab, set `iga.approverRole = hr-approver`.
   REST: `PUT /admin/realms/{realm}/groups/{hr-group-id}` with
   `{ "attributes": { "iga.approverRole": ["hr-approver"] } }`.
4. Optionally, on the same group set `iga.threshold = 2` to require two HR
   approvers.
5. Leave `iga.scopeMode` unset (`any`).
6. Enable IGA (now that governance is configured).

   Result: any change request that adds/removes members of the `hr` group, or
   grants the `hr` group roles, resolves the required role set
   `{hr-approver}`. With scope mode `any`, authorize and commit succeed only
   for an admin who (a) holds `manage-realm` and (b) holds `hr-approver`.
   Other realm admins receive **HTTP 403** "Approver role required:
   [hr-approver] (mode=any)" (`IgaScopeResolver.java:193-194`).

## Ordering: configure governance before enabling IGA

> **Important**
> Set thresholds and approver roles **before** enabling IGA. Once IGA is on,
> changing the realm `iga.threshold` (or any realm attribute) is itself a
> governed `SET_REALM_ATTRIBUTE` change request that must be authorized and
> committed.
>
> This is a direct consequence of the interception logic:
> `IgaRealmAdapter.setAttribute` (`IgaRealmAdapter.java:73-88`) checks
> `isIgaActive()` (`IgaRealmAdapter.java:63-71`); when IGA is already active,
> a write to `iga.threshold`, `iga.scopeMode`, or any other realm attribute is
> recorded as a `SET_REALM_ATTRIBUTE` change request instead of being applied.
> Per-entity attributes on groups/roles/clients are likewise intercepted as
> `SET_GROUP_ATTRIBUTE` / `SET_ROLE_ATTRIBUTE` / `SET_CLIENT_ATTRIBUTE`
> change requests once IGA is on. If you raise the threshold or add approver
> roles only *after* enabling, those very governance changes are blocked
> behind the (possibly weak or empty) policy that was in force at enable time,
> and you may need several approvals just to tighten the policy.
>
> If a realm's governance becomes self-locked, the only escape hatch is the
> permanently exempt `master` realm — IGA is never enforced there
> (`IgaChangeRequestService.java:37`), so a `master` realm administrator can
> still administer other realms' Keycloak objects through master-scoped admin
> APIs. There is no per-realm override.

**Recommended order**

1. Decide the realm-wide `iga.threshold` (e.g. `2`) and set it.
2. Decide `iga.scopeMode` and set it.
3. Create approver roles and assign them.
4. Set `iga.approverRole` / `iga.threshold` on every sensitive
   group/role/client/organization.
5. Enable IGA last.

## The approval workflow: authorize then commit

Approval is **two explicit steps**. Collecting signatures is deliberately
separate from applying the change.

### Step 1: authorize (sign)

`POST /admin/realms/{realm}/iga/change-requests/{id}/authorize`
(`IgaAdminResource.java:194-252`)

- Requires `manage-realm` (`auth.realm().requireManageRealm()`,
  `IgaAdminResource.java:198`).
- The change request must be `PENDING` (else HTTP 409).
- **One signature per admin.** A second authorize from the same admin is
  rejected with HTTP 409 "Caller has already signed this change request".
- The approver-role gate is enforced here (via `SimpleNameAttestor.record` →
  `IgaScopeResolver.requireApprover`).
- **Authorize never applies the change**, even if the threshold is now met
  (`IgaAdminResource.java:245-247`). It only records the signature.

### Step 2: commit (apply)

`POST /admin/realms/{realm}/iga/change-requests/{id}/commit`
(`IgaAdminResource.java:261-311`)

- Requires `manage-realm` (`IgaAdminResource.java:262`).
- The change request must be `PENDING`.
- Re-checks the same approver-role gate
  (`IgaScopeResolver.resolve` + `requireApprover`,
  `IgaAdminResource.java:284-285`).
- Counts recorded signatures; if `count < threshold` it returns **HTTP 412
  Precondition Failed** with `{error, threshold, authCount}`
  (`IgaAdminResource.java:292-301`).
- When the threshold is met it combines the final attestation and calls
  `IgaReplayDispatcher.replay(...)`, which performs the real Keycloak write
  and sets the change request to `APPROVED`
  (`IgaAdminResource.java:303-310`).

**Who can commit:** any admin who passes `manage-realm` *and* the
approver-role gate for that change request. The committer does not have to be
one of the signers, but the threshold must already be satisfied by recorded
signatures. There is no separate "committer" role.

Other change-request operations: `PUT .../change-requests/{id}` edits the rows
and **wipes all existing authorizations**; each change request also supports
comments under `.../change-requests/{id}/comments`. Pending change requests
are listed via `GET .../iga/change-requests` (defaults to `status=PENDING`).
`deny` and comment deletion additionally allow the original author in addition
to `manage-realm` holders.

## Default behavior when nothing is configured

**When IGA is freshly enabled and nothing has `iga.approverRole` or
`iga.threshold` configured, which admin is allowed to sign?**

**Any admin with the realm `manage-realm` permission can authorize *and*
commit *any* change request — there is no narrower built-in "first approver"
role.** Why, from the code:

- Every approval endpoint (`authorize`, `commit`, `list`, `get`, `deny`)
  starts with `auth.realm().requireManageRealm()`
  (`IgaAdminResource.java:198`, `:262`, `:143`, `:179`, `:375`).
- The only additional gate is `IgaScopeResolver.requireApprover(...)`, which
  **returns immediately when the required-roles set is empty**
  (`IgaScopeResolver.java:182-196`, early return at line 183).
- With zero `iga.approverRole` attributes anywhere, every change request
  resolves to an empty scope, so `requireApprover` never blocks.
- With no `iga.threshold` set anywhere, the threshold defaults to **`1`**
  (`IgaScopeResolver.java:212`, defensive clamp at `:229`).

> **Warning**
> Net effect of zero configuration: a single admin holding `manage-realm` can
> self-approve and commit any change with **one** signature. This is not
> meaningful four-eyes governance until you harden it (raise the threshold,
> set approver roles on sensitive scopes, decide scope mode), and you must do
> that hardening **before** enabling IGA (see
> [Ordering](#ordering-configure-governance-before-enabling-iga)). The
> `master` realm admin is also exempt entirely.

## Governing Keycloak Organizations

IGA governs Keycloak Organizations (KC 26.5.5 organization SPI). The
`IgaOrganizationProvider` extends `JpaOrganizationProvider` and intercepts
organization mutations exactly the way `IgaRealmProvider` intercepts
client/group/role creation
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
> Organization **domains** are not a separate governed action. KC 26.5.5 has
> no standalone domain endpoint; domains are part of the organization
> representation and are changed through `UPDATE_ORGANIZATION` (or set at
> `CREATE_ORGANIZATION`). They are governed via the create/update change
> request, which carries the full `OrganizationRepresentation` as `REP_JSON`
> so replay rebuilds attributes and domains through Keycloak's own
> `RepresentationToModel.toModel`
> (`IgaOrganizationProvider.java:42-48`,
> `IgaReplayDispatcher.java:545-570`).

### How organization actions are scoped

`OrganizationModel` supports attributes, so an organization can carry
`iga.approverRole` and `iga.threshold` just like a group, role, or client.
For `UPDATE_ORGANIZATION`, `DELETE_ORGANIZATION`, `ADD_ORG_MEMBER`,
`REMOVE_ORG_MEMBER`, `ORG_INVITE_MEMBER`, `ORG_ADD_IDP`, and
`ORG_REMOVE_IDP`, `IgaScopeResolver` resolves the scope from the organization
itself via `collectOrganizationScope`
(`IgaScopeResolver.java:156-164`, `:275-303`). Set these attributes on the
organization through **Organizations → (organization) → Attributes** in the
console, or by adding them to the organization representation `attributes` map
via `PUT /admin/realms/{realm}/organizations/{org-id}`.

`CREATE_ORGANIZATION` is realm-wide: no organization exists yet, so the scope
is empty and the only gate is `manage-realm` plus the threshold, exactly like
other top-level creates (`IgaScopeResolver.java:165-170`,
`IgaOrganizationProvider.java:117-144`).

### Invitations

> **Note**
> When IGA is active, inviting a member creates a change request and **no
> invitation e-mail or action token is produced until the change request is
> committed**. The interception happens at the `InvitationManager.create`
> SPI seam, strictly *before* the invitation entity is persisted and therefore
> before the action token is serialized and before the e-mail is sent
> (`IgaInvitationManager.java:86-100`,
> `IgaOrganizationProvider.java:248-272`). Denying the change request means
> no invitation, no token, and no e-mail is ever produced — there is nothing
> to undo. On commit, replay re-runs Keycloak's own invitation logic now: the
> invitation is persisted, a fresh `InviteOrgActionToken` is minted, and the
> e-mail is sent at that moment. **Token/invitation validity therefore starts
> at commit (approval) time**, because `expiresAt` is computed inside
> Keycloak's `create()` as `Time.currentTime() +
> realm.getActionTokenGeneratedByAdminLifespan()`
> (`IgaReplayDispatcher.java:618-689`). Replay runs at most once per change
> request, so exactly one invitation/token/e-mail is produced — never a
> duplicate.

## Known limitations

- **Native organization-membership admin event is not emitted for
  IGA-approved invitations.** When `ORG_INVITE_MEMBER` is committed, replay
  faithfully reproduces Keycloak's `OrganizationInvitationResource
  .sendInvitation` mechanics (invitation, token, e-mail) but intentionally
  does **not** fire the trailing `adminEvent...success()` audit event — the
  replay dispatcher has no `AdminEventBuilder`, exactly like every other
  replay action. The **approved IGA change request is the authoritative audit
  record** for the invitation
  (`IgaReplayDispatcher.java:618-651`). Do not rely on a native
  `ORGANIZATION_MEMBERSHIP`-style admin event for IGA-approved invitations;
  audit through the change-request history instead.
- **Role policies do not drive enforcement.** The `IGA_ROLE_POLICY` table /
  `IgaRolePolicyEntity` has a `THRESHOLD` column and there are
  `/iga/role-policies` endpoints, but that `THRESHOLD` is **not** consulted by
  the authorize/commit threshold gate. It is read only by the non-cryptographic
  `IgaFirstAdminSignPreviewService` preview/prototype and echoed back through
  the role-policy REST representation. To control the *enforced* threshold,
  use the realm or per-entity `iga.threshold` attribute — not a role-policy
  row.
- **Composite-role links across separate pending change requests are
  skipped.** During `CREATE_ROLE` replay, if a composite-target role does not
  yet exist (e.g. it is itself sitting in a different pending change request),
  that single composite link is skipped and warn-logged rather than failing
  the whole replay (`IgaReplayDispatcher.java:294-304` for realm composites,
  `:311-317` for client composites). Re-establish the link after the other
  change request is committed.
- **Old pre-`REP_JSON` pending change requests are identity-only.** Change
  requests created before the full-representation capture change lack the
  captured representation. On replay they get at most a bare identity-only
  create (no attributes/mappers/full config); there is no old-format
  compatibility (`IgaReplayDispatcher.java:50-66`). Recreate such change
  requests after upgrading rather than relying on replay.
- **`isIGAEnabled` is case-sensitive and exact.** Only the literal string
  `"true"` enables IGA. Any other value, including `"True"`, leaves it off.
- **The first write after enable is not governed.** Because the enable check
  reads the attribute being mutated, the act of enabling IGA is itself not
  governed by design. Plan the enable as a deliberate, trusted operation, and
  configure governance beforehand.
- **A non-positive realm `iga.threshold` is ignored, not honored.** A value
  of `"0"`, a negative number, or a non-integer is treated as `1` (the same
  positivity rule as the per-entity path), and `resolveThreshold` applies a
  defensive final clamp so it can never return below `1`. A bad realm value
  therefore cannot disable the commit gate — it simply behaves as `1`. Set
  `iga.threshold` to the positive integer you actually want.

## Internals

(For developers.)

- **`IgaRealmProvider`** (`providers/`) — `JpaRealmProvider` subclass; wraps
  the realm in `IgaRealmAdapter` and overrides `add*`
  (client/role/group/client-scope) to intercept creates; persists the change
  request in a separate transaction and throws `IgaPendingApprovalException`.
- **`IgaRealmAdapter` / `Iga*Adapter`** — wrap Keycloak model adapters and
  intercept attribute/relationship/config writes into change requests; gated
  by `isIgaActive()` (enabled and not currently replaying).
- **`IgaOrganizationProvider`** (`providers/`) — `JpaOrganizationProvider`
  subclass; intercepts create/update/delete/member/idp organization
  mutations; returns an `IgaInvitationManager` from `getInvitationManager()`
  so invitations are intercepted at the SPI seam before any token/e-mail.
- **`IgaInvitationManager`** (`providers/`) — decorating `InvitationManager`
  whose `create(...)` records an `ORG_INVITE_MEMBER` change request and throws
  before the invitation entity is persisted; all reads/removes delegate
  straight to the wrapped manager.
- **`IgaPendingApprovalExceptionMapper`** (`rest/`) — maps the interception
  exception to HTTP 202 with the `{status:"PENDING", changeRequestId, …}`
  body.
- **`IgaRepresentationCaptureFilter`** (`rest/`) — `@PreMatching` JAX-RS
  filter that stashes the full request representation on `CREATE_*` admin
  POSTs (including organizations) so replay can rebuild the complete entity
  (`REP_JSON`).
- **`IgaScopeResolver`** (`attestors/`) — walks a change request's
  `rows_json` to derive required approver roles and scoped thresholds;
  enforces the approver gate (`requireApprover`) and computes the effective
  threshold (`resolveThreshold`). Holds the attribute key constants.
- **`SimpleNameAttestor`** (`attestors/`) — default attestor (no
  cryptography): records the approving admin's username as the signature,
  enforces the scope gate on `record`, combines signatures into a JSON array
  on `combineFinal`, and delegates `getThreshold` to `IgaScopeResolver`.
- **`IgaReplayDispatcher`** (`replay/`) — on commit, sets
  `IGA_REPLAY_ACTIVE=true`, replays the recorded operation against the real
  Keycloak model (rebuilding full config from `REP_JSON` for creates,
  replaying relationship/attribute rows, and re-running Keycloak's own
  organization/invitation logic for org actions), writes the final
  attestation, and marks the change request `APPROVED`.
- **`IgaAdminResource`** (`rest/`, `@Path("iga")`) — all operator endpoints:
  `change-requests` (list/get/update/authorize/commit/deny/comments),
  `role-policies`, `authorizers`, `forseti-contracts`, `server-certs`,
  `licensing`, `baseline-review`. Every endpoint requires `manage-realm`
  (deny / comment-delete additionally allow the original author).
- **`TideAdminCompatResource`** (`rest/`, `@Path("tide-admin")`) —
  backwards-compatible `toggle-iga` / `iga-status` endpoints driving the
  `isIGAEnabled` realm attribute.
