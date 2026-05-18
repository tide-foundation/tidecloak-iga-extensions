# IGA (Identity Governance & Administration) — Operator & Admin Guide

This document describes how the IGA approval workflow in `tidecloak-iga-extensions`
actually behaves on the `iga-approval-workflow` branch. It is written from the
code, not from design intent. Where the implementation has gaps or surprising
edges, they are called out explicitly.

Audience: realm operators / administrators. A short **Internals** section at the
end is for developers.

---

## Overview

IGA turns privileged Keycloak administration writes into **change requests (CRs)**
that must be approved before they take effect.

The lifecycle is:

1. **Intercept.** When IGA is enabled for a realm, the IGA model providers
   (`IgaRealmProvider` and the `Iga*Adapter` wrappers) intercept privileged
   writes (create client/user/role/group/client-scope, role grants, group
   membership, composites, scope assignments, protocol mappers, attribute
   writes, realm-config setters, etc.) instead of applying them.
2. **Record + 202.** The interceptor persists a `PENDING` change request in a
   separate transaction (so it survives the rollback of the interrupted write)
   and throws `IgaPendingApprovalException`. `IgaPendingApprovalExceptionMapper`
   converts that to **HTTP 202 Accepted** with a JSON body:

   ```json
   {
     "status": "PENDING",
     "changeRequestId": "<uuid>",
     "entityType": "CLIENT",
     "actionType": "CREATE_CLIENT",
     "message": "Change request created — awaiting approval"
   }
   ```

   The original entity is **not** written. Callers/UI should treat a 202 as
   "queued for approval", not "done".
3. **Approve (authorize).** One or more admins sign the CR via
   `POST .../iga/change-requests/{id}/authorize`. This only records a signature;
   it does not apply the change even if the threshold is already met.
4. **Commit.** Once the signature count meets the threshold, an admin calls
   `POST .../iga/change-requests/{id}/commit`. This replays the recorded
   operation against the real Keycloak model (`IgaReplayDispatcher`) and sets
   the CR to `APPROVED`.

Pending change requests are listed via `GET .../iga/change-requests`
(defaults to `status=PENDING`). In the admin UI this is the **Change Requests**
screen. All `iga/*` endpoints are mounted under the realm admin base, i.e.
`/admin/realms/{realm}/iga/...`.

Statuses a CR can hold: `PENDING`, `APPROVED` (after a successful commit/replay),
`DENIED` (via `POST .../iga/change-requests/{id}/deny`).

---

## Enabling / disabling IGA

IGA is controlled by the **case-sensitive** realm attribute
`isIGAEnabled`. It is "enabled" only when the attribute string is exactly
`"true"` (`IgaChangeRequestService.isIgaEnabled`, `IgaChangeRequestService.java:36-39`).

### Toggle endpoint

`POST /admin/realms/{realm}/tide-admin/toggle-iga`
(`TideAdminCompatResource.java:38-48`) flips `isIGAEnabled` between `"true"` and
`"false"`. It requires `manage-realm` (`auth.realm().requireManageRealm()`).
`GET .../tide-admin/iga-status` reports the current state and requires
`view-realm`.

### Master realm is always exempt

`isIgaEnabled` returns `false` unconditionally when the realm name is `master`
(`IgaChangeRequestService.java:37`). IGA cannot be enforced on the `master`
realm — administration there is never intercepted.

### Enable without approval, disable needs approval

This rule is **confirmed in code**:

- **Enabling** IGA is applied directly. When IGA is OFF and an admin sets
  `isIGAEnabled = true`, `isIgaActive()` (`IgaRealmAdapter.java:63-71`) calls
  `isIgaEnabled(this)` which reads the *attribute currently being written* —
  it is still `false` at that moment — so the write falls into the
  pass-through branch and `super.setAttribute` applies immediately
  (`IgaRealmAdapter.java:74-78`, documented at `IgaRealmAdapter.java:23-28`).
  IGA only "engages" on the *next* privileged write.
- **Disabling** IGA goes through the normal CR flow. Once IGA is ON, an admin
  setting `isIGAEnabled = false` is intercepted as a `SET_REALM_ATTRIBUTE`
  change request (`IgaRealmAdapter.java:74-88`) and must be approved and
  committed like any other privileged realm-attribute write
  (documented at `IgaRealmAdapter.java:30-33`).

> Operational consequence: turning IGA off is itself a governed action. You
> cannot unilaterally disable governance once it is active — it requires the
> same approvals as any other change.

While a realm-attribute/realm-config CR is pending, any other attempt to set or
remove a realm attribute/config on the same realm fails with **HTTP 409**
(`IgaRealmAdapter.checkNoPendingCr`, `IgaRealmAdapter.java:106-111`). Resolve
(approve or deny) the existing CR first.

---

## The approval workflow (authorize vs commit)

Approval is **two explicit steps**. This is intentional — collecting signatures
is separate from applying the change.

### Step 1 — authorize (sign)

`POST /admin/realms/{realm}/iga/change-requests/{id}/authorize`
(`IgaAdminResource.java:193-252`)

- Requires `manage-realm` (`auth.realm().requireManageRealm()`,
  `IgaAdminResource.java:198`).
- The CR must be `PENDING` (else 409).
- **One signature per admin.** A second authorize from the same admin (matched
  by username stored in `PARTIAL_SIG`, or by user id in `AUTHORIZED_BY`) is
  rejected with 409 "Caller has already signed this change request"
  (`IgaAdminResource.java:222-239`).
- The approver-role gate is enforced here (inside
  `SimpleNameAttestor.record` → `IgaScopeResolver.requireApprover`,
  `SimpleNameAttestor.java:50-52`).
- **Authorize never applies the change**, even if the threshold is now met
  (`IgaAdminResource.java:245-247`). It only records the signature.

### Step 2 — commit (apply)

`POST /admin/realms/{realm}/iga/change-requests/{id}/commit`
(`IgaAdminResource.java:258-311`)

- Requires `manage-realm` (`IgaAdminResource.java:262`).
- The CR must be `PENDING`.
- Re-checks the same approver-role gate
  (`IgaScopeResolver.resolve` + `requireApprover`, `IgaAdminResource.java:284-285`).
- Counts recorded signatures; if `count < threshold` it returns **HTTP 412
  Precondition Failed** with `{error, threshold, authCount}`
  (`IgaAdminResource.java:288-301`).
- When the threshold is met it combines the final attestation and calls
  `IgaReplayDispatcher.replay(...)`, which performs the real Keycloak write and
  sets the CR to `APPROVED` (`IgaAdminResource.java:303-310`).

**Who can commit:** any admin who passes `manage-realm` *and* the approver-role
gate for that CR. The committer does not have to be one of the signers, but the
threshold must already be satisfied by recorded signatures. There is no
separate "committer" role.

Other CR operations: `PUT .../change-requests/{id}` edits the rows and **wipes
all existing authorizations** (`IgaChangeRequestService.updateRows`); each CR
also supports comments under `.../change-requests/{id}/comments`.

---

## Setting thresholds

The threshold is the number of distinct admin signatures required before a CR
can be committed. The live resolution path is
`SimpleNameAttestor.getThreshold` → `IgaScopeResolver.resolveThreshold`
(`SimpleNameAttestor.java:88-91`, `IgaScopeResolver.java:186-195`).

**Precedence (highest to lowest):**

1. **Per-scope-entity `iga.threshold` attribute** — if any group / role /
   client *affected by this CR* (resolved by walking `rows_json`, see "Who can
   approve" below) carries an `iga.threshold` attribute, the **maximum** of all
   such positive integer values is used (`IgaScopeResolver.java:187-189`,
   `addThreshold` at `IgaScopeResolver.java:291-298`).
2. **Realm attribute `iga.threshold`** — if no scoped threshold applies, the
   realm attribute `iga.threshold` is parsed as an integer and used
   (`IgaScopeResolver.java:190-193`).
3. **Hardcoded default `1`** — if neither is set (or the realm value is not a
   valid integer), the threshold is **`1`** (`IgaScopeResolver.java:194`).

### How to set each

- **Realm-wide default:** set the realm attribute `iga.threshold` to e.g. `"2"`.
  (Realm attribute writes are themselves governed once IGA is on — see
  "Enabling / disabling IGA".)
- **Per scope entity:** set the attribute `iga.threshold` on the Keycloak
  **group**, **role**, or **client** that the change affects, alongside its
  `iga.approverRole` attribute. Example: a role with
  `iga.approverRole = hr-approver` and `iga.threshold = 3` requires 3
  signatures from `hr-approver` holders for any CR touching that role.

> **Important discrepancy — role policies do NOT drive the live threshold.**
> The `IGA_ROLE_POLICY` table / `IgaRolePolicyEntity` has a `THRESHOLD` column,
> and there are admin endpoints to manage it
> (`GET/POST/DELETE .../iga/role-policies`, `.../iga/role-policies/role/{roleId}`,
> `IgaAdminResource.java:739-849`). **However, that `THRESHOLD` is not consulted
> by the authorize/commit threshold gate.** It is only read by
> `IgaFirstAdminSignPreviewService` (a non-cryptographic preview/prototype,
> `IgaFirstAdminSignPreviewService.java:418`) and echoed back through the
> role-policy REST representation. To control the *enforced* threshold, use the
> realm attribute or per-entity `iga.threshold` attribute described above — not
> the role-policy row. (See "Known limitations".)

---

## Who can approve (approver roles & scope)

By default, **any admin with `manage-realm` can authorize and commit any CR**
(see "Initial setup" below). To restrict approval to specific people, mark the
affected Keycloak entities with the attribute `iga.approverRole`.

### `iga.approverRole`

Set `iga.approverRole = <keycloak-role-name>` on a **group**, **role**, or
**client** (`IgaScopeResolver.ATTR_APPROVER_ROLE = "iga.approverRole"`,
`IgaScopeResolver.java:44`).

For a given CR, `IgaScopeResolver.resolve(...)` walks the CR's `rows_json`
based on its `actionType` and collects the union of `iga.approverRole` values
from the affected entities (`IgaScopeResolver.java:62-156`):

- For user-targeting actions (`GRANT_ROLES`, `JOIN_GROUPS`,
  `SET_USER_ATTRIBUTE`, …) it walks every **group the user belongs to** and
  each group's **ancestor groups** (`collectUserGroupScopes`,
  `walkGroupAncestors`, `IgaScopeResolver.java:259-273`).
- For role-targeting actions it reads the role's `iga.approverRole`
  (`collectRoleScope`, `IgaScopeResolver.java:275-281`).
- For group-targeting actions it walks the group and its ancestors.
- For client-targeting actions it reads the client's `iga.approverRole`
  (`collectClientScope`, `IgaScopeResolver.java:283-289`).
- Realm-wide actions (`CREATE_USER`, `CREATE_ROLE`, `CREATE_GROUP`,
  `CREATE_CLIENT`, `CREATE_CLIENT_SCOPE`, `SET_REALM_*`,
  `BASELINE_APPROVAL`, license/server-cert actions, client-scope scopes)
  yield an **empty scope** — no approver-role requirement is derived; only the
  baseline `manage-realm` gate applies. **Note: creating top-level entities is
  therefore not scope-restricted by approver role.**

The collected set is exposed on the CR representation as
`requiredApproverRoles` for the UI.

### `iga.scopeMode` (any vs all)

Read from the **realm attribute** `iga.scopeMode`
(`IgaScopeResolver.ATTR_SCOPE_MODE = "iga.scopeMode"`, `IgaScopeResolver.java:46`;
gate logic `requireApprover`, `IgaScopeResolver.java:165-179`):

- `iga.scopeMode = all` (case-insensitive) → strict: the approving admin must
  hold **every** role in `requiredApproverRoles`.
- Any other value, or unset → **`any`** (default): the admin needs **at least
  one** of the required roles.

`scopeMode` is **realm-level only** — there is no per-entity scope-mode
attribute. The UI mirrors this exactly (`IgaAdminResource.java:1455-1456`).

If `requiredApproverRoles` is empty, `requireApprover` is a **no-op**
(`IgaScopeResolver.java:166`) and the only gate is `manage-realm`.

### Worked example — "only HR can approve changes to the HR group"

1. On the `hr` Keycloak group, set attribute
   `iga.approverRole = hr-approver`.
2. (Optional) On the same group set `iga.threshold = 2` to require two HR
   approvers.
3. Create the Keycloak role `hr-approver` and assign it to your HR approvers.
4. Now any CR that adds/removes members of the `hr` group, or grants the `hr`
   group roles, resolves `requiredApproverRoles = {hr-approver}`. With the
   default `iga.scopeMode` (`any`), authorize/commit succeed only for an admin
   who (a) has `manage-realm` and (b) holds `hr-approver`. Other realm admins
   get **HTTP 403** "Approver role required: [hr-approver] (mode=any)".

---

## Initial setup / first approvals (the bootstrap answer)

**Question: when IGA is freshly enabled and nothing has `iga.approverRole`
configured, which role is allowed to sign?**

**Factual answer: any admin with the realm `manage-realm` permission can
authorize *and* commit *any* change request — there is no narrower built-in
"first approver" role.**

Why, from the code:

- Every approval endpoint (`authorize`, `commit`, plus list/get/deny) starts
  with `auth.realm().requireManageRealm()` — the JAX-RS auth guard. Cited:
  - `authorize`: `IgaAdminResource.java:198`
  - `commit`: `IgaAdminResource.java:262`
  - `listChangeRequests`: `IgaAdminResource.java:143`
  - `deny`: `IgaAdminResource.java:375`
- The only *additional* gate is `IgaScopeResolver.requireApprover(...)`, and it
  **returns immediately (no-op) when `requiredApproverRoles` is empty**
  (`IgaScopeResolver.java:165-179`, specifically the early `return` at line 166).
- With zero `iga.approverRole` attributes configured anywhere, every CR
  resolves to an empty scope, so `requireApprover` never blocks.
- With no `iga.threshold` set anywhere, the threshold defaults to **`1`**
  (`IgaScopeResolver.java:194`).

**Net effect of default config:** a single admin holding `manage-realm`
(equivalently, the `realm-management` `manage-realm` client role, or a realm
`admin`) can self-approve and commit any change with **one** signature. This is
*not* meaningful four-eyes governance until you harden it. (The master-realm
admin is also exempt entirely — see "Enabling / disabling IGA".)

### Recommended hardening (do this before relying on IGA for governance)

1. **Raise the threshold.** Set the realm attribute `iga.threshold` to at least
   `2` so no single admin can self-approve and commit (note: with threshold ≥ 2
   you need that many *distinct* admins to sign; one admin cannot sign twice).
2. **Set approver roles on sensitive scopes.** Add `iga.approverRole` (and
   optionally a higher per-entity `iga.threshold`) to the groups/roles/clients
   that matter. Create the corresponding Keycloak roles and assign them only to
   trusted approvers.
3. **Decide `iga.scopeMode`.** Leave unset/`any` for "one of the listed roles",
   or set the realm attribute `iga.scopeMode = all` to require approvers to
   hold *every* listed role.
4. **Remember the gaps:** top-level `CREATE_*` actions and realm-wide actions
   are *not* approver-role scoped (empty scope) — they are governed only by
   `manage-realm` + threshold. Restrict who has `manage-realm` accordingly, and
   use a realm-wide `iga.threshold` so even unscoped creates need multiple
   signatures.
5. **Lock down the `master` realm separately** — IGA does not apply there.

---

## Known limitations

- **Role policies do not drive enforcement.** `IGA_ROLE_POLICY.THRESHOLD`
  (and the `/iga/role-policies` endpoints) are **not** read by the live
  authorize/commit threshold gate. Only realm/per-entity `iga.threshold`
  attributes are enforced. Role policies currently feed only the
  `first-admin-sign-preview` prototype. Do not rely on a role-policy threshold
  for governance today.
- **Composite-role links across separate pending CRs are skipped.** During
  `CREATE_ROLE` replay, if a composite-target role does not yet exist (e.g. it
  is itself sitting in a *different* pending CR), that single composite link is
  **skipped and warn-logged** rather than failing the whole replay
  (`IgaReplayDispatcher.java:294-304` for realm composites, `:311-317` for
  client composites). The created role will be missing those composite links;
  re-establish them after the other CR is committed.
- **Old pre-existing pending CRs are identity-only.** Change requests created
  before the full-representation capture change (`REP_JSON`) lack the captured
  representation. On replay they get at most a "bare safety net" create
  (identity only — no attributes/mappers/full config). There is **no
  old-format compatibility**; such CRs are intentionally discarded and will
  under-rebuild by design (`IgaReplayDispatcher.java:50-66`). Recreate them
  after upgrading rather than relying on replay.
- **`isIGAEnabled` is case-sensitive and exact.** Only the literal string
  `"true"` enables IGA. Any other value (including `"True"`) leaves IGA off.
- **First write after enable is a freebie.** Because the enable check reads the
  attribute being mutated, the act of enabling IGA is itself not governed (by
  design). Plan the enable as a deliberate, trusted operation.

---

## Internals (brief, for developers)

- **`IgaRealmProvider`** (`providers/IgaRealmProvider.java`) — `JpaRealmProvider`
  subclass; wraps the realm in `IgaRealmAdapter` and overrides `add*`
  (client/role/group/client-scope) to intercept creates; persists the CR in a
  separate transaction and throws `IgaPendingApprovalException`
  (`recordAndThrow`, lines 88-97).
- **`IgaRealmAdapter` / `Iga*Adapter`** — wrap Keycloak model adapters and
  intercept attribute/relationship/config writes into change requests; gated by
  `isIgaActive()` (enabled + not currently replaying).
- **`IgaPendingApprovalExceptionMapper`** (`rest/`) — maps the interception
  exception to **HTTP 202** with the `{status:"PENDING", changeRequestId, …}`
  body.
- **`IgaRepresentationCaptureFilter`** (`rest/`) — `@PreMatching` JAX-RS filter
  that stashes the full request representation on `CREATE_*` admin POSTs so
  replay can rebuild the complete entity (`REP_JSON`), not just identity.
- **`IgaScopeResolver`** (`attestors/`) — walks a CR's `rows_json` to derive
  `requiredApproverRoles` and scoped thresholds; enforces the approver gate
  (`requireApprover`) and computes the effective threshold
  (`resolveThreshold`). Holds the attribute key constants
  (`iga.approverRole`, `iga.threshold`, `iga.scopeMode`).
- **`SimpleNameAttestor`** (`attestors/`) — default attestor (no cryptography):
  records the approving admin's username as the signature, enforces the scope
  gate on `record`, combines signatures into a JSON array on `combineFinal`,
  and delegates `getThreshold` to `IgaScopeResolver`.
- **`IgaReplayDispatcher`** (`replay/`) — on commit, sets
  `IGA_REPLAY_ACTIVE=true`, replays the recorded operation against the real
  Keycloak model (rebuilding full config from `REP_JSON` for creates, applying
  protocol-mapper `config`, replaying relationship/attribute rows), writes the
  final attestation, and marks the CR `APPROVED`.
- **`IgaAdminResource`** (`rest/`, `@Path("iga")`) — all operator endpoints:
  `change-requests` (list/get/update/authorize/commit/deny/comments),
  `role-policies`, `authorizers`, `forseti-contracts`, `server-certs`,
  `licensing`, `baseline-review`. Every endpoint requires `manage-realm`
  (deny/comment-delete additionally allow the original author).
- **`TideAdminCompatResource`** (`rest/`, `@Path("tide-admin")`) —
  backwards-compatible `toggle-iga` / `iga-status` endpoints driving the
  `isIGAEnabled` realm attribute.
