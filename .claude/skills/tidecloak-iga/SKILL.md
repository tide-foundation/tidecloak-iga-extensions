---
name: tidecloak-iga
description: >
  Deep operating knowledge of TideCloak IGA (Identity Governance & Administration)
  — the capture-then-veto approval pipeline. Use to OPERATE and DIAGNOSE: understand
  why an admin action got captured into a change request (CR), what's needed to
  commit it (threshold + approver role + scope mode), interpret 202/403/412/409/429/404
  responses, walk a CR through authorize -> commit -> replay, reason about ADOPT scans,
  the attestor SPI (simple vs tide), quarantine, and the Tideless-vs-Tide mode boundary.
  Pairs with the iga-diagnostician agent.
---

# TideCloak IGA

IGA is a **capture-then-veto** governance layer over Keycloak admin mutations. When
IGA is enabled on a realm, privileged model changes don't apply immediately — they're
intercepted, written as a PENDING **change request (CR)**, and the original request is
rolled back and answered with **HTTP 202**. An admin then drives the CR:
**authorize** (record a per-admin signature, enforce approver role) → **commit**
(check threshold, then *replay* the change for real and stamp an attestation).

It implements TWO coexisting modes that share the same pipeline:
- **Tideless** (canonical / enforced today): attribute-driven threshold + approver role,
  per-row attestation via `SimpleNameAttestor` (no crypto — the "signature" is the
  admin's username).
- **Tide** (future): per-(linkage-table, owner) **set-signing** via `TideAttestor`,
  whose single crypto swap-point currently returns a dummy SHA-256 digest. There is
  **no runtime cryptographic Tide gate yet** — selecting Tide mode is just a realm
  attribute choosing the dummy attestor.

Code lives almost entirely in the **`iga-core`** Maven module (`org.tidecloak.iga.*`)
of `tidecloak-iga-extensions`. The `ATTESTATION` columns it stamps live in
`tidecloak-override` (KC-core fork); the admin UI consuming `/iga/*` is elsewhere.
Paths below are relative to the `iga-core` source tree.

---

## When to use this skill

- An admin action returned 202 and you need to explain what happened / what's next.
- A CR won't commit (403/412/409) and you need the precise cause and the fix.
- You're reasoning about which roles can approve a CR and how many signatures it needs.
- You're explaining ADOPT (toggle-on attestation of pre-existing state), quarantine,
  bulk authorize, or the Tide-mode seam.

---

## Enablement & suppression — is IGA even active here?

`IgaChangeRequestService.isIgaEnabled` (`providers/IgaChangeRequestService.java:47-50`):
- The **`master`** realm is ALWAYS exempt (returns false).
- Otherwise enabled iff realm attribute **`isIGAEnabled == "true"`**.

`isIgaActive(realm)` = `isIgaEnabled(realm) && !"true".equals(session.getAttribute("IGA_REPLAY_ACTIVE"))`.
The `IGA_REPLAY_ACTIVE` session flag is set during commit-replay so the re-applied
model ops pass straight through the IGA wrappers without being re-captured.

Toggle endpoint: **`POST /admin/realms/{realm}/tide-admin/toggle-iga`**
(`TideAdminCompatResource.toggleIga:74`). Turning IGA **on** also runs the ADOPT scan (§ADOPT).

> The same `isIGAEnabled` attribute is also read in `tidecloak-idp-extensions`
> (`VendorResource.java:1353`), where the legacy IGA wiring is now a decoupled no-op
> (`CommitPreApprovedChanges` just logs and returns). IGA capture/commit does NOT run
> in idp-extensions — that project only *defines* the `tide-vendor-key` component and
> reads the enablement flag.

---

## What gets captured, and where (the interception seams)

IGA-aware model providers extend the stock JPA providers and override mutating methods;
each checks `isIgaActive(realm)`. The shared emit-helper (`IgaRealmProvider.java:~105-112`)
(a) writes the CR on a **fresh session via `runJobInTransaction`** (so it survives the
rollback), (b) `setRollbackOnly()` on the request tx, (c) throws
`IgaPendingApprovalException(crId, entityType, actionType)`.

| Operation | Class / terminal seam | actionType |
|---|---|---|
| Create user (1-arg) | `IgaUserProvider.addUser` → `IgaUserAdapter.getId()` (`:509-594`) | `CREATE_USER` |
| Create user (5-arg, import) | `IgaUserProvider.addUser(...)` (`:155-186`), gated on import mode | `CREATE_USER` (batched) |
| Create role | `IgaRoleAdapter.getName()` | `CREATE_ROLE` |
| Create group | `IgaGroupAdapter.setDescription()` | `CREATE_GROUP` |
| Create client | `IgaClientAdapter.updateClient()` | `CREATE_CLIENT` |
| Create client-scope | `IgaClientScopeAdapter.getId()` | `CREATE_CLIENT_SCOPE` |
| Role grant/revoke, group join/leave, composites, scope assign, scope→role, scope-mappings, protocol mappers, attribute writes, realm config, default groups, web-origins/redirect-uris | `IgaUserAdapter` / `IgaGroupAdapter` / `IgaRoleAdapter` / `IgaClientAdapter` / `IgaClientScopeAdapter` / `IgaRealmAdapter` | `GRANT_ROLES`/`REVOKE_ROLES`/`JOIN_GROUPS`/`LEAVE_GROUPS`/`ADD_COMPOSITE`/`ASSIGN_SCOPE`/`SCOPE_ADD_ROLE`/`SCOPE_MAPPING_ADD`/`ADD_PROTOCOL_MAPPER`/`SET_*_ATTRIBUTE`/… |
| Organizations | `IgaOrganizationProvider`/`IgaOrganizationModel`/`IgaInvitationManager` | `CREATE_ORGANIZATION`/`ADD_ORG_MEMBER`/`ORG_INVITE_MEMBER`/`ORG_ADD_IDP`/… |

**Three subtleties that explain "why did/didn't this capture":**

1. **Terminal-seam + StackWalker suppression.** Creates capture at a single *terminal*
   method (e.g. `IgaUserAdapter.getId()` only fires when the immediate caller is exactly
   `UsersResource#createUser` — `:454-507`). KC's own internal `getId()` calls mid-build
   are skipped. Likewise `IgaRealmProvider.isOnClientCreationPath()` (`:655-688`) and
   `IgaRealmAdapter` (`:401-426`) **fold** the `ASSIGN_SCOPE`/default-scope side-effects
   KC fires *while creating a client* into the parent `CREATE_CLIENT` — so they don't each
   spawn their own CR.
2. **Scratch-then-veto for `CREATE_*`.** A real scratch entity is created so KC's resource
   flow can apply the full representation; the assembled representation is captured into
   `ROWS_JSON`, then the rollback discards the scratch entity — zero rows persist while PENDING.
3. **partialImport batch.** `IgaImportMode` (`providers/IgaImportMode.java`) detects a
   `partialImport` stack frame, *accumulates* captured entities instead of throwing per-entity,
   and emits all per-type CRs in one tx via a `BatchEmitTransaction`, then throws ONE
   `IgaPendingApprovalException(firstCrId, "BATCH", "PARTIAL_IMPORT")` → a single 202.
   (Import-mode seams must NOT `setRollbackOnly()`.)

---

## The CR data model

**`IgaChangeRequestEntity`** → table `IGA_CHANGE_REQUEST` (`entities/IgaChangeRequestEntity.java`):
`ID`, `REALM_ID`, `ENTITY_TYPE` (USER/ROLE/GROUP/CLIENT/CLIENT_SCOPE/ORGANIZATION/edge types/`BATCH`),
`ENTITY_ID` (**VARCHAR(36)** — edges use a synthetic id, see §ADOPT), `ACTION_TYPE`,
`ROWS_JSON` (TEXT — the payload), `STATUS` (`PENDING`/`APPROVED`/`DENIED`/`CANCELLED`),
`REQUESTED_BY`, `CREATED_AT`, `RESOLVED_AT`, `RESOLVED_BY`. State is the `STATUS` string —
there is no separate draft/committed boolean.

**`IgaAuthorizationEntity`** → table `IGA_AUTHORIZATION` (the per-approver approvals table):
`ID`, `CHANGE_REQUEST_ID` (FK), `AUTHORIZED_BY` (admin user id), `APPROVAL` (TEXT — for
`simple` this is the admin's **username**; was `PARTIAL_SIG` before changelog 2.6.0), `CREATED_AT`.

**Where attestation lands:** NOT on the CR. At replay, the final attestation string is
stamped onto the **target KC entity/edge row's `ATTESTATION` column** (those columns are
defined in `tidecloak-override`). Node creates stamp the entity row; relationship CRs stamp
the linkage row (e.g. `USER_ROLE_MAPPING(uid,rid)`).

**`ROWS_JSON` key contract** (authoritative in `replay/IgaReplayDispatcher.java:25-119`):
`ID`=own PK; `CLIENT_UUID`=client UUID; **`CLIENT_ID`=human client id** (the only `*_ID`
that is not a UUID); `USER_ID`/`ROLE_ID`/`GROUP_ID`/`CLIENT_SCOPE_ID`=UUIDs; `REP_JSON`=full
KC representation for every `CREATE_*`; `config`=protocol-mapper config; org keys
`ORG_ID`/`ORG_NAME`/`ORG_ALIAS`/`IDP_ALIAS`/`INVITE_*`. No legacy-format fallback.

The full actionType set is the switch in `IgaReplayDispatcher.doReplay` (`:166-261`) plus the
ADOPT family routed by `IgaReplayExtension`.

---

## CR lifecycle & the REST API

REST resource **`IgaAdminResource`** (`rest/IgaAdminResource.java`), `@Path("iga")` →
`/admin/realms/{realm}/iga`. Every endpoint calls `requireManageRealm()` first.

| Endpoint | What it does |
|---|---|
| `GET /iga/change-requests?status=` (`:157-189`) | list (default PENDING). Each item carries `authorizationCount`, `authorizers[]`, **`readyToCommit`** (PENDING && authCount≥threshold), `threshold`, `requiredApproverRoles`, `scopeMode` (`toRepresentation:1754-1820`). |
| `GET /iga/change-requests/{id}` (`:195-207`) | single CR |
| `POST .../{id}/authorize` (`:213-291`) | record a signature; enforces approver role; does NOT commit even at threshold |
| `POST .../{id}/commit` (`:297-392`) | re-check approver role, check threshold, `combineFinal`, then replay |
| `POST .../{id}/deny` (`:796-810`) | → `STATUS=DENIED` |
| `PUT .../{id}` (`:764-790`) | replace `rows` AND **delete all authorizations** (re-signing required) |
| `POST .../bulk-authorize` (`:436-584`) | body `{actionTypeIn, olderThan?, limit?}`; per-realm cluster mutex (`IgaBulkLock`); per-CR outcomes |
| `POST .../adopt` (`:822-864`) | manual ADOPT CR (409 if already attested) |

ADOPT CRs are uniquely **resumable from CANCELLED** — authorize/commit flip them back to PENDING.

---

## Failure shapes — the diagnostic centerpiece

| HTTP | When | Body / signal | Source |
|---|---|---|---|
| **202** Accepted | action captured into a CR | `Location` header → CR-get endpoint | `IgaPendingApprovalExceptionMapper:36-68` |
| **403** Forbidden | authorize/commit by an admin lacking the required approver role | `"Approver role required: [...] (mode=any\|all)"` | `IgaScopeResolver.requireApprover` → `ForbiddenException` |
| **412** Precondition Failed | commit with `authCount < threshold` | `{error:"Need N more signature(s)", threshold, authCount}` | `IgaAdminResource:346-354` |
| **409** Conflict | (a) CR not in PENDING state; (b) duplicate signature by same admin (same `APPROVAL` username or `AUTHORIZED_BY` id) | `"...not in PENDING state"` / `"Caller has already signed this change request"` | `IgaAdminResource:261-278` |
| **409** Conflict | manual adopt of an already-attested target | `ALREADY_ATTESTED` | `IgaAdminResource:822-864` |
| **429** Too Many Requests | bulk-authorize lost the per-realm cluster lock | — | `IgaBulkLock` |
| **404** Not Found | ADOPT target deleted out-of-band during commit; CR stays PENDING | `{error:"ENTITY_VANISHED", entityType, entityId, realmId}` | `IgaAdminResource:378-388` |
| **409** SIDECAR_CAP_EXCEEDED | toggle-on scan would create > sidecar cap CRs | — | `IgaAdoptScan` |

Bulk-authorize returns **200 even when individual CRs reject** — per-CR outcome is
`COMMITTED` / `REJECTED`(`FORBIDDEN_APPROVER_ROLE`/`THRESHOLD_NOT_MET`/`ENTITY_VANISHED`/…) /
`SKIPPED`(`ALREADY_RESOLVED`). Read the per-CR array, not the HTTP status.

---

## Threshold / approver-role / scope-mode resolution

`IgaScopeResolver` (`attestors/IgaScopeResolver.java`). Attribute keys (`:49-51`):
`iga.threshold`, `iga.approverRole`, `iga.scopeMode`.

- **`resolve(...)`** (`:75-198`) walks the entities a CR affects (from `ROWS_JSON`) per
  actionType and builds a `ResolvedScope` = `{requiredApproverRoles set, thresholds set}`.
  `CREATE_*`, realm-wide actions, and ADOPT_* yield an empty scope (→ realm default).
- **`resolveThreshold(...)`** (`:283-311`): ADOPT_* short-circuits to **1**. Else
  `max(per-scope thresholds)` → else realm `iga.threshold` (honored only if ≥1) → else 1,
  with a final **`Math.max(1, resolved)` clamp** (a non-positive value can never silently
  disable the gate).
- **`requireApprover(...)`** (`:226-249`): ADOPT_* is a no-op. If `requiredApproverRoles`
  is empty → no-op (any `manage-realm` admin can sign). Else `scopeMode`:
  **`any`** = admin holds ≥1 required role; **`all`** = admin holds every required role
  (`"all"` case-insensitive; anything else, incl. unset = `any`). Failure → 403.

### ⚠ THE GOTCHA — per-scope threshold needs same-entity approverRole

In `collectRoleScope` (`:492-498`), `collectClientScope` (`:500-506`),
`walkGroupAncestors` (`:480-490`), and the org/idp collectors, `addThreshold(...)` is called
**inside** the `if (iga.approverRole is non-blank)` block. So an entity that sets
`iga.threshold` but **not** `iga.approverRole` contributes **nothing** — its threshold is
silently dropped and resolution falls back to realm `iga.threshold` / default 1.

> Diagnostic signature: *"I set `iga.threshold=3` on a role but the CR commits with one
> signature."* → That role is missing `iga.approverRole`. Set both on the same entity.

---

## The attestor SPI

- SPI `"iga-attestor"` (`attestors/IgaAttestorSpi.java`); interface `IgaAttestor`
  (`attestors/IgaAttestor.java`): `record(session, cr, admin, payload)` (MUST enforce
  approver role + persist the auth), `combineFinal(session, cr, authorizations)`,
  `getThreshold(session, realm, cr)`, and default `isSetSigned() = false`.
- **Resolution:** `IgaAttestors.resolveAttestor` (`attestors/IgaAttestors.java:21-35`) reads
  realm attribute **`iga.attestor`** (default `"simple"`; falls back to simple if the named
  one is missing) → `session.getProvider(IgaAttestor.class, id)`.
- **`SimpleNameAttestor`** (id `"simple"`, default/enforced): `record` enforces approver role
  then stores `APPROVAL = admin.getUsername()`; `combineFinal` = JSON array of
  `{by, at}`. Per-row, no crypto. This is what every Tideless realm uses.
- **`TideAttestor`** (id `"tide"`, dummy/future, `attestors/TideAttestor.java`):
  `isSetSigned()=true`; implements the FULL per-(linkage-table, owner) **set-signing** —
  `combineFinal` resolves the linkage (`TideSetResolver.linkageFor`), gathers the owner's
  *post-change* member set, canonicalizes (`table=…\nowner=…\nmembers=<sorted>`), and signs
  once at the **single crypto swap-point `sign(byte[])` (`:351-358`)**, which currently
  returns `"TIDE-DUMMY-v1:" + base64(sha256(canonical))`. **Real Midgard `signClaims()`
  swaps in exactly at `sign()`** — nothing else changes. `signSet(...)` (`:305-308`) is the
  reusable helper the dispatcher uses for nested-child and ADOPT-edge set-signing.

`isSetSigned()` is what gates replay fan-out: per-row stamp (simple) vs whole-owner-set
re-sign (tide).

---

## ADOPT coverage & replay

**Toggle-on scan** — `IgaAdoptScan.scan(...)` (`services/IgaAdoptScan.java`), run on OFF→ON.
Finds pre-existing entities/edges with `ATTESTATION IS NULL` and emits one ADOPT CR each
(`ADOPT_USER/ROLE/GROUP/CLIENT/CLIENT_SCOPE/ORGANIZATION` and edge
`ADOPT_COMPOSITE_ROLE/CLIENT_SCOPE_CLIENT/CLIENT_SCOPE_ROLE/PROTOCOL_MAPPER/DEFAULT_CLIENT_SCOPE/SCOPE_MAPPING`).
Skip lanes: **systemFilter** (built-in admin clients/roles + KC default scopes via
`IgaSystemEntityFilter`; opt-out `iga.adopt.includeSystem=true`), already-committed-adopt
(re-toggle idempotency), pending-create, already-attested, system-edges. A **sidecar cap**
(`SIDECAR_CAP_DEFAULT=100_000`, override `iga.adopt.sidecarCap`) refuses toggle-on with
409 if exceeded.

**`edgeSyntheticId`** (`IgaChangeRequestService:356-360`): an edge's composite key (two UUIDs,
~73 chars) overflows the VARCHAR(36) `ENTITY_ID`. Fix: `UUID.nameUUIDFromBytes("type|k1|k2")`
→ a deterministic 36-char id (same edge → same id, for idempotency). The real edge endpoints
live in `ROWS_JSON`, read at replay — never from `ENTITY_ID`.

**Replay.** `IgaReplayExtension.tryReplay` (`replay/IgaReplayExtension.java:189-222`) owns the
ADOPT_* family: node adopt = assert-exists (→ `EntityVanishedException`/404 if gone) + JPQL
`UPDATE … SET attestation=:sig WHERE id=:id AND attestation IS NULL` (no model write) + cache
evict + `STATUS=APPROVED`; edge adopt = per-edge stamp (simple) or whole-owner-set re-sign
(tide). Everything else goes to `IgaReplayDispatcher.replay` (`replay/IgaReplayDispatcher.java`),
which sets `IGA_REPLAY_ACTIVE=true`, runs the `doReplay` switch (rebuild `CREATE_*` from
`REP_JSON`; apply+stamp relationships), then `STATUS=APPROVED`.

The **one explicit `em.flush()`** (`:802-824`) is invitation-specific (`ORG_RESEND_INVITE`):
forces the DELETE of the old invitation before the INSERT of the new one to avoid a unique-key
violation (Hibernate otherwise orders INSERTs before DELETEs in a single flush).

---

## Quarantine (read-time enforcement)

Separate from the CR lifecycle: unsigned/unattested entities are enforced at **read time** in
the adapters (`IgaQuarantineCache`, `IgaUserAdapter.isEnabled` role/group fan-out, client
`isEnabled` REFUSE, scope-mapping STRIP). Managed by the toggle. Relevant when diagnosing
*"the entity exists but logs in disabled / its roles are missing from the token,"* as opposed
to a CR-lifecycle problem. (Not fully mapped here — read the quarantine classes if a diagnosis
hinges on it.)

---

## Modes & the Tide seam (be honest about this)

- **No runtime cryptographic Tide gate exists yet.** No `tide-vendor-key`/`signClaims()`
  detection drives commit. The commit gate is purely `requireApprover` + threshold.
- **Tideless** = `iga.attestor` unset/`simple`. The enforced, canonical mode.
- **Tide seam** = set realm `iga.attestor=tide` → the dummy `TideAttestor` (set-signing with
  a SHA-256 placeholder). Capture / CR model / authorize-commit gates are identical.
- **`IGA_ROLE_POLICY` table + `/iga/role-policies`** (`entities/IgaRolePolicyEntity.java`:
  `NAME`, `POLICY`, `POLICY_SIG`, `CONTRACT_ID`, `THRESHOLD`, …) are stored but **NOT enforced** — the
  Tide-mode scaffold, not a second threshold source. Do NOT wire `IGA_ROLE_POLICY.THRESHOLD`
  into the Tideless gate. These are **realm-level named policies** keyed by `(REALM_ID, NAME)`,
  NOT per-role (the `ROLE_ID` column was dropped in `iga-changelog-2.11.0.xml`). The reserved
  immutable name `tide-realm-admin` (`TideAttestor.TIDE_REALM_ADMIN_POLICY_KEY`) is the M0 admin
  policy. REST: list / get-by-id / get-by-name (`/iga/role-policies/name/{name}`) are
  authenticated-only; the `POST` upsert and the deletes are `manage-realm`-gated and refuse the
  reserved `tide-realm-admin` name with `403`. See `docs/qea-iga-api.md` section 8.
- **`first-admin-sign-preview`** (`POST /iga/change-requests/{id}/first-admin-sign-preview`,
  `IgaFirstAdminSignPreviewService`) resolves a CR to its full signing payload and **logs** it
  — a non-cryptographic preview. This is the documented integration point where a future Tide
  commit handler swaps `requireApprover`+threshold for `signClaims()` verification.
- `tidecloak-idp-extensions` owns the `tide-vendor-key` ComponentModel (Tide-mode marker for
  the crypto stack) and reads `isIGAEnabled`, but its old IGA wiring is a decoupled no-op.

---

## Config surface (operator-settable attributes)

| Attribute | Scope | Read at |
|---|---|---|
| `isIGAEnabled` ("true") | realm | `IgaChangeRequestService:47-50`; toggled via `tide-admin/toggle-iga` |
| `iga.attestor` (simple\|tide) | realm | `IgaAttestors.resolveAttestor:22` |
| `iga.threshold` (int ≥1) | realm + scope entity | `IgaScopeResolver:297` (realm); per-scope via collectors **only if same entity also sets `iga.approverRole`** |
| `iga.approverRole` (role name) | realm + scope entity | `IgaScopeResolver` collectors `:483/493/501` |
| `iga.scopeMode` (any\|all) | realm | `IgaScopeResolver.requireApproverInternal:238` |
| `iga.adopt.includeSystem` ("true") | realm | toggle-on scan — lifts the built-in skip |
| `iga.adopt.sidecarCap` (int) | realm | `IgaAdoptScan` |

---

## Diagnostic playbook (symptom → cause → check)

- **"My admin change returned 202 instead of applying."** Working as designed — IGA is
  enabled and the action was captured. Find the CR via the `Location` header (or
  `GET /iga/change-requests?status=PENDING`) and authorize→commit it.
- **"Commit returns 412."** Under threshold. Body has `threshold` and `authCount`. Get more
  distinct admins to authorize, or lower the threshold. Check resolution: per-scope max →
  realm `iga.threshold` → 1.
- **"Authorize/commit returns 403."** The admin lacks a required approver role. Body lists
  the required roles + mode. Either grant the admin a qualifying role, or fix the
  `iga.approverRole`/`iga.scopeMode` config.
- **"409 on authorize."** Either the CR isn't PENDING (already resolved/denied) or this admin
  already signed it. Distinct admins must sign.
- **"I set a per-entity `iga.threshold` but it's ignored."** THE GOTCHA — the same entity must
  also have `iga.approverRole`, else the threshold is dropped.
- **"Toggle-on created a flood of CRs."** That's the ADOPT scan attesting pre-existing state.
  Built-ins are skipped unless `iga.adopt.includeSystem=true`. If it 409'd, the sidecar cap
  was exceeded.
- **"Commit returned 404 ENTITY_VANISHED."** The ADOPT target was deleted out-of-band; the CR
  stays PENDING. Re-scan or deny the stale CR.
- **"Entity exists but logs in disabled / roles missing from token."** Not a CR-lifecycle
  issue — that's read-time quarantine of an unattested entity.

---

## Source map

`iga-core` module (`org.tidecloak.iga.*`):
- Capture: `providers/Iga{User,Role,Group,Client,ClientScope,Realm}{Provider,Adapter}.java`,
  `providers/IgaImportMode.java`, `providers/IgaChangeRequestService.java`
- CR entities: `entities/IgaChangeRequestEntity.java`, `entities/IgaAuthorizationEntity.java`,
  `entities/IgaRolePolicyEntity.java`, `entities/IgaUnsignedEntityEntity.java`;
  registration `jpa/IgaJpaEntityProvider.java`, changelog `META-INF/iga-changelog-master.xml`
- REST: `rest/IgaAdminResource.java`, `rest/IgaPendingApprovalExceptionMapper.java`,
  `rest/TideAdminCompatResource.java` (toggle)
- Resolution/attestor: `attestors/IgaScopeResolver.java`, `attestors/IgaAttestor*.java`,
  `attestors/IgaAttestors.java`, `attestors/SimpleNameAttestor.java`,
  `attestors/TideAttestor.java`, `attestors/TideSetResolver.java`
- Replay/ADOPT: `replay/IgaReplayDispatcher.java`, `replay/IgaReplayExtension.java`,
  `services/IgaAdoptScan.java`, `services/IgaSystemEntityFilter.java`,
  `services/IgaUnsignedEntityService.java`
- Tide seam: `services/IgaFirstAdminSignPreviewService.java`

Other repos:
- `tidecloak-override` — the `ATTESTATION` columns on ~14 KC entity tables the replay JPQL
  stamps (UserEntity/RoleEntity/GroupEntity/ClientEntity/ClientScopeEntity/CompositeRoleEntity/
  ClientScopeClientMappingEntity/ClientScopeRoleMappingEntity/ProtocolMapperEntity/
  ScopeMappingEntity/DefaultClientScopeRealmMappingEntity/UserRoleMappingEntity/
  UserGroupMembershipEntity/GroupRoleMappingEntity). OrganizationEntity has one too
  (ORG.ATTESTATION, iga-changelog-2.4.0): the org is a first-class node — stamped per-entity
  on CREATE/UPDATE/ADOPT_ORGANIZATION, domains covered by the node attestation (no ORG_DOMAIN
  column), and org membership stays governed by the user_group_membership edge.
- `tidecloak-idp-extensions` — defines `tide-vendor-key` component; reads `isIGAEnabled`
  (`VendorResource.java:1353`, legacy IGA wiring now no-op).
- Admin UI (separate) — consumes `/iga/*`; relies on the CR representation fields
  (`readyToCommit`, `threshold`, `requiredApproverRoles`, `scopeMode`, `authorizers`).
