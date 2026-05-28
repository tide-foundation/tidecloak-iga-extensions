# Extending IGA: contributor guide

> **Last updated:** 2026-05-21. Reflects Phases 1–7 as of commit `742c9eb`
> (branch `iga-approval-workflow`; Phase 7e docs refresh on top of Phase 7d
> backend HEAD). The operator/administrator companion is
> [`docs/IGA.md`](IGA.md).

Audience: developers extending the IGA approval workflow with a new
governed entity type, action, or capture seam.

## TL;DR — the mental model

```
caller
  │  POST /admin/realms/{r}/<thing>           (a privileged write)
  ▼
KC admin resource (RealmAdminResource / UsersResource / ...)
  │  invokes the model SPI
  ▼
RepresentationToModel.createX  (or equivalent)
  │  → IgaRealmProvider.addX  /  IgaUserProvider.addUser  /  IgaOrganizationProvider.create
  │     • single-entity: returns a CAPTURE-MODE adapter (super.addX first → em.find)
  │     • partial-import: same, PLUS IgaImportMode.registerImportX (batch)
  ▼
KC builds the entity end-to-end on that capture-mode adapter (real scratch
entity, persisted in the request tx).
  ▼
Terminal seam fires
  • single-entity: snapshot → write CR in runJobInTransaction (separate tx)
    → setRollbackOnly() on the REQUEST tx → throw IgaPendingApprovalException
  • partial-import: NO throw, NO setRollbackOnly; the row is deferred-harvested
    by BatchEmitTransaction.commit (registered via enlistPrepare on the nested
    import session)
  ▼
ExceptionMapper (single-entity) / BatchEmitTransaction (batch)
  │  scratch JPA tx is discarded (per-entity rollback OR scratch-import rollback)
  │  CRs survive because they were written in a SEPARATE, already-committed tx
  ▼
HTTP 202 + Location: /admin/realms/{r}/iga/change-requests/{id}

  ─── time passes; admins authorize, then commit ───

POST /admin/realms/{r}/iga/change-requests/{id}/commit
  │  IgaScopeResolver.requireApprover  (HTTP 403 if missing role)
  │  if authCount < threshold → HTTP 412 {error, threshold, authCount}
  ▼
IgaReplayDispatcher.replay
  │  sets IGA_REPLAY_ACTIVE = "true"  (every isIgaActive() returns false)
  ▼
Real KC model write (replayCreateX → RepresentationToModel.createX, ...)
  ▼
CR → APPROVED
```

**Three sentences:** Capture writes happen at the **model SPI** layer
(NOT a JAX-RS filter — see [lessons learned](#lessons-learned-with-receipts)).
The interceptor lets Keycloak build the entity end-to-end on a real
scratch model, then at a **terminal seam** snapshots it, writes a
`CREATE_*` change request in a **separate transaction**, and rolls the
request tx back (single-entity) or defers harvest to a batch tx
(partial-import). Replay at commit time re-drives the real model with the
session attribute `IGA_REPLAY_ACTIVE = "true"`, which makes every
`isIgaActive()` return `false` and therefore short-circuits any
re-capture.

## Sections

1. [Architecture overview](#architecture-overview)
2. [The `rowsJson` key contract](#the-rowsjson-key-contract)
3. [The replay side](#the-replay-side)
4. [The lossiness gotcha](#the-lossiness-gotcha)
5. [No clean terminal seam? (and why `enlistAfterCompletion` is a dead end)](#no-clean-terminal-seam-and-why-enlistaftercompletion-is-a-dead-end)
6. [Per-type capture-seam table](#per-type-capture-seam-table)
7. [Phase 4: `partialImport` batch governance](#phase-4-partialimport-batch-governance)
8. [Lessons learned (with receipts)](#lessons-learned-with-receipts)
9. [Recipe: add a new governed entity type](#recipe-add-a-new-governed-entity-type)
10. [Recipe: add a new governed action](#recipe-add-a-new-governed-action)
11. [Testing harness (`e2e/lib/kc.ts`)](#testing-harness-e2elibkts)
12. [Git hygiene and contribution checklist](#git-hygiene-and-contribution-checklist)
13. [Canonical example index](#canonical-example-index)
14. [Phase 6: retroactive ADOPT + quarantine — contributor notes](#phase-6-retroactive-adopt--quarantine--contributor-notes)
15. [Recipe: add a new ADOPT-able entity type](#recipe-add-a-new-adopt-able-entity-type)
16. [Phase 7: organization governance — contributor notes](#phase-7-organization-governance--contributor-notes)
    - [Wire-up lessons (the Phase 7a discoveries)](#wire-up-lessons-the-phase-7a-discoveries)
    - [`attestation` column on `OrganizationEntity`](#attestation-column-on-organizationentity)
    - [IdP-aware scope merge (Phase 7d)](#idp-aware-scope-merge-phase-7d)
    - [SMTP-tolerance pattern (Phase 7a/b)](#smtp-tolerance-pattern-phase-7ab)
    - [`getOrganizationsResource` REST sub-path conventions](#getorganizationsresource-rest-sub-path-conventions)
    - [Quarantine cascade pattern (Phase 7c)](#quarantine-cascade-pattern-phase-7c)

---

## Architecture overview

IGA does **NOT** use a JAX-RS request filter to capture the admin's
intent. That approach was tried and is provably dead (see
[Lessons learned](#lessons-learned-with-receipts) and the
`IgaRepresentationCaptureFilter.java` class javadoc). Capture happens
entirely at the **model SPI layer**.

For a CREATE of an entity type `X`:

1. **`IgaRealmProvider` (or the relevant provider) returns a
   capture-mode adapter from `addX`.** `IgaRealmProvider.addClient` /
   `addRealmRole` / `addClientRole` / `createGroup`
   (`iga-core/.../providers/IgaRealmProvider.java`) call `super.addX(...)`
   to create the **real (scratch) entity**, `em.find(...)` it, and return
   an `Iga*Adapter` constructed with `captureMode = true`. Organizations
   do the same in `IgaOrganizationProvider.create` returning an
   `IgaOrganizationModel` with `captureCreate = true`.

2. **Keycloak applies the COMPLETE incoming representation to that
   scratch entity.** Because the adapter is a real, persisted model in
   capture mode, Keycloak's own builder
   (`RepresentationToModel.createClient`,
   `RoleContainerResource.createRole`, `GroupResource.updateGroup`,
   `RepresentationToModel.toModel` for orgs) sets every admin-supplied
   field on it. The capture-mode adapter's per-setter overrides are inert
   in this mode: each `isIgaActive()` returns `false` when
   `captureMode == true`, so they all fall through to `super`.

3. **At a terminal seam — the last unconditional model call in
   Keycloak's create path — the adapter snapshots and vetoes.** It:
   - snapshots the now-complete model via
     `ModelToRepresentation.toRepresentation(...)`,
   - writes the `CREATE_*` change request (with the full representation
     as `REP_JSON` in `rowsJson`) using
     `KeycloakModelUtils.runJobInTransaction(...)` — a SEPARATE Keycloak
     session/transaction that commits independently and therefore
     SURVIVES the rollback,
   - calls `session.getTransactionManager().setRollbackOnly()` on the
     REQUEST transaction so the scratch entity is discarded,
   - throws `IgaPendingApprovalException`.

   See the [per-type capture-seam table](#per-type-capture-seam-table)
   for the exact terminal seam per entity.

4. **The exception is mapped to HTTP 202 + a `Location` header.**
   `IgaPendingApprovalExceptionMapper`
   (`iga-core/.../rest/IgaPendingApprovalExceptionMapper.java`) returns
   `Response.status(ACCEPTED)` with the `{status:"PENDING",
   changeRequestId, entityType, actionType, message}` body (lines
   36-61) and a synthetic `Location:
   /admin/realms/{realm}/iga/change-requests/{id}` header (lines 53-58)
   so automation can poll the CR. The realm is recovered from the
   request `UriInfo` (lines 71-96), so the model-layer throw sites need
   not carry it.

### Why the rollback is sound (request-tx lifecycle)

Mapping `IgaPendingApprovalException` to a 202 fully CONSUMES it — it
does NOT propagate to `DefaultKeycloakSession#close()`. So the request
tx would otherwise be `commit()`ed and leak the scratch entity. The
explicit `getTransactionManager().setRollbackOnly()` is what flips that:
`DefaultKeycloakSession#close()` calls `closeTransactionManager()`,
which does `if (transactionManager.getRollbackOnly()) rollback(); else
commit();`. With the flag set, `rollback()` runs and every row
Keycloak's builder produced for the scratch entity is discarded. The
202 still stands because the mapper built the response before
`CloseSessionFilter` runs, and `rollback()` cannot escalate to a 500.
This is exactly the idiom `KeycloakErrorHandler#getResponse` uses
(set-rollback-only then return a response) — here applied to a 2xx.

The full, traced proof lives in `IgaClientAdapter.updateClient`
(lines 196-234) and is referenced by every other capture seam.

For **partialImport** the rollback is different — see
[Phase 4](#phase-4-partialimport-batch-governance).

---

## The `rowsJson` key contract

The authoritative contract is the class javadoc at the top of
`iga-core/.../replay/IgaReplayDispatcher.java`. Read it before you
choose keys. There is **no legacy/old-format fallback** — pending CRs
that do not follow the contract are intentionally discarded.

Key rules (verbatim from that javadoc):

- `ID` — the affected row's OWN primary key (UUID). Always.
- `REALM_ID` — realm UUID, where applicable.
- `CLIENT_UUID` — a *referenced* client's UUID (resolve via
  `session.clients().getClientById(realm, uuid)`).
- `CLIENT_ID` — a *referenced* client's HUMAN identifier (e.g.
  `my-app`), NEVER a UUID. This is the single explicit exception to the
  "`*_ID` keys hold a UUID" rule; it exists because it matches
  Keycloak's `CLIENT.CLIENT_ID` column, which is the human client id.
- `CLIENT_SCOPE_ID`, `USER_ID`, `ROLE_ID`, `GROUP_ID` — referenced
  entity UUIDs.
- Human names `USERNAME` / role `NAME` / group `NAME` / scope `NAME` —
  unchanged.
- `REP_JSON` — for every `CREATE_*` action, the full Keycloak
  representation serialized as a JSON string.
- Organizations are keyed by name on create (`ORG_NAME` / `ORG_ALIAS`)
  because the org SPI cannot pin an id on create; by `ORG_ID` for
  update/delete/member actions.

The client resolver `resolveClient` in `IgaReplayDispatcher` encodes the
human-vs-uuid rule: it tries `CLIENT_UUID` → `getClientById`, then falls
back to `CLIENT_ID` → `getClientByClientId`. **Never read a UUID out of
`CLIENT_ID`.**

> **Important**
> The single most important rule: the capture site must write EXACTLY
> the keys the matching `replayCreate*` / `*Direct` reads. They are two
> halves of one contract in two files; a mismatch fails loudly on replay
> by design.

Worked example — `IgaRoleAdapter.getName()` writes:

```java
Map<String, Object> row = new LinkedHashMap<>();
row.put("ID", roleId);
row.put("NAME", roleName);
row.put("REALM_ID", realm.getId());
row.put("CLIENT_ROLE", clientRole);
if (clientRole) {
    if (captureClientUuid != null) row.put("CLIENT_UUID", captureClientUuid);
    if (captureClientId != null)   row.put("CLIENT_ID", captureClientId);
    row.put("CLIENT_REALM_CONSTRAINT", realm.getId());
}
row.put("REP_JSON", repJson);
```

`replayCreateRole` reads exactly `ID`, `NAME`, `CLIENT_ROLE`, `REP_JSON`,
and (for client roles) resolves the owning client via `resolveClient(...)`
— i.e. `CLIENT_UUID` first.

---

## The replay side

On commit, `IgaReplayDispatcher.replay(...)` sets the session attribute
`IGA_REPLAY_ACTIVE = "true"` and dispatches on `cr.getActionType()`
through a single `switch`. Each `CREATE_*` case calls a `replayCreate*`
method that:

1. resolves identity from the contract keys,
2. calls the **real** id-bearing model `add*` (e.g.
   `session.roles().addRealmRole(realm, id, name)`), which lands back in
   `IgaRealmProvider.addX` but, under `IGA_REPLAY_ACTIVE`, returns a
   non-capture adapter that delegates to `super` (no re-interception),
3. if `REP_JSON` is present, rebuilds the full entity by replaying
   Keycloak's own create logic — for client it calls
   `RepresentationToModel.createClient(session, realm, rep)`; for role
   it replays description/attributes/composites manually, mirroring
   exactly what `RoleContainerResource.createRole` does,
4. stamps the final attestation with a JPQL `UPDATE`.

**The `IGA_REPLAY_ACTIVE` bypass is structural.** Every `isIgaActive()`
(and `IgaRealmProvider.isIgaActive`, `IgaUserAdapter.isIgaActive`, etc.)
returns `false` when the session attribute equals `"true"`.
Capture-mode adapters are additionally inert because
`captureMode → isIgaActive() == false`. Any new interception you add
MUST honor this so replay can re-drive the real model without
re-capturing.

> **Note**
> Replay should NOT need changes when you add a new captured type, IF
> the captured representation matches what an existing `replayCreate*`
> already deserializes. Client/group/role/client-scope replay already
> feed `REP_JSON` through Keycloak's own builders. Only add a
> dispatcher case if the type is genuinely new.

`IgaReplayDispatcher.java` is **byte-unchanged** from commit
`d785326` (post-Phase-6a baseline — the BASELINE_APPROVAL stamping step
was removed in `742f944`; that single deletion is the only diff
between `742f944` and `d785326`, and the dispatcher has been frozen at
`d785326` ever since). Phase 6's ADOPT_* replay lives in a separate
`IgaReplayExtension` routed BEFORE the dispatcher's switch — see
[Phase 6 contributor notes](#phase-6-retroactive-adopt--quarantine--contributor-notes).
Verify with:

```bash
git diff --quiet d785326 HEAD -- \
  iga-core/src/main/java/org/tidecloak/iga/replay/IgaReplayDispatcher.java
```

---

## The lossiness gotcha

`ModelToRepresentation.toRepresentation(...)` does NOT serialize every
field of the model. The snapshot is lossy for relationships/secrets
that the representation builder deliberately omits. Verified examples:

- **`RoleModel` composites are dropped.**
  `ModelToRepresentation.toRepresentation(RoleModel)` (KC 26.5.5
  `ModelToRepresentation.java:424`) sets only
  `rep.setComposite(role.isComposite())` (the boolean) and NEVER
  `rep.setComposites(...)`. The method body calls
  `setName` / `setDescription` / `setComposite(role.isComposite())` and
  `return rep` — no `setComposites`.
- **`UserModel`** — credentials and group/role mappings are not in the
  user representation snapshot (consistent with KC's brief user rep;
  *verify the exact omitted set against the KC version in use if you add
  USER fields*).

> **Warning**
> For any field the snapshot drops, the capture-mode adapter must
> intercept the specific model call(s) that carry it and merge the
> result into the snapshot **before** serialization.

### Worked example: role composites

`IgaRoleAdapter` overrides `addCompositeRole` so that, in capture mode,
it records each composite child's identity in the **exact shape**
`replayCreateRole` resolves:

```java
@Override
public void addCompositeRole(RoleModel role) {
    if (captureMode) {
        if (role != null) {
            if (role.isClientRole()) {
                String childClientId = null;
                ClientModel owning = realm.getClientById(role.getContainerId());
                if (owning != null) childClientId = owning.getClientId(); // HUMAN clientId
                if (childClientId != null) {
                    capturedClientComposites
                        .computeIfAbsent(childClientId, k -> new ArrayList<>())
                        .add(role.getName());
                }
            } else {
                capturedRealmComposites.add(role.getName());   // realm-role NAME
            }
        }
        super.addCompositeRole(role); // pass through: real scratch link, discarded on rollback
        return;
    }
    ...
}
```

Then at the terminal seam, after the base snapshot, it folds the
recorded composites back in — exactly the structure `replayCreateRole`
consumes (`Composites.realm` = set of realm-role NAMES;
`Composites.client` = map of HUMAN clientId → list of role names).

When you add a new type, audit which fields its
`ModelToRepresentation.toRepresentation` overload omits, and intercept
exactly those model calls in capture mode.

---

## No clean terminal seam? (and why `enlistAfterCompletion` is a dead end)

The seam must be the **last unconditional model call** Keycloak makes in
the create path, so that when it fires the model is fully built. Client,
group, client-scope and org each have a clean *unconditional last
mutating* call (`updateClient()` / `setDescription()` / `getId()` /
`setDomains()`). **Role does not.**

Verified against `RoleContainerResource.createRole` (KC 26.5.5):

```
167  RoleModel role = roleContainer.addRole(rep.getName());  // -> IgaRealmProvider.add*Role
168  role.setDescription(rep.getDescription());              // UNCONDITIONAL but NOT last
~170 for (...) role.setAttribute(k, v);                      // conditional (attributes != null)
~199 realmRoles ... forEach(role::addCompositeRole);         // conditional (composite present)
~220 clientRoles ... forEach(role::addCompositeRole);        // conditional
225  adminEvent...resourcePath(uriInfo, role.getName())...   // role.getName() UNCONDITIONAL, LAST
227  return Response.created(... role.getName() ...);         // role.getName() again
```

`setDescription` fires first; the attribute loop and the composite loops
are all conditional. There is **no unconditional last *mutating* call**.
The chosen seam is therefore the **getter** `role.getName()` at line
225 — the first and only `getName()` in `createRole`, UNCONDITIONAL and
strictly AFTER setDescription, the attribute loop and the composite
loops, so the model is fully built for both composite and non-composite
roles. It is guarded by a fire-once flag (`captureEmitted`,
`IgaRoleAdapter.java:142-143, 189-194`) so the second `getName()` at
line 227 and any defensive re-entrancy do not re-emit.
`RoleAdapter.setDescription` / `setAttribute` / `addCompositeRole` never
call `getName()` internally, so the seam cannot fire prematurely.

> **Rule of thumb.** When there is no unconditional last *mutating*
> call, choose the first UNCONDITIONAL call (getter or setter) that is
> provably AFTER every conditional mutation in Keycloak's create path,
> and protect it with a fire-once guard so it emits exactly once.

### Why a request-completion synchronization is NOT viable in KC 26.5.5

A natural-looking alternative is to enlist an `afterCompletion`
synchronization (`DefaultKeycloakTransactionManager#enlistAfterCompletion`)
and do the snapshot/veto there. **This is unsound and contributors must
not repeat it.** Verified against
`DefaultKeycloakTransactionManager.commit()` (KC 26.5.5
`DefaultKeycloakTransactionManager.java:114`):

```
commit():
  for tx in prepare:        commitWithTracing(tx)         // first
  for tx in transactions:   commitWithTracing(tx)         // main list — COMMITS HERE
  if no exception:
      for tx in afterCompletion: commitWithTracing(tx)    // ONLY AFTER the above
```

The request `JpaKeycloakTransaction` (enlisted by
`DefaultJpaConnectionProviderFactory`) is in the main `transactions`
list. It is committed **before** the `afterCompletion` list is iterated.
So an `afterCompletion` hook (a) cannot veto the already-committed
scratch entity — it is already in the DB — and (b) runs at session
close, far too late to turn the response into a 202.

`enlistPrepare`, on the other hand, runs in the **prepare** loop —
strictly BEFORE the main list. That is what Phase 4 uses for
`BatchEmitTransaction` (see next section).

---

## Per-type capture-seam table

Cite this table when wiring a new type — it shows exactly which terminal
seam each entity uses and why.

| Entity | Terminal seam | KC call site (rationale) | Notes |
|--------|---------------|---------------------------|-------|
| Role | `IgaRoleAdapter.getName()` (`:187-292`) | `role.getName()` at `RoleContainerResource.createRole` line 225 | No unconditional last mutating call → provably-last unconditional getter + fire-once guard. Composites merged via `addCompositeRole` override (lossy snapshot). |
| Client scope | `IgaClientScopeAdapter.getId()` | First `getId()` after KC sets `name` on the scope — guarded by a "setName-observed" flag, accumulates rep before seam. | Replay rebuilds via `RepresentationToModel`. |
| Group | `IgaGroupAdapter.setDescription(String)` (`:127-194`) | `model.setDescription(rep.getDescription())` at `GroupResource.updateGroup` — final unconditional mutating call. | Single-entity path only. PartialImport uses the deferred-harvest accumulator (see Phase 4). |
| Client | `IgaClientAdapter.updateClient()` (`:181-234`) | `client.updateClient()` at `RepresentationToModel.createClient` line 404 (final unconditional mutation, after `updateClientProperties` / protocol-mapper rebuild / `updateClientScopes`). | **Eager-harvest** since Phase 4 CME fix — see [lesson 3](#lesson-3-storefactorycachesession-enlistprepare-gotcha-phase-4-cme). |
| Organization | `IgaOrganizationModel.setDomains(...)` (`:121-198`) | `model.setDomains(...)` at `RepresentationToModel.toModel` — final unconditional mutating call. | Same seam serves CREATE and UPDATE. |
| User | `IgaUserAdapter.getId()` with a **StackWalker emit predicate** | Immediate caller must be `org.keycloak.services.resources.admin.UsersResource#createUser` (skip all `IgaUserAdapter` frames and `UserAdapter` equals/hashCode/getId reentrancy). | The `getId()` method is called from many KC sites; the StackWalker scopes the emit to the single admin-resource invocation. PartialImport's 5-arg local-storage `addUser` is separately governed via `IgaImportMode.registerImportUser`. |

---

## Phase 4: `partialImport` batch governance

Phase 4 closes the multi-entity gap: a `POST
/admin/realms/{realm}/partialImport` can carry several governed types in
one body, and KC drives the whole import inside a **nested**
`KeycloakSession` via `KeycloakModelUtils.runJobInTransactionWithResult`.
Single-entity seams would (a) abort the whole import on the first
captured entity, and (b) miss the 5-arg local-storage `addUser` seam
that `DefaultExportImportManager.createUser` uses — leaving partialImport
users **ungoverned**.

### Detection

`IgaImportMode.isImportMode(session, realm)`
(`IgaImportMode.java:223-234`) returns `true` iff:

1. IGA is enabled for the realm (and not `master`),
2. `IGA_REPLAY_ACTIVE` is not `"true"` (commit-time replay is a
   single-entity tx, not a partialImport),
3. and the current stack contains any of:
   - `RealmAdminResource#partialImport` frame, **or**
   - `org.keycloak.partialimport.PartialImportManager` frame, **or**
   - any class under `org.keycloak.partialimport.*` /
     `org.keycloak.exportimport.util.*`.

That predicate is the discriminator every per-type `addX` import branch
uses.

### `BatchEmitTransaction` (the prepare-tx hook)

The accumulator (`IgaImportMode.Accumulator`) holds the per-import
pending CRs and the registered deferred-harvest adapters (users, groups,
roles, clients, client-scopes). The first time an entity is accumulated,
IGA enlists a `BatchEmitTransaction` on the nested import session via
`KeycloakSession.getTransactionManager().enlistPrepare(...)`
(`IgaImportMode.java:256-258`).

Why **prepare**, not main or afterCompletion? Source-proven in the
`IgaImportMode` class javadoc against
`DefaultKeycloakTransactionManager.commit()` (KC 26.5.5):

- `commit()` iterates the `prepare` list **first** (`:124-130`).
- Then the main `transactions` list (`:135-141`) — this is where the
  scratch JPA transaction lives.
- Only if no exception was raised, the `afterCompletion` list runs
  (`:154+`).
- If a prepare-tx's `commit()` throws (which
  `BatchEmitTransaction.commit` does), the exception is captured
  (`:127-128`), `if (exception != null) { rollback(exception); return;
  }` (`:131-134`), and `rollback(RuntimeException)` rolls back ALL main
  `transactions` (`:190-196` → `JpaKeycloakTransaction.rollback()` →
  scratch JPA discarded) and rethrows.

The rethrow propagates out through `DefaultKeycloakSession#close()` → the
try-with-resources in `runJobInTransactionWithResult` → out of
`partialImport` → JAX-RS → `IgaPendingApprovalExceptionMapper` → 202.

> **Critical constraint** (from `IgaImportMode.java:74-80`). In import
> mode capture seams MUST NOT call `setRollbackOnly()` on the nested
> session — `closeTransactionManager` checks `getRollbackOnly()` BEFORE
> deciding commit-vs-rollback, and the rollback path **never iterates
> the prepare list**, so a stray `setRollbackOnly()` would skip
> `BatchEmitTransaction.commit` and silently drop the batch. The
> prepare-tx's own throw is what causes the discard.

### Deferred-harvest accumulator

Per-type adapters that need post-build access to the live model register
with the accumulator (`pendingUsers`, `pendingGroups`, `pendingRoles`,
`pendingClients`, `pendingClientScopes`). `BatchEmitTransaction.commit`
walks each list and calls `buildImport<X>PendingCr()` to harvest the
row — by that point KC's import logic has finished applying every
setter to the pass-through scratch model.

```java
for (IgaUserAdapter u : acc.pendingUsers) {
    PendingCr cr = u.buildImportUserPendingCr();
    if (cr != null) acc.pending.add(cr);
}
// ... groups, roles, clients, clientScopes
```

The deferred harvest is per-type lazy by default. **Client is the
exception** — see [lesson 3](#lesson-3-storefactorycachesession-enlistprepare-gotcha-phase-4-cme).

### Batch CR shape

The whole batch is emitted as **N per-type CRs** in one independent
`runJobInTransaction`. The 202 carries **the first CR id** in the batch,
with `entityType = "BATCH"` and `actionType = "PARTIAL_IMPORT"`
(`IgaImportMode.java:584-585`):

```java
throw new IgaPendingApprovalException(firstCrId, "BATCH", "PARTIAL_IMPORT");
```

The E2E spec `e2e/tests/phase4-multientity-governance.spec.ts` asserts
this envelope shape (lines 466-486). Approvers authorize and commit
each per-type CR independently.

> **Note on rollback semantics.** In Phase 4 the **whole nested
> import transaction is the veto**. There is no per-entity
> capture-suppression — every capture-mode adapter is still built and
> KC still applies every field to it; the rollback is what discards
> them all atomically. Single-entity seams that throw mid-flow would
> instead abort the import after the first entity; that is precisely
> why import-mode branches skip the throw.

### KC's `groupRep.path` precondition (vanilla KC, not IGA)

> **Important**
> KC 26.5.5 requires `groupRep.path` on every group representation in a
> `partialImport` payload. `GroupsPartialImport.getModelId`
> (`GroupsPartialImport.java:53`) is
> `findGroupModel(realm, groupRep).getId()`; the inner helper guards
> `if (path == null) return null;` and KC then dereferences the null →
> `NullPointerException` → HTTP 500. This is a KC contract, not an IGA
> constraint. Always populate `path` on every group rep in the payload.

The same applies to E2E tests: see
`e2e/tests/phase4-multientity-governance.spec.ts:148`. **First
diagnostic step** when a KC-side error appears on an IGA-governed path:
send the same payload to an **IGA-disabled** realm. If it still NPEs at
`GroupsPartialImport.java:53`, it is the KC contract.

### `ClientScopesPartialImport` is not registered in KC 26.5.5

> **Note**
> KC 26.5.5 `PartialImportManager` registers handlers for
> Clients/Roles/IdPs/IdP-mappers/Groups/Users only — no
> `ClientScopesPartialImport`. So `CREATE_CLIENT_SCOPE` rows are not
> produced by any current `partialImport` payload, and
> `IgaImportMode.pendingClientScopes` stays empty under partialImport
> today. The IGA `addClientScope` import branch is **defensive parity**
> — it auto-activates if a future KC adds the handler. Keep that
> branch in lock-step with `addClient` (same predicate, same emit
> contract).

---

## Lessons learned (with receipts)

These are concrete pitfalls a future contributor WILL hit if they don't
read this. Each one comes from a verifiable commit in this history.

### Lesson 1: provider-jar JAX-RS request filters do not work in Quarkus KC 26.5.5

> **Warning**
> A `@Provider ContainerRequestFilter` shipped in a provider jar is
> **never invoked** in Quarkus-mode Keycloak. Quarkus indexes providers
> from build-time Jandex; runtime provider jars load via KC's
> `ProviderManager` classloader outside the Quarkus app-archive scan
> RESTEasy uses to discover request/response filters, so the filter is
> never registered.
>
> `ExceptionMapper` IS discovered (that is why the 202 mapping works).
>
> Capture must be at the **model SPI layer**.

Receipt: `IgaRepresentationCaptureFilter.java` class javadoc; the file
is kept as a documented dead shim that always returns `null` from
`pendingRepJson` (lines 73-75). Do not resurrect it.

### Lesson 2: `ModelToRepresentation` is lossy — accumulate intercepted calls

See [The lossiness gotcha](#the-lossiness-gotcha). Concrete fields
verified dropped: `RoleRepresentation.composites`, user credentials,
user group/role mappings.

> **Warning**
> Audit which fields the `ModelToRepresentation.toRepresentation(X)`
> overload omits for any new type. Intercept exactly those setters in
> capture mode and fold the captured state back into the snapshot
> before `MAPPER.writeValueAsString(rep)`.

### <a id="lesson-3-storefactorycachesession-enlistprepare-gotcha-phase-4-cme"></a> Lesson 3: `StoreFactoryCacheSession.enlistPrepare` gotcha (Phase 4 CME)

> **Warning**
> `ModelToRepresentation.toRepresentation(ClientModel, session)` lazily
> constructs `StoreFactoryCacheSession` via
> `session.getProvider(AuthorizationProvider.class)`. Its constructor
> **unconditionally** `enlistPrepare`s on the session's transaction
> manager. If this happens DURING `TM.commit()`'s prepare iteration
> (e.g. inside `BatchEmitTransaction.commit()`), it mutates the very
> `LinkedList` the iterator is walking → `ConcurrentModificationException`.

This was the root cause of the Phase 4 CME fixed in commit `045ac7a`.
Receipts:

- `IgaClientAdapter.java:181-234` — the `updateClient()` override now
  performs **eager harvest** at the terminal create-stack seam
  (`RepresentationToModel.createClient`'s final `client.updateClient()`,
  KC 26.5.5 line 404). At that point `toRepresentation` is invoked while
  the request tx is still in its "main" lifecycle — NOT inside a prepare
  iteration — so `StoreFactoryCacheSession.<init>` can safely
  `enlistPrepare`.
- `IgaImportMode.java:516-529` — the batch-emit loop for clients is
  reduced to a no-op `buildImportClientPendingCr()` that returns the
  already-captured row.

Per-type audit (from commit `045ac7a`'s PM report): only `ClientModel`'s
`toRepresentation` lazy-constructs `StoreFactoryCacheSession`. Users,
groups, roles, client-scopes do not, so they remain on the **lazy**
deferred-harvest path. Apply the same audit when adding a new type:

```
Does this type's `ModelToRepresentation.toRepresentation(X, session)`
call `session.getProvider(AuthorizationProvider.class)` (directly or
transitively)?
  • Yes → EAGER harvest at the create-stack seam, like client.
  • No  → LAZY harvest in BatchEmitTransaction.commit, like users/groups/roles.
```

### Lesson 4: KC `partialImport` requires `groupRep.path` (vanilla KC bug, not IGA)

> **Warning**
> Group reps without `path` NPE at KC's `GroupsPartialImport.java:53`,
> **regardless of whether IGA is enabled**.

Receipt: commit `49f8c4f` ("phase 4 fix: pathless group payload is a
vanilla-KC defect, not an IGA capture-mode bug — fix E2E payload,
sharpen log") and `e2e/tests/phase4-multientity-governance.spec.ts:148`.

> **Diagnostic first step.** When a KC-side error appears on an
> IGA-governed path, **send the same payload to an IGA-disabled realm**
> first. If it still fails the same way, it is a KC contract issue and
> not an IGA bug.

### Lesson 5: no `ClientScopesPartialImport` in KC 26.5.5

> **Note**
> KC 26.5.5's `PartialImportManager` does not register a
> `ClientScopesPartialImport`, so `addClientScope` is never reached via
> the partialImport endpoint today.

Receipt: the per-type source set under
`services/.../partialimport/` contains no `ClientScopesPartialImport.java`,
and `PartialImportManager.java:47-52` registers only
Clients/Roles/IdPs/IdP-mappers/Groups/Users. The IGA `addClientScope`
import branch is wired for forward compatibility; do not remove it.

### Lesson 6: KC declarative UserProfile drops undeclared attributes

> **Warning**
> Custom user attributes must be **declared** in the realm user-profile
> configuration or KC silently strips them on create.

Receipt: `e2e/lib/kc.ts:declareUserProfileAttribute` (lines 547-588) is
the helper every Phase 3 user-rep test calls before creating users.
Without it the captured `UserRepresentation.attributes` does not
contain the test's attribute, and the CR comparison fails.

> **Procedure (operator + test).**
>
> 1. Read the realm's user-profile config:
>    `GET /admin/realms/{realm}/users/profile`.
> 2. Add the attribute under `.attributes[]` with the desired
>    `permissions` and `validations`.
> 3. PUT the modified config back to
>    `/admin/realms/{realm}/users/profile`.
> 4. Then create users — KC will now keep the attribute.

---

## Recipe: add a new governed entity type

Use **role** and **client** as worked examples (`IgaRealmProvider.addRealmRole`,
`IgaRealmProvider.addClient`).

**Procedure**

1. **Identify Keycloak's terminal create-call seam from
   `RepresentationToModel.createX`.** Find the admin REST resource that
   creates the type and the model builder it runs (KC 26.5.5
   `RepresentationToModel.createClient` line 347-404,
   `RoleContainerResource.createRole`,
   `GroupResource.updateGroup`, `RepresentationToModel.toModel`).
   Identify the last UNCONDITIONAL model call (preferring a mutating
   call; fall back to a provably-last unconditional getter + fire-once
   guard, per
   [Rule of thumb](#no-clean-terminal-seam-and-why-enlistaftercompletion-is-a-dead-end)).

2. **Override `realm.addX` (or the equivalent provider entry point) in
   `IgaRealmProvider`.** Provide both branches:
   - **Single-entity** under `isIgaActive(realm)`: call `super.addX(...)`
     to create the real scratch entity, `em.find(...)` it, return an
     `Iga*Adapter` with `captureMode = true`.
   - **Batch** under `IgaImportMode.isImportMode(session, realm)`: same
     setup, then `IgaImportMode.registerImport<Type>(session, realm,
     adapter)` and return the adapter. **NO throw, NO
     `setRollbackOnly()`** on the import path.

3. **Implement the capture-mode adapter (mirror `IgaClientAdapter` /
   `IgaGroupAdapter` for shape).**
   - `isIgaActive()` returns `false` when `captureMode` (so all
     per-setter overrides pass through to `super` and Keycloak builds
     the full model).
   - Override the terminal seam: snapshot via
     `ModelToRepresentation.toRepresentation(...)`, merge any lossy
     fields (see [The lossiness gotcha](#the-lossiness-gotcha)), call
     `buildCaptured<Type>Row(...)`, write the `CREATE_*` CR via
     `KeycloakModelUtils.runJobInTransaction(...)`, call
     `session.getTransactionManager().setRollbackOnly()`, then
     `throw new IgaPendingApprovalException(crId, "<TYPE>",
     "CREATE_<TYPE>")`.
   - Add `buildImport<Type>PendingCr()` returning an
     `IgaImportMode.PendingCr` for the deferred-harvest path (or, for
     eager-harvest types like client, return the already-captured row).
   - If a lossy relationship exists, also override the model call(s)
     that carry it to record it in capture mode (role's
     `addCompositeRole`).

4. **Decide harvest timing** (Phase 4 lesson):
   - **Lazy** at `BatchEmitTransaction.commit` if the type's
     `toRepresentation` is pure JPA reads.
   - **Eager** at the create-stack terminal seam if it triggers any
     provider lookup that `enlistPrepare`s (e.g. anything that touches
     `AuthorizationProvider` like client does — see
     [Lesson 3](#lesson-3-storefactorycachesession-enlistprepare-gotcha-phase-4-cme)).

5. **Pick `rowsJson` keys per the contract**
   (see [The `rowsJson` key contract](#the-rowsjson-key-contract)): `ID`
   = own UUID, `NAME` / human id, `REALM_ID`, referenced entities by
   their contract keys, `REP_JSON` = the full serialized representation.

6. **Wire the batch path:**
   - Add `pendingX` list + `registerImportX(...)` to
     `IgaImportMode.Accumulator` and `IgaImportMode` (mirror
     `registerImportClient`).
   - Extend `BatchEmitTransaction.commit`'s harvest loop to walk the new
     `pendingX` list and call `buildImport<Type>PendingCr()`.

7. **Confirm an existing `replayCreate*` consumes it, or add a
   dispatcher case.** If `REP_JSON` is a representation Keycloak's own
   builder can rebuild (as for client/role/group/client-scope), an
   existing replay path likely already handles it. Only if the type is
   genuinely new: add a `case "CREATE_<TYPE>" ->
   replayCreate<Type>(...)` to the `switch` in
   `IgaReplayDispatcher.doReplay` and write `replayCreate<Type>`
   mirroring Keycloak's create logic faithfully.

   > **Important — `IgaReplayDispatcher` is byte-unchanged from
   > `742f944`.** If your change requires modifying the dispatcher,
   > flag it explicitly in the PR and re-run the full E2E suite. Verify
   > with `git diff --quiet 742f944 HEAD --
   > iga-core/src/main/java/org/tidecloak/iga/replay/IgaReplayDispatcher.java`.

8. **Honor `IGA_REPLAY_ACTIVE` inertness.** Every interception you add
   must no-op when the session attribute is `"true"` so replay
   re-drives the real model without re-capturing.

9. **Scoping / thresholds.** Add the new `CREATE_<TYPE>` (and any
   per-entity actions on it) to the `switch` in
   `IgaScopeResolver.resolve(...)` (`IgaScopeResolver.java:65-171`).
   Top-level `CREATE_*` are realm-wide and intentionally fall to the
   `default:` empty scope. Per-entity actions resolve scope from the
   parent via the `resolve*ScopesFromRows(...)` helpers; add a
   `resolve<Type>ScopesFromRows` if the type carries
   `iga.approverRole` / `iga.threshold` attributes (model the new
   helper on `resolveOrganizationScopesFromRows`).

   > **Remember the
   > [coupling rule](IGA.md#warning-the-approver-role--threshold-coupling-rule):**
   > `addThreshold(...)` runs only under the
   > `iga.approverRole != null && !isBlank()` branch in every collector.
   > If your new type's scope collector mirrors that pattern (as it
   > should), a per-entity `iga.threshold` set alone will be silently
   > ignored. Make sure docs and UI surface the pairing requirement.

10. **Add an E2E spec.** Follow the existing precondition-gate pattern
    (`e2e/tests/phase4-multientity-governance.spec.ts` is the
    canonical example). Payload conforms to KC's
    `<Type>PartialImport.getModelId` contract for the partialImport
    path. Run the full suite; current expected count is **12 passed**.

11. **Verify byte-unchanged dispatcher:**

    ```bash
    git diff --quiet 742f944 HEAD -- \
      iga-core/src/main/java/org/tidecloak/iga/replay/IgaReplayDispatcher.java
    ```

---

## Recipe: add a new governed action

Use an existing simple relationship action as the template:
`USER` `GRANT_ROLES` (`IgaUserAdapter.grantRole`).

**Procedure**

1. **Pick the adapter method to intercept.** Find the inline-mode model
   method that performs the mutation (e.g.
   `UserModel.grantRole(RoleModel)`). Override it in the relevant
   `Iga*Adapter`; gate on `isIgaActive()` and call `super` when inactive:

   ```java
   @Override
   public void grantRole(RoleModel role) {
       if (!isIgaActive()) { super.grantRole(role); return; }
       IgaChangeRequestService service = getService();
       String userId = getId();
       checkNoPendingCr(service, userId);              // one-pending-CR-per-entity
       service.create(realm, "USER", userId, "GRANT_ROLES",
               List.of(Map.of("USER_ID", userId, "ROLE_ID", role.getId())),
               getCurrentUserId());
   }
   ```

   This is a **delta** action: it records the CR via `service.create(...)`
   and returns; it does NOT throw (the inline relationship pattern).
   Attribute actions that must interrupt the write (e.g.
   `SET_*_ATTRIBUTE`) follow the same shape; the create-entity actions
   are the only ones that throw `IgaPendingApprovalException`.

2. **Choose the `rowsJson` row shape per the contract.** For
   `GRANT_ROLES`: `{ "USER_ID": <user uuid>, "ROLE_ID": <role uuid> }`.
   Use the canonical key names (`USER_ID`, `ROLE_ID`, `GROUP`,
   `CLIENT_UUID`, ...) — the replay JPQL and `*Direct` helpers key off
   them exactly.

3. **Add the `IgaReplayDispatcher` switch case.** In `doReplay` add
   `case "<ACTION>" -> ...`. For a relationship add use
   `replayRelationship(...)` with the JPQL that stamps the attestation
   and a `*Direct` lambda that performs the real model call under
   `IGA_REPLAY_ACTIVE`:

   ```java
   case "GRANT_ROLES" -> replayRelationship(session, realm, rows, finalAttestation, em,
       "UPDATE UserRoleMappingEntity e SET e.attestation = :sig "
       + "WHERE e.user.id = :k1 AND e.roleId = :k2",
       "USER_ID", "ROLE_ID",
       r -> grantRoleDirect(session, realm, r));
   ```

   with `grantRoleDirect` doing `user.grantRole(role)` (which passes
   through because `IGA_REPLAY_ACTIVE`).

   > **Important — dispatcher is byte-unchanged from `742f944`.**
   > Modifying it to add a new action is an explicit, reviewable change.

4. **Add `IgaScopeResolver` scoping.** Add a `case "<ACTION>":` to the
   `switch` in `resolve(...)` and call the appropriate
   `resolve*ScopesFromRows(...)` with the row keys for the entities the
   action affects. `GRANT_ROLES`/`REVOKE_ROLES` resolve both the user
   (`USER_ID`) and the role (`ROLE_ID`) scopes
   (`IgaScopeResolver.java:66-70`). If the action is realm-wide, leave
   it on the `default:` branch.

5. **Define the action-type constant.** The action type is the string
   passed to `service.create(realm, type, id, "<ACTION>", rows, ...)`
   and matched in the dispatcher/scope `switch`es. There is **no
   central enum** — the string is the contract; keep it identical at
   the capture site, the dispatcher case and the scope case.

6. **Add an E2E spec** and run the full suite.

---

## Testing harness (`e2e/lib/kc.ts`)

Every E2E spec lives in `e2e/tests/` and uses a stable set of helpers in
`e2e/lib/kc.ts`. The canonical helpers are:

- **Auth / fetch:** `adminToken(...)`, `kcFetch(...)`.
- **Scratch realms:** `createScratchRealm(realm)` —
  spins up a clean realm for the test (idempotent via cleanup).
- **IGA toggling:** `enableIga(realm)` — flips `isIGAEnabled` to
  `"true"` via `tide-admin/toggle-iga` and confirms `iga-status`.
- **Attribute setters (call BEFORE `enableIga`):**
  `setRealmIgaAttr(realm, key, value)`,
  `setGroupIgaAttr(groupId, key, value)`,
  `setRoleIgaAttr(roleName, key, value)`.
- **Admin users:** `createAdminWithRoles(username, password,
  extraRealmRoles)` — provisions a user, sets a password (clearing
  required actions), assigns `manage-realm`, and assigns any extra
  realm roles. Must be called BEFORE `enableIga` so the user creation,
  password set, and role mappings are not themselves governed.
- **User profile:** `declareUserProfileAttribute(realm, attrName)` —
  patches the realm user-profile config to declare a custom attribute
  before any user with that attribute is created. Required for any
  custom user attribute (see
  [Lesson 6](#lesson-6-kc-declarative-userprofile-drops-undeclared-attributes)).
- **CR lifecycle:** `findChangeRequest(realm, predicate)`,
  `getChangeRequestStatus(realm, crId)`,
  `authorizeAs(realm, crId, asAdmin)`,
  `commitAs(realm, crId, asAdmin)`,
  `authorizeAndCommit(realm, crId)` (shortcut for the
  single-signer / zero-config case).
- **partialImport:** `partialImport(request, realm, body)` — wraps
  `POST /admin/realms/{realm}/partialImport`.

### How to write a new spec

```ts
import { test, expect } from '@playwright/test';
import {
  adminToken,
  createScratchRealm,
  createAdminWithRoles,
  setRoleIgaAttr,
  declareUserProfileAttribute,
  enableIga,
  findChangeRequest,
  authorizeAs,
  commitAs,
} from '../lib/kc';

test('my new feature: governs create-frobnicator', async ({ request }) => {
  const REALM = `test-${Date.now()}`;

  // 1. Set up the scratch realm BEFORE enabling IGA: roles, admins,
  //    governance attributes, declarative user-profile (if needed).
  await createScratchRealm(request, REALM);
  await setRoleIgaAttr(request, REALM, 'frobnicators',
      'iga.approverRole', 'frobnicator-approver');
  await setRoleIgaAttr(request, REALM, 'frobnicators',
      'iga.threshold', '2');          // remember: paired with approverRole!
  await createAdminWithRoles(request, REALM, 'alice', 'pw',
      ['frobnicator-approver']);
  await createAdminWithRoles(request, REALM, 'bob',   'pw',
      ['frobnicator-approver']);

  // 2. Enable IGA last.
  await enableIga(request, REALM);

  // 3. Drive the privileged write that should be governed; assert 202.
  const res = await request.post(
    `${process.env.KC_URL}/admin/realms/${REALM}/frobnicators`,
    { headers: { Authorization: `Bearer ${await adminToken(request)}` },
      data: { name: 'frob-1' } });
  expect(res.status()).toBe(202);

  // 4. Authorize from two distinct admins, then commit.
  const cr = await findChangeRequest(request, REALM,
      c => c.actionType === 'CREATE_FROBNICATOR');
  await authorizeAs(request, REALM, cr.id, 'alice', 'pw');
  await authorizeAs(request, REALM, cr.id, 'bob',   'pw');
  await commitAs   (request, REALM, cr.id, 'alice', 'pw');

  // 5. Assert the entity now exists in the real model.
  // ...
});
```

The Phase 4 spec
(`e2e/tests/phase4-multientity-governance.spec.ts`) is the most
elaborate example — it also shows the **precondition gate** pattern
that fails fast and clearly if the IGA jar is not loaded correctly,
rather than producing a misleading test failure.

Current expected E2E count on this branch: **12 passed**.

---

## Git hygiene and contribution checklist

> **Important — hard rules.** These are non-negotiable in this repo:
>
> - Branch from `iga-approval-workflow` (or `main` once it has been
>   promoted). **Do not use an `agent/` prefix** on contributor
>   branches.
> - **Never** use `--no-verify`, `--force`, `--no-gpg-sign`,
>   `-c commit.gpgsign=false`, or `-c core.hooksPath=...`. The repo
>   has no hooks or signing configured; the flags are still a
>   violation. If a hook fails, fix the root cause.
> - **No `Co-Authored-By`** or any co-author/sign-off trailer.
> - Do not push from a contributor / agent session — the maintainer
>   pushes.

**PR checklist**

- [ ] E2E spec for any new governed type, in `e2e/tests/`.
- [ ] Documentation update in `docs/` — operator-facing in
      `docs/IGA.md`, contributor-facing here in
      `docs/EXTENDING-IGA.md`.
- [ ] **Commit body includes a "terminal seam + why" line** for any
      new captured type — name the KC class/method/line of the
      terminal seam and one sentence on why it is the last
      unconditional call.
- [ ] `IgaReplayDispatcher.java` byte-unchanged from `d785326`
      (`git diff --quiet d785326 HEAD -- iga-core/.../replay/IgaReplayDispatcher.java`)
      unless the PR explicitly modifies it. Phase 6 ADOPT lives in
      `IgaReplayExtension`, routed BEFORE the dispatcher — adding a new
      ADOPT-able type should NOT touch the dispatcher (see
      [Recipe](#recipe-add-a-new-adopt-able-entity-type)).
- [ ] Full E2E suite green.

---

## Canonical example index

| Type | Capture file / method | Replay method | Notes |
|------|-----------------------|---------------|-------|
| client | `IgaClientAdapter.updateClient()` (`:181-234`); provider `IgaRealmProvider.addClient` | `IgaReplayDispatcher.replayCreateClient` | Clean unconditional terminal seam at `RepresentationToModel.createClient` line 404; replay re-runs `RepresentationToModel.createClient`. **EAGER harvest** since Phase 4 CME fix (`045ac7a`) — see [Lesson 3](#lesson-3-storefactorycachesession-enlistprepare-gotcha-phase-4-cme). |
| group | `IgaGroupAdapter.setDescription(String)` (`:127-194`); provider `IgaRealmProvider.createGroup` | `IgaReplayDispatcher.replayCreateGroup` | Seam = `GroupResource.updateGroup`'s final `setDescription`; top-level vs child decided by `PARENT_GROUP` key; replay does NOT recurse subGroups. Phase 4 partialImport path uses deferred-harvest accumulator. |
| org | `IgaOrganizationModel.setDomains(...)` (`:121-198`); provider `IgaOrganizationProvider.create` | `replayCreateOrganization` / `replayUpdateOrganization` | One seam serves CREATE and UPDATE; keyed by `ORG_NAME` on create (SPI can't pin id), `ORG_ID` on update; org node stamped per-entity on `ORG.ATTESTATION` (iga-changelog-2.4.0). |
| role | `IgaRoleAdapter.getName()` (`:187-292`) + `addCompositeRole` (`:294-328`); provider `IgaRealmProvider.addRealmRole` / `addClientRole` | `IgaReplayDispatcher.replayCreateRole` | No unconditional last mutating call → seam is the provably-last unconditional getter `getName()` + fire-once guard. Composites LOSSY in `ModelToRepresentation` → recorded in `addCompositeRole`, merged at the seam. Phase 4 partialImport path uses deferred-harvest. |
| user | `IgaUserAdapter.getId()` + StackWalker emit predicate; provider `IgaUserProvider.addUser` (1-arg single-entity, 5-arg partialImport import-mode short-circuit) | `IgaReplayDispatcher.replayCreateUser` | Governs **only the 8 token-affecting fields** (username/enabled/email/emailVerified/firstName/lastName/attributes/groups). Credentials, role mappings, requiredActions, federatedIdentities, createdTimestamp, federationLink are explicitly NOT in the CR. |
| client scope | `IgaClientScopeAdapter.getId()`; provider `IgaRealmProvider.addClientScope` | `IgaReplayDispatcher.replayCreateClientScope` | partialImport branch is **defensive parity** — KC 26.5.5 has no `ClientScopesPartialImport`, so the import path is wired up but never reached today. |
| action (relationship) | `IgaUserAdapter.grantRole` → `GRANT_ROLES` (`:43-56`) | `replayRelationship` + `grantRoleDirect` | Delta action: records CR via `service.create`, does NOT throw. Scoped on `USER_ID` + `ROLE_ID` in `IgaScopeResolver`. |
| batch | `IgaImportMode.BatchEmitTransaction.commit()` (`:441-612`); provider hooks: every `IgaRealmProvider.addX` + `IgaUserProvider.addUser` import-mode branch | (re-uses each per-type `replayCreate*`) | `entityType=BATCH`, `actionType=PARTIAL_IMPORT`; CR id in the 202 is the **first** per-type CR; whole batch rolls back via prepare-tx throw on the nested import session. |
| ADOPT_* (Phase 6) | `IgaAdoptScan.scan` (`:184-341`) → `IgaChangeRequestService.createAdoptCr` per row | `IgaReplayExtension.tryReplay` (`:105-123`) → `replayAdopt` (per-type JPQL stamp + sidecar delete + cache evict) | **No entity-model write on commit** — capture-then-veto for *pre-existing* entities. Routed BEFORE `IgaReplayDispatcher.replay` so dispatcher stays byte-unchanged. Threshold + approver-role gates short-circuited (system-bootstrap). See [Phase 6 section](#phase-6-retroactive-adopt--quarantine--contributor-notes). |

---

## Phase 6: retroactive ADOPT + quarantine — contributor notes

Phases 1–5 govern the *next* admin write: a `POST` becomes a `CREATE_*`
CR; the captured entity does not exist until commit. **Phase 6 governs
entities that already exist** — pre-IGA users, the realm's client list
before `isIGAEnabled` was first set to `"true"`, etc. — by retroactively
emitting an `ADOPT_*` CR on the OFF→ON toggle and **quarantining** the
entity until the ADOPT commits.

### Design recap

Two layers — no overlap, both required.

1. **One sidecar table, one bit of state per entity**:
   `IGA_UNSIGNED_ENTITY` (PK = `(realmId, entityType, entityId)`,
   payload = the ADOPT CR id, see
   `iga-core/.../services/IgaUnsignedEntityService.java`). The toggle-on
   scan inserts one row per quarantined entity; ADOPT replay deletes
   the matching row; toggle-off bulk-deletes the realm.
2. **Per-type quarantine overrides on the existing
   IgaUserAdapter / IgaClientAdapter / IgaGroupAdapter (via
   `IgaUserAdapter.getGroupsStream` filter) / IgaClientScopeAdapter**.
   Each consults `IgaQuarantineCache`, which does the
   sidecar-table lookup (with per-request memoisation on session
   attributes — see "the cache" below).

The capture-then-veto and the retroactive-ADOPT machinery share *one*
sidecar abstraction (`IgaUnsignedEntityService.markUnsigned` / `isUnsigned` /
`clearByAdoptCr` / `clearByRealm` / `countByRealm`). There is no
"pre-IGA" vs "post-IGA" distinction at the quarantine call site — a row
either has an `IGA_UNSIGNED_ENTITY` entry (quarantined) or it does not
(operational).

The ADOPT_* replay extension is **deliberately routed BEFORE
`IgaReplayDispatcher.replay`** in `IgaAdminResource.commit`
(`IgaReplayExtension.tryReplay` returns `true` when it owns the CR;
otherwise the dispatcher's switch runs). This keeps the dispatcher
byte-unchanged from `d785326` (and `742f944` for everything else).

### Per-type quarantine hook table

Cite this when adding a new ADOPT-able type.

| Entity | Adapter override | KC call site(s) `isEnabled` fires on | Quarantine cache primitive | Strip vs refuse |
|--------|------------------|--------------------------------------|----------------------------|------------------|
| User | `IgaUserAdapter.isEnabled()` (`:1184-1203`) | `TokenManager:193,267`; `AuthorizationCodeGrantType:121`; `JWTAuthorizationGrantType:114`; `DeviceGrantType:313`; `CibaGrantType:234`; `AbstractTokenExchangeProvider:407`; resource-owner password & browser flows via authenticator-flow | `IgaQuarantineCache.isUserUnsignedWithRoles` (direct + role fan-out, batched IN-clause) | HARD refuse |
| Client | `IgaClientAdapter.isEnabled()` (`:634-649`) | `ClientIdAndSecretAuthenticator:114`; `AbstractJWTClientValidator:124`; `AccessTokenIntrospectionProvider:267` | `IgaQuarantineCache.isClientUnsigned` (single PK probe) | HARD refuse |
| Role (held by user) | folded into `IgaUserAdapter.isEnabled` via the role fan-out branch of `IgaQuarantineCache.isUserUnsignedWithRoles` | (user's `isEnabled` checkpoints — see User row) | batched IN-clause: `SELECT u.entityId FROM IgaUnsignedEntityEntity u WHERE u.realmId=:r AND u.entityType='ROLE' AND u.entityId IN :ids` | HARD refuse on the user (not a silent role strip) |
| Group | `IgaUserAdapter.getGroupsStream()` filter (`:1234-1263`) | OIDC + SAML `GroupMembershipMapper`; `TokenManager`; admin REST reads (kept visible via StackWalker bypass) | `IgaQuarantineCache.isGroupUnsigned` (single PK probe) | SILENT strip from token mapping (admin reads keep the group visible) |
| Client scope | `IgaClientScopeAdapter.getProtocolMappersStream()` (`:724-743`) | `TokenManager` / `OIDCLoginProtocol` token-mapping path; any caller resolving a scope's mappers | `IgaQuarantineCache.isClientScopeUnsigned` (single PK probe) | SILENT strip (returns `Stream.empty()`) |

KC source-line references come from the comment headers in each
adapter file (cross-checked against `keycloak-services` 26.5.5 at the
time the hooks were written). When a new KC release changes these
line numbers, update the comments — they are the only place those
numbers live.

### The `IGA_REPLAY_ACTIVE` gate (and why every new seam must honour it)

`IgaQuarantineCache.isReplayActive(session)` short-circuits every
public method to `false` ("not unsigned") when the session attribute
`IGA_REPLAY_ACTIVE` equals `"true"`. The same gate exists on every
Phase 1–5 capture seam (so commit-time replay doesn't get re-captured).
For Phase 6 it has a second purpose: **ADOPT replay needs to read the
entity it is about to attest.** Without the gate the quarantine would
refuse the replay's own model lookup. `IgaReplayExtension.tryReplay`
sets the attribute around `replayAdopt` (`:113-118`); the toggle
handler sets it around its own `isIGAEnabled` attribute write
(`TideAdminCompatResource.writeIgaAttributeDirect`, `:313-325`) so the
toggle itself is not captured as a `SET_REALM_ATTRIBUTE` CR.

> **Rule.** If you add a new quarantine seam (new entity type, new KC
> checkpoint), the first line of the seam must be:
>
> ```java
> if ("true".equals(session.getAttribute("IGA_REPLAY_ACTIVE"))) {
>     return /* not unsigned */;
> }
> ```
>
> Or — preferably — route through `IgaQuarantineCache` which already
> implements the gate.

### Cache-eviction gotchas (the painful Phase 6c lessons)

Keycloak's caches snapshot `isEnabled` and adapter state at cache-load
time. The Phase 1–5 capture seams never had to worry about this —
they only fire at admin-write time, which already invalidates the
relevant cache entry via KC's own machinery. **Phase 6's quarantine
hooks fire at *read* time, which is exactly where the cache short-circuits
the adapter override.** Three lessons came out of this:

#### Lesson 7: KC's `UserCacheSession` returns a `CachedUser`-backed adapter whose `isEnabled()` reads the cache snapshot, NOT the IGA adapter

Receipt: `keycloak-model-infinispan` `UserAdapter.java:166-168`; the
adapter is built from a `CachedUser` whose `isEnabled` field was set
at cache-load time, before the IGA quarantine could refuse. A user
loaded into the cache BEFORE the OFF→ON toggle keeps returning
`enabled=true` after the toggle even though `IgaUserAdapter.isEnabled`
would refuse.

**Fix**: the toggle handler explicitly evicts the realm's user cache
after the OFF→ON scan (and symmetrically on ON→OFF):
`UserStorageUtil.userCache(session).evict(realm)`
(`TideAdminCompatResource.evictRealmUserCache`,
`TideAdminCompatResource.java:179`). The ADOPT replay extension
additionally per-evicts the just-attested user
(`IgaReplayExtension.evictCacheForAdopt`, USER branch).

ADOPT_ROLE and ADOPT_GROUP **cannot** per-evict the users they unblock
(KC's cache API offers no role→user / group→user reverse index that's
cheaper than walking every member). They fall back to the same
realm-wide user-cache eviction the toggle uses
(`IgaReplayExtension.evictRealmUserCacheFallback`,
`IgaReplayExtension.java:362-378`).

#### Lesson 8: KC's `RealmCacheSession` does the same thing for client / role / group / scope adapters

Receipt: `keycloak-model-infinispan` `RealmCacheSession.java:1170-1192,
1215-1248`; `ClientAdapter.isEnabled()` returns `cached.isEnabled()`
(`ClientAdapter.java:150-152`) rather than delegating. A confidential
client loaded pre-toggle keeps granting `client_credentials` post-toggle.

**Fix**: `evictRealmCache` in `TideAdminCompatResource`
(`:514-626`) walks every client, every realm-role, every client-role,
every group, every client-scope and calls
`CacheRealmProvider.registerClientInvalidation` /
`registerRoleInvalidation` / `registerGroupInvalidation` /
`registerClientScopeInvalidation` per-entity. Per-entity is mandatory:
`registerRealmInvalidation` does NOT cascade to per-entity entries.

The ADOPT replay extension does the same per-attested-entity in
`IgaReplayExtension.evictCacheForAdopt` (CLIENT / ROLE / GROUP /
CLIENT_SCOPE branches).

#### Lesson 9: the toggle's OWN `realm.setAttribute("isIGAEnabled", ...)` write must bypass IGA capture

Receipt: `IgaRealmAdapter.setAttribute` intercepts every realm-attribute
write when `isIgaActive()`; routing the toggle attribute through that
interceptor would create a `SET_REALM_ATTRIBUTE` CR and leave the
realm in a lying state ("enabled=false" in the response while
`isIGAEnabled` remains `"true"` pending CR approval).

**Fix**: the toggle handler sets `IGA_REPLAY_ACTIVE=true` around its
own `realm.setAttribute(IGA_ATTRIBUTE, ...)` call, in a try/finally
that restores the prior value
(`TideAdminCompatResource.writeIgaAttributeDirect`,
`TideAdminCompatResource.java:313-325`). The try/finally is mandatory
— a lingering `IGA_REPLAY_ACTIVE` would silently disable ALL
subsequent IGA capture for the rest of the request, including the
scan/cancel follow-ups.

#### Lesson 10: `IgaClientScopeAdapter.getProtocolMappersStream` must HARD-bypass the quarantine cache when `captureMode=true`

Receipt: `IgaClientScopeAdapter.java:685-722` (the comment header
explains in detail). `RepresentationToModel.createClientScope` (KC
26.5.5 `RepresentationToModel.java:724`) calls
`clientScope.getProtocolMappersStream().collect(...).forEach(removeProtocolMapper)`
STRICTLY AFTER `setName`/`setDescription`/`setProtocol` and STRICTLY
BEFORE the rep's `addProtocolMapper` loop. At that point the
capture-mode terminal-emit predicate
(`captureMode && !captureEmitted && nameObserved && !importDeferred`)
is true; consulting the quarantine cache would call `scope.getId()`,
which routes through this adapter's `getId()` override and triggers
the terminal-EMIT seam mid-`createClientScope`. The CR is written,
the request tx is marked rollback-only, and the rep ends up captured
with ONLY `setName`/`setDescription`/`setProtocol` — the
addProtocolMapper / setAttribute setters never fire.

**Fix**: `if (captureMode) return super.getProtocolMappersStream();`
as the first line of the override. In capture mode no sidecar row
exists yet (the row is only written on ADOPT, never on
`CREATE_CLIENT_SCOPE`), so the quarantine check is structurally
unnecessary and consulting it is positively harmful.

> **Generalisation.** Any future quarantine seam that KC's own
> create/update flow calls *during the build of the capture-mode
> scratch entity* must hard-bypass the cache in capture mode. The cache
> consults `entity.getId()`, which routes through the adapter override,
> which can re-enter the terminal seam. If your terminal seam can be
> reached from any KC builder call that the quarantine seam might
> trigger, gate the quarantine on `captureMode == false` first.

### Admin-context discriminator: StackWalker, not session attribute

`IgaUserAdapter.getGroupsStream()` must strip unsigned groups for the
token-mapping path but **must NOT strip them for admin REST reads** —
otherwise the operator who is supposed to ADOPT the group can no
longer see it. The discriminator is
`IgaUserAdapter.isCalledFromAdminRestResource()`
(`IgaUserAdapter.java:1289-1300`):

```java
private static boolean isCalledFromAdminRestResource() {
    return StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
            .walk(frames -> frames.anyMatch(f -> {
                String cn = f.getDeclaringClass().getName();
                return cn.startsWith("org.keycloak.services.resources.admin.");
            }));
}
```

> **Security-critical: do not replace this with a session attribute.**
> A malicious caller could set an arbitrary session attribute before
> issuing a token-issuance request and trick the gate into not
> stripping. The StackWalker is immune because the discriminator IS the
> call site itself — token-mapping callers
> (`OIDCLoginProtocol.GroupMembershipMapper`, `TokenManager`,
> `AccountRestService`) have NO frame under
> `org.keycloak.services.resources.admin` on the stack. This is the
> same threat model that drives `IgaUserAdapter`'s create-time
> terminal-seam StackWalker.

When the predicate returns `true`, the adapter still emits a
one-shot-per-session WARN log line per visible-but-unsigned group, so
the unsigned membership is surfaced for operator triage.

### ADOPT_* gate bypass mechanism

`IgaScopeResolver.requireApprover` and `resolveThreshold` each have an
**action-type-aware overload** (`IgaScopeResolver.java:213-220` and
`:270-277`) that short-circuits to no-op / `1` when
`IgaReplayExtension.isAdoptAction(actionType)` returns `true`. The
deprecated zero-CR overloads remain for any caller that doesn't have
CR context.

**Why the bypass is in the resolver, not the endpoint:** every code path
that enforces the gate (per-CR authorize, per-CR commit, bulk-authorize
loop, list-representation enrichment) calls the resolver. Centralising
the bypass in one place — and routing both gates through the single
`isAdoptAction` predicate — means a new ADOPT action type is added in
exactly one place (`IgaReplayExtension.isAdoptAction`).

The bypass logs one INFO line per (request, CR, gate) via
`logAdoptBypassOnce` (`IgaScopeResolver.java:308-315`), deduped through
a session attribute so a single request that hits both gates twice
(resolve-then-threshold, list-enrichment, etc.) only logs once.

### Test-harness self-heal pattern

When an E2E spec creates entities BEFORE enabling IGA and then needs to
authenticate as one of those entities AFTER enabling IGA, the Phase 6b
toggle-on adopt scan will quarantine the entity. The spec must commit
the entity's ADOPT_USER (plus any ADOPT_ROLE for the user's
realm/client-role mappings) before the direct-grant request, or the
quarantine refuses with `400 invalid_grant`.

Helpers in `e2e/lib/kc.ts`:

- `userTokenFor(request, realm, username, password)` (`kc.ts:1106-1247`):
  if IGA is on and ADOPT_USER for the user is PENDING, master-admin
  authorize+commit it (plus every PENDING ADOPT_ROLE for a role the user
  holds), then run the direct-grant. Returns the access token string.
- `directGrantTokenForClient(...)` in
  `e2e/tests/phase6c-quarantine.spec.ts:153`: same pattern but targets
  a specific client and self-heals the matching `ADOPT_CLIENT` first.

When adding a new ADOPT-able type, mirror this pattern: detect the
pending ADOPT_X for the test's target entity, master-admin authorize +
commit it, then drive the operation that would otherwise be quarantined.

The master-admin shortcut works because IGA is permanently disabled on
the `master` realm (`IgaChangeRequestService.isIgaEnabled` returns
`false` when the realm name is `master`), and a master-admin has
`manage-realm` on every realm via the cross-realm admin scope. Test
specs that don't have access to a master-admin token must instead
provision the test realm with enough admins to clear the queue under
normal `manage-realm` rules — but at that point the spec is
exercising more than just the change under test.

---

## Recipe: add a new ADOPT-able entity type

Use the five Phase 6b types as worked examples
(USER / ROLE / GROUP / CLIENT / CLIENT_SCOPE).

**Procedure** (each step references the exact file + concrete change
shape):

1. **Add the action type + entity type to
   `IgaReplayExtension`.** Define
   `ACTION_ADOPT_<TYPE> = "ADOPT_<TYPE>"` and
   `ENTITY_TYPE_<TYPE> = "<TYPE>"` constants
   (`IgaReplayExtension.java:62-72`). Extend `isAdoptAction(...)` to
   recognise the new action string (`:91-98`) — this is the single
   source of truth used by both the resolver bypass and the
   resume-from-CANCELLED lane in `IgaAdminResource`.

2. **Add the per-type scanner to `IgaUnsignedRowScanner`**: a JPQL
   projection over the entity table's
   `WHERE realmId = ?1 AND attestation IS NULL` rows. Mirror
   `usersWithNames` / `rolesWithNames` etc. Return rows in DB
   insertion order; the scanner caller is the only place per-type
   counting happens (so the projection's row order does not matter
   for correctness, only for deterministic logs).

3. **Add default-skip rules to `IgaSystemEntityFilter`.** Identify
   the new type's Keycloak built-ins (study
   `RepresentationToModel.getBuiltinClients` or the type's protocol
   factory for KC's auto-created defaults). Extend the
   `BUILTIN_*` / `DEFAULT_*_NAMES` constant sets, then add a new
   branch to `shouldSkip` for the type. Distinguish hard-pinned skips
   (the realm composite — never quarantine) from soft skips
   (`iga.adopt.includeSystem=true` opt-out).

4. **Add the per-type processor to `IgaAdoptScan`.** Add a new
   `for (InfoRow row : scanner.<type>sWithNames(realm.getId())) { processOne(...); }`
   loop in `scan(...)`. Initialise the per-type entry in the `created`
   counter map (`IgaAdoptScan.java:257-262`). Add an entry to the
   per-type `committedAdoptByType` and `pendingCreateByType` skip-set
   maps (`:226-253`).

5. **Add the per-type cache eviction to
   `IgaReplayExtension.evictCacheForAdopt`.** Map the new
   `ACTION_ADOPT_<TYPE>` to the appropriate per-entity invalidation:
   `UserCache.evict(realm, user)` for user-shaped types,
   `CacheRealmProvider.register<X>Invalidation` for realm-cached
   types. If the new type fans out to users (like role or group),
   call `evictRealmUserCacheFallback` after the per-entity invalidation
   so user-cache snapshots are refreshed.

6. **Add the per-type stamp JPQL to
   `IgaReplayExtension.stampJpqlFor`** (`:433-447`):
   `"UPDATE <Entity>Entity e SET e.attestation = :sig WHERE e.id = :id AND e.attestation IS NULL"`.
   Requires an `attestation` column on the entity's JPA mapping.

7. **Add the per-type existence check to
   `IgaReplayExtension.assertEntityExists`** (`:390-425`). Use KC's
   model API (`session.<type>s().get<Type>ById`) rather than raw JPA
   so user-storage federation / cache layers are honoured.

8. **Add the per-type quarantine check to `IgaQuarantineCache`.**
   New `is<Type>Unsigned(session, realm, model)` method mirroring
   `isClientUnsigned` (single PK probe + per-request memoisation under
   `ATTR_PREFIX_<TYPE>`). Or, for a type that needs role-style
   fan-out, mirror `isUserUnsignedWithRoles`.

9. **Add the per-type adapter override** in the relevant
   `Iga<Type>Adapter`. Decide HARD refuse vs SILENT strip per the
   Phase 6c brief (refer to the
   [per-type quarantine hook table](#per-type-quarantine-hook-table)):

   - HARD refuse → override `isEnabled()` to defer to `super` first,
     then return `false` when the quarantine cache says unsigned.
   - SILENT strip → override the specific stream/getter the
     token-mapping path consults (e.g. `getProtocolMappersStream`,
     `getGroupsStream`), filter out unsigned entities.
   - If the type has NO KC checkpoint that would surface the
     quarantine, **document why** rather than skipping the override.
     Then the type's adoption is purely audit (the ADOPT must commit
     for the entity to lose its sidecar row, but no operation against
     the entity is blocked in the meantime).

10. **If the adapter has a `captureMode` flag**, the quarantine
    override MUST hard-bypass in capture mode — see
    [Lesson 10](#lesson-10-igaclientscopeadaptergetprotocolmappersstream-must-hard-bypass-the-quarantine-cache-when-capturemodetrue).
    Test by capturing a `CREATE_<TYPE>` while IGA is on and
    confirming the captured `REP_JSON` is complete.

11. **Extend the test harness self-heal** (`e2e/lib/kc.ts`
    `userTokenFor` and equivalent) to recognise the new ADOPT_<TYPE>
    as a blocker for the operation the new helper drives. Add an E2E
    spec covering: toggle-on quarantines the type, ADOPT commits
    un-quarantine the type, toggle-off cancels pending ADOPTs of the
    type.

12. **Verify dispatcher byte-unchanged** —
    `IgaReplayDispatcher.java` is NOT touched by this recipe (the
    ADOPT lane lives in `IgaReplayExtension`, routed BEFORE the
    dispatcher's switch). Confirm with the standard check (see
    [Git hygiene checklist](#git-hygiene-and-contribution-checklist)).

13. **Cross-link the operator doc.** Add a row to the per-type
    quarantine table in
    [`IGA.md` — Quarantine semantics](IGA.md#quarantine-semantics-per-entity-type)
    so operators know what the new type does under quarantine.

---

## Phase 7: organization governance — contributor notes

Phase 7 brought KC organizations under IGA. The architecture is the same
capture-then-veto + ADOPT + quarantine pattern as Phase 6, with three
differences worth a contributor's attention:

1. The provider extends `JpaOrganizationProvider` (not the cache layer)
   because KC's organization caching lives ON the same
   `OrganizationProviderFactory` SPI as JPA (not in a separate
   `*CacheProviderFactory` like every other entity type). See
   [Wire-up lessons](#wire-up-lessons-the-phase-7a-discoveries) below
   for the priority pitfall.
2. The `OrganizationEntity` schema now carries an **`attestation` column**
   (`ORG.ATTESTATION`, iga-changelog-2.4.0) — the org is a first-class node,
   stamped per-entity on commit; the sidecar table + CR row remain the
   toggle-on ADOPT onramp. See
   [`attestation` column on `OrganizationEntity`](#attestation-column-on-organizationentity).
3. Two of the org action types (`ORG_ADD_IDP` / `ORG_REMOVE_IDP`) bind
   TWO entities — the org AND the linked IdP — so the scope resolver
   merges contributions from both. See
   [IdP-aware scope merge](#idp-aware-scope-merge-phase-7d).

The org governance surface ships with these action types:
`CREATE_ORGANIZATION`, `UPDATE_ORGANIZATION`, `DELETE_ORGANIZATION`,
`ADD_ORG_MEMBER`, `REMOVE_ORG_MEMBER`, `ORG_INVITE_MEMBER`,
`ORG_RESEND_INVITE`, `ORG_ADD_IDP`, `ORG_REMOVE_IDP`. The toggle-on
adopt scan emits `ADOPT_ORGANIZATION` for each pre-existing org
(Phase 7b). While an `ADOPT_ORGANIZATION` is PENDING the org's
`IgaOrganizationModel.isEnabled()` returns `false`, cascading through
every KC org-aware enforcement point that reads `org.isEnabled()`
(Phase 7c — see the
[operator-facing cascade table](IGA.md#quarantine-the-org-isenabled-override-and-its-cascade-phase-7c)).

### Wire-up lessons (the Phase 7a discoveries)

Two latent defects in the initial Phase 7a wire-up that any future org-
adjacent work needs to be aware of. Both were fixed in
commit `5b48b8c` / `102acce` (the Phase 7a fix commits).

**Defect 1: provider-factory priority pitfall.**
Unlike Realm / User / Client / Group / Role caching — which lives under
separate `*CacheProviderFactory` provider types so `order() == 2` above
the stock JPA factory is enough — organization caching lives ON the
same `OrganizationProviderFactory` SPI via
`InfinispanOrganizationProviderFactory.order() == 10`
(KC 26.5.5,
`model/infinispan/.../organization/InfinispanOrganizationProviderFactory.java:80-82`).
Anything with `order() <= 10` LOSES to the Infinispan factory and the
IGA wrapper is never instantiated. The Phase 7a fix bumped
`IgaOrganizationProviderFactory.order() = 20`; future contributors
adding new IGA wrappers in this surface area should leave headroom
above 20 (e.g. 30) for future Tide-side organization wrappers.

Cross-check: the same trade-off exists for every other Iga* provider
that beats a stock cache factory — IGA replaces (not wraps) the cache
layer in exchange for first-class capture authority. The Infinispan
factory's `postInit` (IdP-removed / user-removed event listeners) is
still registered because `postInit` runs on every factory regardless
of which one is selected as the default
(`DefaultKeycloakSessionFactory#initializeProviders`).

**Defect 2: `IgaOrganizationModel.equals/hashCode` must mirror
`OrganizationAdapter`.**
KC's stock `OrganizationAdapter:252-263` defines `equals` by ID and
`hashCode` by ID hash. Wrapping the model without overriding both
methods falls back to `Object` identity → two `IgaOrganizationModel`
wrappers around the same underlying org compare NOT-EQUAL, and KC's
own org-side `anyMatch(organization::equals)` lookups silently fail.
The most visible symptom: `OrganizationProvider.getMemberById` (and the
`isMember` default method that delegates to it) returns `null` for
members that are actually present in the org. Fixed in `102acce` by
mirroring the stock equals/hashCode contract:

```java
@Override
public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof OrganizationModel that)) return false;
    return that.getId().equals(getId());
}

@Override
public int hashCode() {
    return getId().hashCode();
}
```

> **Rule.** Any IGA model wrapper that subclasses or replaces a stock
> KC adapter MUST inherit the adapter's `equals/hashCode` semantics
> verbatim. KC's own provider streams use `anyMatch(::equals)` /
> `.equals(other)` against the wrapped instance — if your override
> degrades to identity equality, you'll get nondeterministic
> not-found bugs that only surface when two distinct wrapper
> instances of the same underlying entity exist in the same session.

### `attestation` column on `OrganizationEntity`

The Phase 6 entity types (`UserEntity`, `KeycloakRoleEntity`,
`KeycloakGroupEntity`, `ClientEntity`, `ClientScopeEntity`) all carry an
`attestation` byte/blob column added by the IGA schema migration. The
column gets stamped on commit and is what
`IgaUnsignedRowScanner.usersWithNames` etc. read to identify
unattested rows during the toggle-on scan.

`OrganizationEntity` is now a **first-class node** in that same set:
`iga-changelog-2.4.0` adds an `ATTESTATION VARCHAR(2048)` column to the
stock KC `ORG` table (the matching `attestation` field on
`OrganizationEntity` ships in `tidecloak-override`). This reverses the
earlier "sidecar-only, no attestation by design" decision. The locked
design calls are:

1. **The org is a NODE → per-entity stamp.** `CREATE_ORGANIZATION`,
   `UPDATE_ORGANIZATION` and `ADOPT_ORGANIZATION` replays stamp the org
   row keyed on the org id, exactly like the other five node types — no
   `TideSetResolver` change (orgs are nodes, not edges/sets).
2. **Domains are covered by the org-node attestation.** There is no
   separate `ORG_DOMAIN` attestation column; domain changes ride inside
   the org rep and are covered by the node stamp.
3. **Org membership stays on the edge.** Members are governed by the
   existing `user_group_membership` edge, so `ADD_ORG_MEMBER` /
   `REMOVE_ORG_MEMBER` (and the idp/invite actions) do NOT re-stamp the
   org node.

The sidecar (`IGA_UNSIGNED_ENTITY.entity_type='ORGANIZATION'`) is still
used for the toggle-on ADOPT onramp; the `ATTESTATION` column is the
per-row signed bit and is what the scanner's `attestation IS NULL`
filter reads to avoid re-enumerating an already-signed org.

Practical consequences for contributors:

- **The toggle-on org scan enumerates only UNSIGNED orgs.**
  `IgaUnsignedRowScanner.organizationsWithNames` carries the same
  `AND o.attestation IS NULL` filter as the other node lanes — a
  stamped org is not re-enumerated. The scan still emits one
  `ADOPT_ORGANIZATION` CR plus one `IGA_UNSIGNED_ENTITY` row per
  unsigned org (subject to the same already-committed-ADOPT skip +
  pending-create-CR skip as Phase 6b, which now act as a second
  CR-level defence on top of the column filter).
- **Per-org cache eviction uses `CacheRealmProvider.registerInvalidation(orgId)`.**
  KC's `InfinispanOrganizationProvider.registerOrganizationInvalidation`
  is package-private, but the cached `CachedOrganization` is keyed on
  the org id alone (`InfinispanOrganizationProvider.java:94` in KC
  26.5.5), and that key is invalidated via the public
  `CacheRealmProvider.registerInvalidation(id)` primitive — the same
  primitive used by `IgaReplayExtension.evictCacheForAdopt`'s
  `ADOPT_ORGANIZATION` branch. Domain-key cache entries (e.g.
  `getByDomainName`) are NOT separately invalidated because no current
  IGA-mediated flow mutates the domain key in a way that would survive
  the per-org invalidation; if a future contributor adds a flow that
  needs that precision (e.g. governing
  `OrganizationDomain.setVerified()` independently), the eviction
  surface needs to expand.

### IdP-aware scope merge (Phase 7d)

`ORG_ADD_IDP` / `ORG_REMOVE_IDP` are the first IGA action types that
bind TWO entities to the same CR — the org id (`ORG_ID` row) AND the
IdP alias (`IDP_ALIAS` row). The scope resolver was extended to call
both `resolveOrganizationScopesFromRows` AND `resolveIdpScopesFromRows`
in the same `case` branch (`IgaScopeResolver.java:174-189`), writing
into a shared `ResolvedScope` instance.

`resolveIdpScopesFromRows` (`:418-442`) does:

1. Pulls each `IDP_ALIAS` row from the captured CR.
2. Looks up the corresponding `IdentityProviderModel` via
   `session.identityProviders().getByAlias(...)`.
3. Calls `collectIdpScope(idp, out)` which reads `iga.approverRole` and
   `iga.threshold` off `IdentityProviderModel.getConfig()` (the
   `Map<String,String>` config map at `server-spi:208`) conditional on
   `iga.approverRole` being non-empty — same coupling rule as
   `collectOrganizationScope` and `collectClientScope`.

If the IdP is missing at resolve time (e.g. it was removed between
capture and commit for `ORG_REMOVE_IDP`), the row is silently skipped
— the org-side scope contribution still applies. This matches the
existing `resolveRoleScopesFromRows` skip-missing semantics.

> **Note**
> `collectIdpScope` does NOT consult `iga.scopeMode` on the IdP — the
> realm-level scopeMode is the single source of truth for whether the
> required-approver-role set is `any` or `all`. Per-IdP scopeMode
> override has no use case today.

**Cache invalidation extension.** `evictRealmCache` in
`TideAdminCompatResource.java:661-703` was extended in Phase 7d to
invalidate both IdP cache keys: `idp.getInternalId()` AND
`realmId + "." + alias + ".idp.alias"` (the alias-keyed lookup path
used by `InfinispanIdentityProviderStorageProvider.cacheKeyIdpAlias`).
Without both keys evicted, an `iga.approverRole` / `iga.threshold` edit
made on an IdP BEFORE the IGA toggle-on could remain cached post-toggle
and an `ORG_ADD_IDP` / `ORG_REMOVE_IDP` CR would resolve against the
pre-edit config — wrong gate verdict. The alias-key suffix string is
identical to KC's private constant; if a future KC release renames it
the eviction will silently no-op until the suffix is updated to match.

### SMTP-tolerance pattern (Phase 7a/b)

`replayOrgInviteMember` (`IgaReplayDispatcher.java:618-744`) wraps
`sendOrgInviteEmail` in `try/catch (EmailException) → log.warn` rather
than rethrowing. The reasoning, documented at
`IgaReplayDispatcher.java:697-708`:

- The invitation row is already persisted by `invitationManager.create(...)`
  before the e-mail send is attempted, and the invite link is stored
  on the invitation entity (`JpaInvitationManager.create` does
  `em.persist + flush` at end of the commit tx). So the invitee can
  still be notified out-of-band (admin UI / resend) even if SMTP is
  down.
- The original requester is long gone by the time replay runs — there
  is no operator to surface the SMTP error to via an HTTP response.
- Failing the commit would discard an already-approved governance
  decision over an infrastructure problem (SMTP down / misconfigured),
  and the surrounding tx rollback would discard the persisted
  invitation row, leaving the system in a state inconsistent with the
  approved CR.

The shared handler is reused by `ORG_INVITE_MEMBER` and
`ORG_RESEND_INVITE` — both replay paths inherit the swallow-and-log
behaviour. The operator-facing warning log line is exactly:

```
IGA replay ORG_INVITE_MEMBER: invitation persisted but e-mail send failed
```

> **Rule.** Any future replay path that produces user-facing side-
> effects via `EmailException`-throwing KC code (password-reset
> e-mails, verify-email actions, etc.) MUST follow this pattern: log
> at WARN, persist the action token / state, return commit success.
> A commit-time exception unrelated to the governed decision is an
> infrastructure problem and must not roll back the approved CR.

### `getOrganizationsResource` REST sub-path conventions

The Phase 7a harness work surfaced a handful of KC org REST conventions
that aren't obvious from the OpenAPI surface. Contributors writing new
org-adjacent harness helpers (or new admin-UI integrations) should
mirror these:

- **Invitations live under `/invitations`, NOT `/members/invitations`.**
  KC mounts `OrganizationInvitationResource` as a sub-resource at
  `/admin/realms/{realm}/organizations/{orgId}/invitations`
  (`OrganizationResource.java:131` in KC 26.5.5). A common
  harness-side mistake is to assume the path is nested under
  `/members/` because invitations conceptually map to future members;
  KC's routing is flat. The `@GET` listing method is at
  `OrganizationInvitationResource.java:231-273`; the `@POST .../resend`
  endpoint is at `:316-334`.
- **IdP link / unlink uses `application/json` with the alias as a
  JSON string in the body, NOT `text/plain`.**
  `OrganizationIdentityProvidersResource.addIdentityProvider` is
  `@Consumes(MediaType.APPLICATION_JSON)`. The body is the IdP id /
  alias as a JSON-string-literal (i.e.
  `JSON.stringify(alias)`). KC strips the surrounding quotes
  server-side at `OrganizationIdentityProvidersResource.java:87`
  (the same `^"|"$` strip applied by
  `OrganizationMemberResource.addMember:99` per
  [KC issue 34401](https://github.com/keycloak/keycloak/issues/34401)).
  Sending the raw alias with `Content-Type: text/plain` works
  against some legacy KC paths but fails on KC 26.5.5 org-IdP link
  with HTTP 415.
- **`POST /organizations/{id}/members` body is also a JSON string,
  same KC34401 strip.** Same convention as IdP link — see
  `OrganizationMemberResource.addMember:98-99` and
  `e2e/lib/kc.ts addOrgMemberById`. The harness sends
  `JSON.stringify(userId)`.

### Quarantine cascade pattern (Phase 7c)

`IgaOrganizationModel.isEnabled` is the first quarantine hook that
**defers to the wrapped delegate's flag first** before consulting the
quarantine cache:

```java
public boolean isEnabled() {
    boolean superEnabled = delegate.isEnabled();
    if (!superEnabled) {
        return false;
    }
    // ... then consult IgaQuarantineCache.isOrganizationUnsigned(...)
}
```

This is intentional: an admin who explicitly disables an org via
`PUT /organizations/{id}` with `enabled=false` should stay disabled
regardless of IGA quarantine state. The quarantine override is purely
ADDITIVE — it can take an enabled org and treat it as disabled, but
it can never un-disable an admin-disabled org. Any future quarantine
override that gates a "boolean attribute the operator can toggle"
should follow this pattern: defer to the delegate first, override only
when the delegate is in the affirmative state.

The cascade is implicit: every KC code path that reads
`org.isEnabled()` observes the override automatically. The Phase 7c
implementation does NOT add a new IGA seam at each cascade point —
the override at the model layer is the entire mechanism. End-to-end
verification of cascade points lives in `e2e/tests/phase7e-org-cascade.spec.ts`
(exercises the OIDC `organization` claim mapper cascade); the other
four documented cascade points
([operator doc table](IGA.md#quarantine-the-org-isenabled-override-and-its-cascade-phase-7c))
are source-grounded only because they require UI / IdP-federation
harness work that's out of scope for the REST-only E2E surface.

