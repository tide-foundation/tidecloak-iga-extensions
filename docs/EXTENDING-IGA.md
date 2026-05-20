# Extending IGA: contributor guide

> **Last updated:** 2026-05-20. Reflects Phases 1–5 as of commit `5276c40`
> (branch `iga-approval-workflow`). The operator/administrator companion
> is [`docs/IGA.md`](IGA.md).

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
`742f944` and must remain so. Verify with:

```bash
git diff --quiet 742f944 HEAD -- \
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
- [ ] `IgaReplayDispatcher.java` byte-unchanged from `742f944`
      (`git diff --quiet 742f944 HEAD -- iga-core/.../replay/IgaReplayDispatcher.java`)
      unless the PR explicitly modifies it.
- [ ] Full E2E suite green; current expected count = **12 passed**.

---

## Canonical example index

| Type | Capture file / method | Replay method | Notes |
|------|-----------------------|---------------|-------|
| client | `IgaClientAdapter.updateClient()` (`:181-234`); provider `IgaRealmProvider.addClient` | `IgaReplayDispatcher.replayCreateClient` | Clean unconditional terminal seam at `RepresentationToModel.createClient` line 404; replay re-runs `RepresentationToModel.createClient`. **EAGER harvest** since Phase 4 CME fix (`045ac7a`) — see [Lesson 3](#lesson-3-storefactorycachesession-enlistprepare-gotcha-phase-4-cme). |
| group | `IgaGroupAdapter.setDescription(String)` (`:127-194`); provider `IgaRealmProvider.createGroup` | `IgaReplayDispatcher.replayCreateGroup` | Seam = `GroupResource.updateGroup`'s final `setDescription`; top-level vs child decided by `PARENT_GROUP` key; replay does NOT recurse subGroups. Phase 4 partialImport path uses deferred-harvest accumulator. |
| org | `IgaOrganizationModel.setDomains(...)` (`:121-198`); provider `IgaOrganizationProvider.create` | `replayCreateOrganization` / `replayUpdateOrganization` | One seam serves CREATE and UPDATE; keyed by `ORG_NAME` on create (SPI can't pin id), `ORG_ID` on update; no attestation column (governed by CR row). |
| role | `IgaRoleAdapter.getName()` (`:187-292`) + `addCompositeRole` (`:294-328`); provider `IgaRealmProvider.addRealmRole` / `addClientRole` | `IgaReplayDispatcher.replayCreateRole` | No unconditional last mutating call → seam is the provably-last unconditional getter `getName()` + fire-once guard. Composites LOSSY in `ModelToRepresentation` → recorded in `addCompositeRole`, merged at the seam. Phase 4 partialImport path uses deferred-harvest. |
| user | `IgaUserAdapter.getId()` + StackWalker emit predicate; provider `IgaUserProvider.addUser` (1-arg single-entity, 5-arg partialImport import-mode short-circuit) | `IgaReplayDispatcher.replayCreateUser` | Governs **only the 8 token-affecting fields** (username/enabled/email/emailVerified/firstName/lastName/attributes/groups). Credentials, role mappings, requiredActions, federatedIdentities, createdTimestamp, federationLink are explicitly NOT in the CR. |
| client scope | `IgaClientScopeAdapter.getId()`; provider `IgaRealmProvider.addClientScope` | `IgaReplayDispatcher.replayCreateClientScope` | partialImport branch is **defensive parity** — KC 26.5.5 has no `ClientScopesPartialImport`, so the import path is wired up but never reached today. |
| action (relationship) | `IgaUserAdapter.grantRole` → `GRANT_ROLES` (`:43-56`) | `replayRelationship` + `grantRoleDirect` | Delta action: records CR via `service.create`, does NOT throw. Scoped on `USER_ID` + `ROLE_ID` in `IgaScopeResolver`. |
| batch | `IgaImportMode.BatchEmitTransaction.commit()` (`:441-612`); provider hooks: every `IgaRealmProvider.addX` + `IgaUserProvider.addUser` import-mode branch | (re-uses each per-type `replayCreate*`) | `entityType=BATCH`, `actionType=PARTIAL_IMPORT`; CR id in the 202 is the **first** per-type CR; whole batch rolls back via prepare-tx throw on the nested import session. |
