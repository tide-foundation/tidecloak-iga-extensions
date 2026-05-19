# Extending IGA: adding a new captured type or action

Audience: developers extending the IGA approval workflow. This is the
developer/contributor companion to the operator-facing [`docs/IGA.md`](IGA.md).

The architecture described here is settled and proven for **client, group,
organization** and (most recently) **role**. Role is the freshest and fullest
worked example — it is the only type with the composites lossiness nuance — so
this guide uses **role** and **client** as its primary examples.

All line numbers below were verified against the working tree at commit
`0505934` (branch `iga-approval-workflow`) and against the extracted Keycloak
26.5.5 source. Where a claim is plumbed through Keycloak internals that are
stable but version-specific, it is called out as such.

## Sections

1. Architecture overview: the capture-then-veto pattern
2. The `rowsJson` key contract
3. The replay side
4. The lossiness gotcha (`ModelToRepresentation` does not serialize everything)
5. No clean terminal seam? (and why `enlistAfterCompletion` is a dead end)
6. Step-by-step: add a new captured ENTITY TYPE
7. Step-by-step: add a new captured ACTION
8. Gotchas and hard rules
9. Canonical example index

---

## 1. Architecture overview: the capture-then-veto pattern

IGA does NOT use a JAX-RS request filter to capture the admin's intent. That
approach was tried and is provably dead (see
`IgaRepresentationCaptureFilter.java` class javadoc and section 8). Capture
happens entirely at the **model SPI layer**.

For a CREATE of an entity type `X`:

1. **`IgaRealmProvider` (or the relevant provider) returns a capture-mode
   adapter from `addX`.** `IgaRealmProvider.addClient` /
   `addRealmRole` / `addClientRole` / `createGroup`
   (`iga-core/.../providers/IgaRealmProvider.java`) call `super.addX(...)` to
   create the **real (scratch) entity**, `em.find(...)` it, and return an
   `Iga*Adapter` constructed with `captureMode = true`. Organizations do the
   same in `IgaOrganizationProvider.create` returning an `IgaOrganizationModel`
   with `captureCreate = true`.

2. **Keycloak applies the COMPLETE incoming representation to that scratch
   entity.** Because the adapter is a real, persisted model in capture mode,
   Keycloak's own builder (`RepresentationToModel.createClient`,
   `RoleContainerResource.createRole`, `GroupResource.updateGroup`,
   `RepresentationToModel.toModel` for orgs) sets every admin-supplied field on
   it. The capture-mode adapter's per-setter overrides are inert in this mode:
   each `isIgaActive()` returns `false` when `captureMode == true`, so they all
   fall through to `super` (see `IgaClientAdapter.isIgaActive` lines 102-112,
   `IgaRoleAdapter.isIgaActive` lines 163-173).

3. **At a terminal seam — the last unconditional model call in Keycloak's
   create path — the adapter snapshots and vetoes.** It:
   - snapshots the now-complete model via
     `ModelToRepresentation.toRepresentation(...)`,
   - writes the `CREATE_*` change request (with the full representation as
     `REP_JSON` in `rowsJson`) using
     `KeycloakModelUtils.runJobInTransaction(...)` — a SEPARATE Keycloak
     session/transaction that commits independently and therefore SURVIVES the
     rollback,
   - calls `session.getTransactionManager().setRollbackOnly()` on the REQUEST
     transaction so the scratch entity is discarded,
   - throws `IgaPendingApprovalException`.

   Canonical terminal seams (all verified):
   - **client** — `IgaClientAdapter.updateClient()`
     (`IgaClientAdapter.java:142-235`); seam is
     `RepresentationToModel.createClient`'s final `client.updateClient()`.
   - **group** — `IgaGroupAdapter.setDescription(String)`
     (`IgaGroupAdapter.java:127-194`); seam is `GroupResource.updateGroup`'s
     final `model.setDescription(rep.getDescription())`.
   - **org** — `IgaOrganizationModel.setDomains(...)`
     (`IgaOrganizationModel.java:121-198`); seam is
     `RepresentationToModel.toModel`'s final `model.setDomains(...)`.
   - **role** — `IgaRoleAdapter.getName()`
     (`IgaRoleAdapter.java:187-292`); seam is `role.getName()` at
     `RoleContainerResource.createRole` (see section 5 for why a getter, not a
     setter).

4. **The exception is mapped to HTTP 202 + a `Location` header.**
   `IgaPendingApprovalExceptionMapper`
   (`iga-core/.../rest/IgaPendingApprovalExceptionMapper.java`) returns
   `Response.status(ACCEPTED)` with the `{status:"PENDING", changeRequestId,
   entityType, actionType, message}` body (lines 36-61) and a synthetic
   `Location: /admin/realms/{realm}/iga/change-requests/{id}` header (lines
   53-58) so automation can poll the CR. The realm is recovered from the
   request `UriInfo` (lines 71-96), so the model-layer throw sites need not
   carry it. Note `ExceptionMapper` providers ARE discovered by Keycloak's
   RESTEasy runtime even though provider-jar request filters are not (see
   section 8).

### Why the rollback is sound (request-tx lifecycle)

Mapping `IgaPendingApprovalException` to a 202 fully CONSUMES it — it does NOT
propagate to `DefaultKeycloakSession#close()`. So the request tx would
otherwise be `commit()`ed and leak the scratch entity. The explicit
`getTransactionManager().setRollbackOnly()` is what flips that:
`DefaultKeycloakSession#close()` calls `closeTransactionManager()`, which does
`if (transactionManager.getRollbackOnly()) rollback(); else commit();`. With
the flag set, `rollback()` runs and every row Keycloak's builder produced for
the scratch entity is discarded. The 202 still stands because the mapper built
the response before `CloseSessionFilter` runs, and `rollback()` cannot escalate
to a 500. This is exactly the idiom `KeycloakErrorHandler#getResponse` uses
(set-rollback-only then return a response) — here applied to a 2xx. The full,
traced proof lives in `IgaClientAdapter.updateClient` (lines 196-234) and is
referenced by every other capture seam.

---

## 2. The `rowsJson` key contract

The authoritative contract is the class javadoc at the top of
`iga-core/.../replay/IgaReplayDispatcher.java` (lines 23-118). Read it before
you choose keys. There is **no legacy/old-format fallback** — pending CRs that
do not follow the contract are intentionally discarded.

Key rules (verbatim from that javadoc):

- `ID` — the affected row's OWN primary key (UUID). Always.
- `REALM_ID` — realm UUID, where applicable.
- `CLIENT_UUID` — a *referenced* client's UUID (resolve via
  `session.clients().getClientById(realm, uuid)`).
- `CLIENT_ID` — a *referenced* client's HUMAN identifier (e.g. `my-app`),
  NEVER a UUID. This is the single explicit exception to the "`*_ID` keys hold
  a UUID" rule; it exists because it matches Keycloak's `CLIENT.CLIENT_ID`
  column, which is the human client id.
- `CLIENT_SCOPE_ID`, `USER_ID`, `ROLE_ID`, `GROUP_ID` — referenced entity
  UUIDs.
- Human names `USERNAME` / role `NAME` / group `NAME` / scope `NAME` —
  unchanged.
- `REP_JSON` — for every `CREATE_*` action, the full Keycloak representation
  serialized as a JSON string.
- Organizations are keyed by name on create (`ORG_NAME`/`ORG_ALIAS`) because
  the org SPI cannot pin an id on create; by `ORG_ID` for update/delete/member
  actions. See the org block of the javadoc (lines 72-117).

The client resolver `resolveClient` (`IgaReplayDispatcher.java:1738-1749`)
encodes the human-vs-uuid rule: it tries `CLIENT_UUID` →
`getClientById`, then falls back to `CLIENT_ID` → `getClientByClientId`. Never
read a UUID out of `CLIENT_ID`.

**The single most important rule: the capture site must write EXACTLY the keys
the matching `replayCreate*` / `*Direct` reads.** They are two halves of one
contract in two files; a mismatch fails loudly on replay by design.

Worked example — `IgaRoleAdapter.getName()` writes
(`IgaRoleAdapter.java:261-271`):

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

`replayCreateRole` (`IgaReplayDispatcher.java:300-323`) reads exactly `ID`,
`NAME`, `CLIENT_ROLE`, `REP_JSON`, and (for client roles) resolves the owning
client via `resolveClient(session, realm, row)` — i.e. `CLIENT_UUID` first.

---

## 3. The replay side

On commit, `IgaReplayDispatcher.replay(...)` sets the session attribute
`IGA_REPLAY_ACTIVE = "true"` (lines 126-133) and dispatches on
`cr.getActionType()` through a single `switch` (lines 154-235). Each `CREATE_*`
case calls a `replayCreate*` method that:

1. resolves identity from the contract keys,
2. calls the **real** id-bearing model `add*` (e.g.
   `session.roles().addRealmRole(realm, id, name)` —
   `IgaReplayDispatcher.java:320-322`), which lands back in
   `IgaRealmProvider.addX` but, under `IGA_REPLAY_ACTIVE`, returns a
   non-capture adapter that delegates to `super` (no re-interception),
3. if `REP_JSON` is present, rebuilds the full entity by replaying Keycloak's
   own create logic — for client it calls
   `RepresentationToModel.createClient(session, realm, rep)`
   (`IgaReplayDispatcher.java:470`); for role it replays
   description/attributes/composites manually, mirroring exactly what
   `RoleContainerResource.createRole` does (lines 326-381),
4. stamps the final attestation with a JPQL `UPDATE`.

**The `IGA_REPLAY_ACTIVE` bypass is structural.** Every `isIgaActive()` (and
`IgaRealmProvider.isIgaActive`, `IgaUserAdapter.isIgaActive`, etc.) returns
`false` when the session attribute equals `"true"` — e.g.
`IgaRoleAdapter.isIgaActive` lines 171-172, `IgaRealmProvider.isIgaActive`
lines 50-51. Capture-mode adapters are additionally inert because
`captureMode → isIgaActive() == false`. Any new interception you add MUST honor
this so replay can re-drive the real model without re-capturing.

**Key consequence: replay should NOT need changes when you add a new captured
type, IF the captured representation matches what an existing `replayCreate*`
already deserializes.** Client/group/role replay already feed
`REP_JSON` through Keycloak's own builders. Only add a dispatcher case if the
type is genuinely new (section 6).

---

## 4. The lossiness gotcha

`ModelToRepresentation.toRepresentation(...)` does NOT serialize every field of
the model. The snapshot is lossy for relationships/secrets that the
representation builder deliberately omits. **Verified examples:**

- **`RoleModel` composites are dropped.**
  `ModelToRepresentation.toRepresentation(RoleModel)` (KC 26.5.5
  `org/keycloak/models/utils/ModelToRepresentation.java:424`) sets only
  `rep.setComposite(role.isComposite())` (the boolean) and NEVER
  `rep.setComposites(...)`. Verified: the method body (lines ~424-434) calls
  `setName` / `setDescription` / `setComposite(role.isComposite())` and
  `return rep` — no `setComposites`.
- **`UserModel`** — credentials and group/role mappings are not in the user
  representation snapshot (consistent with KC's brief user rep; *verify the
  exact omitted set against the KC version in use if you add USER fields*).

**Rule:** for any field the snapshot drops, the capture-mode adapter must
intercept the specific model call(s) that carry it and merge the result into
the snapshot **before** serialization.

### Worked example — role composites (commit `0505934`)

`IgaRoleAdapter` overrides `addCompositeRole` so that, in capture mode, it
records each composite child's identity in the **exact shape**
`replayCreateRole` resolves (`IgaRoleAdapter.java:294-328`):

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

Then at the terminal seam (`IgaRoleAdapter.java:205-234`), after the base
snapshot, it folds the recorded composites back in — exactly the structure
`replayCreateRole` consumes (`Composites.realm` = set of realm-role NAMES;
`Composites.client` = map of HUMAN clientId → list of role names):

```java
RoleRepresentation rep = ModelToRepresentation.toRepresentation(this); // composites NOT set
rep.setId(roleId); rep.setName(roleName); rep.setClientRole(clientRole);

boolean composite = !capturedRealmComposites.isEmpty()
        || !capturedClientComposites.isEmpty();
if (composite) {
    rep.setComposite(true);
    RoleRepresentation.Composites composites = new RoleRepresentation.Composites();
    if (!capturedRealmComposites.isEmpty())
        composites.setRealm(new LinkedHashSet<>(capturedRealmComposites));
    if (!capturedClientComposites.isEmpty())
        composites.setClient(/* deep copy of capturedClientComposites */);
    rep.setComposites(composites);
}
```

`replayCreateRole` then guards on `rep.isComposite() && rep.getComposites() !=
null` and resolves realm composites via `realm.getRole(name)` and client
composites via `realm.getClientByClientId(clientId).getRole(name)`
(`IgaReplayDispatcher.java:342-376`) — i.e. the producer and consumer shapes
are mechanically identical.

When you add a new type, audit which fields its
`ModelToRepresentation.toRepresentation` overload omits, and intercept exactly
those model calls in capture mode.

---

## 5. No clean terminal seam? (and why `enlistAfterCompletion` is a dead end)

The seam must be the **last unconditional model call** Keycloak makes in the
create path, so that when it fires the model is fully built. Client, group and
org each have a clean *unconditional last mutating* call
(`updateClient()` / `setDescription()` / `setDomains()`). **Role does not.**

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

`setDescription` fires first; the attribute loop and the composite loops are
all conditional. There is **no unconditional last *mutating* call**. The chosen
seam is therefore the **getter** `role.getName()` at line 225 — the first and
only `getName()` in `createRole`, UNCONDITIONAL and strictly AFTER
setDescription, the attribute loop and the composite loops, so the model is
fully built for both composite and non-composite roles. It is guarded by a
fire-once flag (`captureEmitted`, `IgaRoleAdapter.java:142-143, 189-194`) so
the second `getName()` at line 227 and any defensive re-entrancy do not
re-emit. `RoleAdapter.setDescription/setAttribute/addCompositeRole` never call
`getName()` internally, so the seam cannot fire prematurely. The exact guidance
given in the guide:

> When there is no unconditional last *mutating* call, choose the first
> UNCONDITIONAL call (getter or setter) that is provably AFTER every
> conditional mutation in Keycloak's create path, and protect it with a
> fire-once guard so it emits exactly once.

### Why a request-completion synchronization is NOT viable in KC 26.5.5

A natural-looking alternative is to enlist an `afterCompletion`
synchronization (`DefaultKeycloakTransactionManager#enlistAfterCompletion`) and
do the snapshot/veto there. **This is unsound and contributors must not repeat
it.** Verified against `DefaultKeycloakTransactionManager.commit()` (KC 26.5.5,
`org/keycloak/services/DefaultKeycloakTransactionManager.java:114`):

```
commit():
  for tx in prepare:        commitWithTracing(tx)         // first
  for tx in transactions:   commitWithTracing(tx)         // main list — COMMITS HERE
  if no exception:
      for tx in afterCompletion: commitWithTracing(tx)    // ONLY AFTER the above
```

The request `JpaKeycloakTransaction` (enlisted by
`DefaultJpaConnectionProviderFactory`) is in the main `transactions` list. It is
committed **before** the `afterCompletion` list is iterated. So an
`afterCompletion` hook (a) cannot veto the already-committed scratch entity —
it is already in the DB — and (b) runs at session close, far too late to turn
the response into a 202. The synchronization idea is a dead end in this
version; the terminal-seam-inside-the-request-tx approach is the only one that
both vetoes the entity and produces the 202.

---

## 6. Step-by-step: add a NEW captured ENTITY TYPE

Checklist (role is the worked example):

1. **Locate Keycloak's create path and its terminal seam.** Find the admin
   REST resource that creates the type and the model builder it runs
   (`RepresentationToModel.createClient`, `RoleContainerResource.createRole`,
   `GroupResource.updateGroup`, `RepresentationToModel.toModel`). Identify the
   last UNCONDITIONAL model call (preferring a mutating call; fall back to a
   provably-last unconditional getter + fire-once guard, section 5).

2. **Make the provider return a capture-mode adapter from `addX`.** In
   `IgaRealmProvider` (or the relevant provider), in the `isIgaActive(realm)`
   branch: call `super.addX(...)` to create the real scratch entity,
   `em.find(...)` it, and `return new Iga*Adapter(..., /*captureMode=*/ true,
   ...)`. See `IgaRealmProvider.addRealmRole` (lines 161-203) and
   `addClientRole` (lines 211-237) for the role pattern, including how the
   owning client UUID / human clientId are threaded into the adapter
   constructor for client roles.

3. **Implement the capture-mode branch in the `Iga*Adapter`.**
   - `isIgaActive()` returns `false` when `captureMode` (so all per-setter
     overrides pass through to `super` and Keycloak builds the full model).
   - Override the terminal seam: snapshot via
     `ModelToRepresentation.toRepresentation(...)`, **merge any lossy fields**
     (section 4), serialize to `REP_JSON`, write the `CREATE_*` CR via
     `KeycloakModelUtils.runJobInTransaction(...)`, call
     `session.getTransactionManager().setRollbackOnly()`, then
     `throw new IgaPendingApprovalException(crId, "<TYPE>", "CREATE_<TYPE>")`.
   - If a lossy relationship exists, also override the model call(s) that carry
     it to record it in capture mode (role's `addCompositeRole`).

4. **Pick `rowsJson` keys per the contract** (section 2): `ID` = own UUID,
   `NAME`/human id, `REALM_ID`, referenced entities by their contract keys,
   `REP_JSON` = the full serialized representation.

5. **Confirm an existing `replayCreate*` consumes it, or add a dispatcher
   case.** If `REP_JSON` is a representation Keycloak's own builder can rebuild
   (as for client/role/group), an existing replay path likely already handles
   it. Only if the type is genuinely new: add a `case "CREATE_<TYPE>" ->
   replayCreate<Type>(...)` to the `switch` in `IgaReplayDispatcher.doReplay`
   (lines 154-235) and write `replayCreate<Type>` mirroring Keycloak's create
   logic faithfully (do not invent behaviour — see `replayCreateRole` lines
   300-389).

6. **Honor `IGA_REPLAY_ACTIVE` inertness.** Every interception you add must
   no-op when the session attribute is `"true"` so replay re-drives the real
   model without re-capturing (section 3).

7. **Scoping / thresholds.** Add the new `CREATE_<TYPE>` (and any
   per-entity actions on it) to the `switch` in
   `IgaScopeResolver.resolve(...)` (`attestors/IgaScopeResolver.java:65-171`).
   Top-level CREATE_* are realm-wide and intentionally fall to the `default:`
   empty scope (no entity exists yet) — see the comment at lines 165-170.
   Per-entity actions resolve scope from the parent via the
   `resolve*ScopesFromRows(...)` helpers; add a `resolve<Type>ScopesFromRows`
   if the type carries `iga.approverRole` / `iga.threshold` attributes (model
   the new helper on `resolveOrganizationScopesFromRows`, lines 293-321).

---

## 7. Step-by-step: add a NEW captured ACTION

Use an existing simple relationship action as the template:
`USER` `GRANT_ROLES` (`IgaUserAdapter.grantRole`, lines 43-56).

1. **Pick the adapter method to intercept.** Find the inline-mode model method
   that performs the mutation (e.g. `UserModel.grantRole(RoleModel)`). Override
   it in the relevant `Iga*Adapter`; gate on `isIgaActive()` and call `super`
   when inactive:

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

   (`IgaUserAdapter.java:43-56`.) Note this is a delta action: it records the
   CR via `service.create(...)` and returns; it does NOT throw (the inline
   relationship pattern). Attribute actions that must interrupt the write
   (e.g. `SET_*_ATTRIBUTE`) follow the same shape; the create-entity actions
   are the only ones that throw `IgaPendingApprovalException`.

2. **Choose the `rowsJson` row shape per the contract** (section 2). For
   `GRANT_ROLES`: `{ "USER_ID": <user uuid>, "ROLE_ID": <role uuid> }`. Use
   the canonical key names (`USER_ID`, `ROLE_ID`, `GROUP`, `CLIENT_UUID`, …) —
   the replay JPQL and `*Direct` helpers key off them exactly.

3. **Add the `IgaReplayDispatcher` switch case.** In `doReplay` (lines
   154-235) add `case "<ACTION>" -> ...`. For a relationship add use
   `replayRelationship(...)` with the JPQL that stamps the attestation and a
   `*Direct` lambda that performs the real model call under
   `IGA_REPLAY_ACTIVE`; for a removal use `replayRevoke(...)`. `GRANT_ROLES`
   (lines 160-163):

   ```java
   case "GRANT_ROLES" -> replayRelationship(session, realm, rows, finalAttestation, em,
       "UPDATE UserRoleMappingEntity e SET e.attestation = :sig WHERE e.user.id = :k1 AND e.roleId = :k2",
       "USER_ID", "ROLE_ID",
       r -> grantRoleDirect(session, realm, r));
   ```

   with `grantRoleDirect` (lines 950-956) doing
   `user.grantRole(role)` (which passes through because `IGA_REPLAY_ACTIVE`).

4. **Add `IgaScopeResolver` scoping.** Add a `case "<ACTION>":` to the
   `switch` in `resolve(...)` and call the appropriate
   `resolve*ScopesFromRows(...)` with the row keys for the entities the action
   affects. `GRANT_ROLES`/`REVOKE_ROLES` resolve both the user (`USER_ID`) and
   the role (`ROLE_ID`) scopes (`IgaScopeResolver.java:66-70`). If the action
   is realm-wide, leave it on the `default:` branch.

5. **Define the action-type constant.** The action type is the string passed
   to `service.create(realm, type, id, "<ACTION>", rows, ...)` and matched in
   the dispatcher/scope `switch`es. There is no central enum — the string is
   the contract; keep it identical at the capture site, the dispatcher case and
   the scope case.

---

## 8. Gotchas and hard rules

- **Master realm is always bypassed.** `IgaChangeRequestService.isIgaEnabled`
  returns `false` when `realm.getName().equals("master")` regardless of the
  `isIGAEnabled` attribute (`IgaChangeRequestService.java:36-39`). New
  interception inherits this via `isIgaActive()`.
- **Never rely on a provider-jar JAX-RS `ContainerRequestFilter`.** It is
  proven non-functional: Keycloak 26.5.5 loads provider jars through its own
  `ProviderManager` classloader, outside the Quarkus app-archive scan RESTEasy
  uses to discover `@Provider` request/response filters, so
  `IgaRepresentationCaptureFilter` was never registered or invoked. It is a
  documented dead shim that always returns `null`
  (`IgaRepresentationCaptureFilter.java` class javadoc;
  `pendingRepJson` lines 73-75). `ExceptionMapper` providers, by contrast,
  ARE discovered (that is why the 202 mapping works). Capture must be at the
  model layer.
- **The 202 + `Location` behavior is the automation contract.** Do not change
  the status, body keys, or the `Location:
  /admin/realms/{realm}/iga/change-requests/{id}` header
  (`IgaPendingApprovalExceptionMapper.java:36-61`); native Admin-REST clients
  poll it.
- **Replay must stay faithful.** Do not fork capture-shape vs replay-shape.
  Whatever the capture site writes to `rowsJson`/`REP_JSON` is exactly what the
  matching replay reads; replay rebuilds via Keycloak's own builders and must
  not invent behaviour Keycloak's create path does not perform (see the
  "no invented behaviour" comments in `replayCreateRole`/`replayCreateGroup`).
- **Always honor `IGA_REPLAY_ACTIVE`.** Any new `isIgaActive()`-style gate
  must return `false` under replay (and under `captureMode`).
- **No `--no-verify` / `--force` / `--no-gpg-sign`.** This repo has no hooks or
  signing; use plain `git commit`. Commits are batched and NOT pushed by the
  PM; no `Co-Authored-By`; no `agent/` branches.

---

## 9. Canonical example index

| Type | Capture file / method | Replay method | Notes |
|------|----------------------|---------------|-------|
| client | `IgaClientAdapter.updateClient()` (`:142-235`); provider `IgaRealmProvider.addClient` (`:258-300`) | `IgaReplayDispatcher.replayCreateClient` (`:440-496`) | Clean unconditional terminal seam (`RepresentationToModel.createClient`'s final `updateClient()`); replay re-runs `RepresentationToModel.createClient`. No lossiness. |
| group | `IgaGroupAdapter.setDescription(String)` (`:127-194`); provider `IgaRealmProvider.createGroup` (`:108-140`) | `IgaReplayDispatcher.replayCreateGroup` (`:392-438`) | Seam = `GroupResource.updateGroup`'s final `setDescription`; top-level vs child decided by `PARENT_GROUP` key; replay does NOT recurse subGroups. |
| org | `IgaOrganizationModel.setDomains(...)` (`:121-198`); provider `IgaOrganizationProvider.create` | `replayCreateOrganization` / `replayUpdateOrganization` (`IgaReplayDispatcher.java:519+`) | One seam serves CREATE and UPDATE; keyed by `ORG_NAME` on create (SPI can't pin id), `ORG_ID` on update; no attestation column (governed by CR row). |
| role | `IgaRoleAdapter.getName()` (`:187-292`) + `addCompositeRole` (`:294-328`); provider `IgaRealmProvider.addRealmRole`/`addClientRole` (`:161-237`) | `IgaReplayDispatcher.replayCreateRole` (`:300-389`) | No unconditional last mutating call → seam is the provably-last unconditional getter `getName()` + fire-once guard. Composites are LOSSY in `ModelToRepresentation` → recorded in `addCompositeRole`, merged at the seam. Fullest example. |
| action (relationship) | `IgaUserAdapter.grantRole` → `GRANT_ROLES` (`:43-56`) | `replayRelationship` + `grantRoleDirect` (`IgaReplayDispatcher.java:160-163, 950-956`) | Delta action: records CR via `service.create`, does NOT throw. Scoped on `USER_ID`+`ROLE_ID` in `IgaScopeResolver`. |
