package org.tidecloak.iga.providers;

import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.GroupModel.Type;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.jpa.JpaRealmProvider;
import org.keycloak.models.jpa.RealmAdapter;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.jpa.entities.ClientScopeEntity;
import org.keycloak.models.jpa.entities.GroupEntity;
import org.keycloak.models.jpa.entities.RealmEntity;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.jboss.logging.Logger;

import jakarta.persistence.EntityManager;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Extends JpaRealmProvider to intercept group/role/client creation and mutations
 * through the IGA approval workflow when IGA is enabled.
 */
public class IgaRealmProvider extends JpaRealmProvider {

    private static final Logger log = Logger.getLogger(IgaRealmProvider.class);

    private final KeycloakSession igaSession;

    public IgaRealmProvider(KeycloakSession session) {
        super(session,
                session.getProvider(JpaConnectionProvider.class).getEntityManager(),
                null, null);
        this.igaSession = session;
    }

    private IgaChangeRequestService getService() {
        EntityManager em = igaSession.getProvider(JpaConnectionProvider.class).getEntityManager();
        return new IgaChangeRequestService(em, igaSession);
    }

    private boolean isIgaActive(RealmModel realm) {
        IgaChangeRequestService service = getService();
        if (!service.isIgaEnabled(realm)) return false;
        Object replay = igaSession.getAttribute("IGA_REPLAY_ACTIVE");
        return !"true".equals(replay);
    }

    // -------------------------------------------------------------------------
    // REALM lookup — wrap with IgaRealmAdapter so realm-attribute writes are
    // intercepted. We only override these two; everything else stays in
    // JpaRealmProvider via super.
    // -------------------------------------------------------------------------

    @Override
    public RealmModel getRealm(String id) {
        RealmModel base = super.getRealm(id);
        if (base == null) return null;
        if (base instanceof RealmAdapter ra) {
            RealmEntity entity = ra.getEntity();
            if (entity != null) {
                return new IgaRealmAdapter(igaSession, em, entity);
            }
        }
        return base;
    }

    @Override
    public RealmModel getRealmByName(String name) {
        RealmModel base = super.getRealmByName(name);
        if (base == null) return null;
        if (base instanceof RealmAdapter ra) {
            RealmEntity entity = ra.getEntity();
            if (entity != null) {
                return new IgaRealmAdapter(igaSession, em, entity);
            }
        }
        return base;
    }

    /**
     * Persist the change request in a SEPARATE Keycloak session/transaction so it survives
     * the rollback caused by the pending-approval exception we throw afterwards, mark the
     * REQUEST transaction rollback-only so {@code DefaultKeycloakSession#close()} rolls back
     * (rather than commits) the in-flight request tx, then throw the pending-approval signal
     * (mapped to HTTP 202 + Location). Same draft-no-persist idiom as
     * {@code IgaClientAdapter#updateClient}: mapping the exception to a 202 CONSUMES it, so
     * without the explicit rollback-only the request tx would be committed at close(); for
     * ASSIGN_SCOPE/REMOVE_SCOPE this is what guarantees the {@code CLIENT_SCOPE_CLIENT}
     * linkage row is NOT written at draft time (we also never call super, so nothing is
     * persisted by the capture path — the rollback-only is belt-and-braces and discards any
     * incidental cache/JPA bookkeeping the admin write started before reaching this seam).
     */
    private void recordAndThrow(RealmModel realm, String entityType, String entityId,
                                 String actionType, List<Map<String, Object>> rows) {
        String[] crIdHolder = new String[1];
        KeycloakModelUtils.runJobInTransaction(igaSession.getKeycloakSessionFactory(), newSession -> {
            RealmModel newRealm = newSession.realms().getRealm(realm.getId());
            EntityManager newEm = newSession.getProvider(JpaConnectionProvider.class).getEntityManager();
            IgaChangeRequestService newService = new IgaChangeRequestService(newEm, newSession);
            crIdHolder[0] = newService.create(newRealm, entityType, entityId, actionType, rows, null).getId();
        });
        igaSession.getTransactionManager().setRollbackOnly();
        throw new IgaPendingApprovalException(crIdHolder[0], entityType, actionType);
    }

    // -------------------------------------------------------------------------
    // GROUP
    // -------------------------------------------------------------------------

    @Override
    public GroupModel createGroup(RealmModel realm, String id, Type type, String name, GroupModel toParent) {
        // partialImport batch governance for GROUP. This branch MUST
        // come BEFORE the single-entity isIgaActive() capture return and is
        // strictly gated by the import-mode predicate; the single-entity
        // admin-create path below is unchanged.
        //
        // Mechanism: create the REAL scratch group via super.createGroup
        // (em.persist + em.flush) so the group is FULLY persisted and queryable by
        // name+parent in the nested import session. Return a capture-mode
        // IgaGroupAdapter whose per-setter overrides all fall straight through
        // to the real GroupAdapter (captureMode bypasses isIgaActive in every
        // attribute/role/setDescription override) AND register it with the
        // BatchEmitTransaction (registerImportGroup → enlistPrepare). The
        // CREATE_GROUP row is harvested ONCE at batch-emit time
        // (buildImportGroupPendingCr → ModelToRepresentation.toRepresentation
        // on the live pass-through model AFTER importGroup has applied every
        // conditional setDescription/setAttribute/grantRole). The whole
        // nested import tx is then vetoed by the BatchEmit prepare-seam throw
        // (DefaultKeycloakTransactionManager.commit → rollback) so
        // the scratch group is discarded atomically; one 202 + Location is
        // returned by IgaPendingApprovalExceptionMapper.
        //
        // ROOT CAUSE NOTE:
        // A "still NPEs at GroupsPartialImport" symptom is NOT an IGA
        // capture-mode artifact. KC's getModelId is
        // `findGroupModel(...).getId()` where findGroupModel ==
        // KeycloakModelUtils.findGroupByPath(session, realm,
        // groupRep.getPath()). findGroupByPath returns null at its first
        // guard (`if (path == null) return null;`) when the GroupRepresentation in
        // the partialImport payload omits `path`, so `.getId()` on the next
        // line NPEs UNCONDITIONALLY, regardless of whether the scratch group
        // is persisted, regardless of IGA. Confirmed by running an
        // IGA-DISABLED vanilla-KC realm with `{"groups":[{"name":"vp-group",
        // "attributes":{...}}]}` (no path): identical HTTP 500 / identical
        // GroupsPartialImport NPE / identical KC-SERVICES0037 stack.
        // KC's own AbstractPartialImportTest.addGroups always sets BOTH
        // setName AND setPath("/" + GROUP_PREFIX + i) — pathless group reps
        // are malformed per KC's partialImport contract, not an IGA defect.
        // Roles/users don't NPE because RealmRolesPartialImport.getModelId
        // uses `.orElse(null)` and
        // UsersPartialImport.getModelId uses a createdIds cache populated by
        // create().
        //
        // The corresponding E2E payload now sets `path` on the group rep so
        // KC's intra-import getModelId resolves the (real, persisted, super-
        // created) scratch group via findGroupByPath → getGroupByName
        // (JpaRealmProvider.getGroupByName:516-539 — name+parent+type=REALM
        // criteria query that finds the scratch group flushed by super.
        // createGroup above).
        if (IgaImportMode.isImportMode(igaSession, realm)) {
            GroupModel base = super.createGroup(realm, id, type, name, toParent);
            if (base == null) return null;
            GroupEntity entity = em.find(GroupEntity.class, base.getId());
            if (entity == null) return base;
            log.infof("IGA multi-entity: capture CREATE_GROUP via partialImport "
                    + "RepresentationToModel.importGroup for name=%s (uuid=%s, "
                    + "parent=%s) — scratch group persisted via super "
                    + "(em.persist+flush, queryable by name+parent in the "
                    + "nested import session); capture-mode adapter is pass-"
                    + "through to the real GroupAdapter and registered for "
                    + "deferred-harvest at the BatchEmit prepare seam. KC's "
                    + "subsequent GroupsPartialImport.getModelId will resolve "
                    + "via findGroupByPath PROVIDED the partialImport payload "
                    + "carries groupRep.path (vanilla-KC requirement, see "
                    + "KeycloakModelUtils.findGroupByPath:800-802 null-path "
                    + "guard — payloads with only `name` NPE in stock KC too)",
                    name, base.getId(),
                    (toParent != null ? toParent.getId() : null));
            IgaGroupAdapter adapter = new IgaGroupAdapter(
                    igaSession, realm, em, entity, /*captureMode=*/ true);
            IgaImportMode.registerImportGroup(igaSession, realm, adapter);
            adapter.markImportDeferred();
            return adapter;
        }
        if (isIgaActive(realm)) {
            // Model-layer accumulate-then-veto, identical mechanism to
            // addClient. Create the REAL (scratch) GroupEntity via super so
            // Keycloak's GroupResource.updateGroup(rep, model, realm, session)
            // can apply the COMPLETE incoming GroupRepresentation (name,
            // attributes, description) to a genuine GroupAdapter. The
            // IgaGroupAdapter is returned in capture mode: every per-setter
            // override falls through to the real adapter, and the LAST mutation
            // KC makes in that path — GroupModel.setDescription()
            // (GroupResource.updateGroup line 300, KC 26.5.5) — is the terminal
            // seam where the now-complete model is snapshotted to a
            // GroupRepresentation, the CREATE_GROUP change request (with full
            // REP_JSON) is written in a separate transaction, the REQUEST
            // transaction is marked rollback-only and IgaPendingApprovalException
            // is thrown (→ HTTP 202). See IgaGroupAdapter#setDescription and the
            // IgaClientAdapter#updateClient lifecycle proof.
            GroupModel base = super.createGroup(realm, id, type, name, toParent);
            if (base == null) return null;
            GroupEntity entity = em.find(GroupEntity.class, base.getId());
            if (entity == null) return base;
            log.debugf("IGA capture CREATE_GROUP: scratch group entity created for name=%s "
                    + "(uuid=%s, parent=%s) — accumulating full representation until the "
                    + "model-layer terminal seam (GroupResource.updateGroup#setDescription)",
                    name, base.getId(), (toParent != null ? toParent.getId() : null));
            return new IgaGroupAdapter(igaSession, realm, em, entity, /*captureMode=*/ true);
        }
        GroupModel base = super.createGroup(realm, id, type, name, toParent);
        if (base == null) return null;
        GroupEntity entity = em.find(GroupEntity.class, base.getId());
        if (entity == null) return base;
        return new IgaGroupAdapter(igaSession, realm, em, entity);
    }

    @Override
    public GroupModel getGroupById(RealmModel realm, String id) {
        GroupModel base = super.getGroupById(realm, id);
        if (base == null) return null;
        GroupEntity entity = em.find(GroupEntity.class, id);
        if (entity == null) return base;
        return new IgaGroupAdapter(igaSession, realm, em, entity);
    }

    // -------------------------------------------------------------------------
    // ROLE
    // -------------------------------------------------------------------------

    @Override
    public RoleModel addRealmRole(RealmModel realm, String name) {
        return addRealmRole(realm, KeycloakModelUtils.generateId(), name);
    }

    @Override
    public RoleModel addRealmRole(RealmModel realm, String id, String name) {
        // partialImport batch governance for REALM ROLE. Same gap
        // class as createGroup: under POST /partialImport, KC's
        // RolesPartialImport.doImport → RepresentationToModel.importRoles →
        // createRole calls realm.addRole(...) (→ here) then applies
        // setDescription/setAttribute CONDITIONALLY and the composites only on
        // a SECOND pass via addComposites; createRole/importRoles NEVER calls
        // role.getName() on the returned adapter, so the single-entity
        // IgaRoleAdapter#getName terminal seam is never reached on the import
        // path (role ungoverned + capture-mode scratch role on the veto path).
        // Fix: identical deferred-harvest mechanism as createGroup / the 5-arg
        // addUser import branch — real scratch role via super, capture-mode
        // adapter (per-setter + composites still pass through to the real
        // model so RealmRolesPartialImport.getModelId resolves a real id),
        // markImportDeferred() makes getName() a pure pass-through, and the
        // CREATE_ROLE row is harvested ONCE for the batch by the
        // BatchEmitTransaction (registerImportRole). No per-entity throw.
        if (IgaImportMode.isImportMode(igaSession, realm)) {
            RoleModel base = super.addRealmRole(realm, id, name);
            if (base == null) return null;
            RoleEntity entity = em.find(RoleEntity.class, base.getId());
            if (entity == null) return base;
            log.infof("IGA multi-entity: capture CREATE_ROLE (realm) via "
                    + "partialImport RepresentationToModel.importRoles for "
                    + "name=%s (uuid=%s) — capture-mode adapter registered "
                    + "with the batch (deferred-harvest; role create proceeds "
                    + "so RealmRolesPartialImport.getModelId resolves)",
                    name, base.getId());
            IgaRoleAdapter adapter = new IgaRoleAdapter(igaSession, realm, em,
                    entity, /*captureMode=*/ true, /*clientUuid=*/ null,
                    /*clientId=*/ null);
            IgaImportMode.registerImportRole(igaSession, realm, adapter);
            adapter.markImportDeferred();
            return adapter;
        }
        if (isIgaActive(realm)) {
            // Model-layer accumulate-then-veto, same proven mechanism as
            // addClient/createGroup. Create the REAL (scratch) RoleEntity via
            // super so Keycloak's RoleContainerResource.createRole can apply the
            // COMPLETE incoming RoleRepresentation (description, attributes AND
            // composites) to a genuine RoleAdapter. The IgaRoleAdapter is
            // returned in capture mode: setDescription/setAttribute fall through
            // to the real adapter, addCompositeRole falls through AND records
            // each composite child's identity (because
            // ModelToRepresentation.toRepresentation(RoleModel) does NOT
            // serialize composites — KC 26.5.5
            // ModelToRepresentation:424-434), and the LAST unconditional model
            // call KC makes in createRole — role.getName() at
            // RoleContainerResource.createRole line 225, AFTER setDescription
            // (168), the setAttribute loop (170-175) and the conditional
            // addCompositeRole loop (186-222) — is the terminal seam where the
            // now-complete model is snapshotted into a RoleRepresentation
            // (base via ModelToRepresentation.toRepresentation PLUS
            // setComposite(true)+setComposites(...) reconstructed from the
            // recorded addCompositeRole calls), the CREATE_ROLE change request
            // (with full REP_JSON) is written in a separate transaction, the
            // REQUEST tx is marked rollback-only and IgaPendingApprovalException
            // is thrown (→ HTTP 202 + Location). The scratch role + composite
            // links are discarded by the request-tx rollback exactly as in
            // IgaClientAdapter. See IgaRoleAdapter capture-mode javadoc.
            RoleModel base = super.addRealmRole(realm, id, name);
            if (base == null) return null;
            RoleEntity entity = em.find(RoleEntity.class, base.getId());
            if (entity == null) return base;
            log.debugf("IGA capture CREATE_ROLE: scratch realm-role entity created for name=%s "
                    + "(uuid=%s) — accumulating full representation until the model-layer "
                    + "terminal seam (RoleContainerResource.createRole#getName)",
                    name, base.getId());
            return new IgaRoleAdapter(igaSession, realm, em, entity, /*captureMode=*/ true,
                    /*clientUuid=*/ null, /*clientId=*/ null);
        }
        RoleModel base = super.addRealmRole(realm, id, name);
        if (base == null) return null;
        RoleEntity entity = em.find(RoleEntity.class, base.getId());
        if (entity == null) return base;
        return new IgaRoleAdapter(igaSession, realm, em, entity);
    }

    @Override
    public RoleModel addClientRole(ClientModel client, String name) {
        return addClientRole(client, KeycloakModelUtils.generateId(), name);
    }

    @Override
    public RoleModel addClientRole(ClientModel client, String id, String name) {
        RealmModel realm = client.getRealm();
        // partialImport batch governance for CLIENT ROLE. Same gap
        // class as addRealmRole: under POST /partialImport, KC's
        // RolesPartialImport.doImport → RepresentationToModel.importRoles
        // (client-roles branch) calls
        // client.addRole(...) (→ here) then conditional setDescription/
        // setAttribute and second-pass addComposites; getName() is never
        // called on the returned adapter. Fix mirrors addRealmRole, with the
        // owning-client linkage carried in the row exactly as the
        // single-entity client-role capture does (CLIENT_UUID/CLIENT_ID) so
        // IgaReplayDispatcher.resolveClient/replayCreateRole is byte-unchanged.
        if (IgaImportMode.isImportMode(igaSession, realm)) {
            RoleModel base = super.addClientRole(client, id, name);
            if (base == null) return null;
            RoleEntity entity = em.find(RoleEntity.class, base.getId());
            if (entity == null) return base;
            log.infof("IGA multi-entity: capture CREATE_ROLE (client) via "
                    + "partialImport RepresentationToModel.importRoles for "
                    + "name=%s (uuid=%s, clientUuid=%s, clientId=%s) — "
                    + "capture-mode adapter registered with the batch "
                    + "(deferred-harvest; role create proceeds so "
                    + "ClientRolesPartialImport.getModelId resolves)",
                    name, base.getId(), client.getId(), client.getClientId());
            IgaRoleAdapter adapter = new IgaRoleAdapter(igaSession, realm, em,
                    entity, /*captureMode=*/ true,
                    /*clientUuid=*/ client.getId(),
                    /*clientId=*/ client.getClientId());
            IgaImportMode.registerImportRole(igaSession, realm, adapter);
            adapter.markImportDeferred();
            return adapter;
        }
        if (isIgaActive(realm)) {
            // Same model-layer accumulate-then-veto as addRealmRole; the only
            // difference is the rowsJson client linkage so replay's
            // resolveClient + replayCreateRole(clientRole=true) path can find
            // the owning client. rowsJson contract (must match
            // IgaReplayDispatcher.resolveClient/replayCreateRole):
            // CLIENT_UUID = client UUID (resolveClient prefers it),
            // CLIENT_ID = human clientId (never a UUID), CLIENT_ROLE = true.
            RoleModel base = super.addClientRole(client, id, name);
            if (base == null) return null;
            RoleEntity entity = em.find(RoleEntity.class, base.getId());
            if (entity == null) return base;
            log.debugf("IGA capture CREATE_ROLE: scratch client-role entity created for name=%s "
                    + "(uuid=%s, clientUuid=%s, clientId=%s) — accumulating full representation "
                    + "until the model-layer terminal seam (RoleContainerResource.createRole#getName)",
                    name, base.getId(), client.getId(), client.getClientId());
            return new IgaRoleAdapter(igaSession, realm, em, entity, /*captureMode=*/ true,
                    /*clientUuid=*/ client.getId(), /*clientId=*/ client.getClientId());
        }
        RoleModel base = super.addClientRole(client, id, name);
        if (base == null) return null;
        RoleEntity entity = em.find(RoleEntity.class, base.getId());
        if (entity == null) return base;
        return new IgaRoleAdapter(igaSession, realm, em, entity);
    }

    @Override
    public RoleModel getRoleById(RealmModel realm, String id) {
        RoleModel base = super.getRoleById(realm, id);
        if (base == null) return null;
        RoleEntity entity = em.find(RoleEntity.class, id);
        if (entity == null) return base;
        return new IgaRoleAdapter(igaSession, realm, em, entity);
    }

    // -------------------------------------------------------------------------
    // CLIENT
    // -------------------------------------------------------------------------

    @Override
    public ClientModel addClient(RealmModel realm, String clientId) {
        return addClient(realm, KeycloakModelUtils.generateId(), clientId);
    }

    @Override
    public ClientModel addClient(RealmModel realm, String id, String clientId) {
        // partialImport batch governance for CLIENT. This branch MUST
        // come BEFORE the single-entity isIgaActive() capture return and is
        // strictly gated by the import-mode predicate; the single-entity
        // admin-create path below is unchanged.
        //
        // Mechanism (mirrors createGroup / addRealmRole / addClientRole /
        // 5-arg addUser exactly): under POST /partialImport,
        // PartialImportManager.saveResources → ClientsPartialImport.doImport →
        // ClientsPartialImport.create calls RepresentationToModel.createClient
        // which in turn calls
        // realm.addClient(rep.getId(), rep.getClientId()) (→ here). KC's very
        // next call after create() returns is ClientsPartialImport.getModelId:
        // `realm.getClientByClientId(
        // getName(clientRep)).getId()`, where getName(clientRep) ==
        // clientRep.getClientId(). That lookup MUST resolve in the nested
        // import session — so we persist the REAL scratch ClientEntity via
        // super.addClient (em.persist+flush in JpaRealmProvider.addClient)
        // exactly like the single-entity branch already does, and return a
        // capture-mode IgaClientAdapter whose every per-setter / every
        // updateClient override falls through to the real ClientAdapter
        // (captureMode bypasses isIgaActive in every override; the terminal
        // updateClient() seam is gated on importDeferred to be a pure pass-
        // through here so KC's createClient finishes normally and the
        // resource-level getModelId lookup succeeds against the persisted
        // scratch client). The CREATE_CLIENT row is harvested ONCE at
        // batch-emit time (buildImportClientPendingCr →
        // ModelToRepresentation.toRepresentation on the live pass-through
        // model AFTER RepresentationToModel.createClient has applied every
        // updateClientProperties field / protocol-mapper / scope / final
        // updateClient). The
        // whole nested import tx is then vetoed by the BatchEmit prepare-seam
        // throw (DefaultKeycloakTransactionManager.commit → rollback)
        // so the scratch client + its mappers + scope links + redirectUri /
        // webOrigin rows are discarded atomically; one 202 + Location is
        // returned by IgaPendingApprovalExceptionMapper.
        if (IgaImportMode.isImportMode(igaSession, realm)) {
            ClientModel base = super.addClient(realm, id, clientId);
            if (base == null) return null;
            ClientEntity entity = em.find(ClientEntity.class, base.getId());
            if (entity == null) return base;
            log.infof("IGA multi-entity: capture CREATE_CLIENT via partialImport "
                    + "ClientsPartialImport.create → RepresentationToModel."
                    + "createClient for clientId=%s (uuid=%s) — scratch client "
                    + "persisted via super (em.persist+flush, queryable by "
                    + "clientId in the nested import session so KC's "
                    + "ClientsPartialImport.getModelId — "
                    + "realm.getClientByClientId(clientId).getId() — "
                    + "resolves); capture-mode adapter is pass-through to the "
                    + "real ClientAdapter and registered for deferred-harvest "
                    + "at the BatchEmit prepare seam (the single-entity "
                    + "updateClient terminal seam is inert for this client)",
                    clientId, base.getId());
            IgaClientAdapter adapter = new IgaClientAdapter(realm, em, igaSession,
                    entity, /*captureMode=*/ true);
            IgaImportMode.registerImportClient(igaSession, realm, adapter);
            adapter.markImportDeferred();
            return adapter;
        }
        if (isIgaActive(realm)) {
            // Model-layer accumulate-then-veto (replaces the dead JAX-RS
            // IgaRepresentationCaptureFilter — provider-jar @Provider
            // ContainerRequestFilters are never discovered by Keycloak's
            // RESTEasy runtime, see report). We do NOT throw here any more.
            //
            // Instead create the REAL (scratch) ClientEntity via super so
            // Keycloak's RepresentationToModel.createClient can apply the
            // COMPLETE incoming ClientRepresentation (webOrigins, redirectUris,
            // attributes, protocol mappers, client scopes, flow flags) to a
            // genuine ClientAdapter. The IgaClientAdapter is returned in
            // capture mode: every per-setter override falls through to the real
            // adapter, and the LAST mutation KC makes in that path —
            // ClientModel.updateClient() (RepresentationToModel.createClient
            // line 404, KC 26.5.5) — is the terminal seam where the now
            // complete model is snapshotted to a ClientRepresentation, the
            // CREATE_CLIENT change request (with full REP_JSON) is written in a
            // separate transaction, the REQUEST transaction is marked
            // rollback-only (igaSession.getTransactionManager()
            // .setRollbackOnly()) and IgaPendingApprovalException is thrown
            // (→ HTTP 202). The scratch entity is never committed: the
            // rollback-only flag makes DefaultKeycloakSession#close() roll the
            // request tx back instead of committing it (mapping the exception
            // to a 202 CONSUMES it, so without the explicit flag close() would
            // commit and leak the scratch client). Throwing LATE (full graph
            // built) is what avoids the original
            // TransientPropertyValueException/cascade.
            ClientModel base = super.addClient(realm, id, clientId);
            if (base == null) return null;
            ClientEntity entity = em.find(ClientEntity.class, base.getId());
            if (entity == null) return base;
            log.debugf("IGA capture CREATE_CLIENT: scratch client entity created for clientId=%s "
                    + "(uuid=%s) — accumulating full representation until the model-layer "
                    + "terminal seam (updateClient)", clientId, base.getId());
            return new IgaClientAdapter(realm, em, igaSession, entity, /*captureMode=*/ true);
        }
        ClientModel base = super.addClient(realm, id, clientId);
        if (base == null) return null;
        ClientEntity entity = em.find(ClientEntity.class, base.getId());
        if (entity == null) return base;
        return new IgaClientAdapter(realm, em, igaSession, entity);
    }

    @Override
    public ClientModel getClientById(RealmModel realm, String id) {
        ClientModel base = super.getClientById(realm, id);
        if (base == null) return null;
        ClientEntity entity = em.find(ClientEntity.class, id);
        if (entity == null) return base;
        return new IgaClientAdapter(realm, em, igaSession, entity);
    }

    @Override
    public ClientModel getClientByClientId(RealmModel realm, String clientId) {
        ClientModel base = super.getClientByClientId(realm, clientId);
        if (base == null) return null;
        if (base.getId() == null) return base;
        ClientEntity entity = em.find(ClientEntity.class, base.getId());
        if (entity == null) return base;
        return new IgaClientAdapter(realm, em, igaSession, entity);
    }

    // -------------------------------------------------------------------------
    // CLIENT-SCOPE ATTACH / DETACH (CLIENT_SCOPE_CLIENT linkage)
    //
    // The capture seam for "attach a client scope to a client" lives HERE, at
    // the provider layer, NOT on IgaClientAdapter. With the infinispan cache ON
    // (the production config), the admin route
    //   PUT /admin/realms/{realm}/clients/{uuid}/default-client-scopes/{scopeId}
    //     → ClientResource.addDefaultClientScope
    //     → client.addClientScope(scope, defaultScope)   [CacheClientAdapter]
    //     → cacheSession.addClientScopes(realm, client, singleton(scope), def)
    //     → RealmCacheSession.addClientScopes
    //     → getClientDelegate().addClientScopes(...)      [== this provider]
    // bypasses the ClientModel delegate entirely, so the old
    // IgaClientAdapter.addClientScope override is dead code (never hit at
    // runtime under cache). The same routing applies to the singular cache
    // adapter calls KC's own create flow makes (RepresentationToModel
    // .updateClientScopes → client.addClientScope, ClientManager
    // .enableServiceAccount → client.addClientScope) and the optional-scope and
    // DELETE routes. So a single override of the provider-interface
    // addClientScopes(Set)/removeClientScope on this class governs ALL of them.
    //
    // Design (approved):
    //  * One addClientScopes(Set) call → ONE ASSIGN_SCOPE CR carrying ALL scopes
    //    in the set, one row per scope (the admin REST route passes a singleton,
    //    so it naturally becomes a 1-row CR; the batch matters for the Set model
    //    path, e.g. AbstractLoginProtocolFactory.addDefaultClientScopes).
    //  * removeClientScope(one) → ONE REMOVE_SCOPE CR, one row.
    //  * Default scopes auto-attached DURING client creation are already folded
    //    into the CREATE_CLIENT CR's REP_JSON (RepresentationToModel.createClient
    //    serializes default/optional scope links), and the service-account-enable
    //    path attaches scopes as part of client setup — so we SUPPRESS standalone
    //    ASSIGN_SCOPE capture on those paths (pass straight through to super) and
    //    only govern LATER, admin-initiated attach/detach on an already-existing
    //    client. Suppression frames (StackWalker, see isOnClientCreationPath):
    //    RepresentationToModel.{createClient,updateClientScopes,
    //    addClientScopeToClient}, ClientManager.{createClient,enableServiceAccount}
    //    and AbstractLoginProtocolFactory.addDefaultClientScopes.
    //  * Replay: IgaReplayDispatcher already handles ASSIGN_SCOPE/REMOVE_SCOPE
    //    by iterating ALL rows (replayRelationship/replayRevoke), so a multi-row
    //    CR replays each scope link + stamps each ClientScopeClientMappingEntity
    //    .attestation. No replay change was needed.
    // -------------------------------------------------------------------------

    @Override
    public void addClientScopes(RealmModel realm, ClientModel client,
                                Set<ClientScopeModel> clientScopes, boolean defaultScope) {
        // Pass-through when IGA is not the governing authority for this write:
        // IGA disabled, replay (IGA_REPLAY_ACTIVE), or a partialImport/import
        // frame on the stack — the SAME gating the other IgaRealmProvider
        // overrides use (isIgaActive + IgaImportMode.isImportMode).
        if (!isIgaActive(realm) || IgaImportMode.isImportMode(igaSession, realm)) {
            super.addClientScopes(realm, client, clientScopes, defaultScope);
            return;
        }
        // Suppress standalone capture on the client-creation / service-account
        // path: those scope links are already governed by the CREATE_CLIENT CR
        // (default/optional scopes ride in its REP_JSON) and must not block or
        // double-govern client creation.
        if (isOnClientCreationPath()) {
            log.debugf("IGA ASSIGN_SCOPE suppressed on client-creation path for "
                    + "client uuid=%s (%d scope(s)) — governed by CREATE_CLIENT CR",
                    client.getId(), clientScopes == null ? 0 : clientScopes.size());
            super.addClientScopes(realm, client, clientScopes, defaultScope);
            return;
        }
        if (clientScopes == null || clientScopes.isEmpty()) {
            // Nothing to govern; let super no-op faithfully.
            super.addClientScopes(realm, client, clientScopes, defaultScope);
            return;
        }

        // Governed admin-initiated attach: emit ONE ASSIGN_SCOPE CR carrying all
        // scopes as multiple rows, then defer persistence to commit/replay.
        String clientUuid = client.getId();
        String clientId = client.getClientId();
        List<Map<String, Object>> rows = new ArrayList<>();
        for (ClientScopeModel scope : clientScopes) {
            // Row shape MUST match IgaReplayDispatcher ASSIGN_SCOPE consumption:
            // CLIENT_UUID = client UUID (stamp key + resolveClient), CLIENT_ID =
            // human clientId, SCOPE_ID = scope UUID, DEFAULT_SCOPE flag.
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("CLIENT_UUID", clientUuid);
            row.put("CLIENT_ID", clientId);
            row.put("SCOPE_ID", scope.getId());
            row.put("DEFAULT_SCOPE", defaultScope);
            rows.add(row);
        }
        log.debugf("IGA capture ASSIGN_SCOPE: client uuid=%s clientId=%s — %d scope(s) "
                + "in one CR (defaultScope=%s)", clientUuid, clientId, rows.size(), defaultScope);
        recordAndThrow(realm, "CLIENT", clientUuid, "ASSIGN_SCOPE", rows);
    }

    @Override
    public void removeClientScope(RealmModel realm, ClientModel client, ClientScopeModel clientScope) {
        if (!isIgaActive(realm) || IgaImportMode.isImportMode(igaSession, realm)) {
            super.removeClientScope(realm, client, clientScope);
            return;
        }
        // updateClientScopes (on the create path) can also call removeClientScope
        // while reconciling default/optional sets; suppress those exactly like
        // the attach side so client creation is never blocked/double-governed.
        if (isOnClientCreationPath()) {
            log.debugf("IGA REMOVE_SCOPE suppressed on client-creation path for "
                    + "client uuid=%s scope=%s — governed by CREATE_CLIENT CR",
                    client.getId(), clientScope == null ? null : clientScope.getId());
            super.removeClientScope(realm, client, clientScope);
            return;
        }
        if (clientScope == null) {
            super.removeClientScope(realm, client, clientScope);
            return;
        }
        String clientUuid = client.getId();
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("CLIENT_UUID", clientUuid);
        row.put("CLIENT_ID", client.getClientId());
        row.put("SCOPE_ID", clientScope.getId());
        log.debugf("IGA capture REMOVE_SCOPE: client uuid=%s scope=%s",
                clientUuid, clientScope.getId());
        recordAndThrow(realm, "CLIENT", clientUuid, "REMOVE_SCOPE", List.of(row));
    }

    /**
     * StackWalker discriminator: are we executing inside Keycloak's
     * client-creation (or service-account-enable) flow, where default/optional
     * client scopes are auto-attached and are ALREADY governed by the
     * CREATE_CLIENT change request? Mirrors the StackWalker idiom used by
     * {@code IgaUserAdapter}/{@code IgaImportMode.inPartialImport} — matches if
     * ANY of the create-path frames is present ANYWHERE on the current stack.
     *
     * <p>Suppression frames (KC 26.5.5):
     * <ul>
     *   <li>{@code RepresentationToModel.createClient} — POST {realm}/clients
     *       and replay; its {@code updateClientScopes} →
     *       {@code addClientScopeToClient} → {@code client.addClientScope}
     *       lands here via the cache adapter.</li>
     *   <li>{@code RepresentationToModel.updateClientScopes} /
     *       {@code addClientScopeToClient} — the actual frames that call
     *       {@code addClientScope}/{@code removeClientScope} during create.</li>
     *   <li>{@code ClientManager.createClient} — the services-layer create
     *       entry point.</li>
     *   <li>{@code ClientManager.enableServiceAccount} — attaches the
     *       service-account scope (ClientManager,
     *       {@code client.addClientScope(serviceAccountScope, true)}).</li>
     *   <li>{@code AbstractLoginProtocolFactory.addDefaultClientScopes}
     *       (server-spi-private) — the protocol-factory hook that calls
     *       {@code client.addClientScopes(Set, boolean)} directly via a
     *       Consumer lambda (so the frame may be the synthetic
     *       {@code lambda$addDefaultClientScopes$N}); matched by class-name
     *       prefix so the lambda frame counts too.</li>
     * </ul>
     * The governed admin route ({@code ClientResource.addDefaultClientScope} /
     * {@code addOptionalClientScope} on an already-existing client) carries NONE
     * of these frames, so it is correctly NOT suppressed.
     */
    private boolean isOnClientCreationPath() {
        return StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames.anyMatch(f -> {
                    String cn = f.getDeclaringClass().getName();
                    String mn = f.getMethodName();
                    if ("org.keycloak.models.utils.RepresentationToModel".equals(cn)
                            && ("createClient".equals(mn)
                                || "updateClientScopes".equals(mn)
                                || "addClientScopeToClient".equals(mn))) {
                        return true;
                    }
                    if ("org.keycloak.services.managers.ClientManager".equals(cn)
                            && ("createClient".equals(mn)
                                || "enableServiceAccount".equals(mn))) {
                        return true;
                    }
                    // AbstractLoginProtocolFactory.addDefaultClientScopes calls
                    // addClientScopes via a Consumer lambda, so the on-stack
                    // frame may be a synthetic lambda$addDefaultClientScopes$N
                    // on the same declaring class — match by class-name prefix.
                    return cn.startsWith(
                            "org.keycloak.protocol.AbstractLoginProtocolFactory");
                }));
    }

    // -------------------------------------------------------------------------
    // CLIENT SCOPE
    // -------------------------------------------------------------------------

    @Override
    public ClientScopeModel addClientScope(RealmModel realm, String id, String name) {
        // partialImport batch governance for CLIENT_SCOPE
        // (defensive parity with addClient). This branch
        // MUST come BEFORE the single-entity isIgaActive() capture return and
        // is strictly gated by the import-mode predicate; the single-entity
        // admin-create path below is unchanged.
        //
        // PartialImportManager
        // registers ONLY ClientsPartialImport / RolesPartialImport /
        // IdentityProvidersPartialImport / IdentityProviderMappersPartialImport
        // / GroupsPartialImport / UsersPartialImport — there is NO
        // ClientScopesPartialImport in the partialimport package, so no
        // current per-type partialImport handler reaches addClientScope. This
        // branch is therefore cheap insurance against (a) future KC versions
        // that add ClientScopesPartialImport, and (b) any indirect
        // multi-entity import path (export/import util, future SPI) that
        // could call addClientScope under a partialImport frame.
        //
        // Mechanism (mirrors addClient exactly): persist the REAL scratch
        // ClientScopeEntity via super.addClientScope (so any inbound resolve
        // by id or by name works in the nested import session — same
        // precondition the single-entity branch already establishes). Return
        // a capture-mode IgaClientScopeAdapter whose per-setter / per-mapper
        // overrides accumulate into capturedRep/capturedMappers/
        // capturedAttributes AND pass through to the real ClientScopeAdapter;
        // the terminal getId() seam is gated on importDeferred to be a pure
        // pass-through here (so KC's createClientScope finishes normally).
        // The CREATE_CLIENT_SCOPE row is harvested ONCE at batch-emit time
        // (buildImportClientScopePendingCr from the SAME accumulator the
        // single-entity getId seam emits from, so REP_JSON is byte-identical
        // and IgaReplayDispatcher.replayCreateClientScope is byte-unchanged).
        // The nested import tx is vetoed by the BatchEmit prepare-seam throw
        // — the scratch scope + mappers + attributes are discarded
        // atomically; one 202 + Location is returned.
        if (IgaImportMode.isImportMode(igaSession, realm)) {
            String resolvedId = (id != null) ? id : KeycloakModelUtils.generateId();
            ClientScopeModel base = super.addClientScope(realm, resolvedId, name);
            if (base == null) return null;
            ClientScopeEntity entity = em.find(ClientScopeEntity.class, base.getId());
            if (entity == null) return base;
            log.infof("IGA multi-entity: capture CREATE_CLIENT_SCOPE via "
                    + "partialImport / multi-entity import for name=%s "
                    + "(uuid=%s) — scratch client-scope persisted via super "
                    + "(em.persist+flush, queryable in the nested import "
                    + "session); capture-mode adapter is pass-through to the "
                    + "real ClientScopeAdapter and registered for deferred-"
                    + "harvest at the BatchEmit prepare seam (DEFENSIVE "
                    + "PARITY: KC 26.5.5 has no ClientScopesPartialImport so "
                    + "no per-type partialImport handler reaches this branch "
                    + "today; the single-entity getId terminal seam is inert "
                    + "for this scope)",
                    name, base.getId());
            IgaClientScopeAdapter adapter = new IgaClientScopeAdapter(realm, em,
                    igaSession, entity, /*captureMode=*/ true);
            IgaImportMode.registerImportClientScope(igaSession, realm, adapter);
            adapter.markImportDeferred();
            return adapter;
        }
        if (isIgaActive(realm)) {
            // Model-layer accumulate-then-veto — the SAME proven mechanism as
            // addRealmRole/addClientRole/addClient/createGroup (replaces the
            // dead JAX-RS IgaRepresentationCaptureFilter.pendingRepJson early
            // throw; provider-jar @Provider request filters are never
            // discovered by Keycloak's RESTEasy runtime, see the addClient
            // comment). Create the REAL (scratch)
            // ClientScopeEntity via super so Keycloak's
            // RepresentationToModel.createClientScope (invoked by
            // ClientScopesResource.createClientScope) can apply the
            // COMPLETE incoming ClientScopeRepresentation (name, description,
            // protocol, protocol mappers WITH full config, attributes) to a
            // genuine ClientScopeAdapter. The IgaClientScopeAdapter is returned
            // in capture mode: every per-setter/mapper override falls straight
            // through to the real adapter, and the FIRST unconditional model
            // call KC makes AFTER the conditional-only createClientScope body —
            // clientScope.getId() at ClientScopesResource.createClientScope
            // (adminEvent.resourcePath, then Response.created) — is the terminal
            // seam where the now-complete model is snapshotted to a
            // ClientScopeRepresentation via
            // ModelToRepresentation.toRepresentation(ClientScopeModel) (which —
            // unlike role's composites — DOES serialize name, description,
            // protocol, protocolMappers WITH full config, AND attributes, so NO
            // field accumulation is needed), the CREATE_CLIENT_SCOPE change request
            // (with full REP_JSON) is written in a separate transaction, the
            // REQUEST transaction is marked rollback-only and
            // IgaPendingApprovalException is thrown (→ HTTP 202 + Location).
            // The scratch scope + its protocol mappers + attributes are
            // discarded by the request-tx rollback exactly as in
            // IgaClientAdapter. See IgaClientScopeAdapter capture-mode javadoc.
            String resolvedId = (id != null) ? id : KeycloakModelUtils.generateId();
            ClientScopeModel base = super.addClientScope(realm, resolvedId, name);
            if (base == null) return null;
            ClientScopeEntity entity = em.find(ClientScopeEntity.class, base.getId());
            if (entity == null) return base;
            log.debugf("IGA capture CREATE_CLIENT_SCOPE: scratch client-scope entity created for "
                    + "name=%s (uuid=%s) — accumulating full representation until the model-layer "
                    + "terminal seam (ClientScopesResource.createClientScope#getId)",
                    name, base.getId());
            return new IgaClientScopeAdapter(realm, em, igaSession, entity, /*captureMode=*/ true);
        }
        ClientScopeModel base = super.addClientScope(realm, id, name);
        if (base == null) return null;
        ClientScopeEntity entity = em.find(ClientScopeEntity.class, base.getId());
        if (entity == null) return base;
        return new IgaClientScopeAdapter(realm, em, igaSession, entity);
    }

    @Override
    public ClientScopeModel getClientScopeById(RealmModel realm, String id) {
        ClientScopeModel base = super.getClientScopeById(realm, id);
        if (base == null) return null;
        ClientScopeEntity entity = em.find(ClientScopeEntity.class, id);
        if (entity == null) return base;
        return new IgaClientScopeAdapter(realm, em, igaSession, entity);
    }
}
