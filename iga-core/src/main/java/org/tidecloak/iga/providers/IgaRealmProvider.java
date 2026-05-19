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
import java.util.List;
import java.util.Map;

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
     * the rollback caused by the pending-approval exception we throw afterwards.
     * Throws the exception to interrupt the original write flow.
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
        throw new IgaPendingApprovalException(crIdHolder[0], entityType, actionType);
    }

    // -------------------------------------------------------------------------
    // GROUP
    // -------------------------------------------------------------------------

    @Override
    public GroupModel createGroup(RealmModel realm, String id, Type type, String name, GroupModel toParent) {
        // Phase 4 — partialImport batch governance for GROUP. This branch MUST
        // come BEFORE the single-entity isIgaActive() capture return.
        //
        // Bug it fixes: under POST /partialImport, KC's
        // GroupsPartialImport.create → RepresentationToModel.importGroup calls
        // realm.createGroup(...) (→ here) then applies setDescription /
        // setAttribute / grantRole only CONDITIONALLY, and
        // AbstractPartialImport.doImport immediately calls
        // GroupsPartialImport.getModelId → KeycloakModelUtils.findGroupByPath
        // (...).getId(). Returning a single-entity capture adapter meant the
        // IgaGroupAdapter#setDescription terminal seam either never fired
        // (no description → ungoverned) or fired per-entity mid-import (the
        // first entity aborted the whole import), and the scratch group on the
        // veto path made findGroupByPath(...) return null → NPE at
        // GroupsPartialImport:53 → KC-SERVICES0037 → HTTP 500.
        //
        // Fix (identical mechanism to the 5-arg addUser deferred-harvest /
        // IgaUserProvider.addUser import branch): create the REAL scratch group
        // via super and return a CAPTURE-mode IgaGroupAdapter so per-setter
        // interception is bypassed and KC's importGroup builds the COMPLETE
        // real model (so findGroupByPath/getModelId resolves a real id).
        // markImportDeferred() makes the setDescription seam inert; the
        // CREATE_GROUP row is harvested ONCE for the batch by the Phase 4
        // BatchEmitTransaction (registerImportGroup), which vetoes/replays it
        // with the rest of the import. No per-entity throw.
        if (IgaImportMode.isImportMode(igaSession, realm)) {
            GroupModel base = super.createGroup(realm, id, type, name, toParent);
            if (base == null) return null;
            GroupEntity entity = em.find(GroupEntity.class, base.getId());
            if (entity == null) return base;
            log.infof("IGA multi-entity: capture CREATE_GROUP via partialImport "
                    + "RepresentationToModel.importGroup for name=%s (uuid=%s, "
                    + "parent=%s) — capture-mode adapter registered with the "
                    + "batch (deferred-harvest; group create proceeds so "
                    + "GroupsPartialImport.getModelId resolves a real id)",
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
        // Phase 4 — partialImport batch governance for REALM ROLE. Same gap
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
        // CREATE_ROLE row is harvested ONCE for the batch by the Phase 4
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
        // Phase 4 — partialImport batch governance for CLIENT ROLE. Same gap
        // class as addRealmRole: under POST /partialImport, KC's
        // RolesPartialImport.doImport → RepresentationToModel.importRoles
        // (client-roles branch, RepresentationToModel:167-174) calls
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
    // CLIENT SCOPE
    // -------------------------------------------------------------------------

    @Override
    public ClientScopeModel addClientScope(RealmModel realm, String id, String name) {
        if (isIgaActive(realm)) {
            // Model-layer accumulate-then-veto — the SAME proven mechanism as
            // addRealmRole/addClientRole/addClient/createGroup (replaces the
            // dead JAX-RS IgaRepresentationCaptureFilter.pendingRepJson early
            // throw; provider-jar @Provider request filters are never
            // discovered by Keycloak's RESTEasy runtime, see the addClient
            // comment / Phase 1 report). Create the REAL (scratch)
            // ClientScopeEntity via super so Keycloak's
            // RepresentationToModel.createClientScope (KC 26.5.5
            // RepresentationToModel.java:715-740, invoked by
            // ClientScopesResource.createClientScope:131) can apply the
            // COMPLETE incoming ClientScopeRepresentation (name, description,
            // protocol, protocol mappers WITH full config, attributes) to a
            // genuine ClientScopeAdapter. The IgaClientScopeAdapter is returned
            // in capture mode: every per-setter/mapper override falls straight
            // through to the real adapter, and the FIRST unconditional model
            // call KC makes AFTER the conditional-only createClientScope body —
            // clientScope.getId() at ClientScopesResource.createClientScope
            // line 133 (adminEvent.resourcePath), again at 135
            // (Response.created) — is the terminal seam where the now-complete
            // model is snapshotted to a ClientScopeRepresentation via
            // ModelToRepresentation.toRepresentation(ClientScopeModel) (which —
            // unlike role's composites — DOES serialize name, description,
            // protocol, protocolMappers WITH full config, AND attributes:
            // KC 26.5.5 ModelToRepresentation.java:821-835, so NO field
            // accumulation is needed), the CREATE_CLIENT_SCOPE change request
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
