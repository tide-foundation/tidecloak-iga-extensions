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
        if (isIgaActive(realm)) {
            String roleId = (id != null) ? id : KeycloakModelUtils.generateId();
            Map<String, Object> row = new java.util.LinkedHashMap<>();
            row.put("ID", roleId);
            row.put("NAME", name);
            row.put("REALM_ID", realm.getId());
            row.put("CLIENT_ROLE", false);
            // Full-representation capture: the JAX-RS filter stashes the POST
            // {realm}/roles RoleRepresentation so replay can rebuild
            // description/attributes/composites, not just the bare id+name.
            String repJson = org.tidecloak.iga.rest.IgaRepresentationCaptureFilter
                    .pendingRepJson(igaSession,
                            org.tidecloak.iga.rest.IgaRepresentationCaptureFilter.TYPE_ROLE);
            if (repJson != null) {
                row.put("REP_JSON", repJson);
            }
            recordAndThrow(realm, "ROLE", roleId, "CREATE_ROLE", List.of(row));
            return null; // unreachable
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
        if (isIgaActive(realm)) {
            String roleId = (id != null) ? id : KeycloakModelUtils.generateId();
            Map<String, Object> row = new java.util.LinkedHashMap<>();
            row.put("ID", roleId);
            row.put("NAME", name);
            row.put("REALM_ID", realm.getId());
            // rowsJson contract: CLIENT_UUID = client UUID,
            // CLIENT_ID = human clientId (never a UUID).
            row.put("CLIENT_UUID", client.getId());
            row.put("CLIENT_ID", client.getClientId());
            row.put("CLIENT_REALM_CONSTRAINT", realm.getId());
            row.put("CLIENT_ROLE", true);
            // Full-representation capture: POST {realm}/clients/{id}/roles.
            String repJson = org.tidecloak.iga.rest.IgaRepresentationCaptureFilter
                    .pendingRepJson(igaSession,
                            org.tidecloak.iga.rest.IgaRepresentationCaptureFilter.TYPE_ROLE);
            if (repJson != null) {
                row.put("REP_JSON", repJson);
            }
            recordAndThrow(realm, "ROLE", roleId, "CREATE_ROLE", List.of(row));
            return null; // unreachable
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
            String resolvedId = (id != null) ? id : KeycloakModelUtils.generateId();
            Map<String, Object> row = new java.util.LinkedHashMap<>();
            row.put("ID", resolvedId);
            row.put("NAME", name);
            row.put("REALM_ID", realm.getId());
            row.put("PROTOCOL", "openid-connect");
            // Full-representation capture: POST {realm}/client-scopes. Replay
            // rebuilds protocol/description/attributes AND protocol mappers
            // (incl. their full config) from the rep.
            String repJson = org.tidecloak.iga.rest.IgaRepresentationCaptureFilter
                    .pendingRepJson(igaSession,
                            org.tidecloak.iga.rest.IgaRepresentationCaptureFilter.TYPE_CLIENT_SCOPE);
            if (repJson != null) {
                row.put("REP_JSON", repJson);
            }
            recordAndThrow(realm, "CLIENT_SCOPE", resolvedId, "CREATE_CLIENT_SCOPE", List.of(row));
            return null; // unreachable
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
