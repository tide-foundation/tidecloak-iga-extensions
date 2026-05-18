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

import jakarta.persistence.EntityManager;
import java.util.List;
import java.util.Map;

/**
 * Extends JpaRealmProvider to intercept group/role/client creation and mutations
 * through the IGA approval workflow when IGA is enabled.
 */
public class IgaRealmProvider extends JpaRealmProvider {

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
            String groupId = (id != null) ? id : KeycloakModelUtils.generateId();
            String parentId = (toParent != null) ? toParent.getId() : null;
            Map<String, Object> row = parentId != null
                    ? Map.of("ID", groupId, "NAME", name, "REALM_ID", realm.getId(), "PARENT_GROUP", parentId)
                    : Map.of("ID", groupId, "NAME", name, "REALM_ID", realm.getId());
            recordAndThrow(realm, "GROUP", groupId, "CREATE_GROUP", List.of(row));
            return null; // unreachable
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
            recordAndThrow(realm, "ROLE", roleId, "CREATE_ROLE",
                    List.of(Map.of(
                            "ID", roleId,
                            "NAME", name,
                            "REALM_ID", realm.getId(),
                            "CLIENT_ROLE", false
                    )));
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
            recordAndThrow(realm, "ROLE", roleId, "CREATE_ROLE",
                    List.of(Map.of(
                            "ID", roleId,
                            "NAME", name,
                            "REALM_ID", realm.getId(),
                            // rowsJson contract: CLIENT_UUID = client UUID,
                            // CLIENT_ID = human clientId (never a UUID).
                            "CLIENT_UUID", client.getId(),
                            "CLIENT_ID", client.getClientId(),
                            "CLIENT_REALM_CONSTRAINT", realm.getId(),
                            "CLIENT_ROLE", true
                    )));
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
            String resolvedId = (id != null) ? id : KeycloakModelUtils.generateId();
            // rowsJson contract: ID = own client UUID, CLIENT_ID = human
            // clientId, CLIENT_UUID = same UUID (referenced-client alias so
            // replay's resolveClient works uniformly), REALM_ID = realm UUID.
            Map<String, Object> row = new java.util.LinkedHashMap<>();
            row.put("ID", resolvedId);
            row.put("CLIENT_UUID", resolvedId);
            row.put("CLIENT_ID", clientId);
            row.put("REALM_ID", realm.getId());
            // PART B: the JAX-RS request filter (IgaClientRepresentationCaptureFilter)
            // buffers POST {realm}/clients and stashes the full
            // ClientRepresentation as a session attribute. If present, capture
            // the FULL representation so replay can rebuild redirectUris,
            // webOrigins, attributes, mappers, scopes and flow flags — not just
            // the bare identity. Absent only for non-REST programmatic callers.
            Object rep = igaSession.getAttribute("IGA_PENDING_CLIENT_REP");
            if (rep instanceof String repJson && !repJson.isEmpty()) {
                row.put("REP_JSON", repJson);
            }
            recordAndThrow(realm, "CLIENT", resolvedId, "CREATE_CLIENT", List.of(row));
            return null; // unreachable
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
            recordAndThrow(realm, "CLIENT_SCOPE", resolvedId, "CREATE_CLIENT_SCOPE",
                    List.of(Map.of(
                            "ID", resolvedId,
                            "NAME", name,
                            "REALM_ID", realm.getId(),
                            "PROTOCOL", "openid-connect"
                    )));
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
