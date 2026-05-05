package org.tidecloak.iga.replay;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;

import jakarta.persistence.EntityManager;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Replays an approved IGA change request by invoking the real Keycloak model
 * operations with IGA_REPLAY_ACTIVE set, then writing the final signature
 * onto the affected rows via JPQL UPDATE.
 */
public class IgaReplayDispatcher {

    private static final Logger log = Logger.getLogger(IgaReplayDispatcher.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<List<Map<String, Object>>> LIST_MAP_REF =
            new TypeReference<List<Map<String, Object>>>() {};

    public static void replay(KeycloakSession session, IgaChangeRequestEntity cr, String finalSignature) {
        session.setAttribute("IGA_REPLAY_ACTIVE", "true");
        try {
            doReplay(session, cr, finalSignature);
        } finally {
            session.removeAttribute("IGA_REPLAY_ACTIVE");
        }
    }

    private static void doReplay(KeycloakSession session, IgaChangeRequestEntity cr, String finalSignature) {
        RealmModel realm = session.realms().getRealm(cr.getRealmId());
        List<Map<String, Object>> rows = parseRows(cr.getRowsJson());
        EntityManager em = getEm(session);

        switch (cr.getActionType()) {
            case "CREATE_USER" -> replayCreateUser(session, realm, rows, finalSignature, em);
            case "CREATE_ROLE" -> replayCreateRole(session, realm, rows, finalSignature, em);
            case "CREATE_GROUP" -> replayCreateGroup(session, realm, rows, finalSignature, em);
            case "CREATE_CLIENT" -> replayCreateClient(session, realm, rows, finalSignature, em);
            case "ADD_PROTOCOL_MAPPER" -> replayAddProtocolMapper(session, realm, cr, rows, finalSignature, em);
            case "GRANT_ROLES" -> replayRelationship(session, realm, rows, finalSignature, em,
                    "UPDATE UserRoleMappingEntity e SET e.signature = :sig WHERE e.userId = :k1 AND e.roleId = :k2",
                    r -> grantRoleDirect(session, realm, r));
            case "REVOKE_ROLES" -> replayRevoke(session, realm, rows, em,
                    r -> revokeRoleDirect(session, realm, r));
            case "JOIN_GROUPS" -> replayRelationship(session, realm, rows, finalSignature, em,
                    "UPDATE UserGroupMembershipEntity e SET e.signature = :sig WHERE e.user = :k1 AND e.group = :k2",
                    r -> joinGroupDirect(session, realm, r));
            case "LEAVE_GROUPS" -> replayRevoke(session, realm, rows, em,
                    r -> leaveGroupDirect(session, realm, r));
            case "GROUP_GRANT_ROLES" -> replayRelationship(session, realm, rows, finalSignature, em,
                    "UPDATE GroupRoleMappingEntity e SET e.signature = :sig WHERE e.group = :k1 AND e.role = :k2",
                    r -> groupGrantRoleDirect(session, realm, r));
            case "GROUP_REVOKE_ROLES" -> replayRevoke(session, realm, rows, em,
                    r -> groupRevokeRoleDirect(session, realm, r));
            case "ADD_COMPOSITE" -> replayRelationship(session, realm, rows, finalSignature, em,
                    "UPDATE CompositeRoleEntity e SET e.signature = :sig WHERE e.composite = :k1 AND e.childRole = :k2",
                    r -> addCompositeDirect(session, realm, r));
            case "REMOVE_COMPOSITE" -> replayRevoke(session, realm, rows, em,
                    r -> removeCompositeDirect(session, realm, r));
            case "ASSIGN_SCOPE" -> replayRelationship(session, realm, rows, finalSignature, em,
                    "UPDATE ClientScopeClientMappingEntity e SET e.signature = :sig WHERE e.clientId = :k1 AND e.clientScopeId = :k2",
                    r -> assignScopeDirect(session, realm, r));
            case "REMOVE_SCOPE" -> replayRevoke(session, realm, rows, em,
                    r -> removeScopeDirect(session, realm, r));
            case "SCOPE_ADD_ROLE" -> replayRelationship(session, realm, rows, finalSignature, em,
                    "UPDATE ClientScopeRoleMappingEntity e SET e.signature = :sig WHERE e.clientScope = :k1 AND e.role = :k2",
                    r -> scopeAddRoleDirect(session, realm, r));
            case "SCOPE_REMOVE_ROLE" -> replayRevoke(session, realm, rows, em,
                    r -> scopeRemoveRoleDirect(session, realm, r));
            case "REQUEST_SERVER_CERT" -> replayRequestServerCert(cr);
            case "INSTALL_LICENSE", "ROTATE_LICENSE" -> replayLicenseAction(cr);
            default -> throw new IllegalArgumentException("Unknown IGA action: " + cr.getActionType());
        }

        // Mark approved
        IgaChangeRequestEntity managed = em.find(IgaChangeRequestEntity.class, cr.getId());
        if (managed != null) {
            managed.setStatus("APPROVED");
            managed.setResolvedAt(System.currentTimeMillis());
        }
    }

    // -------------------------------------------------------------------------
    // CREATE replays
    // -------------------------------------------------------------------------

    private static void replayCreateUser(KeycloakSession session, RealmModel realm,
                                          List<Map<String, Object>> rows, String sig, EntityManager em) {
        for (Map<String, Object> row : rows) {
            String userId = str(row, "ID");
            String username = str(row, "USERNAME");
            // Use the 5-arg addUser to supply our own ID
            session.users().addUser(realm, userId, username, false, false);
            em.createQuery("UPDATE UserEntity e SET e.signature = :sig WHERE e.id = :id")
                    .setParameter("sig", sig)
                    .setParameter("id", userId)
                    .executeUpdate();
        }
    }

    private static void replayCreateRole(KeycloakSession session, RealmModel realm,
                                          List<Map<String, Object>> rows, String sig, EntityManager em) {
        for (Map<String, Object> row : rows) {
            String id = str(row, "ID");
            String name = str(row, "NAME");
            boolean clientRole = Boolean.TRUE.equals(row.get("CLIENT_ROLE"));
            if (clientRole) {
                String clientId = str(row, "CLIENT_ID");
                ClientModel client = session.clients().getClientById(realm, clientId);
                if (client != null) {
                    session.roles().addClientRole(client, id, name);
                }
            } else {
                session.roles().addRealmRole(realm, id, name);
            }
            em.createQuery("UPDATE RoleEntity e SET e.signature = :sig WHERE e.id = :id")
                    .setParameter("sig", sig)
                    .setParameter("id", id)
                    .executeUpdate();
        }
    }

    private static void replayCreateGroup(KeycloakSession session, RealmModel realm,
                                           List<Map<String, Object>> rows, String sig, EntityManager em) {
        for (Map<String, Object> row : rows) {
            String id = str(row, "ID");
            String name = str(row, "NAME");
            String parentId = str(row, "PARENT_GROUP");
            GroupModel parent = (parentId != null) ? session.groups().getGroupById(realm, parentId) : null;
            session.groups().createGroup(realm, id, name, parent);
            em.createQuery("UPDATE GroupEntity e SET e.signature = :sig WHERE e.id = :id")
                    .setParameter("sig", sig)
                    .setParameter("id", id)
                    .executeUpdate();
        }
    }

    private static void replayCreateClient(KeycloakSession session, RealmModel realm,
                                            List<Map<String, Object>> rows, String sig, EntityManager em) {
        for (Map<String, Object> row : rows) {
            String id = str(row, "ID");
            session.clients().addClient(realm, id, id);
            em.createQuery("UPDATE ClientEntity e SET e.signature = :sig WHERE e.id = :id")
                    .setParameter("sig", sig)
                    .setParameter("id", id)
                    .executeUpdate();
        }
    }

    private static void replayAddProtocolMapper(KeycloakSession session, RealmModel realm,
                                                 IgaChangeRequestEntity cr, List<Map<String, Object>> rows,
                                                 String sig, EntityManager em) {
        for (Map<String, Object> row : rows) {
            String clientId = str(row, "CLIENT_ID");
            String mapperId = str(row, "ID");
            ClientModel client = session.clients().getClientById(realm, clientId);
            if (client != null) {
                org.keycloak.models.ProtocolMapperModel model = new org.keycloak.models.ProtocolMapperModel();
                model.setId(mapperId);
                model.setName(str(row, "NAME"));
                model.setProtocol(str(row, "PROTOCOL"));
                model.setProtocolMapper(str(row, "PROTOCOL_MAPPER_NAME"));
                client.addProtocolMapper(model);
                em.createQuery("UPDATE ProtocolMapperEntity e SET e.signature = :sig WHERE e.id = :id")
                        .setParameter("sig", sig)
                        .setParameter("id", mapperId)
                        .executeUpdate();
            }
        }
    }

    // -------------------------------------------------------------------------
    // Server cert request — sidecar approval (no model write here)
    // -------------------------------------------------------------------------

    /**
     * REQUEST_SERVER_CERT approval grants the workload the right to receive a
     * cert. The sidecar IGA_SERVER_CERT_DRAFT is NOT touched here — issuance
     * is decoupled and happens via POST /iga/server-certs/{draftId}/issue once
     * the signing infrastructure produces the cert + trust bundle. The
     * surrounding doReplay() will mark the parent change request APPROVED.
     */
    private static void replayRequestServerCert(IgaChangeRequestEntity cr) {
        log.infof("REQUEST_SERVER_CERT approved for change request %s — awaiting cert issuance via /iga/server-certs/{draftId}/issue",
                cr.getId());
    }

    // -------------------------------------------------------------------------
    // License install/rotate — sidecar approval (no model write here)
    // -------------------------------------------------------------------------

    /**
     * INSTALL_LICENSE / ROTATE_LICENSE approval grants the realm permission to
     * install or rotate a license. The sidecar IGA_LICENSING_DRAFT is NOT
     * touched here — issuance is decoupled and happens via
     * POST /iga/licensing/drafts/{draftId}/issue once the licensing
     * infrastructure produces the signed license. The surrounding doReplay()
     * will mark the parent change request APPROVED.
     */
    private static void replayLicenseAction(IgaChangeRequestEntity cr) {
        log.infof("License action %s approved for change request %s — awaiting issuance via /iga/licensing/drafts/{draftId}/issue",
                cr.getActionType(), cr.getId());
    }

    // -------------------------------------------------------------------------
    // Relationship replays (add + write sig)
    // -------------------------------------------------------------------------

    private static void replayRelationship(KeycloakSession session, RealmModel realm,
                                            List<Map<String, Object>> rows, String sig, EntityManager em,
                                            String updateJpql, Consumer<Map<String, Object>> addOp) {
        for (Map<String, Object> row : rows) {
            addOp.accept(row);
        }
        // Signature update uses the first row's keys
        if (!rows.isEmpty() && sig != null && !sig.isEmpty()) {
            Map<String, Object> row = rows.get(0);
            // Determine k1/k2 from the JPQL pattern — we extract via the row values by position
            List<Object> keys = extractKeys(row, updateJpql);
            if (keys.size() >= 2) {
                em.createQuery(updateJpql)
                        .setParameter("sig", sig)
                        .setParameter("k1", keys.get(0))
                        .setParameter("k2", keys.get(1))
                        .executeUpdate();
            }
        }
    }

    private static void replayRevoke(KeycloakSession session, RealmModel realm,
                                      List<Map<String, Object>> rows, EntityManager em,
                                      Consumer<Map<String, Object>> removeOp) {
        for (Map<String, Object> row : rows) {
            removeOp.accept(row);
        }
    }

    // -------------------------------------------------------------------------
    // Direct model operations (called with IGA_REPLAY_ACTIVE = true)
    // -------------------------------------------------------------------------

    private static void grantRoleDirect(KeycloakSession session, RealmModel realm, Map<String, Object> row) {
        String userId = str(row, "USER_ID");
        String roleId = str(row, "ROLE_ID");
        org.keycloak.models.UserModel user = session.users().getUserById(realm, userId);
        RoleModel role = session.roles().getRoleById(realm, roleId);
        if (user != null && role != null) user.grantRole(role);
    }

    private static void revokeRoleDirect(KeycloakSession session, RealmModel realm, Map<String, Object> row) {
        String userId = str(row, "USER_ID");
        String roleId = str(row, "ROLE_ID");
        org.keycloak.models.UserModel user = session.users().getUserById(realm, userId);
        RoleModel role = session.roles().getRoleById(realm, roleId);
        if (user != null && role != null) user.deleteRoleMapping(role);
    }

    private static void joinGroupDirect(KeycloakSession session, RealmModel realm, Map<String, Object> row) {
        String userId = str(row, "USER");
        String groupId = str(row, "GROUP");
        org.keycloak.models.UserModel user = session.users().getUserById(realm, userId);
        GroupModel group = session.groups().getGroupById(realm, groupId);
        if (user != null && group != null) user.joinGroup(group);
    }

    private static void leaveGroupDirect(KeycloakSession session, RealmModel realm, Map<String, Object> row) {
        String userId = str(row, "USER");
        String groupId = str(row, "GROUP");
        org.keycloak.models.UserModel user = session.users().getUserById(realm, userId);
        GroupModel group = session.groups().getGroupById(realm, groupId);
        if (user != null && group != null) user.leaveGroup(group);
    }

    private static void groupGrantRoleDirect(KeycloakSession session, RealmModel realm, Map<String, Object> row) {
        String groupId = str(row, "GROUP");
        String roleId = str(row, "ROLE");
        GroupModel group = session.groups().getGroupById(realm, groupId);
        RoleModel role = session.roles().getRoleById(realm, roleId);
        if (group != null && role != null) group.grantRole(role);
    }

    private static void groupRevokeRoleDirect(KeycloakSession session, RealmModel realm, Map<String, Object> row) {
        String groupId = str(row, "GROUP");
        String roleId = str(row, "ROLE");
        GroupModel group = session.groups().getGroupById(realm, groupId);
        RoleModel role = session.roles().getRoleById(realm, roleId);
        if (group != null && role != null) group.deleteRoleMapping(role);
    }

    private static void addCompositeDirect(KeycloakSession session, RealmModel realm, Map<String, Object> row) {
        String compositeId = str(row, "COMPOSITE");
        String childId = str(row, "CHILD_ROLE");
        RoleModel composite = session.roles().getRoleById(realm, compositeId);
        RoleModel child = session.roles().getRoleById(realm, childId);
        if (composite != null && child != null) composite.addCompositeRole(child);
    }

    private static void removeCompositeDirect(KeycloakSession session, RealmModel realm, Map<String, Object> row) {
        String compositeId = str(row, "COMPOSITE");
        String childId = str(row, "CHILD_ROLE");
        RoleModel composite = session.roles().getRoleById(realm, compositeId);
        RoleModel child = session.roles().getRoleById(realm, childId);
        if (composite != null && child != null) composite.removeCompositeRole(child);
    }

    private static void assignScopeDirect(KeycloakSession session, RealmModel realm, Map<String, Object> row) {
        String clientId = str(row, "CLIENT_ID");
        String scopeId = str(row, "SCOPE_ID");
        boolean defaultScope = Boolean.TRUE.equals(row.get("DEFAULT_SCOPE"));
        ClientModel client = session.clients().getClientById(realm, clientId);
        ClientScopeModel scope = session.clientScopes().getClientScopeById(realm, scopeId);
        if (client != null && scope != null) client.addClientScope(scope, defaultScope);
    }

    private static void removeScopeDirect(KeycloakSession session, RealmModel realm, Map<String, Object> row) {
        String clientId = str(row, "CLIENT_ID");
        String scopeId = str(row, "SCOPE_ID");
        ClientModel client = session.clients().getClientById(realm, clientId);
        ClientScopeModel scope = session.clientScopes().getClientScopeById(realm, scopeId);
        if (client != null && scope != null) client.removeClientScope(scope);
    }

    private static void scopeAddRoleDirect(KeycloakSession session, RealmModel realm, Map<String, Object> row) {
        String scopeId = str(row, "SCOPE_ID");
        String roleId = str(row, "ROLE_ID");
        ClientScopeModel scope = session.clientScopes().getClientScopeById(realm, scopeId);
        RoleModel role = session.roles().getRoleById(realm, roleId);
        if (scope != null && role != null) scope.addScopeMapping(role);
    }

    private static void scopeRemoveRoleDirect(KeycloakSession session, RealmModel realm, Map<String, Object> row) {
        String scopeId = str(row, "SCOPE_ID");
        String roleId = str(row, "ROLE_ID");
        ClientScopeModel scope = session.clientScopes().getClientScopeById(realm, scopeId);
        RoleModel role = session.roles().getRoleById(realm, roleId);
        if (scope != null && role != null) scope.deleteScopeMapping(role);
    }

    // -------------------------------------------------------------------------
    // Utilities
    // -------------------------------------------------------------------------

    private static EntityManager getEm(KeycloakSession session) {
        return session.getProvider(JpaConnectionProvider.class).getEntityManager();
    }

    private static List<Map<String, Object>> parseRows(String rowsJson) {
        try {
            return MAPPER.readValue(rowsJson, LIST_MAP_REF);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse rows JSON", e);
        }
    }

    private static String str(Map<String, Object> row, String key) {
        Object v = row.get(key);
        return v != null ? v.toString() : null;
    }

    /**
     * Extract the two relationship key values from the row based on the JPQL WHERE clause params :k1 and :k2.
     * We map the JPQL entity field names to row key names.
     */
    private static List<Object> extractKeys(Map<String, Object> row, String jpql) {
        // Parse key names from JPQL: "e.fieldA = :k1 AND e.fieldB = :k2"
        // Simple heuristic: look for patterns "e.<field> = :k1" and "e.<field> = :k2"
        java.util.regex.Pattern k1Pat = java.util.regex.Pattern.compile("e\\.(\\w+)\\s*=\\s*:k1");
        java.util.regex.Pattern k2Pat = java.util.regex.Pattern.compile("e\\.(\\w+)\\s*=\\s*:k2");
        java.util.regex.Matcher m1 = k1Pat.matcher(jpql);
        java.util.regex.Matcher m2 = k2Pat.matcher(jpql);
        if (m1.find() && m2.find()) {
            String field1 = m1.group(1);
            String field2 = m2.group(1);
            // Map JPA field names to row map keys (camelCase -> uppercase)
            Object v1 = findValue(row, field1);
            Object v2 = findValue(row, field2);
            if (v1 != null && v2 != null) return List.of(v1, v2);
        }
        return List.of();
    }

    private static Object findValue(Map<String, Object> row, String jpaField) {
        // Try exact match first, then uppercase
        if (row.containsKey(jpaField)) return row.get(jpaField);
        String upper = jpaField.toUpperCase();
        if (row.containsKey(upper)) return row.get(upper);
        // Try common mappings
        return switch (jpaField) {
            case "userId" -> row.get("USER_ID");
            case "roleId" -> row.get("ROLE_ID");
            case "user" -> row.get("USER");
            case "group" -> row.get("GROUP");
            case "role" -> row.get("ROLE");
            case "composite" -> row.get("COMPOSITE");
            case "childRole" -> row.get("CHILD_ROLE");
            case "clientId" -> row.get("CLIENT_ID");
            case "clientScopeId" -> row.get("SCOPE_ID");
            case "clientScope" -> row.get("SCOPE_ID");
            default -> null;
        };
    }
}
