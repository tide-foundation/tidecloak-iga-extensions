package org.tidecloak.iga.replay;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
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
import jakarta.persistence.Query;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Replays an approved IGA change request by invoking the real Keycloak model
 * operations with IGA_REPLAY_ACTIVE set, then writing the final attestation
 * onto the affected rows via JPQL UPDATE.
 */
public class IgaReplayDispatcher {

    private static final Logger log = Logger.getLogger(IgaReplayDispatcher.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<List<Map<String, Object>>> LIST_MAP_REF =
            new TypeReference<List<Map<String, Object>>>() {};

    public static void replay(KeycloakSession session, IgaChangeRequestEntity cr, String finalAttestation) {
        session.setAttribute("IGA_REPLAY_ACTIVE", "true");
        try {
            doReplay(session, cr, finalAttestation);
        } finally {
            session.removeAttribute("IGA_REPLAY_ACTIVE");
        }
    }

    private static void doReplay(KeycloakSession session, IgaChangeRequestEntity cr, String finalAttestation) {
        RealmModel realm = session.realms().getRealm(cr.getRealmId());
        EntityManager em = getEm(session);

        // BASELINE_APPROVAL has a structured rows_json with a top-level
        // "tables" object — it doesn't match the flat List shape used by
        // every other action. Handle it before the generic parse.
        if ("BASELINE_APPROVAL".equals(cr.getActionType())) {
            replayBaselineApproval(em, cr, finalAttestation);
            IgaChangeRequestEntity managedBaseline = em.find(IgaChangeRequestEntity.class, cr.getId());
            if (managedBaseline != null) {
                managedBaseline.setStatus("APPROVED");
                managedBaseline.setResolvedAt(System.currentTimeMillis());
            }
            return;
        }

        List<Map<String, Object>> rows = parseRows(cr.getRowsJson());

        switch (cr.getActionType()) {
            case "CREATE_USER" -> replayCreateUser(session, realm, rows, finalAttestation, em);
            case "CREATE_ROLE" -> replayCreateRole(session, realm, rows, finalAttestation, em);
            case "CREATE_GROUP" -> replayCreateGroup(session, realm, rows, finalAttestation, em);
            case "CREATE_CLIENT" -> replayCreateClient(session, realm, rows, finalAttestation, em);
            case "ADD_PROTOCOL_MAPPER" -> replayAddProtocolMapper(session, realm, cr, rows, finalAttestation, em);
            case "GRANT_ROLES" -> replayRelationship(session, realm, rows, finalAttestation, em,
                    "UPDATE UserRoleMappingEntity e SET e.attestation = :sig WHERE e.userId = :k1 AND e.roleId = :k2",
                    r -> grantRoleDirect(session, realm, r));
            case "REVOKE_ROLES" -> replayRevoke(session, realm, rows, em,
                    r -> revokeRoleDirect(session, realm, r));
            case "JOIN_GROUPS" -> replayRelationship(session, realm, rows, finalAttestation, em,
                    "UPDATE UserGroupMembershipEntity e SET e.attestation = :sig WHERE e.user = :k1 AND e.group = :k2",
                    r -> joinGroupDirect(session, realm, r));
            case "LEAVE_GROUPS" -> replayRevoke(session, realm, rows, em,
                    r -> leaveGroupDirect(session, realm, r));
            case "GROUP_GRANT_ROLES" -> replayRelationship(session, realm, rows, finalAttestation, em,
                    "UPDATE GroupRoleMappingEntity e SET e.attestation = :sig WHERE e.group = :k1 AND e.role = :k2",
                    r -> groupGrantRoleDirect(session, realm, r));
            case "GROUP_REVOKE_ROLES" -> replayRevoke(session, realm, rows, em,
                    r -> groupRevokeRoleDirect(session, realm, r));
            case "ADD_COMPOSITE" -> replayRelationship(session, realm, rows, finalAttestation, em,
                    "UPDATE CompositeRoleEntity e SET e.attestation = :sig WHERE e.composite = :k1 AND e.childRole = :k2",
                    r -> addCompositeDirect(session, realm, r));
            case "REMOVE_COMPOSITE" -> replayRevoke(session, realm, rows, em,
                    r -> removeCompositeDirect(session, realm, r));
            case "ASSIGN_SCOPE" -> replayRelationship(session, realm, rows, finalAttestation, em,
                    "UPDATE ClientScopeClientMappingEntity e SET e.attestation = :sig WHERE e.clientId = :k1 AND e.clientScopeId = :k2",
                    r -> assignScopeDirect(session, realm, r));
            case "REMOVE_SCOPE" -> replayRevoke(session, realm, rows, em,
                    r -> removeScopeDirect(session, realm, r));
            case "SCOPE_ADD_ROLE" -> replayRelationship(session, realm, rows, finalAttestation, em,
                    "UPDATE ClientScopeRoleMappingEntity e SET e.attestation = :sig WHERE e.clientScope = :k1 AND e.role = :k2",
                    r -> scopeAddRoleDirect(session, realm, r));
            case "SCOPE_REMOVE_ROLE" -> replayRevoke(session, realm, rows, em,
                    r -> scopeRemoveRoleDirect(session, realm, r));
            case "REQUEST_SERVER_CERT" -> replayRequestServerCert(cr);
            case "INSTALL_LICENSE", "ROTATE_LICENSE" -> replayLicenseAction(cr);

            // ----- Attribute writes -----
            case "SET_USER_ATTRIBUTE" -> replaySetUserAttribute(session, realm, rows, finalAttestation, em);
            case "REMOVE_USER_ATTRIBUTE" -> replayRemoveUserAttribute(session, realm, rows, em);
            case "SET_CLIENT_ATTRIBUTE" -> replaySetClientAttribute(session, realm, rows, finalAttestation, em);
            case "REMOVE_CLIENT_ATTRIBUTE" -> replayRemoveClientAttribute(session, realm, rows, em);
            case "SET_CLIENT_SCOPE_ATTRIBUTE" -> replaySetClientScopeAttribute(session, realm, rows, finalAttestation, em);
            case "REMOVE_CLIENT_SCOPE_ATTRIBUTE" -> replayRemoveClientScopeAttribute(session, realm, rows, em);
            case "SET_GROUP_ATTRIBUTE" -> replaySetGroupAttribute(session, realm, rows, finalAttestation, em);
            case "REMOVE_GROUP_ATTRIBUTE" -> replayRemoveGroupAttribute(session, realm, rows, em);
            case "SET_ROLE_ATTRIBUTE" -> replaySetRoleAttribute(session, realm, rows, finalAttestation, em);
            case "REMOVE_ROLE_ATTRIBUTE" -> replayRemoveRoleAttribute(session, realm, rows, em);
            case "SET_REALM_ATTRIBUTE" -> replaySetRealmAttribute(session, realm, rows, finalAttestation, em);
            case "REMOVE_REALM_ATTRIBUTE" -> replayRemoveRealmAttribute(session, realm, rows, em);

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
            em.createQuery("UPDATE UserEntity e SET e.attestation = :sig WHERE e.id = :id")
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
            em.createQuery("UPDATE RoleEntity e SET e.attestation = :sig WHERE e.id = :id")
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
            em.createQuery("UPDATE GroupEntity e SET e.attestation = :sig WHERE e.id = :id")
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
            em.createQuery("UPDATE ClientEntity e SET e.attestation = :sig WHERE e.id = :id")
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
                em.createQuery("UPDATE ProtocolMapperEntity e SET e.attestation = :sig WHERE e.id = :id")
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
        // Attestation update uses the first row's keys
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
    // Attribute replays.
    //
    // Approach: rebuild the attribute(s) by calling the underlying model's
    // setAttribute/removeAttribute (with IGA_REPLAY_ACTIVE = true so the IGA
    // wrappers pass straight through), then UPDATE the just-written rows with
    // the final attestation via JPQL. The attribute entities
    // (UserAttributeEntity / ClientAttributeEntity / ClientScopeAttributeEntity
    // / GroupAttributeEntity / RoleAttributeEntity / RealmAttributeEntity) all
    // declare an {@code attestation} field (see tidecloak-override).
    //
    // Multi-value SET requests carry one row per value. We group rows by
    // (parent_id, name) so the model write is a single setAttribute(name,
    // values) call, matching the original admin intent.
    // -------------------------------------------------------------------------

    private static java.util.Map<String, java.util.LinkedHashMap<String, java.util.List<String>>>
            groupByParentAndName(List<Map<String, Object>> rows, String parentKey) {
        java.util.Map<String, java.util.LinkedHashMap<String, java.util.List<String>>> out = new java.util.LinkedHashMap<>();
        for (Map<String, Object> row : rows) {
            String pid = str(row, parentKey);
            String name = str(row, "NAME");
            String value = str(row, "VALUE");
            if (pid == null || name == null) continue;
            out.computeIfAbsent(pid, k -> new java.util.LinkedHashMap<>())
                    .computeIfAbsent(name, k -> new java.util.ArrayList<>())
                    .add(value);
        }
        return out;
    }

    // ----- USER -----

    private static void replaySetUserAttribute(KeycloakSession session, RealmModel realm,
                                                List<Map<String, Object>> rows, String sig, EntityManager em) {
        var grouped = groupByParentAndName(rows, "USER_ID");
        for (var ue : grouped.entrySet()) {
            String userId = ue.getKey();
            org.keycloak.models.UserModel user = session.users().getUserById(realm, userId);
            if (user == null) continue;
            for (var ne : ue.getValue().entrySet()) {
                String name = ne.getKey();
                java.util.List<String> values = ne.getValue();
                user.setAttribute(name, values);
                stampSigJpql(em,
                        "UPDATE UserAttributeEntity e SET e.attestation = :sig " +
                                "WHERE e.user.id = :pid AND e.name = :name",
                        sig, userId, name);
            }
        }
    }

    private static void replayRemoveUserAttribute(KeycloakSession session, RealmModel realm,
                                                   List<Map<String, Object>> rows, EntityManager em) {
        for (Map<String, Object> row : rows) {
            String userId = str(row, "USER_ID");
            String name = str(row, "NAME");
            org.keycloak.models.UserModel user = session.users().getUserById(realm, userId);
            if (user != null && name != null) user.removeAttribute(name);
        }
    }

    // ----- CLIENT -----

    private static void replaySetClientAttribute(KeycloakSession session, RealmModel realm,
                                                  List<Map<String, Object>> rows, String sig, EntityManager em) {
        for (Map<String, Object> row : rows) {
            String clientId = str(row, "CLIENT_ID");
            String name = str(row, "NAME");
            String value = str(row, "VALUE");
            ClientModel client = session.clients().getClientById(realm, clientId);
            if (client == null || name == null) continue;
            client.setAttribute(name, value);
            stampSigJpql(em,
                    "UPDATE ClientAttributeEntity e SET e.attestation = :sig " +
                            "WHERE e.client.id = :pid AND e.name = :name",
                    sig, clientId, name);
        }
    }

    private static void replayRemoveClientAttribute(KeycloakSession session, RealmModel realm,
                                                     List<Map<String, Object>> rows, EntityManager em) {
        for (Map<String, Object> row : rows) {
            String clientId = str(row, "CLIENT_ID");
            String name = str(row, "NAME");
            ClientModel client = session.clients().getClientById(realm, clientId);
            if (client != null && name != null) client.removeAttribute(name);
        }
    }

    // ----- CLIENT_SCOPE -----

    private static void replaySetClientScopeAttribute(KeycloakSession session, RealmModel realm,
                                                       List<Map<String, Object>> rows, String sig, EntityManager em) {
        for (Map<String, Object> row : rows) {
            String scopeId = str(row, "SCOPE_ID");
            String name = str(row, "NAME");
            String value = str(row, "VALUE");
            ClientScopeModel scope = session.clientScopes().getClientScopeById(realm, scopeId);
            if (scope == null || name == null) continue;
            scope.setAttribute(name, value);
            stampSigJpql(em,
                    "UPDATE ClientScopeAttributeEntity e SET e.attestation = :sig " +
                            "WHERE e.clientScope.id = :pid AND e.name = :name",
                    sig, scopeId, name);
        }
    }

    private static void replayRemoveClientScopeAttribute(KeycloakSession session, RealmModel realm,
                                                          List<Map<String, Object>> rows, EntityManager em) {
        for (Map<String, Object> row : rows) {
            String scopeId = str(row, "SCOPE_ID");
            String name = str(row, "NAME");
            ClientScopeModel scope = session.clientScopes().getClientScopeById(realm, scopeId);
            if (scope != null && name != null) scope.removeAttribute(name);
        }
    }

    // ----- GROUP -----

    private static void replaySetGroupAttribute(KeycloakSession session, RealmModel realm,
                                                 List<Map<String, Object>> rows, String sig, EntityManager em) {
        var grouped = groupByParentAndName(rows, "GROUP_ID");
        for (var ge : grouped.entrySet()) {
            String groupId = ge.getKey();
            GroupModel group = session.groups().getGroupById(realm, groupId);
            if (group == null) continue;
            for (var ne : ge.getValue().entrySet()) {
                String name = ne.getKey();
                java.util.List<String> values = ne.getValue();
                group.setAttribute(name, values);
                stampSigJpql(em,
                        "UPDATE GroupAttributeEntity e SET e.attestation = :sig " +
                                "WHERE e.group.id = :pid AND e.name = :name",
                        sig, groupId, name);
            }
        }
    }

    private static void replayRemoveGroupAttribute(KeycloakSession session, RealmModel realm,
                                                    List<Map<String, Object>> rows, EntityManager em) {
        for (Map<String, Object> row : rows) {
            String groupId = str(row, "GROUP_ID");
            String name = str(row, "NAME");
            GroupModel group = session.groups().getGroupById(realm, groupId);
            if (group != null && name != null) group.removeAttribute(name);
        }
    }

    // ----- ROLE -----

    private static void replaySetRoleAttribute(KeycloakSession session, RealmModel realm,
                                                List<Map<String, Object>> rows, String sig, EntityManager em) {
        var grouped = groupByParentAndName(rows, "ROLE_ID");
        for (var re : grouped.entrySet()) {
            String roleId = re.getKey();
            RoleModel role = session.roles().getRoleById(realm, roleId);
            if (role == null) continue;
            for (var ne : re.getValue().entrySet()) {
                String name = ne.getKey();
                java.util.List<String> values = ne.getValue();
                role.setAttribute(name, values);
                stampSigJpql(em,
                        "UPDATE RoleAttributeEntity e SET e.attestation = :sig " +
                                "WHERE e.role.id = :pid AND e.name = :name",
                        sig, roleId, name);
            }
        }
    }

    private static void replayRemoveRoleAttribute(KeycloakSession session, RealmModel realm,
                                                   List<Map<String, Object>> rows, EntityManager em) {
        for (Map<String, Object> row : rows) {
            String roleId = str(row, "ROLE_ID");
            String name = str(row, "NAME");
            RoleModel role = session.roles().getRoleById(realm, roleId);
            if (role != null && name != null) role.removeAttribute(name);
        }
    }

    // ----- REALM -----

    private static void replaySetRealmAttribute(KeycloakSession session, RealmModel realm,
                                                 List<Map<String, Object>> rows, String sig, EntityManager em) {
        for (Map<String, Object> row : rows) {
            String realmId = str(row, "REALM_ID");
            String name = str(row, "NAME");
            String value = str(row, "VALUE");
            RealmModel target = (realmId != null && realmId.equals(realm.getId()))
                    ? realm
                    : session.realms().getRealm(realmId);
            if (target == null || name == null) continue;
            target.setAttribute(name, value);
            stampSigJpql(em,
                    "UPDATE RealmAttributeEntity e SET e.attestation = :sig " +
                            "WHERE e.realm.id = :pid AND e.name = :name",
                    sig, realmId, name);
        }
    }

    private static void replayRemoveRealmAttribute(KeycloakSession session, RealmModel realm,
                                                    List<Map<String, Object>> rows, EntityManager em) {
        for (Map<String, Object> row : rows) {
            String realmId = str(row, "REALM_ID");
            String name = str(row, "NAME");
            RealmModel target = (realmId != null && realmId.equals(realm.getId()))
                    ? realm
                    : session.realms().getRealm(realmId);
            if (target != null && name != null) target.removeAttribute(name);
        }
    }

    /**
     * Run a JPQL UPDATE that stamps the final attestation on every row of an
     * attribute entity matching (parent_id, name). Multi-value attributes share
     * the (parent_id, name) tuple — every row gets the same attestation.
     */
    private static void stampSigJpql(EntityManager em, String jpql, String sig, String parentId, String name) {
        if (sig == null || sig.isEmpty()) return;
        em.createQuery(jpql)
                .setParameter("sig", sig)
                .setParameter("pid", parentId)
                .setParameter("name", name)
                .executeUpdate();
    }

    // -------------------------------------------------------------------------
    // BASELINE_APPROVAL replay — sweep every snapshotted unsigned row and
    // stamp the final attestation on it. Uses native SQL because the ATTESTATION
    // column was added by a Liquibase changelog at the DB layer; the JPA
    // entity classes don't (yet) expose `attestation` as a Hibernate field.
    // -------------------------------------------------------------------------

    private static void replayBaselineApproval(EntityManager em, IgaChangeRequestEntity cr, String finalAttestation) {
        if (finalAttestation == null || finalAttestation.isEmpty()) {
            log.warnf("BASELINE_APPROVAL %s has no final attestation; skipping attestation writes", cr.getId());
            return;
        }
        JsonNode root;
        try {
            root = MAPPER.readTree(cr.getRowsJson());
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse BASELINE rows_json for CR " + cr.getId(), e);
        }
        JsonNode tables = root.get("tables");
        if (tables == null || !tables.isObject()) {
            log.warnf("BASELINE_APPROVAL %s has no tables payload", cr.getId());
            return;
        }

        // Info tables — single id column
        updateBatchById(em, tables, "user_entity",
                "UPDATE USER_ENTITY SET ATTESTATION = ? WHERE ID IN (:ids) AND ATTESTATION IS NULL",
                "id", finalAttestation);
        updateBatchById(em, tables, "keycloak_role",
                "UPDATE KEYCLOAK_ROLE SET ATTESTATION = ? WHERE ID IN (:ids) AND ATTESTATION IS NULL",
                "id", finalAttestation);
        updateBatchById(em, tables, "keycloak_group",
                "UPDATE KEYCLOAK_GROUP SET ATTESTATION = ? WHERE ID IN (:ids) AND ATTESTATION IS NULL",
                "id", finalAttestation);
        updateBatchById(em, tables, "client",
                "UPDATE CLIENT SET ATTESTATION = ? WHERE ID IN (:ids) AND ATTESTATION IS NULL",
                "id", finalAttestation);
        updateBatchById(em, tables, "protocol_mapper",
                "UPDATE PROTOCOL_MAPPER SET ATTESTATION = ? WHERE ID IN (:ids) AND ATTESTATION IS NULL",
                "id", finalAttestation);

        // Relationship tables — composite key match, one update per row
        updatePairs(em, tables, "user_role_mapping",
                "UPDATE USER_ROLE_MAPPING SET ATTESTATION = ? WHERE USER_ID = ? AND ROLE_ID = ?",
                "USER_ID", "ROLE_ID", finalAttestation);
        updatePairs(em, tables, "user_group_membership",
                "UPDATE USER_GROUP_MEMBERSHIP SET ATTESTATION = ? WHERE USER_ID = ? AND GROUP_ID = ?",
                "USER", "GROUP", finalAttestation);
        updatePairs(em, tables, "group_role_mapping",
                "UPDATE GROUP_ROLE_MAPPING SET ATTESTATION = ? WHERE GROUP_ID = ? AND ROLE_ID = ?",
                "GROUP", "ROLE", finalAttestation);
        updatePairs(em, tables, "composite_role",
                "UPDATE COMPOSITE_ROLE SET ATTESTATION = ? WHERE COMPOSITE = ? AND CHILD_ROLE = ?",
                "COMPOSITE", "CHILD_ROLE", finalAttestation);
        updatePairs(em, tables, "client_scope_client",
                "UPDATE CLIENT_SCOPE_CLIENT SET ATTESTATION = ? WHERE CLIENT_ID = ? AND SCOPE_ID = ?",
                "CLIENT_ID", "SCOPE_ID", finalAttestation);
        updatePairs(em, tables, "client_scope_role_mapping",
                "UPDATE CLIENT_SCOPE_ROLE_MAPPING SET ATTESTATION = ? WHERE SCOPE_ID = ? AND ROLE_ID = ?",
                "SCOPE_ID", "ROLE_ID", finalAttestation);

        // ----- Attribute tables (1.8.0+) -----
        // Each row in the snapshot carries (parent_id, name, value); the
        // composite key for the row is (parent_id, name, value) because
        // multi-value attributes share parent_id+name. We update by
        // (parent_id, name) AND value = :val to pin a single row precisely
        // (or "value IS NULL" when value is null).
        updateAttributeRowsJpql(em, tables, "user_attribute",
                "UPDATE UserAttributeEntity e SET e.attestation = :sig " +
                        "WHERE e.user.id = :pid AND e.name = :name AND e.value %s",
                "user_id", finalAttestation);
        updateAttributeRowsJpql(em, tables, "client_attributes",
                "UPDATE ClientAttributeEntity e SET e.attestation = :sig " +
                        "WHERE e.client.id = :pid AND e.name = :name AND e.value %s",
                "client_id", finalAttestation);
        updateAttributeRowsJpql(em, tables, "client_scope_attributes",
                "UPDATE ClientScopeAttributeEntity e SET e.attestation = :sig " +
                        "WHERE e.clientScope.id = :pid AND e.name = :name AND e.value %s",
                "scope_id", finalAttestation);
        updateAttributeRowsJpql(em, tables, "group_attribute",
                "UPDATE GroupAttributeEntity e SET e.attestation = :sig " +
                        "WHERE e.group.id = :pid AND e.name = :name AND e.value %s",
                "group_id", finalAttestation);
        updateAttributeRowsJpql(em, tables, "role_attribute",
                "UPDATE RoleAttributeEntity e SET e.attestation = :sig " +
                        "WHERE e.role.id = :pid AND e.name = :name AND e.value %s",
                "role_id", finalAttestation);
        updateAttributeRowsJpql(em, tables, "realm_attribute",
                "UPDATE RealmAttributeEntity e SET e.attestation = :sig " +
                        "WHERE e.realm.id = :pid AND e.name = :name AND e.value %s",
                "realm_id", finalAttestation);
    }

    /**
     * Update each (parent_id, name, value) attribute row with the final
     * attestation using JPQL. The {@code value} field may be NULL (single-value
     * clear), so we pick {@code IS NULL} vs {@code = :val} dynamically — JPQL
     * (like SQL) does not fold {@code col = NULL} to TRUE for NULL values.
     */
    private static void updateAttributeRowsJpql(EntityManager em, JsonNode tables, String tableName,
                                                 String jpqlTemplate, String parentKey, String sig) {
        JsonNode arr = tables.get(tableName);
        if (arr == null || !arr.isArray() || arr.size() == 0) return;

        int total = 0;
        for (JsonNode row : arr) {
            JsonNode pid = row.get(parentKey);
            JsonNode name = row.get("name");
            JsonNode value = row.get("value");
            if (pid == null || pid.isNull() || name == null || name.isNull()) continue;

            boolean valueNull = (value == null || value.isNull());
            String jpql = String.format(jpqlTemplate, valueNull ? "IS NULL" : "= :val");
            Query q = em.createQuery(jpql)
                    .setParameter("sig", sig)
                    .setParameter("pid", pid.asText())
                    .setParameter("name", name.asText());
            if (!valueNull) q.setParameter("val", value.asText());
            total += q.executeUpdate();
        }
        log.debugf("BASELINE replay: updated %d rows in %s", total, tableName);
    }

    /**
     * Batch-update rows by primary id using a single native SQL statement.
     * Uses the Hibernate-supported `:ids` IN-list parameter form.
     */
    private static void updateBatchById(EntityManager em, JsonNode tables, String tableName,
                                         String sql, String idKey, String sig) {
        JsonNode arr = tables.get(tableName);
        if (arr == null || !arr.isArray() || arr.size() == 0) return;

        List<String> ids = new ArrayList<>(arr.size());
        for (JsonNode row : arr) {
            JsonNode v = row.get(idKey);
            if (v != null && !v.isNull()) ids.add(v.asText());
        }
        if (ids.isEmpty()) return;

        Query q = em.createNativeQuery(sql);
        q.setParameter(1, sig);
        q.setParameter("ids", ids);
        int updated = q.executeUpdate();
        log.debugf("BASELINE replay: updated %d rows in %s", updated, tableName);
    }

    /**
     * Run one UPDATE per row for relationship tables (composite primary key).
     * Native SQL with positional parameters: ?1=attestation, ?2=key1, ?3=key2.
     */
    private static void updatePairs(EntityManager em, JsonNode tables, String tableName,
                                     String sql, String key1, String key2, String sig) {
        JsonNode arr = tables.get(tableName);
        if (arr == null || !arr.isArray() || arr.size() == 0) return;

        int total = 0;
        for (JsonNode row : arr) {
            JsonNode v1 = row.get(key1);
            JsonNode v2 = row.get(key2);
            if (v1 == null || v1.isNull() || v2 == null || v2.isNull()) continue;
            Query q = em.createNativeQuery(sql);
            q.setParameter(1, sig);
            q.setParameter(2, v1.asText());
            q.setParameter(3, v2.asText());
            total += q.executeUpdate();
        }
        log.debugf("BASELINE replay: updated %d rows in %s", total, tableName);
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
