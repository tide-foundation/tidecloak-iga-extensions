package org.tidecloak.base.iga.ChangeSetCommitter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.*;
import org.keycloak.services.resources.admin.AdminAuth;
import org.tidecloak.base.iga.ChangeSetCommitter.ChangeSetCommitter;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.Base64;
import java.util.stream.Collectors;

public class BasicIGACommitter implements ChangeSetCommitter {

    private static final ObjectMapper M = new ObjectMapper();

    @Override
    public Response commit(ChangeSetRequest changeSet,
                           EntityManager em,
                           KeycloakSession session,
                           RealmModel realm,
                           Object draftEntity,
                           AdminAuth auth) throws Exception {

        ChangesetRequestEntity cre = em.find(
                ChangesetRequestEntity.class,
                new ChangesetRequestEntity.Key(changeSet.getChangeSetId(), changeSet.getType())
        );
        if (cre == null) {
            throw new BadRequestException("Replay changeset not found: " + changeSet.getChangeSetId());
        }

        String repJson = new String(Base64.getDecoder().decode(cre.getDraftRequest()), StandardCharsets.UTF_8);
        JsonNode rep = M.readTree(repJson);

        String op = text(rep, "op");
        if (op.isBlank()) op = "assign";

        String repType = text(rep, "repType");
        if (repType.isBlank()) repType = inferRepType(rep);

        switch (repType) {
            case "UserRoleMapping"          -> applyUserRole(realm, session, rep, op);
            case "UserGroupMembership"      -> applyUserGroup(realm, session, rep, op);
            case "GroupRoleMapping"         -> applyGroupRole(realm, session, rep, op);
            case "CompositeRole"            -> applyCompositeRole(realm, session, rep, op);
            case "RealmDefaultRole"         -> applyRealmDefaultRole(realm, session, rep, op);

            case "ClientFullScope"          -> applyClientFullScope(realm, session, rep);
            case "ClientDefaultClientScope" -> applyClientDefaultClientScope(realm, session, rep, op);
            case "RealmDefaultClientScope"  -> applyRealmDefaultClientScope(realm, session, rep, op);

            case "ClientProtocolMapper"     -> applyClientProtocolMapper(realm, session, rep, op);
            case "ClientScopeProtocolMapper"-> applyClientScopeProtocolMapper(realm, session, rep, op);

            default -> {
                if (rep.has("fullScopeEnabled")) {
                    applyClientFullScope(realm, session, rep);
                } else if (rep.has("userId") && rep.has("roleId")) {
                    applyUserRole(realm, session, rep, op);
                } else if (rep.has("userId") && rep.has("groupId")) {
                    applyUserGroup(realm, session, rep, op);
                } else if (rep.has("groupId") && rep.has("roleId")) {
                    applyGroupRole(realm, session, rep, op);
                } else if (rep.has("compositeRoleId") && rep.has("childRoleId")) {
                    applyCompositeRole(realm, session, rep, op);
                } else if (rep.has("realmDefault") && rep.has("roleId")) {
                    applyRealmDefaultRole(realm, session, rep, op);
                } else if (rep.has("clientId") && rep.has("clientScopeId")) {
                    applyClientDefaultClientScope(realm, session, rep, op);
                } else if (rep.has("realmDefault") && rep.has("clientScopeId")) {
                    applyRealmDefaultClientScope(realm, session, rep, op);
                } else if (rep.has("mapper") && rep.has("clientId")) {
                    applyClientProtocolMapper(realm, session, rep, op);
                } else if (rep.has("mapper") && rep.has("clientScopeId")) {
                    applyClientScopeProtocolMapper(realm, session, rep, op);
                } else {
                    return Response.ok("Replay applied (no-op: rep type not recognized)").build();
                }
            }
        }

        return Response.ok("Replay applied and committed").build();
    }

    // ---------- Handlers ----------

    private static void applyUserRole(RealmModel realm, KeycloakSession session, JsonNode rep, String op) {
        String userId = text(rep, "userId");
        String roleId = text(rep, "roleId");
        require(!userId.isBlank(), "USER_ROLE rep missing userId");
        require(!roleId.isBlank(), "USER_ROLE rep missing roleId");

        UserModel user = session.users().getUserById(realm, userId);
        require(user != null, "User not found: " + userId);

        RoleModel role = findRole(realm, session, roleId);
        require(role != null, "Role not found: " + roleId);

        if (isRemove(op)) user.deleteRoleMapping(role);
        else              user.grantRole(role);
    }

    private static void applyUserGroup(RealmModel realm, KeycloakSession session, JsonNode rep, String op) {
        String userId = text(rep, "userId");
        String groupId = text(rep, "groupId");
        require(!userId.isBlank(), "USER_GROUP rep missing userId");
        require(!groupId.isBlank(), "USER_GROUP rep missing groupId");

        UserModel user = session.users().getUserById(realm, userId);
        require(user != null, "User not found: " + userId);

        GroupModel group = realm.getGroupById(groupId);
        if (group == null) {
            group = realm.getGroupsStream().filter(g -> groupId.equals(g.getName())).findFirst().orElse(null);
        }
        require(group != null, "Group not found: " + groupId);

        if (isRemove(op)) user.leaveGroup(group);
        else              user.joinGroup(group);
    }

    private static void applyGroupRole(RealmModel realm, KeycloakSession session, JsonNode rep, String op) {
        String groupId = text(rep, "groupId");
        String roleId = text(rep, "roleId");
        require(!groupId.isBlank(), "GROUP_ROLE rep missing groupId");
        require(!roleId.isBlank(), "GROUP_ROLE rep missing roleId");

        GroupModel group = realm.getGroupById(groupId);
        if (group == null) {
            group = realm.getGroupsStream().filter(g -> groupId.equals(g.getName())).findFirst().orElse(null);
        }
        require(group != null, "Group not found: " + groupId);

        RoleModel role = findRole(realm, session, roleId);
        require(role != null, "Role not found: " + roleId);

        if (isRemove(op)) group.deleteRoleMapping(role);
        else              group.grantRole(role);
    }

    private static void applyCompositeRole(RealmModel realm, KeycloakSession session, JsonNode rep, String op) {
        String parentId = text(rep, "compositeRoleId");
        String childId  = text(rep, "childRoleId");
        require(!parentId.isBlank() && !childId.isBlank(), "COMPOSITE_ROLE rep missing compositeRoleId/childRoleId");

        RoleModel parent = findRole(realm, session, parentId);
        RoleModel child  = findRole(realm, session, childId);
        require(parent != null, "Parent role not found: " + parentId);
        require(child  != null, "Child role not found: " + childId);

        if (isRemove(op)) parent.removeCompositeRole(child);
        else              parent.addCompositeRole(child);
    }

    private static void applyRealmDefaultRole(RealmModel realm, KeycloakSession session, JsonNode rep, String op) {
        String roleId = text(rep, "roleId");
        require(!roleId.isBlank(), "REALM_DEFAULT_ROLE rep missing roleId");

        RoleModel defaultRole = realm.getDefaultRole();
        require(defaultRole != null, "Realm default role not found");

        RoleModel role = findRole(realm, session, roleId);
        require(role != null, "Role not found: " + roleId);

        if (isRemove(op)) defaultRole.removeCompositeRole(role);
        else              defaultRole.addCompositeRole(role);
    }

    private static void applyClientFullScope(RealmModel realm, KeycloakSession session, JsonNode rep) {
        String clientRef = text(rep, "clientId");
        require(!clientRef.isBlank(), "CLIENT_FULLSCOPE rep missing clientId");
        ClientModel client = findClient(realm, clientRef);
        require(client != null, "Client not found: " + clientRef);

        boolean enabled = rep.path("fullScopeEnabled").asBoolean(true);
        client.setFullScopeAllowed(enabled);
    }

    private static void applyClientDefaultClientScope(RealmModel realm, KeycloakSession session, JsonNode rep, String op) {
        String clientRef = text(rep, "clientId");
        String scopeRef  = text(rep, "clientScopeId");
        String scopeType = text(rep, "scopeType"); // "default" | "optional"
        if (scopeType.isBlank()) scopeType = "default";
        require(!clientRef.isBlank() && !scopeRef.isBlank(), "CLIENT_DEFAULT_CLIENT_SCOPE rep missing clientId/clientScopeId");

        ClientModel client = findClient(realm, clientRef);
        require(client != null, "Client not found: " + clientRef);

        ClientScopeModel scope = findClientScope(realm, scopeRef);
        require(scope != null, "Client scope not found: " + scopeRef);

        boolean makeDefault = "default".equalsIgnoreCase(scopeType);
        if (isRemove(op)) {
            client.removeClientScope(scope);
        } else {
            client.addClientScope(scope, makeDefault);
        }
    }

    private static void applyRealmDefaultClientScope(RealmModel realm, KeycloakSession session, JsonNode rep, String op) {
        String scopeRef  = text(rep, "clientScopeId");
        String scopeType = text(rep, "scopeType"); // "default" | "optional"
        if (scopeType.isBlank()) scopeType = "default";
        require(!scopeRef.isBlank(), "REALM_DEFAULT_CLIENT_SCOPE rep missing clientScopeId");

        ClientScopeModel scope = findClientScope(realm, scopeRef);
        require(scope != null, "Client scope not found: " + scopeRef);

        boolean isDefault = "default".equalsIgnoreCase(scopeType);
        if (isRemove(op)) {
            // Keycloak uses a unified remover for both default & optional:
            realm.removeDefaultClientScope(scope);
        } else {
            // unified adder with boolean flag:
            realm.addDefaultClientScope(scope, isDefault);
        }
    }

    private static void applyClientProtocolMapper(RealmModel realm, KeycloakSession session, JsonNode rep, String op) {
        String clientRef = text(rep, "clientId");
        require(!clientRef.isBlank(), "CLIENT_MAPPER rep missing clientId");

        ClientModel client = findClient(realm, clientRef);
        require(client != null, "Client not found: " + clientRef);

        ProtocolMapperModel mapper = toMapper(rep.path("mapper"));
        require(mapper != null, "Missing/invalid mapper");

        List<ProtocolMapperModel> current = client.getProtocolMappersStream().collect(Collectors.toList());
        ProtocolMapperModel existing = findMapper(current, mapper);

        if (isRemove(op)) {
            require(existing != null, "Mapper not found to remove: " + mapper.getId() + "/" + mapper.getName());
            client.removeProtocolMapper(existing);
        } else {
            if (existing == null) {
                client.addProtocolMapper(mapper);
            } else {
                existing.setProtocol(mapper.getProtocol());
                existing.setProtocolMapper(mapper.getProtocolMapper());
                existing.setConfig(mapper.getConfig());
                client.updateProtocolMapper(existing);
            }
        }
    }

    private static void applyClientScopeProtocolMapper(RealmModel realm, KeycloakSession session, JsonNode rep, String op) {
        String scopeRef = text(rep, "clientScopeId");
        require(!scopeRef.isBlank(), "CLIENT_SCOPE_MAPPER rep missing clientScopeId");

        ClientScopeModel scope = findClientScope(realm, scopeRef);
        require(scope != null, "Client scope not found: " + scopeRef);

        ProtocolMapperModel mapper = toMapper(rep.path("mapper"));
        require(mapper != null, "Missing/invalid mapper");

        List<ProtocolMapperModel> current = scope.getProtocolMappersStream().collect(Collectors.toList());
        ProtocolMapperModel existing = findMapper(current, mapper);

        if (isRemove(op)) {
            require(existing != null, "Mapper not found to remove: " + mapper.getId() + "/" + mapper.getName());
            scope.removeProtocolMapper(existing);
        } else {
            if (existing == null) {
                scope.addProtocolMapper(mapper);
            } else {
                existing.setProtocol(mapper.getProtocol());
                existing.setProtocolMapper(mapper.getProtocolMapper());
                existing.setConfig(mapper.getConfig());
                scope.updateProtocolMapper(existing);
            }
        }
    }

    // ---------- Helpers ----------

    private static boolean isRemove(String op) {
        return "remove".equalsIgnoreCase(op) || "delete".equalsIgnoreCase(op);
    }

    private static void require(boolean cond, String msg) {
        if (!cond) throw new BadRequestException(msg);
    }

    private static String text(JsonNode n, String field) {
        JsonNode v = n.get(field);
        return (v != null && v.isTextual()) ? v.asText() : "";
    }

    private static String inferRepType(JsonNode rep) {
        if (rep.has("fullScopeEnabled")) return "ClientFullScope";
        if (rep.has("mapper") && rep.has("clientId")) return "ClientProtocolMapper";
        if (rep.has("mapper") && rep.has("clientScopeId")) return "ClientScopeProtocolMapper";
        if (rep.has("userId") && rep.has("roleId")) return "UserRoleMapping";
        if (rep.has("userId") && rep.has("groupId")) return "UserGroupMembership";
        if (rep.has("groupId") && rep.has("roleId")) return "GroupRoleMapping";
        if (rep.has("compositeRoleId") && rep.has("childRoleId")) return "CompositeRole";
        if (rep.has("realmDefault") && rep.has("roleId")) return "RealmDefaultRole";
        if (rep.has("clientId") && rep.has("clientScopeId")) return "ClientDefaultClientScope";
        if (rep.has("realmDefault") && rep.has("clientScopeId")) return "RealmDefaultClientScope";
        return "";
    }

    private static RoleModel findRole(RealmModel realm, KeycloakSession session, String ref) {
        RoleModel byId = session.roles().getRoleById(realm, ref);
        if (byId != null) return byId;

        RoleModel byName = realm.getRole(ref);
        if (byName != null) return byName;

        for (ClientModel c : realm.getClientsStream().collect(Collectors.toList())) {
            RoleModel cr = c.getRole(ref);
            if (cr != null) return cr;
        }
        return null;
    }

    private static ClientModel findClient(RealmModel realm, String ref) {
        ClientModel c = realm.getClientById(ref);
        if (c != null) return c;
        return realm.getClientByClientId(ref);
    }

    private static ClientScopeModel findClientScope(RealmModel realm, String ref) {
        ClientScopeModel byId = realm.getClientScopeById(ref);
        if (byId != null) return byId;
        return realm.getClientScopesStream()
                .filter(cs -> ref.equals(cs.getName()))
                .findFirst()
                .orElse(null);
    }

    private static ProtocolMapperModel toMapper(JsonNode n) {
        if (n == null || !n.isObject()) return null;
        ProtocolMapperModel m = new ProtocolMapperModel();
        if (n.hasNonNull("id"))    m.setId(n.get("id").asText());
        if (n.hasNonNull("name"))  m.setName(n.get("name").asText());
        if (n.hasNonNull("protocol")) m.setProtocol(n.get("protocol").asText());
        if (n.hasNonNull("protocolMapper")) m.setProtocolMapper(n.get("protocolMapper").asText());

        if (n.has("config") && n.get("config").isObject()) {
            Map<String, String> cfg = new HashMap<>();
            n.get("config").fields().forEachRemaining(e -> cfg.put(e.getKey(), e.getValue().asText()));
            m.setConfig(cfg);
        } else {
            m.setConfig(new HashMap<>());
        }
        return m.getName() == null ? null : m;
    }

    private static ProtocolMapperModel findMapper(List<ProtocolMapperModel> list, ProtocolMapperModel probe) {
        if (probe.getId() != null) {
            for (ProtocolMapperModel m : list) {
                if (probe.getId().equals(m.getId())) return m;
            }
        }
        if (probe.getName() != null) {
            for (ProtocolMapperModel m : list) {
                if (probe.getName().equals(m.getName())) return m;
            }
        }
        return null;
    }
}
