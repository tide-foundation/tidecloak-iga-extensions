package org.tidecloak.iga.providers;

// TODO: when Midgard.signClaims() is ready, replace logger.info call with the real sign + persist signature flow.
// This service is a prototype for the FirstAdmin signing flow — it resolves a change request to its full
// signing payload (with all foreign keys expanded to full entity data), logs it, and returns it.
// NO actual cryptography happens here yet.

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.jboss.logging.Logger;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.tidecloak.iga.entities.IgaAuthorizationEntity;
import org.tidecloak.iga.entities.IgaAuthorizerEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.entities.IgaForsetiContractEntity;
import org.tidecloak.iga.entities.IgaRolePolicyEntity;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Resolves a change request to its full signing payload (all foreign keys
 * expanded to full entity data), logs it, and returns it.
 *
 * Prototype for the FirstAdmin signing flow. No cryptography is performed —
 * the resolved payload is logged so it can be inspected, and returned to the
 * caller as JSON.
 */
public class IgaFirstAdminSignPreviewService {

    private static final Logger log = Logger.getLogger(IgaFirstAdminSignPreviewService.class);

    private static final ObjectMapper PRETTY_MAPPER = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);

    private final EntityManager em;
    private final KeycloakSession session;
    private final RealmModel realm;
    private final IgaChangeRequestService changeRequestService;
    private final IgaRolePolicyService rolePolicyService;
    private final IgaAuthorizerService authorizerService;
    private final IgaForsetiContractService forsetiContractService;

    public IgaFirstAdminSignPreviewService(EntityManager em,
                                            KeycloakSession session,
                                            RealmModel realm,
                                            IgaChangeRequestService changeRequestService,
                                            IgaRolePolicyService rolePolicyService,
                                            IgaAuthorizerService authorizerService,
                                            IgaForsetiContractService forsetiContractService) {
        this.em = em;
        this.session = session;
        this.realm = realm;
        this.changeRequestService = changeRequestService;
        this.rolePolicyService = rolePolicyService;
        this.authorizerService = authorizerService;
        this.forsetiContractService = forsetiContractService;
    }

    /**
     * Build the resolved payload for the given change request and log it.
     * Returns the payload as a Map for JAX-RS serialization. Returns null if
     * the CR does not exist or belongs to a different realm.
     */
    public Map<String, Object> buildAndLog(String changeRequestId) {
        IgaChangeRequestEntity cr = em.find(IgaChangeRequestEntity.class, changeRequestId);
        if (cr == null || !realm.getId().equals(cr.getRealmId())) {
            return null;
        }
        Map<String, Object> payload = build(cr);
        try {
            String pretty = PRETTY_MAPPER.writeValueAsString(payload);
            log.infof("[FirstAdmin sign preview] %s", pretty);
        } catch (JsonProcessingException e) {
            log.warnf(e, "[FirstAdmin sign preview] Failed to serialise payload for CR %s", changeRequestId);
        }
        return payload;
    }

    // -------------------------------------------------------------------------
    // Top-level payload assembly
    // -------------------------------------------------------------------------

    private Map<String, Object> build(IgaChangeRequestEntity cr) {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("changeRequest", changeRequestSection(cr));
        root.put("subject", subjectSection(cr));
        if ("USER".equals(cr.getEntityType())) {
            root.put("subjectState", subjectStateForUser(cr.getEntityId()));
        }
        List<Map<String, Object>> rows = parseRowsSafe(cr.getRowsJson());
        root.put("resolvedRows", resolvedRows(cr, rows));
        root.put("rolePolicies", rolePoliciesSection(cr, rows));
        root.put("authorizers", authorizersSection());
        root.put("existingAuthorizations", existingAuthorizationsSection(cr.getId()));
        return root;
    }

    private Map<String, Object> changeRequestSection(IgaChangeRequestEntity cr) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", cr.getId());
        m.put("realmId", cr.getRealmId());
        m.put("entityType", cr.getEntityType());
        m.put("entityId", cr.getEntityId());
        m.put("actionType", cr.getActionType());
        m.put("status", cr.getStatus());
        m.put("requestedBy", cr.getRequestedBy());
        m.put("createdAt", cr.getCreatedAt());
        m.put("rows", parseRowsSafe(cr.getRowsJson()));
        return m;
    }

    // -------------------------------------------------------------------------
    // Subject entity resolution
    // -------------------------------------------------------------------------

    private Map<String, Object> subjectSection(IgaChangeRequestEntity cr) {
        String entityType = cr.getEntityType();
        String entityId = cr.getEntityId();
        if (entityType == null || entityId == null) return null;
        return switch (entityType) {
            case "USER" -> userSummary(entityId);
            case "GROUP" -> groupSummary(entityId);
            case "ROLE" -> roleSummary(entityId);
            case "CLIENT" -> clientSummary(entityId);
            default -> Map.of("entityType", entityType, "entityId", entityId, "note", "unsupported entity type");
        };
    }

    private Map<String, Object> userSummary(String userId) {
        UserModel user = session.users().getUserById(realm, userId);
        if (user == null) {
            return notFound("USER", userId);
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", user.getId());
        m.put("username", user.getUsername());
        m.put("email", user.getEmail());
        m.put("firstName", user.getFirstName());
        m.put("lastName", user.getLastName());
        m.put("enabled", user.isEnabled());
        m.put("createdTimestamp", user.getCreatedTimestamp());
        m.put("attributes", attributesAsMap(user.getAttributes()));
        return m;
    }

    private Map<String, Object> groupSummary(String groupId) {
        GroupModel group = session.groups().getGroupById(realm, groupId);
        if (group == null) {
            return notFound("GROUP", groupId);
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", group.getId());
        m.put("name", group.getName());
        m.put("path", buildGroupPath(group));
        m.put("parentId", group.getParentId());
        m.put("attributes", attributesAsMap(group.getAttributes()));
        return m;
    }

    private Map<String, Object> roleSummary(String roleId) {
        RoleModel role = session.roles().getRoleById(realm, roleId);
        if (role == null) {
            return notFound("ROLE", roleId);
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", role.getId());
        m.put("name", role.getName());
        m.put("description", role.getDescription());
        m.put("isClientRole", role.isClientRole());
        m.put("containerId", role.getContainerId());
        m.put("attributes", attributesAsMap(role.getAttributes()));
        return m;
    }

    private Map<String, Object> roleSummaryWithComposites(String roleId) {
        RoleModel role = session.roles().getRoleById(realm, roleId);
        if (role == null) {
            return notFound("ROLE", roleId);
        }
        Map<String, Object> m = new LinkedHashMap<>(roleSummary(roleId));
        List<Map<String, Object>> composites = new ArrayList<>();
        role.getCompositesStream().forEach(child -> {
            Map<String, Object> c = new LinkedHashMap<>();
            c.put("id", child.getId());
            c.put("name", child.getName());
            c.put("isClientRole", child.isClientRole());
            c.put("containerId", child.getContainerId());
            composites.add(c);
        });
        m.put("composites", composites);
        return m;
    }

    private Map<String, Object> clientSummary(String clientId) {
        ClientModel client = session.clients().getClientById(realm, clientId);
        if (client == null) {
            return notFound("CLIENT", clientId);
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", client.getId());
        m.put("clientId", client.getClientId());
        m.put("name", client.getName());
        m.put("description", client.getDescription());
        m.put("enabled", client.isEnabled());
        m.put("protocol", client.getProtocol());
        m.put("attributes", client.getAttributes());
        return m;
    }

    private Map<String, Object> clientScopeSummary(String scopeId) {
        ClientScopeModel scope = session.clientScopes().getClientScopeById(realm, scopeId);
        if (scope == null) {
            return notFound("CLIENT_SCOPE", scopeId);
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", scope.getId());
        m.put("name", scope.getName());
        m.put("description", scope.getDescription());
        m.put("protocol", scope.getProtocol());
        return m;
    }

    // -------------------------------------------------------------------------
    // Subject (user) current state
    // -------------------------------------------------------------------------

    private Map<String, Object> subjectStateForUser(String userId) {
        UserModel user = session.users().getUserById(realm, userId);
        if (user == null) {
            return Map.of("note", "user not found");
        }

        List<Map<String, Object>> realmRoles = new ArrayList<>();
        List<RoleModel> directRoles = new ArrayList<>();
        user.getRoleMappingsStream().forEach(directRoles::add);
        for (RoleModel role : directRoles) {
            if (!role.isClientRole()) {
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("id", role.getId());
                r.put("name", role.getName());
                r.put("attributes", attributesAsMap(role.getAttributes()));
                realmRoles.add(r);
            }
        }

        Map<String, List<String>> clientRoles = new LinkedHashMap<>();
        for (RoleModel role : directRoles) {
            if (role.isClientRole()) {
                String containerId = role.getContainerId();
                ClientModel container = session.clients().getClientById(realm, containerId);
                String clientKey = container != null ? container.getClientId() : containerId;
                clientRoles.computeIfAbsent(clientKey, k -> new ArrayList<>()).add(role.getName());
            }
        }

        List<Map<String, Object>> groups = new ArrayList<>();
        user.getGroupsStream().forEach(g -> {
            Map<String, Object> gm = new LinkedHashMap<>();
            gm.put("id", g.getId());
            gm.put("name", g.getName());
            gm.put("path", buildGroupPath(g));
            groups.add(gm);
        });

        // Effective roles = direct + composite expansion (transitive)
        Set<String> seen = new HashSet<>();
        List<Map<String, Object>> effective = new ArrayList<>();
        for (RoleModel role : directRoles) {
            collectEffectiveRoles(role, seen, effective);
        }

        Map<String, Object> m = new LinkedHashMap<>();
        m.put("currentRealmRoles", realmRoles);
        m.put("currentClientRoles", clientRoles);
        m.put("currentGroups", groups);
        m.put("effectiveRoles", effective);
        return m;
    }

    private void collectEffectiveRoles(RoleModel role, Set<String> seen, List<Map<String, Object>> out) {
        if (role == null || !seen.add(role.getId())) return;
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("id", role.getId());
        r.put("name", role.getName());
        r.put("isClientRole", role.isClientRole());
        r.put("containerId", role.getContainerId());
        out.add(r);
        if (role.isComposite()) {
            role.getCompositesStream().forEach(child -> collectEffectiveRoles(child, seen, out));
        }
    }

    // -------------------------------------------------------------------------
    // Per-row resolution
    // -------------------------------------------------------------------------

    private List<Map<String, Object>> resolvedRows(IgaChangeRequestEntity cr, List<Map<String, Object>> rows) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (rows == null) return out;
        String action = cr.getActionType();
        for (Map<String, Object> row : rows) {
            out.add(resolveRow(action, row));
        }
        return out;
    }

    private Map<String, Object> resolveRow(String actionType, Map<String, Object> row) {
        Map<String, Object> resolved = new LinkedHashMap<>();
        resolved.put("raw", row);
        switch (actionType) {
            case "GRANT_ROLES", "REVOKE_ROLES" -> {
                String userId = str(row, "USER_ID");
                String roleId = str(row, "ROLE_ID");
                if (userId != null) resolved.put("user", userSummary(userId));
                if (roleId != null) {
                    resolved.put("role", roleSummaryWithComposites(roleId));
                    Map<String, Object> policy = rolePolicyForRole(roleId);
                    if (policy != null) resolved.put("rolePolicy", policy);
                }
            }
            case "JOIN_GROUPS", "LEAVE_GROUPS" -> {
                String userId = str(row, "USER");
                String groupId = str(row, "GROUP");
                if (userId != null) resolved.put("user", userSummary(userId));
                if (groupId != null) resolved.put("group", groupSummary(groupId));
            }
            case "GROUP_GRANT_ROLES", "GROUP_REVOKE_ROLES" -> {
                String groupId = str(row, "GROUP");
                String roleId = str(row, "ROLE");
                if (groupId != null) resolved.put("group", groupSummary(groupId));
                if (roleId != null) {
                    resolved.put("role", roleSummaryWithComposites(roleId));
                    Map<String, Object> policy = rolePolicyForRole(roleId);
                    if (policy != null) resolved.put("rolePolicy", policy);
                }
            }
            case "ADD_COMPOSITE", "REMOVE_COMPOSITE" -> {
                String compositeId = str(row, "COMPOSITE");
                String childId = str(row, "CHILD_ROLE");
                if (compositeId != null) resolved.put("composite", roleSummaryWithComposites(compositeId));
                if (childId != null) resolved.put("childRole", roleSummaryWithComposites(childId));
            }
            case "ASSIGN_SCOPE", "REMOVE_SCOPE" -> {
                // rowsJson contract: CLIENT_UUID holds the client UUID;
                // clientSummary resolves by UUID via getClientById. CLIENT_ID
                // is the human identifier and must NOT be passed here.
                String clientUuid = str(row, "CLIENT_UUID");
                String scopeId = str(row, "SCOPE_ID");
                if (clientUuid != null) resolved.put("client", clientSummary(clientUuid));
                if (scopeId != null) resolved.put("clientScope", clientScopeSummary(scopeId));
            }
            case "SCOPE_ADD_ROLE", "SCOPE_REMOVE_ROLE" -> {
                String scopeId = str(row, "SCOPE_ID");
                String roleId = str(row, "ROLE_ID");
                if (scopeId != null) resolved.put("clientScope", clientScopeSummary(scopeId));
                if (roleId != null) resolved.put("role", roleSummaryWithComposites(roleId));
            }
            case "CREATE_USER", "CREATE_ROLE", "CREATE_GROUP", "CREATE_CLIENT",
                  "ADD_PROTOCOL_MAPPER",
                  "REQUEST_SERVER_CERT", "INSTALL_LICENSE", "ROTATE_LICENSE" ->
                    resolved.put("note", "would create new entity");
            default -> resolved.put("note", "unrecognised action type — raw row only");
        }
        return resolved;
    }

    // -------------------------------------------------------------------------
    // Role policy + Forseti contract
    // -------------------------------------------------------------------------

    private Map<String, Object> rolePoliciesSection(IgaChangeRequestEntity cr, List<Map<String, Object>> rows) {
        Map<String, Object> out = new LinkedHashMap<>();
        Set<String> roleIds = new HashSet<>();
        if ("ROLE".equals(cr.getEntityType()) && cr.getEntityId() != null) {
            roleIds.add(cr.getEntityId());
        }
        if (rows != null) {
            for (Map<String, Object> row : rows) {
                addIfPresent(roleIds, str(row, "ROLE_ID"));
                addIfPresent(roleIds, str(row, "ROLE"));
                addIfPresent(roleIds, str(row, "COMPOSITE"));
                addIfPresent(roleIds, str(row, "CHILD_ROLE"));
            }
        }
        for (String roleId : roleIds) {
            Map<String, Object> p = rolePolicyForRole(roleId);
            if (p != null) out.put(roleId, p);
        }
        return out;
    }

    private Map<String, Object> rolePolicyForRole(String roleId) {
        IgaRolePolicyEntity policy = rolePolicyService.findByRealmAndRole(realm.getId(), roleId);
        if (policy == null) return null;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", policy.getId());
        m.put("realmId", policy.getRealmId());
        m.put("roleId", policy.getRoleId());
        m.put("policy", policy.getPolicy());
        m.put("policySig", policy.getPolicySig());
        m.put("contractId", policy.getContractId());
        m.put("approvalType", policy.getApprovalType());
        m.put("executionType", policy.getExecutionType());
        m.put("threshold", policy.getThreshold());
        m.put("policyData", policy.getPolicyData());
        m.put("createdAt", policy.getCreatedAt());
        m.put("updatedAt", policy.getUpdatedAt());
        if (policy.getContractId() != null) {
            IgaForsetiContractEntity contract = forsetiContractService.findById(policy.getContractId());
            if (contract != null) {
                Map<String, Object> c = new LinkedHashMap<>();
                c.put("id", contract.getId());
                c.put("realmId", contract.getRealmId());
                c.put("contractHash", contract.getContractHash());
                c.put("contractCode", contract.getContractCode());
                c.put("name", contract.getName());
                c.put("createdAt", contract.getCreatedAt());
                c.put("updatedAt", contract.getUpdatedAt());
                m.put("contract", c);
            }
        }
        return m;
    }

    // -------------------------------------------------------------------------
    // Authorizers + existing authorizations
    // -------------------------------------------------------------------------

    private List<Map<String, Object>> authorizersSection() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (IgaAuthorizerEntity a : authorizerService.listByRealm(realm.getId())) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", a.getId());
            m.put("type", a.getType());
            m.put("providerId", a.getProviderId());
            m.put("authorizerCertificate", a.getAuthorizerCertificate());
            out.add(m);
        }
        return out;
    }

    private List<Map<String, Object>> existingAuthorizationsSection(String changeRequestId) {
        List<Map<String, Object>> out = new ArrayList<>();
        TypedQuery<IgaAuthorizationEntity> q = em.createNamedQuery(
                "IgaAuthorization.findByChangeRequest", IgaAuthorizationEntity.class);
        q.setParameter("changeRequestId", changeRequestId);
        for (IgaAuthorizationEntity a : q.getResultList()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", a.getId());
            m.put("authorizedBy", a.getAuthorizedBy());
            m.put("partialSig", a.getPartialSig());
            m.put("createdAt", a.getCreatedAt());
            out.add(m);
        }
        return out;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private List<Map<String, Object>> parseRowsSafe(String json) {
        if (json == null || json.isBlank()) return List.of();
        try {
            return changeRequestService.parseRows(json);
        } catch (Exception e) {
            return List.of();
        }
    }

    private static Map<String, Object> notFound(String type, String id) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("type", type);
        m.put("id", id);
        m.put("note", "entity not found");
        return m;
    }

    private static String str(Map<String, Object> row, String key) {
        Object v = row.get(key);
        return v != null ? v.toString() : null;
    }

    private static void addIfPresent(Set<String> set, String value) {
        if (value != null && !value.isBlank()) set.add(value);
    }

    private static Map<String, List<String>> attributesAsMap(Map<String, List<String>> attrs) {
        if (attrs == null) return Map.of();
        Map<String, List<String>> m = new LinkedHashMap<>();
        attrs.forEach((k, v) -> m.put(k, v != null ? new ArrayList<>(v) : List.of()));
        return m;
    }

    private static String buildGroupPath(GroupModel group) {
        // Reproduce the "/parent/child" form that Keycloak returns from KeycloakModelUtils
        StringBuilder sb = new StringBuilder();
        GroupModel current = group;
        while (current != null) {
            sb.insert(0, "/" + current.getName());
            current = current.getParent();
        }
        return sb.length() == 0 ? "/" : sb.toString();
    }
}
