package org.tidecloak.iga.attestors;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.ForbiddenException;
import org.keycloak.models.ClientModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Resolves the scope-based approval policies that apply to a particular
 * {@link IgaChangeRequestEntity}.
 *
 * <p>Admins can mark Keycloak groups, roles or clients with the attribute
 * {@code iga.approverRole = <keycloak-role-name>} to require that any admin
 * approving a change affecting that entity (or any user that belongs to a
 * scope-marked group) hold the named role. An optional {@code iga.threshold}
 * attribute on the same entity overrides the realm default for that scope.</p>
 *
 * <p>The {@link #resolve(KeycloakSession, RealmModel, IgaChangeRequestEntity)}
 * method walks the change request's {@code rows_json}, looks up the affected
 * users / groups / roles / clients, and collects the union of required
 * approver roles and thresholds. Callers then use
 * {@link #requireApprover(RealmModel, UserModel, ResolvedScope)} to enforce
 * the policy and {@link #resolveThreshold(RealmModel, ResolvedScope)} to
 * compute the effective threshold.</p>
 */
public final class IgaScopeResolver {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<List<Map<String, Object>>> ROWS_TYPE =
            new TypeReference<List<Map<String, Object>>>() {};

    public static final String ATTR_APPROVER_ROLE = "iga.approverRole";
    public static final String ATTR_THRESHOLD = "iga.threshold";
    public static final String ATTR_SCOPE_MODE = "iga.scopeMode";

    private IgaScopeResolver() {
    }

    public static final class ResolvedScope {
        public final Set<String> requiredApproverRoles = new LinkedHashSet<>();
        public final Set<Integer> thresholds = new LinkedHashSet<>();
    }

    /**
     * Walk the affected entities for the given change request and collect
     * scope-marked approver roles + thresholds. Never returns {@code null};
     * actions whose semantics are realm-wide (e.g. create-user, license
     * issuance, baseline approval) yield an empty {@link ResolvedScope}.
     */
    public static ResolvedScope resolve(KeycloakSession session, RealmModel realm, IgaChangeRequestEntity cr) {
        ResolvedScope scope = new ResolvedScope();
        if (cr == null || cr.getActionType() == null) return scope;
        switch (cr.getActionType()) {
            case "GRANT_ROLES":
            case "REVOKE_ROLES":
                resolveUserScopesFromRows(session, realm, cr, scope, "USER_ID");
                resolveRoleScopesFromRows(session, realm, cr, scope, "ROLE_ID");
                break;
            case "JOIN_GROUPS":
            case "LEAVE_GROUPS":
                resolveUserScopesFromRows(session, realm, cr, scope, "USER");
                resolveGroupScopesFromRows(session, realm, cr, scope, "GROUP");
                break;
            case "GROUP_GRANT_ROLES":
            case "GROUP_REVOKE_ROLES":
                resolveGroupScopesFromRows(session, realm, cr, scope, "GROUP");
                resolveRoleScopesFromRows(session, realm, cr, scope, "ROLE");
                break;
            case "ADD_COMPOSITE":
            case "REMOVE_COMPOSITE":
                resolveRoleScopesFromRows(session, realm, cr, scope, "COMPOSITE");
                break;
            case "ASSIGN_SCOPE":
            case "REMOVE_SCOPE":
            case "ADD_PROTOCOL_MAPPER":
                resolveClientScopesFromRows(session, realm, cr, scope, "CLIENT_ID");
                break;
            case "SCOPE_ADD_ROLE":
            case "SCOPE_REMOVE_ROLE":
                // Client scope scopes have no first-class iga.approverRole today;
                // fall through to the realm default.
                break;
            // -----------------------------------------------------------------
            // Attribute writes — resolve scopes from the parent entity. The
            // attribute itself never carries iga.approverRole; the scope rules
            // live on the user/group/role/client/realm being mutated.
            // -----------------------------------------------------------------
            case "SET_USER_ATTRIBUTE":
            case "REMOVE_USER_ATTRIBUTE":
                resolveUserScopesFromRows(session, realm, cr, scope, "USER_ID");
                break;
            case "SET_CLIENT_ATTRIBUTE":
            case "REMOVE_CLIENT_ATTRIBUTE":
                resolveClientScopesFromRows(session, realm, cr, scope, "CLIENT_ID");
                break;
            case "SET_CLIENT_SCOPE_ATTRIBUTE":
            case "REMOVE_CLIENT_SCOPE_ATTRIBUTE":
                // Client scopes have no first-class iga.approverRole today;
                // fall through to the realm default.
                break;
            case "SET_GROUP_ATTRIBUTE":
            case "REMOVE_GROUP_ATTRIBUTE":
                resolveGroupScopesFromRows(session, realm, cr, scope, "GROUP_ID");
                break;
            case "SET_ROLE_ATTRIBUTE":
            case "REMOVE_ROLE_ATTRIBUTE":
                resolveRoleScopesFromRows(session, realm, cr, scope, "ROLE_ID");
                break;
            case "SET_REALM_ATTRIBUTE":
            case "REMOVE_REALM_ATTRIBUTE":
                // Realm-level attribute writes have no per-entity scope; fall
                // through to the realm-default approver/threshold.
                break;
            // CREATE_USER / CREATE_ROLE / CREATE_GROUP / CREATE_CLIENT and
            // realm-wide action types (BASELINE_APPROVAL, REQUEST_SERVER_CERT,
            // INSTALL_LICENSE, ROTATE_LICENSE) intentionally leave the scope empty.
            default:
                break;
        }
        return scope;
    }

    /**
     * Verify the admin holds the role(s) required by the resolved scope. When
     * the scope carries no required roles the call is a no-op so that the
     * caller's existing realm-admin check remains the only gate.
     *
     * @throws ForbiddenException if the admin lacks the required role(s)
     */
    public static void requireApprover(RealmModel realm, UserModel admin, ResolvedScope scope) {
        if (scope == null || scope.requiredApproverRoles.isEmpty()) return;

        boolean strict = "all".equalsIgnoreCase(realm.getAttribute(ATTR_SCOPE_MODE));
        Set<String> adminRoleNames = admin.getRoleMappingsStream()
                                          .map(RoleModel::getName)
                                          .collect(Collectors.toSet());
        boolean ok = strict
                ? adminRoleNames.containsAll(scope.requiredApproverRoles)
                : scope.requiredApproverRoles.stream().anyMatch(adminRoleNames::contains);
        if (!ok) {
            throw new ForbiddenException("Approver role required: " + scope.requiredApproverRoles
                    + " (mode=" + (strict ? "all" : "any") + ")");
        }
    }

    /**
     * Resolve the effective threshold. Returns the maximum of all thresholds
     * declared on scope-marked entities, falling back to the realm
     * {@code iga.threshold} attribute, and finally to 1.
     */
    public static int resolveThreshold(RealmModel realm, ResolvedScope scope) {
        if (scope != null && !scope.thresholds.isEmpty()) {
            return scope.thresholds.stream().mapToInt(Integer::intValue).max().orElse(1);
        }
        String t = realm.getAttribute(ATTR_THRESHOLD);
        if (t != null) {
            try { return Integer.parseInt(t); } catch (NumberFormatException ignored) { }
        }
        return 1;
    }

    // -------------------------------------------------------------------------
    // Internals
    // -------------------------------------------------------------------------

    private static List<Map<String, Object>> rows(IgaChangeRequestEntity cr) {
        String json = cr.getRowsJson();
        if (json == null || json.isBlank()) return List.of();
        try {
            List<Map<String, Object>> parsed = MAPPER.readValue(json, ROWS_TYPE);
            return parsed != null ? parsed : List.of();
        } catch (Exception e) {
            // Non-array payloads (e.g. BASELINE_APPROVAL's {tables: ...}) get no scope info.
            return List.of();
        }
    }

    private static String str(Map<String, Object> row, String key) {
        Object v = row.get(key);
        return v != null ? v.toString() : null;
    }

    private static void resolveUserScopesFromRows(KeycloakSession session, RealmModel realm,
                                                   IgaChangeRequestEntity cr, ResolvedScope out, String key) {
        for (Map<String, Object> row : rows(cr)) {
            String id = str(row, key);
            if (id == null) continue;
            UserModel user = session.users().getUserById(realm, id);
            if (user != null) collectUserGroupScopes(user, out);
        }
    }

    private static void resolveGroupScopesFromRows(KeycloakSession session, RealmModel realm,
                                                    IgaChangeRequestEntity cr, ResolvedScope out, String key) {
        for (Map<String, Object> row : rows(cr)) {
            String id = str(row, key);
            if (id == null) continue;
            GroupModel group = session.groups().getGroupById(realm, id);
            if (group != null) walkGroupAncestors(group, out);
        }
    }

    private static void resolveRoleScopesFromRows(KeycloakSession session, RealmModel realm,
                                                   IgaChangeRequestEntity cr, ResolvedScope out, String key) {
        for (Map<String, Object> row : rows(cr)) {
            String id = str(row, key);
            if (id == null) continue;
            RoleModel role = session.roles().getRoleById(realm, id);
            if (role != null) collectRoleScope(role, out);
        }
    }

    private static void resolveClientScopesFromRows(KeycloakSession session, RealmModel realm,
                                                     IgaChangeRequestEntity cr, ResolvedScope out, String key) {
        for (Map<String, Object> row : rows(cr)) {
            String id = str(row, key);
            if (id == null) continue;
            ClientModel client = session.clients().getClientById(realm, id);
            if (client != null) collectClientScope(client, out);
        }
    }

    /** Walk every group the user belongs to (and each group's ancestors) and harvest scope attributes. */
    private static void collectUserGroupScopes(UserModel user, ResolvedScope out) {
        user.getGroupsStream().forEach(g -> walkGroupAncestors(g, out));
    }

    private static void walkGroupAncestors(GroupModel g, ResolvedScope out) {
        GroupModel cur = g;
        while (cur != null) {
            String role = cur.getFirstAttribute(ATTR_APPROVER_ROLE);
            if (role != null && !role.isBlank()) {
                out.requiredApproverRoles.add(role.trim());
                addThreshold(cur.getFirstAttribute(ATTR_THRESHOLD), out);
            }
            cur = cur.getParent();
        }
    }

    private static void collectRoleScope(RoleModel role, ResolvedScope out) {
        String r = role.getFirstAttribute(ATTR_APPROVER_ROLE);
        if (r != null && !r.isBlank()) {
            out.requiredApproverRoles.add(r.trim());
            addThreshold(role.getFirstAttribute(ATTR_THRESHOLD), out);
        }
    }

    private static void collectClientScope(ClientModel client, ResolvedScope out) {
        String r = client.getAttribute(ATTR_APPROVER_ROLE);
        if (r != null && !r.isBlank()) {
            out.requiredApproverRoles.add(r.trim());
            addThreshold(client.getAttribute(ATTR_THRESHOLD), out);
        }
    }

    private static void addThreshold(String raw, ResolvedScope out) {
        if (raw == null) return;
        try {
            int v = Integer.parseInt(raw.trim());
            if (v > 0) out.thresholds.add(v);
        } catch (NumberFormatException ignored) {
        }
    }
}
