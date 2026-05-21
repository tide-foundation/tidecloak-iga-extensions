package org.tidecloak.iga.attestors;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.ForbiddenException;
import org.jboss.logging.Logger;
import org.keycloak.models.ClientModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.replay.IgaReplayExtension;

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

    private static final Logger log = Logger.getLogger(IgaScopeResolver.class);

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<List<Map<String, Object>>> ROWS_TYPE =
            new TypeReference<List<Map<String, Object>>>() {};

    public static final String ATTR_APPROVER_ROLE = "iga.approverRole";
    public static final String ATTR_THRESHOLD = "iga.threshold";
    public static final String ATTR_SCOPE_MODE = "iga.scopeMode";

    /**
     * Session-attribute key prefix used to dedupe the "ADOPT gate bypass" INFO
     * log line so we emit it at most once per (request, CR, gate) instead of
     * once per call. The same CR is typically inspected several times in one
     * request (resolve-then-threshold, list-representation enrichment, etc.).
     */
    private static final String ADOPT_BYPASS_LOG_KEY_PREFIX = "iga.adoptBypass.logged.";

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
     * issuance) yield an empty {@link ResolvedScope}.
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
                resolveClientScopesFromRows(session, realm, cr, scope, "CLIENT_ID");
                break;
            case "ADD_PROTOCOL_MAPPER":
            case "UPDATE_PROTOCOL_MAPPER":
            case "REMOVE_PROTOCOL_MAPPER":
                // Protocol mappers may live under a client OR a client scope.
                // Walk both possible parent ids; the row-shape carries one or
                // the other so the lookups for the absent one are no-ops.
                resolveClientScopesFromRows(session, realm, cr, scope, "CLIENT_ID");
                // Client scope scopes have no first-class iga.approverRole
                // today, so we don't walk CLIENT_SCOPE_ID as a parent — falls
                // through to the realm default.
                break;
            case "SCOPE_ADD_ROLE":
            case "SCOPE_REMOVE_ROLE":
                // Client scope scopes have no first-class iga.approverRole today;
                // fall through to the realm default.
                break;
            // -----------------------------------------------------------------
            // Realm-level structural writes — no per-entity scope; fall through
            // to the realm-default approver/threshold.
            // -----------------------------------------------------------------
            case "SET_REALM_CONFIG":
            case "ADD_REALM_DEFAULT_GROUP":
            case "REMOVE_REALM_DEFAULT_GROUP":
            case "CREATE_CLIENT_SCOPE":
                break;
            case "UPDATE_CLIENT_WEB_ORIGINS":
            case "UPDATE_CLIENT_REDIRECT_URIS":
                resolveClientScopesFromRows(session, realm, cr, scope, "client_id");
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
            // -----------------------------------------------------------------
            // Organizations. OrganizationModel supports attributes, so an org
            // may carry iga.approverRole / iga.threshold and is scoped just
            // like a group/client. CREATE_ORGANIZATION is realm-wide (no org
            // exists yet) → empty scope, exactly like the other top-level
            // creates.
            // -----------------------------------------------------------------
            case "UPDATE_ORGANIZATION":
            case "DELETE_ORGANIZATION":
            case "ADD_ORG_MEMBER":
            case "REMOVE_ORG_MEMBER":
            case "ORG_INVITE_MEMBER":
            case "ORG_RESEND_INVITE":
            case "ORG_ADD_IDP":
            case "ORG_REMOVE_IDP":
                // Two-entity scope (mirrors GRANT_ROLES which binds user+role):
                // ORG_ADD_IDP / ORG_REMOVE_IDP bind both the org and the linked
                // IdP, so collect scope contributions from both entities. The
                // existing ResolvedScope merge semantics — union of required
                // approver roles, max of thresholds (see
                // resolveThresholdInternal:280) — apply automatically once
                // both helpers write into the same `scope` instance. IdP
                // attributes live in IdentityProviderModel.getConfig()
                // (server-spi:208) so a separate resolver branch reads them
                // out of the IdP's config map.
                resolveOrganizationScopesFromRows(session, realm, cr, scope, "ORG_ID");
                resolveIdpScopesFromRows(session, realm, cr, scope, "IDP_ALIAS");
                break;
            // CREATE_USER / CREATE_ROLE / CREATE_GROUP / CREATE_CLIENT /
            // CREATE_ORGANIZATION, the Phase 6+ ADOPT_* family, and realm-wide
            // action types (REQUEST_SERVER_CERT, INSTALL_LICENSE,
            // ROTATE_LICENSE) intentionally leave the scope empty.
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
     * @deprecated Prefer
     *     {@link #requireApprover(KeycloakSession, RealmModel, UserModel, ResolvedScope, IgaChangeRequestEntity)}
     *     so the ADOPT_* system-bootstrap bypass can short-circuit the gate.
     *     Retained for any caller that has no CR context.
     */
    @Deprecated
    public static void requireApprover(RealmModel realm, UserModel admin, ResolvedScope scope) {
        requireApproverInternal(realm, admin, scope);
    }

    /**
     * Action-type-aware variant. ADOPT_* CRs are a system-bootstrap onramp
     * (the entity already exists in production pre-IGA) — applying the realm's
     * approver-role gate to them creates a chicken-and-egg deadlock where
     * high-threshold realms with pre-IGA admins can't bootstrap. For ADOPT_*
     * action types this method is a no-op; all other action types fall through
     * to the same enforcement path as before. The caller's {@code manage-realm}
     * check (see {@code IgaAdminResource.authorize}/{@code commit}) remains
     * the only gate for ADOPT.
     */
    public static void requireApprover(KeycloakSession session, RealmModel realm, UserModel admin,
                                       ResolvedScope scope, IgaChangeRequestEntity cr) {
        if (cr != null && IgaReplayExtension.isAdoptAction(cr.getActionType())) {
            logAdoptBypassOnce(session, cr, "requireApprover");
            return;
        }
        requireApproverInternal(realm, admin, scope);
    }

    private static void requireApproverInternal(RealmModel realm, UserModel admin, ResolvedScope scope) {
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
     *
     * <p>The realm-level {@code iga.threshold} is subject to the same
     * positivity rule as the per-entity path (see {@link #addThreshold}): a
     * non-integer or {@code < 1} value is ignored and treated as the default
     * {@code 1}. A non-positive realm value must not be honoured literally,
     * because {@code authCount < threshold} would never trip and the commit
     * gate could be silently disabled. A defensive final clamp guarantees this
     * method can never return a value {@code < 1} regardless of the source.</p>
     *
     * @deprecated Prefer
     *     {@link #resolveThreshold(KeycloakSession, RealmModel, ResolvedScope, IgaChangeRequestEntity)}
     *     so the ADOPT_* system-bootstrap bypass (threshold=1) can short-circuit
     *     the gate. Retained for any caller that has no CR context.
     */
    @Deprecated
    public static int resolveThreshold(RealmModel realm, ResolvedScope scope) {
        return resolveThresholdInternal(realm, scope);
    }

    /**
     * Action-type-aware variant. ADOPT_* CRs are a system-bootstrap onramp
     * (the entity already exists in production pre-IGA) — applying the realm's
     * governance threshold to them creates a chicken-and-egg deadlock where
     * high-threshold realms with pre-IGA admins can't bootstrap. For ADOPT_*
     * action types this method returns {@code 1} unconditionally, regardless
     * of realm-level or per-scope {@code iga.threshold}. All other action
     * types fall through to the same threshold-resolution path as before.
     */
    public static int resolveThreshold(KeycloakSession session, RealmModel realm,
                                       ResolvedScope scope, IgaChangeRequestEntity cr) {
        if (cr != null && IgaReplayExtension.isAdoptAction(cr.getActionType())) {
            logAdoptBypassOnce(session, cr, "resolveThreshold");
            return 1;
        }
        return resolveThresholdInternal(realm, scope);
    }

    private static int resolveThresholdInternal(RealmModel realm, ResolvedScope scope) {
        int resolved = 1;
        if (scope != null && !scope.thresholds.isEmpty()) {
            resolved = scope.thresholds.stream().mapToInt(Integer::intValue).max().orElse(1);
        } else {
            String t = realm.getAttribute(ATTR_THRESHOLD);
            if (t != null) {
                try {
                    int parsed = Integer.parseInt(t.trim());
                    // Mirror the per-entity rule (addThreshold, > 0): a
                    // non-positive realm value is invalid and falls back to
                    // the default 1 rather than being honoured literally.
                    if (parsed >= 1) resolved = parsed;
                } catch (NumberFormatException ignored) { }
            }
        }
        // Defence-in-depth: never return a threshold that could disable the
        // commit gate, irrespective of how `resolved` was computed.
        return Math.max(1, resolved);
    }

    /**
     * Emit one INFO log line per (request, CR, gate) when the ADOPT_*
     * system-bootstrap bypass fires. A single request can hit the threshold +
     * approver-role paths several times (resolve-then-threshold during
     * commit, list-representation enrichment, etc.); without dedup the log
     * would balloon. We key on the {@link KeycloakSession} attribute map so
     * the suppression is per-request (no JVM-wide map / no eviction concern).
     */
    private static void logAdoptBypassOnce(KeycloakSession session, IgaChangeRequestEntity cr, String gate) {
        if (cr == null) return;
        String key = ADOPT_BYPASS_LOG_KEY_PREFIX + gate + "." + cr.getId();
        if (session != null && session.getAttribute(key) != null) return;
        if (session != null) session.setAttribute(key, Boolean.TRUE);
        log.infof("IGA ADOPT gate bypass: actionType=%s CR=%s — threshold=1, no approver-role check (system-bootstrap action) [gate=%s]",
                cr.getActionType(), cr.getId(), gate);
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
            // Non-array payloads get no scope info.
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

    private static void resolveOrganizationScopesFromRows(KeycloakSession session, RealmModel realm,
                                                          IgaChangeRequestEntity cr, ResolvedScope out,
                                                          String key) {
        org.keycloak.organization.OrganizationProvider orgs =
                session.getProvider(org.keycloak.organization.OrganizationProvider.class);
        if (orgs == null) return;
        for (Map<String, Object> row : rows(cr)) {
            String id = str(row, key);
            if (id == null) continue;
            org.keycloak.models.OrganizationModel org = orgs.getById(id);
            if (org != null) collectOrganizationScope(org, out);
        }
    }

    /**
     * Walk the CR rows for the IdP alias column ({@code IDP_ALIAS}) and harvest
     * scope contributions from each linked IdP. Used by ORG_ADD_IDP /
     * ORG_REMOVE_IDP — the row shape carries both ORG_ID and IDP_ALIAS (see
     * IgaOrganizationProvider.recordIdp:337-343), so this helper is a sibling
     * to {@link #resolveOrganizationScopesFromRows} called from the same case
     * branch. We look the IdP up via {@code session.identityProviders()
     * .getByAlias(alias)} (the canonical SPI surface KC uses everywhere else,
     * e.g. OrganizationIdentityProvidersResource.addIdentityProvider:131); if
     * the IdP can't be resolved (e.g. it's already been detached at commit
     * time for ORG_REMOVE_IDP), the row is silently skipped — the org-side
     * contribution still gates the change, and the resolver is best-effort.
     */
    private static void resolveIdpScopesFromRows(KeycloakSession session, RealmModel realm,
                                                 IgaChangeRequestEntity cr, ResolvedScope out,
                                                 String key) {
        for (Map<String, Object> row : rows(cr)) {
            String alias = str(row, key);
            if (alias == null || alias.isBlank()) continue;
            IdentityProviderModel idp;
            try {
                idp = session.identityProviders().getByAlias(alias);
            } catch (RuntimeException ignored) {
                // Storage failures (e.g. stale read during a parallel detach)
                // must never break the gate — fall through to the org-only
                // contribution.
                continue;
            }
            if (idp != null) collectIdpScope(idp, out);
        }
    }

    /**
     * Harvest iga.approverRole / iga.threshold from an IdP's config map.
     * IdentityProviderModel exposes only the full config map
     * ({@link IdentityProviderModel#getConfig()} — server-spi:208), so we
     * read the keys directly. Mirrors {@link #collectClientScope} (single
     * value per key, no per-attribute list shape).
     */
    private static void collectIdpScope(IdentityProviderModel idp, ResolvedScope out) {
        Map<String, String> config = idp.getConfig();
        if (config == null) return;
        String role = config.get(ATTR_APPROVER_ROLE);
        if (role != null && !role.isBlank()) {
            out.requiredApproverRoles.add(role.trim());
            addThreshold(config.get(ATTR_THRESHOLD), out);
        }
    }

    /**
     * Harvest iga.approverRole / iga.threshold from an organization's
     * attributes. {@code OrganizationModel} exposes only the full attribute
     * map (no getFirstAttribute), so read the first value of each key.
     */
    private static void collectOrganizationScope(org.keycloak.models.OrganizationModel org,
                                                 ResolvedScope out) {
        Map<String, List<String>> attrs = org.getAttributes();
        if (attrs == null) return;
        String role = firstAttr(attrs, ATTR_APPROVER_ROLE);
        if (role != null && !role.isBlank()) {
            out.requiredApproverRoles.add(role.trim());
            addThreshold(firstAttr(attrs, ATTR_THRESHOLD), out);
        }
    }

    private static String firstAttr(Map<String, List<String>> attrs, String key) {
        List<String> v = attrs.get(key);
        return (v == null || v.isEmpty()) ? null : v.get(0);
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
