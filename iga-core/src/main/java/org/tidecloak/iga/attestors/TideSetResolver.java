package org.tidecloak.iga.attestors;

import java.util.Map;

/**
 * Single source of truth for the per-(table, owner) SET-SIGNING model.
 *
 * <p>The signing unit for a LINKAGE table is a per-(table, owner) SET: all rows
 * in that table that share the same owner key are signed as ONE aggregate. When
 * a row is added or removed, the owner's WHOLE set is re-signed and that one
 * signature is written to EVERY row in the owner's set. NODE tables
 * (user_entity, keycloak_role, client, client_scope, keycloak_group, realm) stay
 * PER-ENTITY (one row = its own signature over its own state).
 *
 * <p>This resolver maps an IGA {@code actionType} to:
 * <ul>
 *   <li>whether the action targets a LINKAGE table that participates in
 *       set-signing ({@link #isLinkage(String)});</li>
 *   <li>the linkage descriptor — the owning JPA entity, the owner (group-by)
 *       JPA field, the member JPA field, and the rowsJson key carrying the
 *       owner value — used both to gather the owner's post-change set and to
 *       fan the set signature out across every row of the owner set
 *       ({@link #linkageFor(String)}).</li>
 * </ul>
 *
 * <p>The owner (group-by) key per linkage table is:
 * <pre>
 *   user_role_mapping          owner = user_id
 *   user_group_membership      owner = user_id
 *   group_role_mapping         owner = group_id
 *   composite_role             owner = composite (parent role id)
 *   client_scope_client        owner = client_id
 *   client_scope_role_mapping  owner = client_scope id (SCOPE_ID)
 *   scope_mapping              owner = client_id
 *   default_client_scope       owner = realm_id
 *   protocol_mapper            owner = client_id OR client_scope_id (its owning parent)
 * </pre>
 *
 * <p>The JPA field names mirror EXACTLY the per-row stamp JPQL that
 * {@code IgaReplayDispatcher} already uses for each action, so the set fan-out
 * is the identical UPDATE minus the member-key predicate.
 */
public final class TideSetResolver {

    private TideSetResolver() {
    }

    /**
     * Descriptor for one linkage table's set-signing shape.
     *
     * @param entityName    JPA entity simple name (for JPQL FROM/UPDATE).
     * @param ownerField    JPA field path for the owner (group-by) column.
     * @param memberField   JPA field path for the member column (the per-row
     *                      key that distinguishes rows within an owner's set).
     * @param ownerRowKey   rowsJson key carrying the owner value on the CR row.
     * @param memberRowKey  rowsJson key carrying the member value on the CR row.
     * @param table         physical table name (documentation / canonical form).
     */
    public record Linkage(String entityName,
                          String ownerField,
                          String memberField,
                          String ownerRowKey,
                          String memberRowKey,
                          String table) {

        /** JPQL that fans the set signature out across the WHOLE owner set. */
        public String fanOutStampJpql() {
            return "UPDATE " + entityName + " e SET e.attestation = :sig WHERE e." + ownerField + " = :owner";
        }

        /** JPQL that reads the CURRENT member set for an owner (pre-change). */
        public String selectMembersJpql() {
            return "SELECT e." + memberField + " FROM " + entityName + " e WHERE e." + ownerField + " = :owner";
        }
    }

    /**
     * True iff this action type writes a LINKAGE-table row that participates in
     * per-(table, owner) set-signing. The ADD side of every governed linkage
     * relationship returns a descriptor; node creates and non-linkage actions
     * return {@code null} (per-entity behaviour preserved).
     */
    public static boolean isLinkage(String actionType) {
        return linkageFor(actionType) != null;
    }

    /**
     * Resolve the linkage descriptor for an ADD-side linkage action, or
     * {@code null} for anything else (node creates, attribute writes, revokes,
     * realm structural writes, ADOPT_*, organizations, ...).
     *
     * <p>Only the ADD-side actions are returned: a REMOVE deletes the row, so
     * there is no row to stamp — but the set fan-out on a REMOVE still re-signs
     * the SURVIVING rows. Both directions are handled by the dispatcher via the
     * same descriptor (the dispatcher already computes the post-change set
     * BEFORE replay applies the delta). The mapping below therefore also
     * recognises the matching REMOVE action types so the dispatcher can re-sign
     * the shrunken set.
     */
    public static Linkage linkageFor(String actionType) {
        if (actionType == null) return null;
        switch (actionType) {
            // user_role_mapping — owner = user_id, member = role_id.
            case "GRANT_ROLES":
            case "REVOKE_ROLES":
                return new Linkage("UserRoleMappingEntity", "user.id", "roleId",
                        "USER_ID", "ROLE_ID", "user_role_mapping");
            // user_group_membership — owner = user_id, member = group_id.
            case "JOIN_GROUPS":
            case "LEAVE_GROUPS":
                return new Linkage("UserGroupMembershipEntity", "user.id", "groupId",
                        "USER", "GROUP", "user_group_membership");
            // group_role_mapping — owner = group_id, member = role_id.
            case "GROUP_GRANT_ROLES":
            case "GROUP_REVOKE_ROLES":
                return new Linkage("GroupRoleMappingEntity", "group.id", "roleId",
                        "GROUP", "ROLE", "group_role_mapping");
            // composite_role — owner = parent role id, member = child role id.
            case "ADD_COMPOSITE":
            case "REMOVE_COMPOSITE":
                return new Linkage("CompositeRoleEntity", "parentRole.id", "childRole.id",
                        "COMPOSITE", "CHILD_ROLE", "composite_role");
            // client_scope_client — owner = client_id (UUID), member = scope_id.
            case "ASSIGN_SCOPE":
            case "REMOVE_SCOPE":
                return new Linkage("ClientScopeClientMappingEntity", "clientId", "clientScopeId",
                        "CLIENT_UUID", "SCOPE_ID", "client_scope_client");
            // client_scope_role_mapping — owner = client_scope id, member = role id.
            case "SCOPE_ADD_ROLE":
            case "SCOPE_REMOVE_ROLE":
                return new Linkage("ClientScopeRoleMappingEntity", "clientScope.id", "role.id",
                        "SCOPE_ID", "ROLE_ID", "client_scope_role_mapping");
            // scope_mapping — owner = client_id (UUID), member = role id.
            case "SCOPE_MAPPING_ADD":
            case "SCOPE_MAPPING_REMOVE":
                return new Linkage("ScopeMappingEntity", "clientId", "roleId",
                        "CLIENT_UUID", "ROLE_ID", "scope_mapping");
            // default_client_scope — owner = realm_id, member = scope id.
            case "REALM_DEFAULT_SCOPE_ADD":
            case "REALM_DEFAULT_SCOPE_REMOVE":
                return new Linkage("DefaultClientScopeRealmMappingEntity", "realm.id", "clientScopeId",
                        "REALM_ID", "SCOPE_ID", "default_client_scope");
            // protocol_mapper — owner = client_id OR client_scope_id (its parent),
            // member = mapper id. Owner key is resolved per-row by the dispatcher
            // (CLIENT_UUID/CLIENT_ID → client.id, else CLIENT_SCOPE_ID →
            // clientScope.id); the descriptor here is the CLIENT-owned shape, the
            // dispatcher swaps the owner field for the scope-owned variant when
            // the row carries a CLIENT_SCOPE_ID instead. See PROTOCOL_MAPPER_*.
            case "ADD_PROTOCOL_MAPPER":
                return new Linkage("ProtocolMapperEntity", "client.id", "id",
                        "CLIENT_UUID", "ID", "protocol_mapper");
            default:
                return null;
        }
    }

    /**
     * Protocol-mapper owner field variant for a SCOPE-owned mapper (parent is a
     * client_scope, not a client). Used by the dispatcher when the CR row
     * carries a CLIENT_SCOPE_ID rather than CLIENT_UUID/CLIENT_ID.
     */
    public static final String PROTOCOL_MAPPER_SCOPE_OWNER_FIELD = "clientScope.id";

    /**
     * Resolve the owner VALUE from a CR row for the given linkage. Returns the
     * raw rowsJson value at the linkage's {@code ownerRowKey}, or {@code null}
     * if absent. For protocol_mapper the dispatcher resolves the owner itself
     * (client vs scope) — this helper is for the simple single-key linkages.
     */
    public static String ownerValue(Linkage linkage, Map<String, Object> row) {
        if (linkage == null || row == null) return null;
        Object v = row.get(linkage.ownerRowKey());
        return v != null ? v.toString() : null;
    }
}
