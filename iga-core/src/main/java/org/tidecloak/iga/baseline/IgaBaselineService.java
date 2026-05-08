package org.tidecloak.iga.baseline;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import org.jboss.logging.Logger;
import org.keycloak.models.RealmModel;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Builds the BASELINE_APPROVAL change request — a single CR that snapshots
 * every unsigned row in every IGA-tracked table for a realm, so that one
 * approval ceremony retroactively signs all pre-IGA data.
 *
 * Read queries use JPQL: every IGA-tracked entity (USER_ENTITY, KEYCLOAK_ROLE,
 * KEYCLOAK_GROUP, CLIENT, CLIENT_SCOPE, PROTOCOL_MAPPER, the relationship
 * tables, and the six attribute tables) declares an {@code attestation} field
 * via the tidecloak-override module, so we can navigate them with the standard
 * Keycloak JPA pattern.
 */
public class IgaBaselineService {

    private static final Logger log = Logger.getLogger(IgaBaselineService.class);
    public static final ObjectMapper MAPPER = new ObjectMapper();

    public static final String SCOPE = "BASELINE";
    public static final String ACTION_TYPE = "BASELINE_APPROVAL";
    public static final String ENTITY_TYPE = "REALM";

    // Table names exposed in the JSON payload.
    public static final String T_USER = "user_entity";
    public static final String T_ROLE = "keycloak_role";
    public static final String T_GROUP = "keycloak_group";
    public static final String T_CLIENT = "client";
    public static final String T_CLIENT_SCOPE = "client_scope";
    public static final String T_PROTOCOL_MAPPER = "protocol_mapper";
    public static final String T_USER_ROLE = "user_role_mapping";
    public static final String T_USER_GROUP = "user_group_membership";
    public static final String T_GROUP_ROLE = "group_role_mapping";
    public static final String T_COMPOSITE = "composite_role";
    public static final String T_CLIENT_SCOPE_CLIENT = "client_scope_client";
    public static final String T_CLIENT_SCOPE_ROLE = "client_scope_role_mapping";

    // Attribute tables (added in IGA 1.8.0 — intercepted by the workflow).
    public static final String T_USER_ATTRIBUTE = "user_attribute";
    public static final String T_CLIENT_ATTRIBUTES = "client_attributes";
    public static final String T_CLIENT_SCOPE_ATTRIBUTES = "client_scope_attributes";
    public static final String T_GROUP_ATTRIBUTE = "group_attribute";
    public static final String T_ROLE_ATTRIBUTE = "role_attribute";
    public static final String T_REALM_ATTRIBUTE = "realm_attribute";

    private final EntityManager em;

    public IgaBaselineService(EntityManager em) {
        this.em = em;
    }

    /**
     * Find a PENDING BASELINE_APPROVAL for the realm, if one exists.
     */
    public IgaChangeRequestEntity findPending(String realmId) {
        List<IgaChangeRequestEntity> existing = em.createQuery(
                "SELECT cr FROM IgaChangeRequestEntity cr " +
                        "WHERE cr.realmId = :realmId AND cr.actionType = :actionType AND cr.status = 'PENDING'",
                IgaChangeRequestEntity.class)
                .setParameter("realmId", realmId)
                .setParameter("actionType", ACTION_TYPE)
                .getResultList();
        return existing.isEmpty() ? null : existing.get(0);
    }

    /**
     * Snapshot every unsigned row across the 11 IGA-tracked tables for the
     * given realm into a fresh IGA_CHANGE_REQUEST. Returns the snapshot info
     * either as a CR (when row_count > 0) or with the empty-set signal
     * (rowCount == 0).
     */
    public BaselineResult buildAndPersist(RealmModel realm, String requestedBy) {
        String realmId = realm.getId();
        long snapshotAt = System.currentTimeMillis();

        Map<String, List<Map<String, Object>>> tables = collectAllUnsignedRows(realmId);

        long total = tables.values().stream().mapToLong(List::size).sum();
        if (total == 0) {
            return new BaselineResult(null, 0L, Map.of());
        }

        ObjectNode root = MAPPER.createObjectNode();
        root.put("scope", SCOPE);
        root.put("realm_id", realmId);
        root.put("snapshot_at", snapshotAt);
        root.put("row_count", total);

        ObjectNode tablesNode = root.putObject("tables");
        Map<String, Long> summary = new LinkedHashMap<>();
        for (Map.Entry<String, List<Map<String, Object>>> e : tables.entrySet()) {
            if (e.getValue().isEmpty()) continue;
            ArrayNode arr = tablesNode.putArray(e.getKey());
            for (Map<String, Object> row : e.getValue()) {
                arr.add(MAPPER.valueToTree(row));
            }
            summary.put(e.getKey(), (long) e.getValue().size());
        }

        String rowsJson;
        try {
            rowsJson = MAPPER.writeValueAsString(root);
        } catch (Exception ex) {
            throw new RuntimeException("Failed to serialize baseline snapshot", ex);
        }

        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setId(UUID.randomUUID().toString());
        cr.setRealmId(realmId);
        cr.setEntityType(ENTITY_TYPE);
        cr.setEntityId(realmId);
        cr.setActionType(ACTION_TYPE);
        cr.setRowsJson(rowsJson);
        cr.setStatus("PENDING");
        cr.setRequestedBy(requestedBy);
        cr.setCreatedAt(snapshotAt);
        em.persist(cr);
        em.flush();

        log.infof("Created BASELINE_APPROVAL change request %s for realm %s with %d unsigned rows across %d tables",
                cr.getId(), realmId, total, summary.size());

        return new BaselineResult(cr, total, summary);
    }

    /**
     * Collect unsigned rows for all 11 IGA-tracked tables, scoped to a realm.
     * Tables with no unsigned rows are returned with empty lists; the caller
     * is expected to omit those entries when building the JSON payload.
     */
    private Map<String, List<Map<String, Object>>> collectAllUnsignedRows(String realmId) {
        Map<String, List<Map<String, Object>>> out = new LinkedHashMap<>();

        // -------- Info tables (have a direct realm field or equivalent) --------

        out.put(T_USER, queryRows(
                "SELECT u.id, u.username, u.email FROM UserEntity u " +
                        "WHERE u.realmId = ?1 AND u.attestation IS NULL",
                List.of(realmId), List.of("id", "_username", "_email")));

        out.put(T_ROLE, queryRows(
                "SELECT r.id, r.name FROM RoleEntity r " +
                        "WHERE r.realmId = ?1 AND r.attestation IS NULL",
                List.of(realmId), List.of("id", "_name")));

        // GroupEntity's realm field is named `realm` (column REALM_ID).
        out.put(T_GROUP, queryRows(
                "SELECT g.id, g.name FROM GroupEntity g " +
                        "WHERE g.realm = ?1 AND g.attestation IS NULL",
                List.of(realmId), List.of("id", "_name")));

        out.put(T_CLIENT, queryRows(
                "SELECT c.id, c.clientId FROM ClientEntity c " +
                        "WHERE c.realmId = ?1 AND c.attestation IS NULL",
                List.of(realmId), List.of("id", "_clientId")));

        // CLIENT_SCOPE — added in IGA 2.0.0. Direct realmId field.
        out.put(T_CLIENT_SCOPE, queryRows(
                "SELECT cs.id, cs.name FROM ClientScopeEntity cs " +
                        "WHERE cs.realmId = ?1 AND cs.attestation IS NULL",
                List.of(realmId), List.of("id", "_name")));

        // PROTOCOL_MAPPER: scoped to clients in the realm. Each row also carries
        // its parent client id for replay convenience.
        out.put(T_PROTOCOL_MAPPER, queryRows(
                "SELECT pm.id, pm.name, pm.client.id FROM ProtocolMapperEntity pm " +
                        "WHERE pm.client.realmId = ?1 AND pm.attestation IS NULL",
                List.of(realmId), List.of("id", "_name", "_clientId")));

        // -------- Relationship tables (no direct realm column) --------

        // USER_ROLE_MAPPING — navigate through `user` for realm scope; explicit
        // entity join to RoleEntity by id for the friendly role name.
        out.put(T_USER_ROLE, queryRows(
                "SELECT urm.user.id, urm.roleId, urm.user.username, r.name " +
                        "FROM UserRoleMappingEntity urm " +
                        "LEFT JOIN RoleEntity r ON r.id = urm.roleId " +
                        "WHERE urm.user.realmId = ?1 AND urm.attestation IS NULL",
                List.of(realmId), List.of("USER_ID", "ROLE_ID", "_user", "_role")));

        // USER_GROUP_MEMBERSHIP — payload still uses canonical "USER"/"GROUP" labels.
        out.put(T_USER_GROUP, queryRows(
                "SELECT ugm.user.id, ugm.groupId, ugm.user.username, g.name " +
                        "FROM UserGroupMembershipEntity ugm " +
                        "LEFT JOIN GroupEntity g ON g.id = ugm.groupId " +
                        "WHERE ugm.user.realmId = ?1 AND ugm.attestation IS NULL",
                List.of(realmId), List.of("USER", "GROUP", "_user", "_group")));

        // GROUP_ROLE_MAPPING — group has realm field directly
        out.put(T_GROUP_ROLE, queryRows(
                "SELECT grm.group.id, grm.roleId, grm.group.name, r.name " +
                        "FROM GroupRoleMappingEntity grm " +
                        "LEFT JOIN RoleEntity r ON r.id = grm.roleId " +
                        "WHERE grm.group.realm = ?1 AND grm.attestation IS NULL",
                List.of(realmId), List.of("GROUP", "ROLE", "_group", "_role")));

        // COMPOSITE_ROLE — entity uses parentRole/childRole (both ManyToOne)
        out.put(T_COMPOSITE, queryRows(
                "SELECT cr.parentRole.id, cr.childRole.id, cr.parentRole.name, cr.childRole.name " +
                        "FROM CompositeRoleEntity cr " +
                        "WHERE cr.parentRole.realmId = ?1 AND cr.attestation IS NULL",
                List.of(realmId), List.of("COMPOSITE", "CHILD_ROLE", "_parent", "_child")));

        // CLIENT_SCOPE_CLIENT — clientId/clientScopeId are plain @Column scalars,
        // so we explicit-join their parent entities for the friendly names.
        out.put(T_CLIENT_SCOPE_CLIENT, queryRows(
                "SELECT csc.clientId, csc.clientScopeId, c.clientId, cs.name " +
                        "FROM ClientScopeClientMappingEntity csc " +
                        "JOIN ClientEntity c ON c.id = csc.clientId " +
                        "LEFT JOIN ClientScopeEntity cs ON cs.id = csc.clientScopeId " +
                        "WHERE c.realmId = ?1 AND csc.attestation IS NULL",
                List.of(realmId), List.of("CLIENT_ID", "SCOPE_ID", "_client", "_scope")));

        // CLIENT_SCOPE_ROLE_MAPPING — clientScope and role are ManyToOne
        out.put(T_CLIENT_SCOPE_ROLE, queryRows(
                "SELECT csrm.clientScope.id, csrm.role.id, csrm.clientScope.name, csrm.role.name " +
                        "FROM ClientScopeRoleMappingEntity csrm " +
                        "WHERE csrm.clientScope.realmId = ?1 AND csrm.attestation IS NULL",
                List.of(realmId), List.of("SCOPE_ID", "ROLE_ID", "_scope", "_role")));

        // -------- Attribute tables (intercepted by IGA 1.8.0+) --------
        // Each table joins to its parent entity for realm scoping.

        // USER_ATTRIBUTE — UserEntity has realmId
        out.put(T_USER_ATTRIBUTE, queryRows(
                "SELECT ua.user.id, ua.name, ua.value FROM UserAttributeEntity ua " +
                        "WHERE ua.user.realmId = ?1 AND ua.attestation IS NULL",
                List.of(realmId), List.of("user_id", "name", "value")));

        // CLIENT_ATTRIBUTES — ClientEntity has realmId
        out.put(T_CLIENT_ATTRIBUTES, queryRows(
                "SELECT ca.client.id, ca.name, ca.value FROM ClientAttributeEntity ca " +
                        "WHERE ca.client.realmId = ?1 AND ca.attestation IS NULL",
                List.of(realmId), List.of("client_id", "name", "value")));

        // CLIENT_SCOPE_ATTRIBUTES — ClientScopeEntity has realmId
        out.put(T_CLIENT_SCOPE_ATTRIBUTES, queryRows(
                "SELECT csa.clientScope.id, csa.name, csa.value FROM ClientScopeAttributeEntity csa " +
                        "WHERE csa.clientScope.realmId = ?1 AND csa.attestation IS NULL",
                List.of(realmId), List.of("scope_id", "name", "value")));

        // GROUP_ATTRIBUTE — GroupEntity's realm field is `realm`
        out.put(T_GROUP_ATTRIBUTE, queryRows(
                "SELECT ga.group.id, ga.name, ga.value FROM GroupAttributeEntity ga " +
                        "WHERE ga.group.realm = ?1 AND ga.attestation IS NULL",
                List.of(realmId), List.of("group_id", "name", "value")));

        // ROLE_ATTRIBUTE — RoleEntity has realmId
        out.put(T_ROLE_ATTRIBUTE, queryRows(
                "SELECT ra.role.id, ra.name, ra.value FROM RoleAttributeEntity ra " +
                        "WHERE ra.role.realmId = ?1 AND ra.attestation IS NULL",
                List.of(realmId), List.of("role_id", "name", "value")));

        // REALM_ATTRIBUTE — RealmEntity exposes id; navigate via the @ManyToOne realm
        out.put(T_REALM_ATTRIBUTE, queryRows(
                "SELECT rea.realm.id, rea.name, rea.value FROM RealmAttributeEntity rea " +
                        "WHERE rea.realm.id = ?1 AND rea.attestation IS NULL",
                List.of(realmId), List.of("realm_id", "name", "value")));

        return out;
    }

    /**
     * Run a positional JPQL query and convert each result tuple into a
     * Map<String, Object> using the supplied column-name list. JPQL projections
     * return {@code Object[]} (or a scalar for single-column SELECTs); we map
     * positionally onto the supplied logical column names so the JSON snapshot
     * shape is independent of the underlying entity/field naming.
     */
    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> queryRows(String jpql, List<Object> params, List<String> columns) {
        Query q = em.createQuery(jpql);
        for (int i = 0; i < params.size(); i++) {
            q.setParameter(i + 1, params.get(i));
        }
        List<Object> rows = q.getResultList();
        List<Map<String, Object>> out = new ArrayList<>(rows.size());
        for (Object o : rows) {
            // Single-column rows come back as a scalar, not Object[].
            Object[] arr = (o instanceof Object[]) ? (Object[]) o : new Object[]{o};
            Map<String, Object> row = new LinkedHashMap<>();
            for (int i = 0; i < columns.size() && i < arr.length; i++) {
                row.put(columns.get(i), arr[i] != null ? arr[i].toString() : null);
            }
            out.add(row);
        }
        return out;
    }

    /**
     * Result tuple from a baseline build. cr == null indicates "no unsigned
     * rows existed; nothing was persisted".
     */
    public static final class BaselineResult {
        public final IgaChangeRequestEntity cr;
        public final long totalRows;
        public final Map<String, Long> summary;

        public BaselineResult(IgaChangeRequestEntity cr, long totalRows, Map<String, Long> summary) {
            this.cr = cr;
            this.totalRows = totalRows;
            this.summary = summary;
        }
    }

    /**
     * Parse the rows_json blob produced by buildAndPersist back into a
     * JsonNode tree.
     */
    public static JsonNode parseRows(String rowsJson) {
        try {
            return MAPPER.readTree(rowsJson);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse baseline rows_json", e);
        }
    }
}
