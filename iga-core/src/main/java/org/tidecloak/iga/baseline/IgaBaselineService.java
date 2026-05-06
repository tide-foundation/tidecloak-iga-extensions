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
 * Read queries use native SQL because the SIGNATURE column was added by the
 * IGA Liquibase changelog at the DB layer; the Keycloak JPA entity classes
 * do not (yet) declare a `signature` field. Native SQL keeps us decoupled
 * from any future JPA mapping.
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

        // -------- Info tables (have a direct REALM_ID column or equivalent) --------

        out.put(T_USER, queryRows(
                "SELECT ID AS id, USERNAME AS \"_username\", EMAIL AS \"_email\" " +
                        "FROM USER_ENTITY WHERE REALM_ID = ? AND SIGNATURE IS NULL",
                List.of(realmId), List.of("id", "_username", "_email")));

        out.put(T_ROLE, queryRows(
                "SELECT ID AS id, NAME AS \"_name\" " +
                        "FROM KEYCLOAK_ROLE WHERE REALM_ID = ? AND SIGNATURE IS NULL",
                List.of(realmId), List.of("id", "_name")));

        out.put(T_GROUP, queryRows(
                "SELECT ID AS id, NAME AS \"_name\" " +
                        "FROM KEYCLOAK_GROUP WHERE REALM_ID = ? AND SIGNATURE IS NULL",
                List.of(realmId), List.of("id", "_name")));

        out.put(T_CLIENT, queryRows(
                "SELECT ID AS id, CLIENT_ID AS \"_clientId\" " +
                        "FROM CLIENT WHERE REALM_ID = ? AND SIGNATURE IS NULL",
                List.of(realmId), List.of("id", "_clientId")));

        // PROTOCOL_MAPPER: scoped to clients in the realm. Each row also carries
        // its parent client id for replay convenience.
        out.put(T_PROTOCOL_MAPPER, queryRows(
                "SELECT pm.ID AS id, pm.NAME AS \"_name\", c.ID AS \"_clientId\" " +
                        "FROM PROTOCOL_MAPPER pm " +
                        "JOIN CLIENT c ON pm.CLIENT_ID = c.ID " +
                        "WHERE c.REALM_ID = ? AND pm.SIGNATURE IS NULL",
                List.of(realmId), List.of("id", "_name", "_clientId")));

        // -------- Relationship tables (no direct realm column) --------

        // USER_ROLE_MAPPING — join via USER_ENTITY for realm scope, also via
        // KEYCLOAK_ROLE for the friendly role name display.
        out.put(T_USER_ROLE, queryRows(
                "SELECT urm.USER_ID AS \"USER_ID\", urm.ROLE_ID AS \"ROLE_ID\", " +
                        "u.USERNAME AS \"_user\", r.NAME AS \"_role\" " +
                        "FROM USER_ROLE_MAPPING urm " +
                        "JOIN USER_ENTITY u ON urm.USER_ID = u.ID " +
                        "LEFT JOIN KEYCLOAK_ROLE r ON urm.ROLE_ID = r.ID " +
                        "WHERE u.REALM_ID = ? AND urm.SIGNATURE IS NULL",
                List.of(realmId), List.of("USER_ID", "ROLE_ID", "_user", "_role")));

        // USER_GROUP_MEMBERSHIP — column names map to USER_ID, GROUP_ID; the
        // payload exposes them under the canonical "USER" / "GROUP" labels
        // already used by the rest of the IGA replay code.
        out.put(T_USER_GROUP, queryRows(
                "SELECT ugm.USER_ID AS \"USER\", ugm.GROUP_ID AS \"GROUP\", " +
                        "u.USERNAME AS \"_user\", g.NAME AS \"_group\" " +
                        "FROM USER_GROUP_MEMBERSHIP ugm " +
                        "JOIN USER_ENTITY u ON ugm.USER_ID = u.ID " +
                        "LEFT JOIN KEYCLOAK_GROUP g ON ugm.GROUP_ID = g.ID " +
                        "WHERE u.REALM_ID = ? AND ugm.SIGNATURE IS NULL",
                List.of(realmId), List.of("USER", "GROUP", "_user", "_group")));

        // GROUP_ROLE_MAPPING — group has REALM_ID directly
        out.put(T_GROUP_ROLE, queryRows(
                "SELECT grm.GROUP_ID AS \"GROUP\", grm.ROLE_ID AS \"ROLE\", " +
                        "g.NAME AS \"_group\", r.NAME AS \"_role\" " +
                        "FROM GROUP_ROLE_MAPPING grm " +
                        "JOIN KEYCLOAK_GROUP g ON grm.GROUP_ID = g.ID " +
                        "LEFT JOIN KEYCLOAK_ROLE r ON grm.ROLE_ID = r.ID " +
                        "WHERE g.REALM_ID = ? AND grm.SIGNATURE IS NULL",
                List.of(realmId), List.of("GROUP", "ROLE", "_group", "_role")));

        // COMPOSITE_ROLE — join via parent role for realm scope
        out.put(T_COMPOSITE, queryRows(
                "SELECT cr.COMPOSITE AS \"COMPOSITE\", cr.CHILD_ROLE AS \"CHILD_ROLE\", " +
                        "rp.NAME AS \"_parent\", rc.NAME AS \"_child\" " +
                        "FROM COMPOSITE_ROLE cr " +
                        "JOIN KEYCLOAK_ROLE rp ON cr.COMPOSITE = rp.ID " +
                        "LEFT JOIN KEYCLOAK_ROLE rc ON cr.CHILD_ROLE = rc.ID " +
                        "WHERE rp.REALM_ID = ? AND cr.SIGNATURE IS NULL",
                List.of(realmId), List.of("COMPOSITE", "CHILD_ROLE", "_parent", "_child")));

        // CLIENT_SCOPE_CLIENT — join via CLIENT for realm scope
        out.put(T_CLIENT_SCOPE_CLIENT, queryRows(
                "SELECT csc.CLIENT_ID AS \"CLIENT_ID\", csc.SCOPE_ID AS \"SCOPE_ID\", " +
                        "c.CLIENT_ID AS \"_client\", cs.NAME AS \"_scope\" " +
                        "FROM CLIENT_SCOPE_CLIENT csc " +
                        "JOIN CLIENT c ON csc.CLIENT_ID = c.ID " +
                        "LEFT JOIN CLIENT_SCOPE cs ON csc.SCOPE_ID = cs.ID " +
                        "WHERE c.REALM_ID = ? AND csc.SIGNATURE IS NULL",
                List.of(realmId), List.of("CLIENT_ID", "SCOPE_ID", "_client", "_scope")));

        // CLIENT_SCOPE_ROLE_MAPPING — CLIENT_SCOPE has REALM_ID
        out.put(T_CLIENT_SCOPE_ROLE, queryRows(
                "SELECT csrm.SCOPE_ID AS \"SCOPE_ID\", csrm.ROLE_ID AS \"ROLE_ID\", " +
                        "cs.NAME AS \"_scope\", r.NAME AS \"_role\" " +
                        "FROM CLIENT_SCOPE_ROLE_MAPPING csrm " +
                        "JOIN CLIENT_SCOPE cs ON csrm.SCOPE_ID = cs.ID " +
                        "LEFT JOIN KEYCLOAK_ROLE r ON csrm.ROLE_ID = r.ID " +
                        "WHERE cs.REALM_ID = ? AND csrm.SIGNATURE IS NULL",
                List.of(realmId), List.of("SCOPE_ID", "ROLE_ID", "_scope", "_role")));

        // -------- Attribute tables (intercepted by IGA 1.8.0+) --------
        // Each table joins to its parent entity for realm scoping.

        // USER_ATTRIBUTE — join to USER_ENTITY for realm scope
        out.put(T_USER_ATTRIBUTE, queryRows(
                "SELECT ua.USER_ID AS \"user_id\", ua.NAME AS \"name\", ua.VALUE AS \"value\" " +
                        "FROM USER_ATTRIBUTE ua " +
                        "JOIN USER_ENTITY u ON ua.USER_ID = u.ID " +
                        "WHERE u.REALM_ID = ? AND ua.SIGNATURE IS NULL",
                List.of(realmId), List.of("user_id", "name", "value")));

        // CLIENT_ATTRIBUTES — join to CLIENT for realm scope
        out.put(T_CLIENT_ATTRIBUTES, queryRows(
                "SELECT ca.CLIENT_ID AS \"client_id\", ca.NAME AS \"name\", ca.VALUE AS \"value\" " +
                        "FROM CLIENT_ATTRIBUTES ca " +
                        "JOIN CLIENT c ON ca.CLIENT_ID = c.ID " +
                        "WHERE c.REALM_ID = ? AND ca.SIGNATURE IS NULL",
                List.of(realmId), List.of("client_id", "name", "value")));

        // CLIENT_SCOPE_ATTRIBUTES — CLIENT_SCOPE has REALM_ID
        out.put(T_CLIENT_SCOPE_ATTRIBUTES, queryRows(
                "SELECT csa.SCOPE_ID AS \"scope_id\", csa.NAME AS \"name\", csa.VALUE AS \"value\" " +
                        "FROM CLIENT_SCOPE_ATTRIBUTES csa " +
                        "JOIN CLIENT_SCOPE cs ON csa.SCOPE_ID = cs.ID " +
                        "WHERE cs.REALM_ID = ? AND csa.SIGNATURE IS NULL",
                List.of(realmId), List.of("scope_id", "name", "value")));

        // GROUP_ATTRIBUTE — KEYCLOAK_GROUP has REALM_ID
        out.put(T_GROUP_ATTRIBUTE, queryRows(
                "SELECT ga.GROUP_ID AS \"group_id\", ga.NAME AS \"name\", ga.VALUE AS \"value\" " +
                        "FROM GROUP_ATTRIBUTE ga " +
                        "JOIN KEYCLOAK_GROUP g ON ga.GROUP_ID = g.ID " +
                        "WHERE g.REALM_ID = ? AND ga.SIGNATURE IS NULL",
                List.of(realmId), List.of("group_id", "name", "value")));

        // ROLE_ATTRIBUTE — KEYCLOAK_ROLE has REALM_ID
        out.put(T_ROLE_ATTRIBUTE, queryRows(
                "SELECT ra.ROLE_ID AS \"role_id\", ra.NAME AS \"name\", ra.VALUE AS \"value\" " +
                        "FROM ROLE_ATTRIBUTE ra " +
                        "JOIN KEYCLOAK_ROLE r ON ra.ROLE_ID = r.ID " +
                        "WHERE r.REALM_ID = ? AND ra.SIGNATURE IS NULL",
                List.of(realmId), List.of("role_id", "name", "value")));

        // REALM_ATTRIBUTE — direct REALM_ID column
        out.put(T_REALM_ATTRIBUTE, queryRows(
                "SELECT REALM_ID AS \"realm_id\", NAME AS \"name\", VALUE AS \"value\" " +
                        "FROM REALM_ATTRIBUTE WHERE REALM_ID = ? AND SIGNATURE IS NULL",
                List.of(realmId), List.of("realm_id", "name", "value")));

        return out;
    }

    /**
     * Run a positional native query and convert each result tuple into a
     * Map<String, Object> using the supplied column-name list. Aliases set
     * via SQL `AS` are honored on most JDBC drivers, but Hibernate's native
     * query handling is inconsistent across drivers — so we use positional
     * mapping to be robust.
     */
    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> queryRows(String sql, List<Object> params, List<String> columns) {
        Query q = em.createNativeQuery(sql);
        for (int i = 0; i < params.size(); i++) {
            q.setParameter(i + 1, params.get(i));
        }
        List<Object[]> rows = (List<Object[]>) q.getResultList();
        List<Map<String, Object>> out = new ArrayList<>(rows.size());
        for (Object o : rows) {
            // Single-column rows come back as a scalar, not Object[]; we don't
            // currently issue any single-column queries here but guard anyway.
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
