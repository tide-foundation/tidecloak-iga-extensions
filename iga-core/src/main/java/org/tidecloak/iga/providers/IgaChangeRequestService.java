package org.tidecloak.iga.providers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.organization.OrganizationProvider;
import org.tidecloak.iga.entities.IgaAuthorizationEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.entities.IgaCommentEntity;
import org.tidecloak.iga.replay.IgaReplayExtension;
import org.tidecloak.iga.services.IgaUnsignedEntityService;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class IgaChangeRequestService {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<List<Map<String, Object>>> LIST_MAP_REF =
            new TypeReference<List<Map<String, Object>>>() {};

    private final EntityManager em;
    private final KeycloakSession session;

    public IgaChangeRequestService(EntityManager em, KeycloakSession session) {
        this.em = em;
        this.session = session;
    }

    /**
     * Returns true if IGA is enabled for the given realm.
     * Master realm always returns false.
     */
    public boolean isIgaEnabled(RealmModel realm) {
        if ("master".equals(realm.getName())) return false;
        return "true".equals(realm.getAttribute("isIGAEnabled"));
    }

    /**
     * Find the first PENDING change request matching the given realm/entityType/entityId.
     */
    public IgaChangeRequestEntity findPending(String realmId, String entityType, String entityId) {
        TypedQuery<IgaChangeRequestEntity> query = em.createNamedQuery(
                "IgaChangeRequest.findPendingByEntity", IgaChangeRequestEntity.class);
        query.setParameter("realmId", realmId);
        query.setParameter("entityType", entityType);
        query.setParameter("entityId", entityId);
        List<IgaChangeRequestEntity> results = query.getResultList();
        return results.isEmpty() ? null : results.get(0);
    }

    /**
     * Find the first PENDING change request for ({@code realmId}, {@code entityType},
     * {@code entityId}) that is an <em>exact duplicate</em> of the proposed change:
     * same {@code actionType} AND a row payload equal (key-for-key, ignoring order)
     * to one of {@code rows}. Returns {@code null} when no such duplicate exists.
     *
     * <p>This distinguishes a genuine re-request of an already-pending action (the
     * admin clicked "grant role X" twice → idempotent, surface the existing CR as a
     * 202 "already pending") from a <em>different</em> pending change on the same
     * entity (e.g. a pending grant of role Y, or a pending group join) which the
     * per-entity {@link #findPending} guard treats as a conflict. The entity-keyed
     * {@code findPending} alone cannot tell these apart — it matches ANY pending CR
     * on the user regardless of action or target.</p>
     */
    public IgaChangeRequestEntity findDuplicatePending(String realmId, String entityType,
                                                       String entityId, String actionType,
                                                       List<Map<String, Object>> rows) {
        TypedQuery<IgaChangeRequestEntity> query = em.createNamedQuery(
                "IgaChangeRequest.findPendingByEntity", IgaChangeRequestEntity.class);
        query.setParameter("realmId", realmId);
        query.setParameter("entityType", entityType);
        query.setParameter("entityId", entityId);
        for (IgaChangeRequestEntity cr : query.getResultList()) {
            if (!actionType.equals(cr.getActionType())) {
                continue;
            }
            List<Map<String, Object>> existingRows = parseRows(cr.getRowsJson());
            if (rowsContainAll(existingRows, rows)) {
                return cr;
            }
        }
        return null;
    }

    /**
     * True iff every map in {@code needles} is present (by equals) in {@code haystack}.
     * Map equality is order-independent, so {@code {USER_ID,ROLE_ID}} rows compare
     * structurally regardless of JSON key order.
     */
    private static boolean rowsContainAll(List<Map<String, Object>> haystack,
                                          List<Map<String, Object>> needles) {
        if (needles == null || needles.isEmpty()) {
            return false;
        }
        for (Map<String, Object> needle : needles) {
            if (haystack == null || !haystack.contains(needle)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Create a new change request for the given realm/entity.
     */
    public IgaChangeRequestEntity create(RealmModel realm, String entityType, String entityId,
                                          String actionType, List<Map<String, Object>> rows,
                                          String requestedBy) {
        return create(realm, entityType, entityId, actionType, rows, requestedBy, null);
    }

    /**
     * Create a new change request for the given realm/entity, optionally with a
     * prerequisite-CR dependency list (see
     * {@link IgaChangeRequestEntity#setDependsOnList(List)}). A non-empty
     * {@code dependsOn} list marks this CR as <em>blocked</em> until every
     * listed CR is APPROVED — the commit path enforces this with a 412.
     */
    public IgaChangeRequestEntity create(RealmModel realm, String entityType, String entityId,
                                          String actionType, List<Map<String, Object>> rows,
                                          String requestedBy, List<String> dependsOn) {
        IgaChangeRequestEntity entity = new IgaChangeRequestEntity();
        entity.setId(UUID.randomUUID().toString());
        entity.setRealmId(realm.getId());
        entity.setEntityType(entityType);
        entity.setEntityId(entityId);
        entity.setActionType(actionType);
        entity.setRowsJson(serializeRows(rows));
        entity.setStatus("PENDING");
        entity.setRequestedBy(requestedBy);
        entity.setCreatedAt(System.currentTimeMillis());
        entity.setDependsOnList(dependsOn);
        em.persist(entity);
        em.flush();
        return entity;
    }

    /**
     * Find PENDING CRs in {@code realmId} matching {@code entityType} +
     * {@code actionType}. Unlike {@link #findPending} this does NOT key on
     * entityId, because several action types share one entityId (e.g. every
     * CLIENT-scoped action on a client uses the client UUID as entityId) — the
     * caller disambiguates by inspecting each CR's ROWS_JSON.
     */
    public List<IgaChangeRequestEntity> findPendingByAction(String realmId, String entityType,
                                                            String actionType) {
        return em.createQuery(
                        "SELECT cr FROM IgaChangeRequestEntity cr " +
                                "WHERE cr.realmId = :realmId " +
                                "AND cr.entityType = :entityType " +
                                "AND cr.actionType = :actionType " +
                                "AND cr.status = 'PENDING'", IgaChangeRequestEntity.class)
                .setParameter("realmId", realmId)
                .setParameter("entityType", entityType)
                .setParameter("actionType", actionType)
                .getResultList();
    }

    /**
     * Create a per-entity ADOPT change request for an entity that
     * already exists in the realm but has not yet been attested.
     *
     * <p>Builds the per-entity REP_JSON capture via Keycloak's own
     * {@code ModelToRepresentation}, persists a PENDING
     * {@code ADOPT_<entityType>} change request, and inserts a sidecar row
     * into {@code IGA_UNSIGNED_ENTITY} linking back to the new CR. The
     * matching {@link org.tidecloak.iga.replay.IgaReplayExtension#tryReplay}
     * path will, on commit, verify the entity still exists, stamp its
     * attestation column, delete the sidecar row, and mark the CR APPROVED.
     *
     * <p>Throws {@link IllegalArgumentException} for an unsupported
     * {@code entityType} or when the entity is not resolvable in the realm —
     * a toggle-on scan should never see this, but it protects an
     * unit/E2E driver from creating a dangling CR.</p>
     *
     * <p>Throws {@link AlreadyAttestedException} when the target
     * entity's {@code attestation} column is non-null. The toggle-on scan
     * already filters to {@code attestation IS NULL} at the JPQL level so
     * never triggers this; the manual {@code POST /iga/adopt} endpoint maps
     * the exception to a 409 CONFLICT. The pre-check is a single SELECT per
     * call and leaves the existing happy path byte-identical for unattested
     * entities (lookup happens BEFORE any persist).</p>
     *
     * @param realm        target realm (must be IGA-enabled — caller's check)
     * @param entityType   one of USER | ROLE | GROUP | CLIENT | CLIENT_SCOPE
     * @param entityId     the entity's UUID
     * @param requestedBy  admin user id stamped on the CR
     * @return the new CR's id (UUID)
     */
    public String createAdoptCr(RealmModel realm, String entityType, String entityId,
                                 String requestedBy) {
        return createAdoptCr(realm, entityType, entityId, requestedBy, false);
    }

    /**
     * Overload with {@code attestationOnly}. When {@code true}, the ADOPT CR signs the
     * entity's producer unit column(s) on commit (the manual-signing redesign,
     * 2026-06-06) but does NOT write the {@code IGA_UNSIGNED_ENTITY} sidecar row — so the
     * entity is NEVER subjected to read-time quarantine. This is the path for KC
     * system/infrastructure entities (built-in admin clients + their roles, KC default
     * client-scopes, default realm roles): they must appear in the signed login closure
     * (the uniform read is all-or-nothing) but full IGA governance would quarantine them
     * and brick KC internals. The {@code attestationOnly} marker is also recorded in the
     * CR's rowsJson for audit.
     */
    public String createAdoptCr(RealmModel realm, String entityType, String entityId,
                                 String requestedBy, boolean attestationOnly) {
        if (realm == null || entityType == null || entityId == null) {
            throw new IllegalArgumentException(
                    "createAdoptCr requires non-null realm + entityType + entityId");
        }
        // Refuse to enqueue an ADOPT CR for an already-attested
        // entity. Single SELECT against the underlying info-table's
        // attestation column; if the entity row is missing the existing
        // model lookup below will surface the more specific
        // "not found in realm" IllegalArgumentException so callers don't
        // need to disambiguate "missing" from "already attested" here.
        if (isAlreadyAttested(entityType, entityId)) {
            throw new AlreadyAttestedException(entityType, entityId);
        }
        String actionType;
        Map<String, Object> repRow;
        switch (entityType) {
            case IgaReplayExtension.ENTITY_TYPE_USER: {
                UserModel u = session.users().getUserById(realm, entityId);
                if (u == null) {
                    throw new IllegalArgumentException(
                            "createAdoptCr: USER " + entityId + " not found in realm " + realm.getId());
                }
                actionType = IgaReplayExtension.ACTION_ADOPT_USER;
                repRow = buildAdoptRow(entityId, u.getUsername(),
                        serializeRep(ModelToRepresentation.toRepresentation(session, realm, u)));
                break;
            }
            case IgaReplayExtension.ENTITY_TYPE_ROLE: {
                RoleModel r = session.roles().getRoleById(realm, entityId);
                if (r == null) {
                    throw new IllegalArgumentException(
                            "createAdoptCr: ROLE " + entityId + " not found in realm " + realm.getId());
                }
                actionType = IgaReplayExtension.ACTION_ADOPT_ROLE;
                repRow = buildAdoptRow(entityId, r.getName(),
                        serializeRep(ModelToRepresentation.toRepresentation(r)));
                break;
            }
            case IgaReplayExtension.ENTITY_TYPE_GROUP: {
                GroupModel g = session.groups().getGroupById(realm, entityId);
                if (g == null) {
                    throw new IllegalArgumentException(
                            "createAdoptCr: GROUP " + entityId + " not found in realm " + realm.getId());
                }
                actionType = IgaReplayExtension.ACTION_ADOPT_GROUP;
                repRow = buildAdoptRow(entityId, g.getName(),
                        serializeRep(ModelToRepresentation.toRepresentation(g, false)));
                break;
            }
            case IgaReplayExtension.ENTITY_TYPE_CLIENT: {
                ClientModel c = session.clients().getClientById(realm, entityId);
                if (c == null) {
                    throw new IllegalArgumentException(
                            "createAdoptCr: CLIENT " + entityId + " not found in realm " + realm.getId());
                }
                actionType = IgaReplayExtension.ACTION_ADOPT_CLIENT;
                repRow = buildAdoptRow(entityId, c.getClientId(),
                        serializeRep(ModelToRepresentation.toRepresentation(c, session)));
                break;
            }
            case IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE: {
                ClientScopeModel cs = session.clientScopes().getClientScopeById(realm, entityId);
                if (cs == null) {
                    throw new IllegalArgumentException(
                            "createAdoptCr: CLIENT_SCOPE " + entityId + " not found in realm " + realm.getId());
                }
                actionType = IgaReplayExtension.ACTION_ADOPT_CLIENT_SCOPE;
                repRow = buildAdoptRow(entityId, cs.getName(),
                        serializeRep(ModelToRepresentation.toRepresentation(cs)));
                break;
            }
            case IgaReplayExtension.ENTITY_TYPE_ORGANIZATION: {
                // Resolve through the OrganizationProvider SPI
                // (federation + cache layers honoured, same idiom as the
                // other five entity-type lookups). The OrganizationProvider
                // factory is loaded when the organizations feature is on for
                // the realm; if it's not installed at all we surface
                // IllegalArgumentException to keep the error class symmetric
                // with the other branches.
                OrganizationProvider orgs = session.getProvider(OrganizationProvider.class);
                if (orgs == null) {
                    throw new IllegalArgumentException(
                            "createAdoptCr: ORGANIZATION " + entityId + " — OrganizationProvider not installed");
                }
                OrganizationModel o = orgs.getById(entityId);
                if (o == null) {
                    throw new IllegalArgumentException(
                            "createAdoptCr: ORGANIZATION " + entityId + " not found in realm " + realm.getId());
                }
                actionType = IgaReplayExtension.ACTION_ADOPT_ORGANIZATION;
                // briefRepresentation=false → include attributes (mirrors the
                // CREATE/UPDATE_ORGANIZATION capture path in
                // IgaOrganizationModel.setDomains — same serialization shape).
                repRow = buildAdoptRow(entityId, o.getName(),
                        serializeRep(ModelToRepresentation.toRepresentation(o, false)));
                break;
            }
            default:
                throw new IllegalArgumentException(
                        "createAdoptCr: unsupported entityType '" + entityType
                                + "' (expected USER | ROLE | GROUP | CLIENT | CLIENT_SCOPE | ORGANIZATION)");
        }

        if (attestationOnly) {
            repRow.put("ATTESTATION_ONLY", Boolean.TRUE);
        }

        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setId(UUID.randomUUID().toString());
        cr.setRealmId(realm.getId());
        cr.setEntityType(entityType);
        cr.setEntityId(entityId);
        cr.setActionType(actionType);
        cr.setRowsJson(serializeRows(List.of(repRow)));
        cr.setStatus("PENDING");
        cr.setRequestedBy(requestedBy);
        cr.setCreatedAt(System.currentTimeMillis());
        em.persist(cr);

        // Sidecar row linking the unattested entity to its ADOPT CR — drives read-time
        // quarantine. SKIPPED for attestation-only system-entity CRs: they sign on commit
        // but must never be quarantined (quarantining a built-in admin client / default
        // scope / system role would brick KC internals + the very surface used to commit).
        if (!attestationOnly) {
            IgaUnsignedEntityService.markUnsigned(em, realm.getId(), entityType, entityId, cr.getId());
        }

        em.flush();
        return cr.getId();
    }

    /**
     * Commit 2 — create a per-EDGE ADOPT change request for an edge that
     * already exists in the realm (admin-configured before IGA was enabled)
     * but whose {@code attestation} column is still NULL.
     *
     * <p>Unlike {@link #createAdoptCr} (single-id nodes), an edge has a
     * COMPOSITE key. We persist BOTH keys in the CR's rowsJson under the same
     * key names the matching {@code IgaReplayDispatcher} edge stamp uses
     * (COMPOSITE/CHILD_ROLE, CLIENT_UUID/SCOPE_ID, SCOPE_ID/ROLE_ID, or the
     * mapper ID).
     *
     * <p><b>FIX (ENTITY_ID overflow):</b> the original attempt set
     * {@code entityId = key1 + "|" + key2}. Two concatenated UUIDs are ~73
     * chars and {@code IGA_CHANGE_REQUEST.ENTITY_ID} / {@code
     * IGA_UNSIGNED_ENTITY.ENTITY_ID} are both {@code VARCHAR(36)} — the INSERT
     * blew the column, aborted the toggle-on transaction, and emitted 0 ADOPT
     * CRs. We now derive a <b>deterministic synthetic 36-char id</b> via
     * {@link #edgeSyntheticId(String, String, String)}
     * ({@code UUID.nameUUIDFromBytes(type|k1|k2)}). It is stable (same edge →
     * same id, for re-toggle idempotency / sidecar PK uniqueness) and always
     * fits 36 chars. The real edge endpoints live in {@code rowsJson} (which is
     * {@code TEXT}); the replay already reads the keys from there, never from
     * {@code entityId}.</p>
     *
     * <p>No REP_JSON / model rebuild — edge ADOPT only stamps.</p>
     *
     * @param entityType  COMPOSITE_ROLE | CLIENT_SCOPE_CLIENT | CLIENT_SCOPE_ROLE
     *                    | PROTOCOL_MAPPER (the edge entity types)
     * @param key1        first composite key (parent role id / client uuid /
     *                    scope id / mapper id)
     * @param key2        second composite key (child role id / scope id /
     *                    role id / owning-node id for mapper; informational)
     * @param actionType  the matching ADOPT_* edge action type
     * @return the new CR's id
     */
    public String createAdoptEdgeCr(RealmModel realm, String entityType,
                                    String key1, String key2,
                                    String actionType, String requestedBy) {
        return createAdoptEdgeCr(realm, entityType, key1, key2, actionType, requestedBy, false);
    }

    /**
     * Overload with {@code attestationOnly} (see the node {@link #createAdoptCr} overload).
     * When {@code true}, no {@code IGA_UNSIGNED_ENTITY} sidecar is written for the edge,
     * so it is never quarantined; the edge's producer column is still stamped on commit.
     */
    public String createAdoptEdgeCr(RealmModel realm, String entityType,
                                    String key1, String key2,
                                    String actionType, String requestedBy, boolean attestationOnly) {
        if (realm == null || entityType == null || key1 == null || actionType == null) {
            throw new IllegalArgumentException(
                    "createAdoptEdgeCr requires non-null realm + entityType + key1 + actionType");
        }
        String syntheticEntityId = edgeSyntheticId(entityType, key1, key2);

        Map<String, Object> row = new LinkedHashMap<>();
        switch (entityType) {
            case IgaReplayExtension.ENTITY_TYPE_COMPOSITE_ROLE:
                row.put("COMPOSITE", key1);
                row.put("CHILD_ROLE", key2);
                break;
            case IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE_CLIENT:
                row.put("CLIENT_UUID", key1);
                row.put("SCOPE_ID", key2);
                break;
            case IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE_ROLE:
                row.put("SCOPE_ID", key1);
                row.put("ROLE_ID", key2);
                break;
            case IgaReplayExtension.ENTITY_TYPE_PROTOCOL_MAPPER:
                // Mapper stamp keys by its own id (key1); key2 is the owning
                // node id, kept for audit/debug only.
                row.put("ID", key1);
                if (key2 != null) row.put("OWNER_NODE_ID", key2);
                break;
            case IgaReplayExtension.ENTITY_TYPE_REALM_DEFAULT_SCOPE:
                // DEFAULT_CLIENT_SCOPE row keyed (REALM_ID, SCOPE_ID) — the
                // replay stamp keys on the entity's realm.id + clientScopeId.
                row.put("REALM_ID", key1);
                row.put("SCOPE_ID", key2);
                break;
            case IgaReplayExtension.ENTITY_TYPE_SCOPE_MAPPING:
                // SCOPE_MAPPING row keyed (CLIENT_ID, ROLE_ID). key1 is the
                // client UUID (== SCOPE_MAPPING.CLIENT_ID), key2 the role id —
                // the stamp keys on ScopeMappingEntity.clientId + .roleId.
                row.put("CLIENT_UUID", key1);
                row.put("ROLE_ID", key2);
                break;
            default:
                throw new IllegalArgumentException(
                        "createAdoptEdgeCr: unsupported edge entityType '" + entityType + "'");
        }
        if (attestationOnly) {
            row.put("ATTESTATION_ONLY", Boolean.TRUE);
        }

        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setId(UUID.randomUUID().toString());
        cr.setRealmId(realm.getId());
        cr.setEntityType(entityType);
        cr.setEntityId(syntheticEntityId);
        cr.setActionType(actionType);
        cr.setRowsJson(serializeRows(List.of(row)));
        cr.setStatus("PENDING");
        cr.setRequestedBy(requestedBy);
        cr.setCreatedAt(System.currentTimeMillis());
        em.persist(cr);

        // No sidecar for attestation-only system-edge CRs (no quarantine). See node overload.
        if (!attestationOnly) {
            IgaUnsignedEntityService.markUnsigned(em, realm.getId(), entityType, syntheticEntityId, cr.getId());
        }

        em.flush();
        return cr.getId();
    }

    /**
     * Manual-signing redesign (2026-06-06) — create the ATTESTATION-ONLY ADOPT CR for the
     * REALM NODE. The realm contributes two login-emitted producer units (realm_config #0,
     * realm_default_groups_set #15) keyed on the realmId; neither had any ADOPT path
     * before, so their dedicated columns stayed NULL and the uniform login read
     * fail-closed. Committing this CR stamps those two columns (TideAttestor's ADOPT_REALM
     * case). Always attestation-only — the realm is never a quarantineable entity, so no
     * sidecar is written. Idempotent at the scan level via a per-realm pending/approved
     * skip the caller computes; this method itself just emits one CR.
     *
     * @return the new CR's id
     */
    public String createAdoptRealmCr(RealmModel realm, String requestedBy) {
        if (realm == null) {
            throw new IllegalArgumentException("createAdoptRealmCr requires non-null realm");
        }
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("ID", realm.getId());
        row.put("ATTESTATION_ONLY", Boolean.TRUE);

        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setId(UUID.randomUUID().toString());
        cr.setRealmId(realm.getId());
        cr.setEntityType(IgaReplayExtension.ENTITY_TYPE_REALM);
        cr.setEntityId(realm.getId());
        cr.setActionType(IgaReplayExtension.ACTION_ADOPT_REALM);
        cr.setRowsJson(serializeRows(List.of(row)));
        cr.setStatus("PENDING");
        cr.setRequestedBy(requestedBy);
        cr.setCreatedAt(System.currentTimeMillis());
        em.persist(cr);
        // No sidecar — the realm node is never quarantined.
        em.flush();
        return cr.getId();
    }

    /**
     * Deterministic synthetic 36-char id for an edge ADOPT CR / sidecar row.
     *
     * <p>An edge has a COMPOSITE key (e.g. parent+child role id) that does not
     * fit the {@code VARCHAR(36)} {@code ENTITY_ID} columns. We hash the edge's
     * identity ({@code type|key1|key2}) into a name-based (v3) UUID — always a
     * canonical 36-char string. The same edge always maps to the same id, which
     * is what the re-toggle idempotency skip-set (already-committed ADOPT) and
     * the sidecar PK {@code (realmId, entityType, entityId)} both rely on.</p>
     *
     * <p>Used by BOTH the CR/sidecar writer here and the toggle-on scan's
     * already-committed-ADOPT skip lookup ({@code IgaAdoptScan.processOneEdge}),
     * so the two sides agree byte-for-byte on the synthetic id. The real edge
     * endpoints are persisted in {@code rowsJson} for the replay stamp.</p>
     */
    public static String edgeSyntheticId(String entityType, String key1, String key2) {
        String seed = entityType + "|" + (key1 == null ? "" : key1)
                + "|" + (key2 == null ? "" : key2);
        return UUID.nameUUIDFromBytes(seed.getBytes(java.nio.charset.StandardCharsets.UTF_8)).toString();
    }

    private static Map<String, Object> buildAdoptRow(String entityId, String humanName, String repJson) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("ID", entityId);
        if (humanName != null) row.put("NAME", humanName);
        if (repJson != null) row.put("REP_JSON", repJson);
        return row;
    }

    private static String serializeRep(Object rep) {
        if (rep == null) return null;
        try {
            return MAPPER.writeValueAsString(rep);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("createAdoptCr: failed to serialize representation", e);
        }
    }

    /**
     * Add an authorization record to an existing change request.
     */
    public IgaAuthorizationEntity authorize(String changeRequestId, String authorizedBy, String approval) {
        IgaChangeRequestEntity cr = em.find(IgaChangeRequestEntity.class, changeRequestId);
        if (cr == null) {
            throw new IllegalArgumentException("Change request not found: " + changeRequestId);
        }
        IgaAuthorizationEntity auth = new IgaAuthorizationEntity();
        auth.setId(UUID.randomUUID().toString());
        auth.setChangeRequest(cr);
        auth.setAuthorizedBy(authorizedBy);
        auth.setApproval(approval);
        auth.setCreatedAt(System.currentTimeMillis());
        em.persist(auth);
        em.flush();
        return auth;
    }

    /**
     * Count authorizations for a change request.
     */
    public long countAuthorizations(String changeRequestId) {
        TypedQuery<Long> query = em.createNamedQuery("IgaAuthorization.countByChangeRequest", Long.class);
        query.setParameter("changeRequestId", changeRequestId);
        return query.getSingleResult();
    }

    /**
     * Deny a change request.
     */
    public void deny(String changeRequestId, String deniedBy) {
        IgaChangeRequestEntity cr = em.find(IgaChangeRequestEntity.class, changeRequestId);
        if (cr == null) {
            throw new IllegalArgumentException("Change request not found: " + changeRequestId);
        }
        cr.setStatus("DENIED");
        cr.setResolvedAt(System.currentTimeMillis());
        cr.setResolvedBy(deniedBy);
        em.flush();
    }

    /**
     * Update the rows of an existing change request and delete all its authorizations.
     */
    public void updateRows(String changeRequestId, List<Map<String, Object>> newRows) {
        IgaChangeRequestEntity cr = em.find(IgaChangeRequestEntity.class, changeRequestId);
        if (cr == null) {
            throw new IllegalArgumentException("Change request not found: " + changeRequestId);
        }
        // Delete existing authorizations
        em.createNamedQuery("IgaAuthorization.deleteByChangeRequest")
                .setParameter("changeRequestId", changeRequestId)
                .executeUpdate();
        cr.getAuthorizations().clear();
        cr.setRowsJson(serializeRows(newRows));
        em.flush();
    }

    /**
     * Merge {@code newRows} into an existing PENDING change request's ROWS_JSON.
     *
     * <p>Used to <em>coalesce</em> multiple same-entity attribute writes that
     * arrive within a SINGLE admin request (e.g. a realm-settings save that
     * touches several config fields, or {@code LinkTideAccount} writing
     * {@code tideUserKey} + {@code vuid}). The FIRST write for an entity creates
     * the CR; each SUBSEQUENT write for the SAME entity in the SAME request folds
     * its row(s) into that already-created CR instead of throwing a
     * self-conflict. See the request-scoped marker in {@code IgaUserAdapter} /
     * {@code IgaRealmAdapter}.</p>
     *
     * <p>Merge rule: a new row REPLACES an existing row that shares the same
     * identity key (the row's {@code NAME} for attribute rows, or {@code key} for
     * realm-config rows); otherwise the new row is APPENDED. Rows with no
     * identity key are always appended (e.g. multi-value attribute rows that
     * intentionally carry repeated {@code NAME}s — those are handled by the
     * caller passing the full replacement set for that name; see below). This
     * keeps "last write wins" semantics for a given attribute/config key within
     * the request, matching how the un-governed (non-IGA) path would behave.</p>
     *
     * <p>Also clears any authorizations on the CR — exactly like
     * {@link #updateRows} — because the CR's content changed and any prior
     * approval no longer covers the new row set.</p>
     *
     * <p><b>Multi-value attributes:</b> when the caller writes a multi-value
     * attribute (one CR row per value, all sharing one {@code NAME}), it passes
     * the COMPLETE new row set for that name AND the name to clear via
     * {@code namesToReplace} so this method first drops every existing row with a
     * matching {@code NAME}, then appends the new rows. This preserves the
     * one-row-per-value contract the replay relies on.</p>
     *
     * @param changeRequestId the existing PENDING CR id
     * @param newRows         rows to merge in
     * @param namesToReplace  identity-key values whose existing rows should be
     *                        dropped wholesale before appending {@code newRows}
     *                        (used for multi-value / removal writes); may be empty
     */
    public void appendRows(String changeRequestId, List<Map<String, Object>> newRows,
                           java.util.Set<String> namesToReplace) {
        IgaChangeRequestEntity cr = em.find(IgaChangeRequestEntity.class, changeRequestId);
        if (cr == null) {
            throw new IllegalArgumentException("Change request not found: " + changeRequestId);
        }
        List<Map<String, Object>> merged = new java.util.ArrayList<>(parseRows(cr.getRowsJson()));

        // 1. Drop every existing row whose identity key is being replaced
        //    wholesale (multi-value / removal writes pass the full new set).
        if (namesToReplace != null && !namesToReplace.isEmpty()) {
            merged.removeIf(r -> namesToReplace.contains(rowIdentityKey(r)));
        }

        // 2. Merge each new row: replace a single existing row with the same
        //    identity key, else append. Rows already removed in step 1 fall
        //    through to append.
        for (Map<String, Object> nr : newRows) {
            String nk = rowIdentityKey(nr);
            boolean replaced = false;
            if (nk != null && (namesToReplace == null || !namesToReplace.contains(nk))) {
                for (int i = 0; i < merged.size(); i++) {
                    if (nk.equals(rowIdentityKey(merged.get(i)))) {
                        merged.set(i, nr);
                        replaced = true;
                        break;
                    }
                }
            }
            if (!replaced) {
                merged.add(nr);
            }
        }

        // Content changed → drop stale authorizations (mirror updateRows).
        em.createNamedQuery("IgaAuthorization.deleteByChangeRequest")
                .setParameter("changeRequestId", changeRequestId)
                .executeUpdate();
        cr.getAuthorizations().clear();
        cr.setRowsJson(serializeRows(merged));
        em.flush();
    }

    /**
     * Identity key for coalescing: a CR row keys on {@code NAME} (attribute
     * rows) or {@code key} (realm-config rows). Returns {@code null} when the
     * row carries neither, in which case the row is treated as un-mergeable
     * (always appended).
     */
    private static String rowIdentityKey(Map<String, Object> row) {
        Object name = row.get("NAME");
        if (name != null) return name.toString();
        Object key = row.get("key");
        if (key != null) return key.toString();
        return null;
    }

    // -------------------------------------------------------------------------
    // Request-scoped coalescing marker.
    //
    // Records, per KeycloakSession (== per admin request), which CR id this
    // request created for a given entity, keyed "entityType|entityId". A
    // SUBSEQUENT same-entity write in the SAME request whose pending CR id is in
    // the marker coalesces into that CR (appendRows); a pending CR that is NOT
    // in the marker is a genuine foreign/prior CR and still 409s. Keying by CR
    // id (not just the entity) is the correctness invariant: an in-flight admin
    // never folds their change into an unrelated admin's pending CR.
    // -------------------------------------------------------------------------

    private static final String MARKER_ATTR = "IGA_REQUEST_CR_MARKER";

    @SuppressWarnings("unchecked")
    private static Map<String, String> markerMap(KeycloakSession session) {
        Object m = session.getAttribute(MARKER_ATTR);
        if (m instanceof Map) {
            return (Map<String, String>) m;
        }
        Map<String, String> fresh = new java.util.HashMap<>();
        session.setAttribute(MARKER_ATTR, fresh);
        return fresh;
    }

    private static String markerKey(String entityType, String entityId, String actionType) {
        return entityType + "|" + entityId + "|" + actionType;
    }

    /**
     * Record that THIS request created {@code crId} for ({@code entityType},
     * {@code entityId}, {@code actionType}).
     *
     * <p>The marker keys on {@code actionType} as well as the entity: a CR
     * carries a SINGLE action type (the replay dispatches per-CR, not per-row),
     * so a follow-up write of a DIFFERENT action type on the same entity (e.g.
     * SET then REMOVE) must NOT fold into the first CR — it keys to a different
     * (empty) marker slot, falls through to the foreign-pending-CR check, and
     * 409s exactly as the pre-fix one-CR-per-entity rule did.</p>
     */
    public void markRequestCr(String entityType, String entityId, String actionType, String crId) {
        markerMap(session).put(markerKey(entityType, entityId, actionType), crId);
    }

    /**
     * Is {@code crId} a CR that THIS request created (under ANY action type)?
     * Used to distinguish a genuinely foreign pending CR (→ 409) from one this
     * same request created under a different action type on the same entity
     * (e.g. SET_REALM_ATTRIBUTE then SET_REALM_CONFIG in one realm save) — the
     * latter must NOT 409.
     */
    public boolean isRequestCr(String crId) {
        if (crId == null) return false;
        return markerMap(session).containsValue(crId);
    }

    /**
     * The CR id THIS request created for ({@code entityType}, {@code entityId},
     * {@code actionType}), or {@code null} if none.
     */
    public String getRequestCr(String entityType, String entityId, String actionType) {
        return markerMap(session).get(markerKey(entityType, entityId, actionType));
    }

    /**
     * Coalescing create: the single entry point the attribute-write seams use
     * instead of {@code checkNoPendingCr} + {@code create}.
     *
     * <p>Behaviour (see the request-scoped marker doc above):</p>
     * <ol>
     *   <li>If THIS request already created a CR for ({@code entityType},
     *       {@code entityId}) and that CR is still PENDING → fold {@code rows}
     *       into it via {@link #appendRows} and return its id. NO conflict.</li>
     *   <li>Else if a PENDING CR exists for the entity that this request did NOT
     *       create (a foreign / prior CR) → throw {@link IgaConflictException}
     *       (409), exactly as before.</li>
     *   <li>Else create a fresh PENDING CR, record it in the request marker, and
     *       return its id.</li>
     * </ol>
     *
     * <p>The marker is keyed by CR id so step 1 can only ever extend a CR THIS
     * request created — never an unrelated admin's in-flight CR (which always
     * falls to step 2's 409).</p>
     *
     * @param namesToReplace identity-key values (NAME / config key) whose prior
     *                       rows should be dropped wholesale before the new rows
     *                       are appended on the coalesce path (multi-value /
     *                       removal writes). May be empty/null for single-value
     *                       last-write-wins.
     * @return the CR id (new or coalesced-into)
     */
    public String coalesceOrCreate(RealmModel realm, String entityType, String entityId,
                                   String actionType, List<Map<String, Object>> rows,
                                   String requestedBy, java.util.Set<String> namesToReplace) {
        String markedCrId = getRequestCr(entityType, entityId, actionType);
        if (markedCrId != null) {
            IgaChangeRequestEntity marked = em.find(IgaChangeRequestEntity.class, markedCrId);
            if (marked != null && "PENDING".equals(marked.getStatus())) {
                // Same-request, same-entity, same-action follow-up write → coalesce.
                appendRows(markedCrId, rows, namesToReplace);
                return markedCrId;
            }
            // Marked CR vanished or is no longer PENDING (committed/denied within
            // the request) — fall through; a brand-new CR is correct.
        }
        // No CR from THIS request under THIS action type. A pending CR on the
        // entity that this request did NOT create at all is genuinely foreign →
        // 409. A pending CR this request created under a DIFFERENT action type
        // (e.g. a realm save touching both SET_REALM_ATTRIBUTE and
        // SET_REALM_CONFIG) is NOT foreign — let it create a second CR keyed to
        // the new action type rather than 409.
        IgaChangeRequestEntity existing = findPending(realm.getId(), entityType, entityId);
        if (existing != null && !isRequestCr(existing.getId())) {
            throw new IgaConflictException(existing.getId());
        }
        IgaChangeRequestEntity created = create(realm, entityType, entityId, actionType, rows, requestedBy);
        markRequestCr(entityType, entityId, actionType, created.getId());
        return created.getId();
    }

    /**
     * Deserialize rowsJson into a List<Map<String, Object>>.
     */
    public List<Map<String, Object>> parseRows(String rowsJson) {
        try {
            return MAPPER.readValue(rowsJson, LIST_MAP_REF);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to parse rows JSON", e);
        }
    }

    private String serializeRows(List<Map<String, Object>> rows) {
        try {
            return MAPPER.writeValueAsString(rows);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize rows to JSON", e);
        }
    }

    // -------------------------------------------------------------------------
    // Comments
    // -------------------------------------------------------------------------

    /**
     * Add a free-form admin comment to a change request.
     */
    public IgaCommentEntity addComment(String changeRequestId, String userId, String username, String comment) {
        IgaChangeRequestEntity cr = em.find(IgaChangeRequestEntity.class, changeRequestId);
        if (cr == null) {
            throw new IllegalArgumentException("Change request not found: " + changeRequestId);
        }
        IgaCommentEntity entity = new IgaCommentEntity();
        entity.setId(UUID.randomUUID().toString());
        entity.setChangeRequest(cr);
        entity.setUserId(userId);
        entity.setUsername(username);
        entity.setComment(comment);
        entity.setCreatedAt(System.currentTimeMillis());
        em.persist(entity);
        em.flush();
        return entity;
    }

    /**
     * Update the text of an existing comment. Sets updatedAt.
     */
    public IgaCommentEntity updateComment(String commentId, String newText) {
        IgaCommentEntity entity = em.find(IgaCommentEntity.class, commentId);
        if (entity == null) {
            throw new IllegalArgumentException("Comment not found: " + commentId);
        }
        entity.setComment(newText);
        entity.setUpdatedAt(System.currentTimeMillis());
        em.flush();
        return entity;
    }

    /**
     * Delete a comment by id.
     */
    public void deleteComment(String commentId) {
        IgaCommentEntity entity = em.find(IgaCommentEntity.class, commentId);
        if (entity == null) {
            throw new IllegalArgumentException("Comment not found: " + commentId);
        }
        em.remove(entity);
        em.flush();
    }

    /**
     * List comments for a change request, ordered by createdAt ASC.
     */
    public List<IgaCommentEntity> listComments(String changeRequestId) {
        TypedQuery<IgaCommentEntity> query = em.createNamedQuery(
                "IgaComment.findByChangeRequest", IgaCommentEntity.class);
        query.setParameter("crId", changeRequestId);
        return query.getResultList();
    }

    // -------------------------------------------------------------------------
    // Bulk-authorize PENDING CR selector. See
    // IgaAdminResource#bulkAuthorize. Backed by IDX_IGA_CR_REALM_ACTION_STATUS
    // (REALM_ID, ACTION_TYPE, STATUS). Applies LIMIT at the query level so a
    // wide actionTypeIn filter cannot pull a runaway result set into memory.
    // Order is createdAt ASC so oldest PENDING CRs drain first — operationally
    // matches the FIFO mental model of "clear the queue".
    // -------------------------------------------------------------------------

    /**
     * Project PENDING CRs in (realmId) matching any actionType in
     * {@code actionTypes} with {@code createdAt <= olderThan} when non-null.
     * Ordered by createdAt ASC, capped at {@code limit}.
     *
     * @param realmId      target realm
     * @param actionTypes  non-empty list of action-type strings to match
     * @param olderThan    optional epoch-millis upper bound on createdAt
     *                     (inclusive); {@code null} disables the filter
     * @param limit        max rows to return (caller enforces hard cap; this
     *                     method passes through to setMaxResults verbatim)
     */
    public List<IgaChangeRequestEntity> listPendingByActionTypeIn(String realmId,
                                                                   List<String> actionTypes,
                                                                   Long olderThan,
                                                                   int limit) {
        if (actionTypes == null || actionTypes.isEmpty()) {
            return java.util.Collections.emptyList();
        }
        StringBuilder jpql = new StringBuilder(
                "SELECT cr FROM IgaChangeRequestEntity cr " +
                        "WHERE cr.realmId = :realmId " +
                        "AND cr.status = 'PENDING' " +
                        "AND cr.actionType IN :actionTypes");
        if (olderThan != null) {
            jpql.append(" AND cr.createdAt <= :olderThan");
        }
        jpql.append(" ORDER BY cr.createdAt ASC");
        TypedQuery<IgaChangeRequestEntity> query = em.createQuery(
                        jpql.toString(), IgaChangeRequestEntity.class)
                .setParameter("realmId", realmId)
                .setParameter("actionTypes", actionTypes);
        if (olderThan != null) {
            query.setParameter("olderThan", olderThan);
        }
        return query.setMaxResults(limit).getResultList();
    }

    /**
     * Project the PENDING CRs in {@code realmId} whose id is in {@code crIds}.
     * Ordered by createdAt ASC, capped at {@code limit}. Unlike
     * {@link #listPendingByActionTypeIn} this keys on the exact CR ids — used by
     * the firstAdmin auto-commit sweep, which classifies eligibility PER CR
     * (e.g. an ADOPT_* CR is only auto-eligible when its target is a
     * system/stock-default entity, and a default-role ADD_COMPOSITE only when
     * benign) and so cannot drive the bulk engine by action type alone (a single
     * action type may contain both eligible and ineligible CRs).
     *
     * @param realmId target realm
     * @param crIds   non-empty list of CR ids to match (already PENDING-filtered
     *                + de-duplicated by the caller); empty → empty result
     * @param limit   max rows to return
     */
    public List<IgaChangeRequestEntity> listPendingByIdIn(String realmId,
                                                          List<String> crIds,
                                                          int limit) {
        if (crIds == null || crIds.isEmpty()) {
            return java.util.Collections.emptyList();
        }
        return em.createQuery(
                        "SELECT cr FROM IgaChangeRequestEntity cr " +
                                "WHERE cr.realmId = :realmId " +
                                "AND cr.status = 'PENDING' " +
                                "AND cr.id IN :crIds " +
                                "ORDER BY cr.createdAt ASC", IgaChangeRequestEntity.class)
                .setParameter("realmId", realmId)
                .setParameter("crIds", crIds)
                .setMaxResults(limit)
                .getResultList();
    }

    // -------------------------------------------------------------------------
    // Already-attested guard. See createAdoptCr JavaDoc.
    // -------------------------------------------------------------------------

    /**
     * Thrown by {@link #createAdoptCr} when the target entity already has its
     * {@code attestation} column populated. The manual {@code POST /iga/adopt}
     * endpoint maps this to a 409 CONFLICT with body {@code {error:
     * "ALREADY_ATTESTED", entityType, entityId}}. The toggle-on scan
     * never triggers this (it filters {@code attestation IS NULL} at JPQL)
     * but defensively catches it for visibility.
     */
    public static final class AlreadyAttestedException extends RuntimeException {
        private final String entityType;
        private final String entityId;

        public AlreadyAttestedException(String entityType, String entityId) {
            super("ADOPT refused: " + entityType + " " + entityId
                    + " is already attested");
            this.entityType = entityType;
            this.entityId = entityId;
        }

        public String getEntityType() { return entityType; }
        public String getEntityId() { return entityId; }
    }

    /**
     * Single-SELECT probe of the entity's own {@code attestation} column.
     * Returns {@code true} when the row exists AND its attestation is
     * non-null. Returns {@code false} when the row is missing OR the
     * attestation is null — the caller's downstream model lookup will surface
     * the missing-row case with a more specific error message.
     */
    private boolean isAlreadyAttested(String entityType, String entityId) {
        String jpql;
        switch (entityType) {
            case org.tidecloak.iga.replay.IgaReplayExtension.ENTITY_TYPE_USER:
                jpql = "SELECT u.attestation FROM UserEntity u WHERE u.id = :id";
                break;
            case org.tidecloak.iga.replay.IgaReplayExtension.ENTITY_TYPE_ROLE:
                jpql = "SELECT r.attestation FROM RoleEntity r WHERE r.id = :id";
                break;
            case org.tidecloak.iga.replay.IgaReplayExtension.ENTITY_TYPE_GROUP:
                jpql = "SELECT g.attestation FROM GroupEntity g WHERE g.id = :id";
                break;
            case org.tidecloak.iga.replay.IgaReplayExtension.ENTITY_TYPE_CLIENT:
                jpql = "SELECT c.attestation FROM ClientEntity c WHERE c.id = :id";
                break;
            case org.tidecloak.iga.replay.IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE:
                jpql = "SELECT cs.attestation FROM ClientScopeEntity cs WHERE cs.id = :id";
                break;
            case org.tidecloak.iga.replay.IgaReplayExtension.ENTITY_TYPE_ORGANIZATION:
                jpql = "SELECT o.attestation FROM OrganizationEntity o WHERE o.id = :id";
                break;
            default:
                // Unsupported types are rejected by the switch below; let the
                // existing branch surface the more specific
                // IllegalArgumentException.
                return false;
        }
        List<?> results = em.createQuery(jpql)
                .setParameter("id", entityId)
                .setMaxResults(1)
                .getResultList();
        if (results.isEmpty()) return false;
        Object attestation = results.get(0);
        return attestation != null;
    }
}
