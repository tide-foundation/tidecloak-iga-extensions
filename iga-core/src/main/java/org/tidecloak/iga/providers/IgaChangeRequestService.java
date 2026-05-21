package org.tidecloak.iga.providers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.ModelToRepresentation;
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
     * Create a new change request for the given realm/entity.
     */
    public IgaChangeRequestEntity create(RealmModel realm, String entityType, String entityId,
                                          String actionType, List<Map<String, Object>> rows,
                                          String requestedBy) {
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
        em.persist(entity);
        em.flush();
        return entity;
    }

    /**
     * Phase 6a — create a per-entity ADOPT change request for an entity that
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
     * a Phase 6b toggle-on scan should never see this, but it protects an
     * unit/E2E driver from creating a dangling CR.</p>
     *
     * <p>Phase 6b — throws {@link AlreadyAttestedException} when the target
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
        if (realm == null || entityType == null || entityId == null) {
            throw new IllegalArgumentException(
                    "createAdoptCr requires non-null realm + entityType + entityId");
        }
        // Phase 6b — refuse to enqueue an ADOPT CR for an already-attested
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
            default:
                throw new IllegalArgumentException(
                        "createAdoptCr: unsupported entityType '" + entityType
                                + "' (expected USER | ROLE | GROUP | CLIENT | CLIENT_SCOPE)");
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

        // Sidecar row linking the unattested entity to its ADOPT CR.
        IgaUnsignedEntityService.markUnsigned(em, realm.getId(), entityType, entityId, cr.getId());

        em.flush();
        return cr.getId();
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
    public IgaAuthorizationEntity authorize(String changeRequestId, String authorizedBy, String partialSig) {
        IgaChangeRequestEntity cr = em.find(IgaChangeRequestEntity.class, changeRequestId);
        if (cr == null) {
            throw new IllegalArgumentException("Change request not found: " + changeRequestId);
        }
        IgaAuthorizationEntity auth = new IgaAuthorizationEntity();
        auth.setId(UUID.randomUUID().toString());
        auth.setChangeRequest(cr);
        auth.setAuthorizedBy(authorizedBy);
        auth.setPartialSig(partialSig);
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
    // Phase 6e — bulk-authorize PENDING CR selector. See
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

    // -------------------------------------------------------------------------
    // Phase 6b — already-attested guard. See createAdoptCr JavaDoc.
    // -------------------------------------------------------------------------

    /**
     * Thrown by {@link #createAdoptCr} when the target entity already has its
     * {@code attestation} column populated. The manual {@code POST /iga/adopt}
     * endpoint maps this to a 409 CONFLICT with body {@code {error:
     * "ALREADY_ATTESTED", entityType, entityId}}. The Phase 6b toggle-on scan
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
