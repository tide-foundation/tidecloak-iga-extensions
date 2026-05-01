package org.tidecloak.iga.providers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.tidecloak.iga.entities.IgaAuthorizationEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
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
        return "true".equals(realm.getAttribute("iga.enabled"));
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
}
