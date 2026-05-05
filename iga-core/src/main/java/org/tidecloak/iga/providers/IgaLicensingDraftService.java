package org.tidecloak.iga.providers;

import org.keycloak.models.RealmModel;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.entities.IgaLicensingDraftEntity;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

/**
 * Service for managing pending realm license install/rotate operations.
 *
 * Sidecar pattern: a parent {@link IgaChangeRequestEntity} drives the approval
 * flow (action_type = "INSTALL_LICENSE" or "ROTATE_LICENSE") and the
 * {@link IgaLicensingDraftEntity} sidecar holds licensing-specific data
 * (the issued signature, populated on issuance).
 */
public class IgaLicensingDraftService {

    private final EntityManager em;
    private final IgaChangeRequestService changeRequestService;

    public IgaLicensingDraftService(EntityManager em, IgaChangeRequestService changeRequestService) {
        this.em = em;
        this.changeRequestService = changeRequestService;
    }

    /**
     * Create a new license install/rotate request. Inserts BOTH the parent
     * IGA_CHANGE_REQUEST row (entity_type=REALM, action_type=actionType)
     * AND the IGA_LICENSING_DRAFT sidecar linked via the changeRequest FK.
     *
     * Returns the sidecar entity with {@code changeRequest} populated.
     */
    public IgaLicensingDraftEntity createRequest(RealmModel realm,
                                                  String requestedBy,
                                                  String actionType) {
        IgaChangeRequestEntity cr = changeRequestService.create(
                realm,
                "REALM",
                realm.getId(),
                actionType,
                Collections.emptyList(),
                requestedBy);

        long now = System.currentTimeMillis();
        IgaLicensingDraftEntity entity = new IgaLicensingDraftEntity();
        entity.setId(UUID.randomUUID().toString());
        entity.setChangeRequest(cr);
        entity.setRealmId(realm.getId());
        entity.setActionType(actionType);
        entity.setCreatedAt(now);
        em.persist(entity);
        em.flush();
        return entity;
    }

    /**
     * Set the issued license signature on the sidecar. Stamps updatedAt.
     */
    public IgaLicensingDraftEntity setSignature(String draftId, String signature) {
        IgaLicensingDraftEntity entity = em.find(IgaLicensingDraftEntity.class, draftId);
        if (entity == null) {
            throw new IllegalArgumentException("Licensing draft not found: " + draftId);
        }
        long now = System.currentTimeMillis();
        entity.setSignature(signature);
        entity.setUpdatedAt(now);
        em.flush();
        return entity;
    }

    /**
     * Find a draft by id. Returns null if not found.
     */
    public IgaLicensingDraftEntity findById(String id) {
        return em.find(IgaLicensingDraftEntity.class, id);
    }

    /**
     * List all drafts for a realm, ordered by createdAt DESC.
     */
    public List<IgaLicensingDraftEntity> listByRealm(String realmId) {
        TypedQuery<IgaLicensingDraftEntity> query = em.createNamedQuery(
                "IgaLicensingDraft.findByRealm", IgaLicensingDraftEntity.class);
        query.setParameter("realmId", realmId);
        return query.getResultList();
    }

    /**
     * Delete a draft by id. No-op if it doesn't exist. Does NOT delete the
     * parent change request (FK is ON DELETE SET NULL).
     */
    public void deleteById(String id) {
        IgaLicensingDraftEntity existing = em.find(IgaLicensingDraftEntity.class, id);
        if (existing == null) {
            return;
        }
        em.remove(existing);
        em.flush();
    }
}
