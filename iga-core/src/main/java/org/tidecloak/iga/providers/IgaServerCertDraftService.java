package org.tidecloak.iga.providers;

import org.keycloak.models.RealmModel;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.entities.IgaServerCertDraftEntity;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Service for managing pending workload TLS / SPIFFE certificate requests.
 *
 * Sidecar pattern: a parent {@link IgaChangeRequestEntity} drives the approval
 * flow (action_type = "REQUEST_SERVER_CERT") and the {@link IgaServerCertDraftEntity}
 * sidecar holds cert-specific data (public key, instance id, issued cert, trust
 * bundle, revocation state).
 */
public class IgaServerCertDraftService {

    private final EntityManager em;
    private final IgaChangeRequestService changeRequestService;

    public IgaServerCertDraftService(EntityManager em, IgaChangeRequestService changeRequestService) {
        this.em = em;
        this.changeRequestService = changeRequestService;
    }

    /**
     * Create a new server-cert request. Inserts BOTH the parent
     * IGA_CHANGE_REQUEST row (entity_type=CLIENT, action_type=REQUEST_SERVER_CERT)
     * AND the IGA_SERVER_CERT_DRAFT sidecar linked via the changeRequest FK.
     *
     * Returns the sidecar entity with {@code changeRequest} populated.
     */
    public IgaServerCertDraftEntity createRequest(RealmModel realm,
                                                   String requestedBy,
                                                   String clientId,
                                                   String instanceId,
                                                   String spiffeId,
                                                   String publicKey,
                                                   String publicKeyFingerprint,
                                                   Long requestedLifetime,
                                                   String signedPolicy) {
        // Build the row payload that the parent CR carries. This is what the
        // replay dispatcher will see when REQUEST_SERVER_CERT is approved.
        Map<String, Object> row = new HashMap<>();
        row.put("client_id", clientId);
        row.put("instance_id", instanceId);
        if (spiffeId != null) row.put("spiffe_id", spiffeId);
        row.put("public_key", publicKey);
        if (publicKeyFingerprint != null) row.put("public_key_fingerprint", publicKeyFingerprint);
        if (requestedLifetime != null) row.put("requested_lifetime", requestedLifetime);

        IgaChangeRequestEntity cr = changeRequestService.create(
                realm,
                "CLIENT",
                clientId,
                "REQUEST_SERVER_CERT",
                List.of(row),
                requestedBy);

        long now = System.currentTimeMillis();
        IgaServerCertDraftEntity entity = new IgaServerCertDraftEntity();
        entity.setId(UUID.randomUUID().toString());
        entity.setChangeRequest(cr);
        entity.setRealmId(realm.getId());
        entity.setClientId(clientId);
        entity.setInstanceId(instanceId);
        entity.setSpiffeId(spiffeId);
        entity.setPublicKey(publicKey);
        entity.setPublicKeyFingerprint(publicKeyFingerprint);
        entity.setRequestedLifetime(requestedLifetime);
        entity.setSignedPolicy(signedPolicy);
        entity.setRevoked(false);
        entity.setCreatedAt(now);
        em.persist(entity);
        em.flush();
        return entity;
    }

    /**
     * Set the issued certificate + trust bundle on the sidecar. If the parent
     * change request is still PENDING it is also marked APPROVED here (used
     * when issuance is driven from outside the replay dispatcher path).
     */
    public IgaServerCertDraftEntity issueCert(String draftId, String certificate, String trustBundle) {
        IgaServerCertDraftEntity entity = em.find(IgaServerCertDraftEntity.class, draftId);
        if (entity == null) {
            throw new IllegalArgumentException("Server cert draft not found: " + draftId);
        }
        long now = System.currentTimeMillis();
        entity.setCertificate(certificate);
        entity.setTrustBundle(trustBundle);
        entity.setUpdatedAt(now);

        IgaChangeRequestEntity cr = entity.getChangeRequest();
        if (cr != null && "PENDING".equals(cr.getStatus())) {
            cr.setStatus("APPROVED");
            cr.setResolvedAt(now);
        }

        em.flush();
        return entity;
    }

    /**
     * Mark a draft as revoked. Sets revoked=true and stamps revokedAt + updatedAt.
     */
    public IgaServerCertDraftEntity revoke(String draftId) {
        IgaServerCertDraftEntity entity = em.find(IgaServerCertDraftEntity.class, draftId);
        if (entity == null) {
            throw new IllegalArgumentException("Server cert draft not found: " + draftId);
        }
        long now = System.currentTimeMillis();
        entity.setRevoked(true);
        entity.setRevokedAt(now);
        entity.setUpdatedAt(now);
        em.flush();
        return entity;
    }

    /**
     * Find a draft by id. Returns null if not found.
     */
    public IgaServerCertDraftEntity findById(String id) {
        return em.find(IgaServerCertDraftEntity.class, id);
    }

    /**
     * List all drafts for a realm, ordered by createdAt DESC.
     */
    public List<IgaServerCertDraftEntity> listByRealm(String realmId) {
        TypedQuery<IgaServerCertDraftEntity> query = em.createNamedQuery(
                "IgaServerCertDraft.findByRealm", IgaServerCertDraftEntity.class);
        query.setParameter("realmId", realmId);
        return query.getResultList();
    }

    /**
     * List active drafts for a realm — non-revoked AND issued (certificate is set).
     */
    public List<IgaServerCertDraftEntity> listActive(String realmId) {
        TypedQuery<IgaServerCertDraftEntity> query = em.createNamedQuery(
                "IgaServerCertDraft.findActive", IgaServerCertDraftEntity.class);
        query.setParameter("realmId", realmId);
        return query.getResultList();
    }

    /**
     * List drafts for a (realm, instance) pair, ordered by createdAt DESC.
     */
    public List<IgaServerCertDraftEntity> findByRealmAndInstance(String realmId, String instanceId) {
        TypedQuery<IgaServerCertDraftEntity> query = em.createNamedQuery(
                "IgaServerCertDraft.findByRealmAndInstance", IgaServerCertDraftEntity.class);
        query.setParameter("realmId", realmId);
        query.setParameter("instanceId", instanceId);
        return query.getResultList();
    }

    /**
     * Delete a draft by id. No-op if it doesn't exist.
     */
    public void deleteById(String id) {
        IgaServerCertDraftEntity existing = em.find(IgaServerCertDraftEntity.class, id);
        if (existing == null) {
            return;
        }
        em.remove(existing);
        em.flush();
    }
}
