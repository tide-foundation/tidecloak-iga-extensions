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
 * Service for managing pending workload TLS certificate requests.
 *
 * Sidecar pattern: a parent {@link IgaChangeRequestEntity} drives the approval
 * flow (action_type = "REQUEST_SERVER_CERT") and the {@link IgaServerCertDraftEntity}
 * sidecar holds cert-specific data (public key, issued cert, trust bundle,
 * revocation state).
 */
public class IgaServerCertDraftService {

    private final EntityManager em;
    private final IgaChangeRequestService changeRequestService;

    public IgaServerCertDraftService(EntityManager em, IgaChangeRequestService changeRequestService) {
        this.em = em;
        this.changeRequestService = changeRequestService;
    }

    /**
     * Create a new server-cert request with no prerequisite. See
     * {@link #createRequest(RealmModel, String, String, String, String, String, String, List)}.
     */
    public IgaServerCertDraftEntity createRequest(RealmModel realm,
                                                   String requestedBy,
                                                   String clientId,
                                                   String csr,
                                                   String publicKey,
                                                   String publicKeyFingerprint,
                                                   String serialNumber) {
        return createRequest(realm, requestedBy, clientId, csr, publicKey, publicKeyFingerprint,
                serialNumber, null);
    }

    /**
     * Create a new server-cert request. Inserts BOTH the parent
     * IGA_CHANGE_REQUEST row (entity_type=CLIENT, action_type=REQUEST_SERVER_CERT)
     * AND the IGA_SERVER_CERT_DRAFT sidecar linked via the changeRequest FK.
     *
     * <p>A non-empty {@code dependsOn} marks the CR blocked until every listed prerequisite CR is
     * APPROVED — the commit path enforces that with a 412. The enrolment flow uses it to chain a
     * client certificate to the realm certificate it will be anchored by: issuing a workload leaf
     * before the realm root CA exists produces a certificate that cannot complete a handshake.
     *
     * Returns the sidecar entity with {@code changeRequest} populated.
     *
     * @param dependsOn prerequisite CR ids, or null/empty for an unblocked request
     */
    public IgaServerCertDraftEntity createRequest(RealmModel realm,
                                                   String requestedBy,
                                                   String clientId,
                                                   String csr,
                                                   String publicKey,
                                                   String publicKeyFingerprint,
                                                   String serialNumber,
                                                   List<String> dependsOn) {
        // Build the row payload that the parent CR carries. This is what the
        // replay dispatcher will see when REQUEST_SERVER_CERT is approved.
        Map<String, Object> row = new HashMap<>();
        row.put("client_id", clientId);
        row.put("public_key", publicKey);
        if (publicKeyFingerprint != null) row.put("public_key_fingerprint", publicKeyFingerprint);
        if (serialNumber != null) row.put("serial_number", serialNumber);

        IgaChangeRequestEntity cr = changeRequestService.create(
                realm,
                "CLIENT",
                clientId,
                "REQUEST_SERVER_CERT",
                List.of(row),
                requestedBy,
                dependsOn);

        long now = System.currentTimeMillis();
        IgaServerCertDraftEntity entity = new IgaServerCertDraftEntity();
        entity.setId(UUID.randomUUID().toString());
        entity.setChangeRequest(cr);
        entity.setRealmId(realm.getId());
        entity.setClientId(clientId);
        entity.setCsr(csr);
        entity.setPublicKey(publicKey);
        entity.setPublicKeyFingerprint(publicKeyFingerprint);
        entity.setSerialNumber(serialNumber);
        entity.setRevoked(false);
        entity.setCreatedAt(now);
        em.persist(entity);
        em.flush();
        return entity;
    }

    /**
     * Store the validated certificate from a committed signing round.
     *
     * <p>Sidecar only — the parent CR's status is NOT touched here. The commit path owns the CR
     * lifecycle (the replay dispatcher's tail sets APPROVED + resolvedAt once replay returns), and
     * having a sidecar service reach up and resolve its own parent would put that transition in two
     * places that could disagree.
     */
    public IgaServerCertDraftEntity issueCert(String draftId, String certificate,
                                              Long notBefore, Long notAfter) {
        IgaServerCertDraftEntity entity = em.find(IgaServerCertDraftEntity.class, draftId);
        if (entity == null) {
            throw new IllegalArgumentException("Server cert draft not found: " + draftId);
        }
        entity.setCertificate(certificate);
        entity.setNotBefore(notBefore);
        entity.setNotAfter(notAfter);
        entity.setUpdatedAt(System.currentTimeMillis());
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
     * List drafts for a (realm, public-key fingerprint) pair, ordered by createdAt DESC.
     * Backs the enrolment endpoint's duplicate-request guard: the fingerprint identifies the
     * keypair a CSR is asking to have certified.
     */
    public List<IgaServerCertDraftEntity> findByRealmAndFingerprint(String realmId, String fingerprint) {
        TypedQuery<IgaServerCertDraftEntity> query = em.createNamedQuery(
                "IgaServerCertDraft.findByRealmAndFingerprint", IgaServerCertDraftEntity.class);
        query.setParameter("realmId", realmId);
        query.setParameter("fingerprint", fingerprint);
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
