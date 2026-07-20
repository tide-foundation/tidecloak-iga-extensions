package org.tidecloak.iga.providers;

import org.tidecloak.iga.entities.IgaLicenseHistoryEntity;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import java.util.List;
import java.util.UUID;

/**
 * Service for the append-only IGA_LICENSE_HISTORY audit log.
 *
 * No update operation — every issuance creates a new row.
 */
public class IgaLicenseHistoryService {

    private final EntityManager em;

    public IgaLicenseHistoryService(EntityManager em) {
        this.em = em;
    }

    /**
     * Record a new license issuance. Generates UUID + createdAt and persists.
     */
    public IgaLicenseHistoryEntity record(String realmId,
                                           String providerId,
                                           String vrk,
                                           String gvrk,
                                           String gvrkCertificate,
                                           String vvkId,
                                           String customerId,
                                           String vendorId,
                                           String payerPub,
                                           String walletId,
                                           Long expiry) {
        IgaLicenseHistoryEntity entity = new IgaLicenseHistoryEntity();
        entity.setId(UUID.randomUUID().toString());
        entity.setRealmId(realmId);
        entity.setProviderId(providerId);
        entity.setVrk(vrk);
        entity.setGvrk(gvrk);
        entity.setGvrkCertificate(gvrkCertificate);
        entity.setVvkId(vvkId);
        entity.setCustomerId(customerId);
        entity.setVendorId(vendorId);
        entity.setPayerPub(payerPub);
        entity.setWalletId(walletId);
        entity.setExpiry(expiry);
        entity.setCreatedAt(System.currentTimeMillis());
        em.persist(entity);
        em.flush();
        return entity;
    }

    public IgaLicenseHistoryEntity findById(String id) {
        return em.find(IgaLicenseHistoryEntity.class, id);
    }

    /**
     * Returns the most recently created history row matching the given gVRK,
     * or null if no row matches.
     */
    public IgaLicenseHistoryEntity findLatestByGvrk(String gvrk) {
        TypedQuery<IgaLicenseHistoryEntity> query = em.createNamedQuery(
                "IgaLicenseHistory.findLatestByGvrk", IgaLicenseHistoryEntity.class);
        query.setParameter("gvrk", gvrk);
        query.setMaxResults(1);
        List<IgaLicenseHistoryEntity> results = query.getResultList();
        return results.isEmpty() ? null : results.get(0);
    }

    public List<IgaLicenseHistoryEntity> listByRealm(String realmId) {
        TypedQuery<IgaLicenseHistoryEntity> query = em.createNamedQuery(
                "IgaLicenseHistory.findByRealm", IgaLicenseHistoryEntity.class);
        query.setParameter("realmId", realmId);
        return query.getResultList();
    }

    public List<IgaLicenseHistoryEntity> listByProvider(String providerId) {
        TypedQuery<IgaLicenseHistoryEntity> query = em.createNamedQuery(
                "IgaLicenseHistory.findByProvider", IgaLicenseHistoryEntity.class);
        query.setParameter("providerId", providerId);
        return query.getResultList();
    }
}
