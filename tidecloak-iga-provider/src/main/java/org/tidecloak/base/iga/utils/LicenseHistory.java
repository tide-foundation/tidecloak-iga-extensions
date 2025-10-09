package org.tidecloak.base.iga.utils;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceException;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.jpa.entities.ComponentEntity;
import org.tidecloak.jpa.entities.Licensing.LicenseHistoryEntity;

public final class LicenseHistory {
    private static final Logger LOG = Logger.getLogger(LicenseHistory.class);

    private LicenseHistory() {}

    /**
     * New slim API — NOTE: your schema requires PROVIDER_ID NOT NULL.
     * Keep this only if you truly have a nullable PROVIDER_ID (you don't).
     * Prefer the overload with ComponentModel below.
     */
    public static void AddLicenseToHistory(
            String vrk,
            String gvrk,
            String vvkId,
            String customerId,
            String vendorId,
            String payerPub,
            long expiry,
            KeycloakSession session
    ) {
        // Your schema has PROVIDER_ID NOT NULL; without provider we cannot persist safely.
        LOG.warn("AddLicenseToHistory called without ComponentModel; skipping because PROVIDER_ID is NOT NULL");
    }

    /**
     * Back-compat + correct for your schema:
     * PROVIDER_ID is set from the passed ComponentModel.
     */
    public static void AddLicenseToHistory(
            ComponentModel componentModel,
            String vrk,
            String gvrk,
            String gvrkCertificate,
            String vvkId,
            String customerId,
            String vendorId,
            String payerPub,
            long expiry,
            KeycloakSession session
    ) {
        if (session == null) return;
        if (componentModel == null) {
            LOG.warn("componentModel is null; cannot set PROVIDER_ID. Skipping history insert.");
            return;
        }

        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        // Lightweight reference; does not SELECT
        ComponentEntity providerRef = em.getReference(ComponentEntity.class, componentModel.getId());

        // De-dupe by provider + keys + expiry (prevents duplicates when toggling)
        Long cnt = em.createQuery(
                        "SELECT COUNT(l) FROM LicenseHistoryEntity l " +
                                "WHERE l.componentEntity = :prov AND l.VRK = :vrk AND l.GVRK = :gvrk AND l.expiry = :exp",
                        Long.class)
                .setParameter("prov", providerRef)
                .setParameter("vrk", vrk)
                .setParameter("gvrk", gvrk)
                .setParameter("exp", expiry)
                .getSingleResult();

        if (cnt != null && cnt > 0L) {
            return; // already recorded
        }

        LicenseHistoryEntity e = new LicenseHistoryEntity();
        e.setId(org.keycloak.models.utils.KeycloakModelUtils.generateId());
        e.setComponentEntity(providerRef);     // <-- sets PROVIDER_ID (required)
        e.setVRK(vrk);
        e.setGVRK(gvrk);
        e.setGVRKCertificate(gvrkCertificate);
        e.setVvkId(vvkId);
        e.setCustomerId(customerId);
        e.setVendorId(vendorId);
        e.setPayerPub(payerPub);
        e.setExpiry(expiry);

        try {
            em.persist(e);
            em.flush();
        } catch (PersistenceException pe) {
            // Unique/constraint races — safe to ignore
            LOG.debug("Duplicate license-history insert ignored (PersistenceException).", pe);
        } catch (RuntimeException re) {
            final String msg = re.getMessage();
            if (msg != null && msg.toLowerCase().contains("duplicate")) {
                LOG.debug("Duplicate license-history insert ignored (RuntimeException).", re);
            } else {
                throw re;
            }
        }
    }
}
