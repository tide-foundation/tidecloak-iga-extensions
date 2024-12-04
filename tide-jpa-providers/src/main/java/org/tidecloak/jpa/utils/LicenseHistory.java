package org.tidecloak.jpa.utils;

import jakarta.persistence.EntityManager;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.jpa.entities.ComponentEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.tidecloak.jpa.entities.Licensing.LicenseHistoryEntity;

public class LicenseHistory {

    public static void AddLicenseToHistory(ComponentModel componentModel, String VRK, String gVRK, String vvkId,
                                           String customerId, String vendorId, String payerPub, Long expiry,
                                           KeycloakSession session) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        if (!componentModel.getProviderId().equalsIgnoreCase("tide-vendor-key")) {
            throw new IllegalArgumentException("Only tide-vendor-key components supported, you have provided " + componentModel.getProviderId());
        }

        ComponentEntity componentEntity = em.getReference(ComponentEntity.class, componentModel.getId());
        LicenseHistoryEntity licenseHistoryEntity = new LicenseHistoryEntity();
        licenseHistoryEntity.setId(KeycloakModelUtils.generateId());
        licenseHistoryEntity.setComponentEntity(componentEntity);
        licenseHistoryEntity.setVRK(VRK);
        licenseHistoryEntity.setGVRK(gVRK);
        licenseHistoryEntity.setVvkId(vvkId);
        licenseHistoryEntity.setCustomerId(customerId);
        licenseHistoryEntity.setVendorId(vendorId);
        licenseHistoryEntity.setPayerPub(payerPub);
        licenseHistoryEntity.setExpiry(expiry);

        em.persist(licenseHistoryEntity);
        em.flush();
    }
}
