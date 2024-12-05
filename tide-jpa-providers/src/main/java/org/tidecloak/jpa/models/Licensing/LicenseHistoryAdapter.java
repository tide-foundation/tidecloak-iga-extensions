package org.tidecloak.jpa.models.Licensing;

import jakarta.persistence.EntityManager;
import jakarta.ws.rs.BadRequestException;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.jpa.entities.ComponentEntity;
import org.tidecloak.jpa.entities.Licensing.LicenseHistoryEntity;

import java.util.List;

public class LicenseHistoryAdapter {

    public static List<LicenseHistoryEntity> GetLicenseHistory(KeycloakSession session, RealmModel realmModel){
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        ComponentModel componentModel = session.realms().getRealm(realmModel.getId()).getComponentsStream()
                .filter(x -> "tide-vendor-key".equals(x.getProviderId()))  // Use .equals for string comparison
                .findFirst()
                .orElse((null));

        if(componentModel == null) {
            throw new BadRequestException("There is no tide-vendor-key component set up for this realm, " + realmModel.getName());
        }

        ComponentEntity keyProviderEntity = em.getReference(ComponentEntity.class, componentModel.getId());


        return em.createNamedQuery("getLicenseHistoryForKey", LicenseHistoryEntity.class)
                .setParameter("componentEntity", keyProviderEntity)
                .getResultList();


    }
}
