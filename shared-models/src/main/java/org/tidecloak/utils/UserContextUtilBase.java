package org.tidecloak.utils;

import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.jpa.entities.UserEntity;
import org.tidecloak.enums.DraftStatus;
import org.tidecloak.jpa.entities.UserClientAccessProofEntity;

import java.util.Set;

public class UserContextUtilBase {

    public Set<RoleModel> getDeepUserRoleMappings(UserModel user, KeycloakSession session, RealmModel realm, DraftStatus draftStatus) {
        // Default implementation (can be overridden by subclasses)
        return Set.of(); // Return empty set as default
    }

    public static UserClientAccessProofEntity getUserContext(KeycloakSession session, String clientId, UserModel userModel) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        UserEntity user = em.getReference(UserEntity.class, userModel.getId());

        try {
            return em.createNamedQuery("getAccessProofByUserIdAndClientId", UserClientAccessProofEntity.class)
                    .setParameter("user", user)
                    .setParameter("clientId", clientId)
                    .getSingleResult();
        } catch (NoResultException e) {
            return null;
        }
    }
}
