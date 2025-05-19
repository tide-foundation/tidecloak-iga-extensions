package org.tidecloak.shared.utils;

import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.tidecloak.jpa.entities.drafting.TideClientDraftEntity;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.jpa.entities.UserClientAccessProofEntity;

import java.util.Set;

public class UserContextUtilBase {

    public Set<RoleModel> getDeepUserRoleMappings(UserModel user, KeycloakSession session, RealmModel realm, DraftStatus draftStatus) {
        return Set.of(); // Return empty set as default
    }

    public Set<RoleModel> expandActiveCompositeRoles(KeycloakSession session, Set<RoleModel> roles){
        return Set.of();
    };


    public static UserClientAccessProofEntity getUserContext(KeycloakSession session, String clientId, UserModel userModel) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        UserEntity user = em.getReference(UserEntity.class, userModel.getId());

        try {
            return em.createNamedQuery("getAccessProofByUserAndClientId", UserClientAccessProofEntity.class)
                    .setParameter("user", user)
                    .setParameter("clientId", clientId)
                    .getSingleResult();
        } catch (NoResultException e) {
            // get the default usercontext for the lcient
            return null;
        }
    }

    public static TideClientDraftEntity getDefaultUserContext(KeycloakSession session, String clientId) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        ClientEntity client = em.getReference(ClientEntity.class, clientId);

        try {
            return em.createNamedQuery("getClientFullScopeStatus", TideClientDraftEntity.class)
                    .setParameter("client", client)
                    .getSingleResult();
        } catch (NoResultException e) {
            // get the default usercontext for the lcient
            return null;
        }
    }

    public static UserContextUtilBase getUserContextUtil() {
        try {
            // Attempt to load the real implementation dynamically
            return (UserContextUtilBase) Class.forName("org.tidecloak.iga.ChangeSetProcessors.utils.UserContextUtils")
                    .getDeclaredConstructor()
                    .newInstance();
        } catch (ClassNotFoundException e) {
            // Log that the real implementation was not found
            System.out.println("Real implementation not found. Using base implementation.");
        } catch (Exception e) {
            // Handle any other exceptions during instantiation
            System.err.println("Error instantiating UserContextUtils: " + e.getMessage());
        }

        // Fallback to base class implementation
        return new UserContextUtilBase() {
            @Override
            public Set<RoleModel> expandActiveCompositeRoles(KeycloakSession session, Set<RoleModel> roles) {
                return Set.of();
            }
        };
    }

}
