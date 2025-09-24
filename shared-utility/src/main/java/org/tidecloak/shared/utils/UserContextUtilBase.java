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
import org.tidecloak.jpa.entities.UserClientAccessProofEntity;
import org.tidecloak.jpa.entities.drafting.TideClientDraftEntity;
import org.tidecloak.shared.enums.DraftStatus;

import java.util.Set;

/**
 * Base utility with minimal defaults. The real implementation is loaded dynamically
 * from the new engine at: org.tidecloak.base.iga.usercontext.UserContextUtils
 */
public class UserContextUtilBase {

    /** New engine can override to provide deep role mapping expansion. */
    public Set<RoleModel> getDeepUserRoleMappings(UserModel user, KeycloakSession session, RealmModel realm, DraftStatus draftStatus) {
        return Set.of(); // default: empty
    }

    /** New engine can override to provide composite expansion for ACTIVE roles. */
    public Set<RoleModel> expandActiveCompositeRoles(KeycloakSession session, Set<RoleModel> roles) {
        return Set.of(); // default: empty
    }

    /**
     * Active user context for (user, client).
     * Returns the persisted UserClientAccessProofEntity row if present, otherwise null.
     */
    public static UserClientAccessProofEntity getUserContext(KeycloakSession session, String clientId, UserModel userModel) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        UserEntity user = em.getReference(UserEntity.class, userModel.getId());

        try {
            return em.createNamedQuery("getAccessProofByUserAndClientId", UserClientAccessProofEntity.class)
                    .setParameter("user", user)
                    .setParameter("clientId", clientId)
                    .getSingleResult();
        } catch (NoResultException e) {
            // No active user-context yet for (user, client)
            return null;
        }
    }

    /**
     * Returns the client's default user-context configuration row (if your project keeps this
     * in TideClientDraftEntity via named query "getClientFullScopeStatus"). Otherwise null.
     */
    public static TideClientDraftEntity getDefaultUserContext(KeycloakSession session, String clientId) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        ClientEntity client = em.getReference(ClientEntity.class, clientId);

        try {
            return em.createNamedQuery("getClientFullScopeStatus", TideClientDraftEntity.class)
                    .setParameter("client", client)
                    .getSingleResult();
        } catch (NoResultException e) {
            // No default user-context row for this client
            return null;
        }
    }

    /**
     * Factory that prefers the real implementation from the new engine.
     * Fallback is this base class with no-ops.
     */
    public static UserContextUtilBase getUserContextUtil() {
        final String implClass = "org.tidecloak.base.iga.usercontext.UserContextUtils";
        try {
            return (UserContextUtilBase) Class.forName(implClass)
                    .getDeclaredConstructor()
                    .newInstance();
        } catch (ClassNotFoundException e) {
            System.out.println("UserContextUtils implementation not found at " + implClass + ". Using base implementation.");
        } catch (Exception e) {
            System.err.println("Error instantiating " + implClass + ": " + e.getMessage());
        }

        return new UserContextUtilBase() {
            @Override
            public Set<RoleModel> expandActiveCompositeRoles(KeycloakSession session, Set<RoleModel> roles) {
                return Set.of();
            }
        };
    }
}
