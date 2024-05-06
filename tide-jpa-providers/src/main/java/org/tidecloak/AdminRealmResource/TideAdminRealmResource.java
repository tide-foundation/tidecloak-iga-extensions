package org.tidecloak.AdminRealmResource;

import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.keycloak.services.resources.admin.permissions.UserPermissionEvaluator;

import org.tidecloak.interfaces.DraftStatus;
import org.tidecloak.jpa.entities.drafting.TideUserDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;

public class TideAdminRealmResource {

    private final KeycloakSession session;
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;

    public TideAdminRealmResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth) {
        this.session = session;
        this.realm = realm;
        this.auth = auth;
    }

    @GET
    @Path("users/{user-id}/roles/{role-id}/draft/status")
    public DraftStatus getUserRoleAssignmentDraftStatus(@PathParam("user-id") String userId, @PathParam("role-id") String roleId) {
        // do the authorization with the existing admin permissions (e.g. realm management roles)
        final UserPermissionEvaluator userPermissionEvaluator = auth.users();
        userPermissionEvaluator.requireQuery();

        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        UserEntity userEntity = em.find(UserEntity.class, userId);

        try {
            return em.createNamedQuery("getUserRoleAssignmentDraftEntity", TideUserRoleMappingDraftEntity.class)
                    .setParameter("user", userEntity)
                    .setParameter("roleId", roleId)
                    .getSingleResult().getDraftStatus();
        } catch (NoResultException e) {
            return null;
        }

    }

    @GET
    @Path("users/{user-id}/draft/status")
    public DraftStatus getUserDraftStatus(@PathParam("user-id") String id) {
        // do the authorization with the existing admin permissions (e.g. realm management roles)
        final UserPermissionEvaluator userPermissionEvaluator = auth.users();
        userPermissionEvaluator.requireQuery();

        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        UserEntity userEntity = em.find(UserEntity.class, id);

        try {
            return em.createNamedQuery("getTideUserDraftEntity", TideUserDraftEntity.class)
                    .setParameter("user", userEntity)
                    .getSingleResult().getDraftStatus();
        } catch (NoResultException e) {
            // Handle case where no draft status is found
            System.out.println("I AM NULL");
            return null;
        }

    }

//    @GET
//    @Path("composite/{parent-id}/child/{child-id}/draft/status")
//    public DraftStatus getRoleDraftStatus(@PathParam("parent-id") String parentId, @PathParam("child-id") String childId) {
//        // do the authorization with the existing admin permissions (e.g. realm management roles)
//        final UserPermissionEvaluator userPermissionEvaluator = auth.users();
//        userPermissionEvaluator.requireQuery();
//
//        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
//
//        TideCompositeRoleDraftEntity entity = em.find(TideCompositeRoleDraftEntity.class, new TideCompositeRoleDraftEntity.Key(parentId, childId));
//
//        if (entity == null){
//            return null;
//        }
//
//        return entity.getDraftStatus();
//
//
//    }
}
