package org.tidecloak.base.iga.interfaces;

import jakarta.persistence.EntityManager;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.jpa.entities.ComponentEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.managers.Auth;
import org.tidecloak.jpa.entities.AuthorizerEntity;

import java.util.List;

public class AuthorizerAdapter {

    public static void CreateAuthorizerEntity(KeycloakSession session, String authorizerType, String authorizer, String authorizerCertificate, String componentModelId) throws Exception {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        ComponentEntity componentEntity = em.find(ComponentEntity.class, componentModelId);

        if ( componentEntity == null){
            throw new Exception("No component entity found with this id " + componentModelId + ". Check if a tide-vendor-key exists as a key provider for this realm.");
        }
        AuthorizerEntity entity = new AuthorizerEntity();
        entity.setAuthorizer(authorizer);
        entity.setId(KeycloakModelUtils.generateId());
        entity.setAuthorizerCertificate(authorizerCertificate);
        entity.setKeyProvider(componentEntity);
        entity.setType(authorizerType);
        em.persist(entity);
        em.flush();

    }

    public static List<AuthorizerEntity> GetRealmAuthorizers(KeycloakSession session, String componentModelId) throws Exception {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        return em.createNamedQuery("getAuthorizerByProviderId", AuthorizerEntity.class)
                .setParameter("ID", componentModelId).getResultList();
    }
}