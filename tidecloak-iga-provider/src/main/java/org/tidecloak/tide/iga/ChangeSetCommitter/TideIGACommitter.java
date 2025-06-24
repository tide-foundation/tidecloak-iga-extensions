package org.tidecloak.tide.iga.ChangeSetCommitter;

import jakarta.persistence.EntityManager;
import jakarta.ws.rs.core.Response;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminAuth;
import org.tidecloak.base.iga.ChangeSetCommitter.ChangeSetCommitter;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.tide.iga.authorizer.Authorizer;
import org.tidecloak.tide.iga.authorizer.AuthorizerFactory;
import org.tidecloak.jpa.entities.AuthorizerEntity;
import org.tidecloak.shared.Constants;

import java.util.List;

public class TideIGACommitter implements ChangeSetCommitter {
    @Override
    public Response commit(ChangeSetRequest changeSet, EntityManager em, KeycloakSession session, RealmModel realm, Object draftEntity, AdminAuth auth) throws Exception {
        // Check for key provider
        ComponentModel componentModel = realm.getComponentsStream()
                .filter(x -> x.getProviderId().equalsIgnoreCase(Constants.TIDE_VENDOR_KEY))  // Use .equals for string comparison
                .findFirst()
                .orElse(null);

        if (componentModel == null) {
            // No key provider, use non-IGA logic
            return null;
        }

        // Fetch authorizers
        List<AuthorizerEntity> realmAuthorizers = em.createNamedQuery("getAuthorizerByProviderIdAndTypes", AuthorizerEntity.class)
                .setParameter("ID", componentModel.getId())
                .setParameter("types", List.of("firstAdmin", "multiAdmin"))
                .getResultList();

        if (realmAuthorizers.isEmpty()) {
            throw new Exception("Authorizer not found for this realm.");
        }

        AuthorizerEntity primaryAuthorizer = realmAuthorizers.get(0);
        String authorizerType = primaryAuthorizer.getType();

        // Delegate to the appropriate sub-strategy
        Authorizer authorizerSigner = AuthorizerFactory.getCommitter(authorizerType);
        if (authorizerSigner != null) {
            return authorizerSigner.commitWithAuthorizer(changeSet, em, session, realm, draftEntity, auth, primaryAuthorizer, componentModel);
        }
        return Response.status(Response.Status.BAD_REQUEST).entity("Unsupported authorizer type").build();
    }
}