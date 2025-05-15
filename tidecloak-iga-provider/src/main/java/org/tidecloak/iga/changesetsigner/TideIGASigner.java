package org.tidecloak.iga.changesetsigner;

import jakarta.persistence.EntityManager;
import jakarta.ws.rs.core.Response;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminAuth;
import org.midgard.models.UserContext.UserContext;
import org.tidecloak.iga.changesetprocessors.models.ChangeSetRequest;
import org.tidecloak.iga.changesetsigner.authorizer.Authorizer;
import org.tidecloak.iga.changesetsigner.authorizer.AuthorizerFactory;
import org.tidecloak.iga.utils.IGAUtils;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.AuthorizerEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.shared.Constants;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class TideIGASigner implements ChangeSetSigner{
    @Override
    public Response sign(ChangeSetRequest changeSet, EntityManager em, KeycloakSession session, RealmModel realm, Object draftEntity, AdminAuth auth) throws Exception {
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
        Authorizer authorizerSigner = AuthorizerFactory.getSigner(authorizerType);
        if (authorizerSigner != null) {
            Response resp = authorizerSigner.signWithAuthorizer(changeSet, em, session, realm, draftEntity, auth, primaryAuthorizer, componentModel);
            return  resp;
        }

        return Response.status(Response.Status.BAD_REQUEST).entity("Unsupported authorizer type").build();
    }
}
