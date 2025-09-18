package org.tidecloak.tide.iga.ChangeSetCommitter;

import jakarta.persistence.EntityManager;
import jakarta.ws.rs.core.Response;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminAuth;
import org.tidecloak.base.iga.ChangeSetCommitter.BasicIGACommitter;
import org.tidecloak.base.iga.ChangeSetCommitter.ChangeSetCommitter;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.tide.iga.authorizer.Authorizer;
import org.tidecloak.tide.iga.authorizer.AuthorizerFactory;
import org.tidecloak.jpa.entities.AuthorizerEntity;
import org.tidecloak.shared.Constants;

import java.util.List;

public class TideIGACommitter implements ChangeSetCommitter {
    @Override
    public Response commit(ChangeSetRequest changeSet,
                           EntityManager em,
                           KeycloakSession session,
                           RealmModel realm,
                           Object draftEntity,
                           AdminAuth auth) throws Exception {

        ComponentModel kp = realm.getComponentsStream()
                .filter(x -> x.getProviderId().equalsIgnoreCase(Constants.TIDE_VENDOR_KEY))
                .findFirst()
                .orElse(null);

        // No Tide key provider → just apply to DB
        if (kp == null) {
            return new BasicIGACommitter().commit(changeSet, em, session, realm, draftEntity, auth);
        }

        // Authorizer (firstAdmin/multiAdmin)
        List<AuthorizerEntity> realmAuthorizers = em.createNamedQuery(
                        "getAuthorizerByProviderIdAndTypes", AuthorizerEntity.class)
                .setParameter("ID", kp.getId())
                .setParameter("types", List.of("firstAdmin", "multiAdmin"))
                .getResultList();

        if (realmAuthorizers.isEmpty()) {
            throw new IllegalStateException("Authorizer not found for realm.");
        }

        AuthorizerEntity primary = realmAuthorizers.get(0);
        Authorizer committer = AuthorizerFactory.getCommitter(primary.getType());
        if (committer == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Unsupported authorizer type: " + primary.getType())
                    .build();
        }

        // 1) crypto / threshold / AP updates
        Response sig = committer.commitWithAuthorizer(
                changeSet, em, session, realm, draftEntity, auth, primary, kp);

        // 2) apply replay “rep” to DB
        Response applied = new BasicIGACommitter().commit(
                changeSet, em, session, realm, draftEntity, auth);

        return applied != null ? applied : sig;
    }
}
