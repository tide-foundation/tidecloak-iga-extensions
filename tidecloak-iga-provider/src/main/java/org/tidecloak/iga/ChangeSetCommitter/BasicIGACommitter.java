package org.tidecloak.iga.ChangeSetCommitter;

import jakarta.persistence.EntityManager;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminAuth;
import org.tidecloak.iga.changesetprocessors.models.ChangeSetRequest;

public class BasicIGACommitter implements ChangeSetCommitter{
    @Override
    public Response commit(ChangeSetRequest changeSet, EntityManager em, KeycloakSession session, RealmModel realm, Object draftEntity, AdminAuth auth) throws Exception {
        // Commit using tide "firstAdmin" authorizer.

    }
}
