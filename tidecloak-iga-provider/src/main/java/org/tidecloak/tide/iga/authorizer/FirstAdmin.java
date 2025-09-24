package org.tidecloak.tide.iga.authorizer;

import jakarta.persistence.EntityManager;
import jakarta.ws.rs.core.Response;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.*;
import org.keycloak.services.resources.admin.AdminAuth;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.jpa.entities.AuthorizerEntity;

public class FirstAdmin implements Authorizer {

    @Override
    public Response signWithAuthorizer(ChangeSetRequest changeSet, EntityManager em, KeycloakSession session, RealmModel realm, Object draftEntity, AdminAuth auth, AuthorizerEntity authorizer, ComponentModel componentModel) throws Exception {
        // For FirstAdmin, re-route to MultiAdmin path (single-admin flows still go through approvals UI)
        return new MultiAdmin().signWithAuthorizer(changeSet, em, session, realm, draftEntity, auth, authorizer, componentModel);
    }

    @Override
    public Response commitWithAuthorizer(ChangeSetRequest changeSet, EntityManager em, KeycloakSession session, RealmModel realm, Object draftEntity, AdminAuth auth, AuthorizerEntity authorizer, ComponentModel componentModel) throws Exception {
        // Delegate to MultiAdmin commit (keeps one code path; thresholds still apply)
        return new MultiAdmin().commitWithAuthorizer(changeSet, em, session, realm, draftEntity, auth, authorizer, componentModel);
    }
}
