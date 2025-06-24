package org.tidecloak.tide.iga.authorizer;

import jakarta.persistence.EntityManager;
import jakarta.ws.rs.core.Response;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminAuth;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.jpa.entities.AuthorizerEntity;

public interface Authorizer {
    Response signWithAuthorizer(ChangeSetRequest changeSet, EntityManager em, KeycloakSession session, RealmModel realm, Object draftEntity, AdminAuth auth, AuthorizerEntity authorizer, ComponentModel componentModel) throws Exception;

    Response commitWithAuthorizer(ChangeSetRequest changeSet, EntityManager em, KeycloakSession session, RealmModel realm, Object draftEntity, AdminAuth auth, AuthorizerEntity authorizer, ComponentModel componentModel) throws Exception;
}
