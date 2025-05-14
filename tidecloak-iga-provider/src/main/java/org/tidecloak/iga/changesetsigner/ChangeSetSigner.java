package org.tidecloak.iga.changesetsigner;

import jakarta.persistence.EntityManager;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminAuth;
import org.tidecloak.iga.changesetprocessors.models.ChangeSetRequest;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;

public interface  ChangeSetSigner {
    Response sign(ChangeSetRequest changeSet, EntityManager em, KeycloakSession session, RealmModel realm, Object draftEntity, AdminAuth auth) throws Exception;
}
