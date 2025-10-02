package org.tidecloak.base.iga.ChangeSetSigner;

import jakarta.persistence.EntityManager;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.resources.admin.AdminAuth;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import java.util.*;

public interface  ChangeSetSigner {
    Response sign(ChangeSetRequest changeSet, EntityManager em, KeycloakSession session, RealmModel realm, List<?> draftEntities, AdminAuth adminAuth) throws Exception;
}
