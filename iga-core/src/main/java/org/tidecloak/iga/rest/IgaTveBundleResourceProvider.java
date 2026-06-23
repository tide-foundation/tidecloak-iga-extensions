package org.tidecloak.iga.rest;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;

public class IgaTveBundleResourceProvider implements AdminRealmResourceProvider {

    private final KeycloakSession session;

    public IgaTveBundleResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource(KeycloakSession session, RealmModel realm,
                              AdminPermissionEvaluator auth, AdminEventBuilder adminEvent) {
        return new IgaTveBundleResource(session, realm, auth);
    }

    @Override
    public void close() {
    }
}
