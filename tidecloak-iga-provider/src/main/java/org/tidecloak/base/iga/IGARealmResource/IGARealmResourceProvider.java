package org.tidecloak.base.iga.IGARealmResource;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;

public class IGARealmResourceProvider
        implements AdminRealmResourceProviderFactory, AdminRealmResourceProvider {

    public static final String PROVIDER_ID = "tide-admin";

    @Override
    public AdminRealmResourceProvider create(KeycloakSession session) {
        // This provider is stateless; returning `this` is fine. If you prefer,
        // you can return `new IGARealmResourceProvider()` instead.
        return this;
    }

    @Override
    public Object getResource(KeycloakSession session,
                              RealmModel realm,
                              AdminPermissionEvaluator auth,
                              AdminEventBuilder adminEvent) {
        return new IGARealmResource(session, realm, auth);
    }

    @Override
    public void init(Config.Scope config) {
        // no-op
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // no-op
    }

    @Override
    public void close() {
        // no-op
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
