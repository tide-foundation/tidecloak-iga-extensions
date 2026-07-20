package org.tidecloak.iga.rest;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory;

public class TideAdminCompatResourceProviderFactory implements AdminRealmResourceProviderFactory {

    public static final String ID = "tide-admin";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public AdminRealmResourceProvider create(KeycloakSession session) {
        return new TideAdminCompatResourceProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
