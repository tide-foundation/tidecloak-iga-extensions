package org.tidecloak.iga.rest;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory;

public class IgaAdminResourceProviderFactory implements AdminRealmResourceProviderFactory {

    public static final String ID = "iga";

    @Override
    public IgaAdminResourceProvider create(KeycloakSession session) {
        return new IgaAdminResourceProvider(session);
    }

    @Override
    public String getId() {
        return ID;
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
