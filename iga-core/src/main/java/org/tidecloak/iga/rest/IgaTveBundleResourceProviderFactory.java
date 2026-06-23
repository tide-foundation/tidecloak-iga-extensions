package org.tidecloak.iga.rest;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory;

public class IgaTveBundleResourceProviderFactory implements AdminRealmResourceProviderFactory {

    public static final String ID = "iga-tve";

    @Override
    public IgaTveBundleResourceProvider create(KeycloakSession session) {
        return new IgaTveBundleResourceProvider(session);
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
