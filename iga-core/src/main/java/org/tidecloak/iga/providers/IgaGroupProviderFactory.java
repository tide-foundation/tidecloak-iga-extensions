package org.tidecloak.iga.providers;

import org.keycloak.Config;
import org.keycloak.models.GroupProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class IgaGroupProviderFactory implements GroupProviderFactory<IgaRealmProvider> {

    public static final String ID = "iga-group-provider";

    @Override
    public IgaRealmProvider create(KeycloakSession session) {
        return new IgaRealmProvider(session);
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public int order() {
        return 2;
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
