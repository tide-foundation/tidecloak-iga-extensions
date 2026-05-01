package org.tidecloak.iga.jpa;

import org.keycloak.Config;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class IgaJpaEntityProviderFactory implements JpaEntityProviderFactory {

    public static final String ID = "iga-entity-provider";

    @Override
    public IgaJpaEntityProvider create(KeycloakSession session) {
        return new IgaJpaEntityProvider();
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
