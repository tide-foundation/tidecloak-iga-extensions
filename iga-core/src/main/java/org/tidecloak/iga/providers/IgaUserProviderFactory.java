package org.tidecloak.iga.providers;

import org.keycloak.Config;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserProviderFactory;

import jakarta.persistence.EntityManager;

public class IgaUserProviderFactory implements UserProviderFactory<IgaUserProvider> {

    public static final String ID = "iga-user-provider";

    @Override
    public IgaUserProvider create(KeycloakSession session) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        return new IgaUserProvider(session, em);
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
