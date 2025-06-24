package org.tidecloak.base.iga.interfaces;

import jakarta.persistence.EntityManager;
import org.keycloak.Config;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;

import static org.keycloak.models.jpa.JpaRealmProviderFactory.PROVIDER_PRIORITY;

public class TideRoleProviderFactory implements RoleProviderFactory {

    @Override
    public RoleProvider create(KeycloakSession session) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        return new TideRealmProvider(session, em, null, null);
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

    @Override
    public String getId() {
        return "tide-role-provider";
    }

    @Override
    public int order() {
        return PROVIDER_PRIORITY;
    }
}
