package org.tidecloak.base.iga.serveridentity;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class ServerIdentityResourceProviderFactory implements RealmResourceProviderFactory {
    @Override
    public RealmResourceProvider create(KeycloakSession keycloakSession) {
        return new ServerIdentityResourceProvider(keycloakSession);
    }

    @Override
    public void init(Config.Scope scope) {
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return "tide-server-identity";
    }
}
