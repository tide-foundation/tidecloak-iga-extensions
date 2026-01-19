package org.tidecloak.base.iga.IGARealmResource;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class PolicyResourceProviderFactory implements RealmResourceProviderFactory {
    @Override
    public RealmResourceProvider create(KeycloakSession keycloakSession) {
        return new PolicyResourceProvider(keycloakSession);
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
        return "tide-policy-resources";
    }
}
