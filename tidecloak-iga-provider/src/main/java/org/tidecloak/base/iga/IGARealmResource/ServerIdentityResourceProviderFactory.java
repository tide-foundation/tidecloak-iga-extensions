package org.tidecloak.base.iga.IGARealmResource;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class ServerIdentityResourceProviderFactory implements RealmResourceProviderFactory {
    @Override
    public RealmResourceProvider create(KeycloakSession keycloakSession) {
        // Lazy load to avoid classloading issues during Quarkus augmentation
        try {
            Class<?> clazz = Class.forName("org.tidecloak.base.iga.serveridentity.ServerIdentityResourceProvider");
            return (RealmResourceProvider) clazz.getConstructor(KeycloakSession.class).newInstance(keycloakSession);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create ServerIdentityResourceProvider", e);
        }
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
