package org.tidecloak.iga.rest;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Factory for the public {@code tide-server-identity} realm resource (workload
 * cert-request endpoint). Registered via
 * META-INF/services/org.keycloak.services.resource.RealmResourceProviderFactory.
 *
 * URL: /realms/{realm}/tide-server-identity/...
 */
public class ServerIdentityResourceProviderFactory implements RealmResourceProviderFactory {

    public static final String ID = "tide-server-identity";

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new ServerIdentityResourceProvider(session);
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
