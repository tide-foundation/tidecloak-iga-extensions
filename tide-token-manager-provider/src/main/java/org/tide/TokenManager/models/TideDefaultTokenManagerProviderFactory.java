package org.tide.TokenManager.models;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.TokenManager;
import org.keycloak.models.TokenManagerFactory;

public class TideDefaultTokenManagerProviderFactory implements TokenManagerFactory {

    public static final String ID = "tide-default-token-manager";

    @Override
    public TokenManager create(KeycloakSession session) {
        return new TideDefaultTokenManagerProvider(session);
    }

    @Override public void init(Config.Scope config) {
        org.jboss.logging.Logger.getLogger(getClass()).info("TideDefaultTokenManagerProviderFactory INIT");
    }
    @Override public void postInit(KeycloakSessionFactory factory) {}
    @Override public void close() {}
    @Override public String getId() { return ID; }
}
