package org.tide.TokenManager.oidc;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.spi.TokenManagerProvider;
import org.keycloak.protocol.oidc.spi.TokenManagerProviderFactory;

public class TideTokenManagerProviderFactory implements TokenManagerProviderFactory {

    private static final Logger log = Logger.getLogger(TideTokenManagerProviderFactory.class);

    @Override
    public TokenManagerProvider create(KeycloakSession session) {
        return new TideTokenManagerProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
        log.info("TideTokenManagerProviderFactory INIT");
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) { }

    @Override
    public void close() { }

    @Override
    public String getId() {
        return "tide-oidc-token-manager";
    }
}
