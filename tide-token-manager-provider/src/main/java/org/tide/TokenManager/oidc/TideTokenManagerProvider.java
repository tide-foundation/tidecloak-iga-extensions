package org.tide.TokenManager.oidc;

import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.spi.TokenManagerProvider;

/**
 * SPI provider that supplies our custom TokenManager.
 */
public class TideTokenManagerProvider implements TokenManagerProvider {

    private final TideTokenManager tokenManager;

    public TideTokenManagerProvider(KeycloakSession session) {
        this.tokenManager = new TideTokenManager();  // see class below
    }

    @Override
    public TokenManager get() {
        return tokenManager;
    }
}
