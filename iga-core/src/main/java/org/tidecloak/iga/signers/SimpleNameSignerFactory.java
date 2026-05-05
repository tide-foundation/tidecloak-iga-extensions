package org.tidecloak.iga.signers;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Factory for the default {@link SimpleNameSigner}.
 */
public class SimpleNameSignerFactory implements IgaSignerFactory {

    @Override
    public IgaSigner create(KeycloakSession session) {
        return new SimpleNameSigner(session);
    }

    @Override
    public String getId() {
        return SimpleNameSigner.ID;
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
    public int order() {
        return 0;
    }
}
