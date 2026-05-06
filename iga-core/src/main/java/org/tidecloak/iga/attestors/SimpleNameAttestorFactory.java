package org.tidecloak.iga.attestors;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Factory for the default {@link SimpleNameAttestor}.
 */
public class SimpleNameAttestorFactory implements IgaAttestorFactory {

    @Override
    public IgaAttestor create(KeycloakSession session) {
        return new SimpleNameAttestor(session);
    }

    @Override
    public String getId() {
        return SimpleNameAttestor.ID;
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
