package org.tidecloak.iga.attestors;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Factory for the DUMMY set-signing {@link TideAttestor} (id {@code tide}).
 * Selected when the realm attribute {@code iga.attestor=tide}.
 */
public class TideAttestorFactory implements IgaAttestorFactory {

    @Override
    public IgaAttestor create(KeycloakSession session) {
        return new TideAttestor(session);
    }

    @Override
    public String getId() {
        return TideAttestor.ID;
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
