package org.tidecloak.iga.providers;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Factory for {@link DefaultIgaSystemProvisionerProvider}. Registered with id
 * {@code "default"} (the only implementation), so
 * {@code session.getProvider(IgaSystemProvisionerProvider.class)} resolves it
 * without a named id.
 */
public class DefaultIgaSystemProvisionerProviderFactory
        implements IgaSystemProvisionerProviderFactory {

    public static final String ID = "default";

    @Override
    public IgaSystemProvisionerProvider create(KeycloakSession session) {
        return new DefaultIgaSystemProvisionerProvider(session);
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

    @Override
    public int order() {
        return 0;
    }
}
