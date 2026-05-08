package org.tidecloak.iga.providers;

import org.keycloak.Config;
import org.keycloak.models.ClientScopeProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Registers IgaRealmProvider as the active ClientScopeProvider so that
 * {@code session.clientScopes().addClientScope(...)} routes through the IGA
 * interception layer (and creates a {@code CREATE_CLIENT_SCOPE} change request
 * when IGA is enabled).
 *
 * <p>JpaRealmProvider implements both RealmProvider and ClientScopeProvider
 * but Keycloak resolves them through separate factories. We mirror that
 * pattern so the IGA interceptor on {@code addClientScope} actually runs.
 */
public class IgaClientScopeProviderFactory implements ClientScopeProviderFactory<IgaRealmProvider> {

    public static final String ID = "iga-client-scope-provider";

    @Override
    public IgaRealmProvider create(KeycloakSession session) {
        return new IgaRealmProvider(session);
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public int order() {
        return 2;
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
