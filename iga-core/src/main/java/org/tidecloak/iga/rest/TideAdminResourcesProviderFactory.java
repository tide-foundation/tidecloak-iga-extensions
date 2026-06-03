package org.tidecloak.iga.rest;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory;

/**
 * Registers the {@code tideAdminResources} admin-REST provider.
 *
 * <p>The factory id <em>is</em> the URL segment: with id {@code tideAdminResources}
 * Keycloak mounts the provider at {@code /admin/realms/{realm}/tideAdminResources/*},
 * which is exactly what the admin-client {@code tideProvider} calls. This restores
 * those routes from inside the deployed {@code iga-core} jar after the old
 * {@code tidecloak-iga-provider} module (which carried the original
 * {@code TideAdminRealmResourceProvider}, gated behind the {@code tide-iga} Maven
 * profile) stopped being built/deployed.
 */
public class TideAdminResourcesProviderFactory implements AdminRealmResourceProviderFactory {

    public static final String ID = "tideAdminResources";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public AdminRealmResourceProvider create(KeycloakSession session) {
        return new TideAdminResourcesProvider(session);
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
