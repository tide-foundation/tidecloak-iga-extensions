package org.tidecloak.iga.providers;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.organization.OrganizationProvider;
import org.keycloak.organization.OrganizationProviderFactory;
import org.keycloak.organization.jpa.JpaOrganizationProviderFactory;

/**
 * Registers {@link IgaOrganizationProvider} as the active
 * {@link OrganizationProvider}, wrapping Keycloak 26.5.5's
 * {@link JpaOrganizationProviderFactory}. Mirrors {@link IgaRealmProviderFactory}:
 * a higher {@link #order()} than the stock factory's default (0) makes Keycloak
 * pick the IGA wrapper, while feature-gating ({@code isSupported}) and lifecycle
 * ({@code init}/{@code postInit} — the latter registers KC's organization
 * group-type provider-event listener) are delegated to a real
 * {@code JpaOrganizationProviderFactory} so organization behaviour outside the
 * IGA interception points is byte-for-byte stock Keycloak.
 */
public class IgaOrganizationProviderFactory implements OrganizationProviderFactory {

    public static final String ID = "iga-organization-provider";

    private final JpaOrganizationProviderFactory delegate = new JpaOrganizationProviderFactory();

    @Override
    public OrganizationProvider create(KeycloakSession session) {
        return new IgaOrganizationProvider(session);
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public int order() {
        // Beat the stock JpaOrganizationProviderFactory (default order 0), same
        // approach as IgaRealmProviderFactory / IgaClientProviderFactory.
        return 2;
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        // Honour Keycloak's ORGANIZATION feature gate exactly (delegated).
        return delegate.isSupported(config);
    }

    @Override
    public void init(Config.Scope config) {
        delegate.init(config);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Registers KC's organization group-type ProviderEventListener.
        delegate.postInit(factory);
    }

    @Override
    public void close() {
        delegate.close();
    }
}
