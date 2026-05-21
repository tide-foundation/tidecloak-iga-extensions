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
 * a higher {@link #order()} than every other registered factory makes Keycloak
 * pick the IGA wrapper (see
 * {@code DefaultKeycloakSessionFactory#assignDefaultProvider}, which picks
 * {@code max(order())} above 0), while feature-gating ({@code isSupported}) and
 * lifecycle ({@code init}/{@code postInit} — the latter registers KC's
 * organization group-type provider-event listener) are delegated to a real
 * {@code JpaOrganizationProviderFactory} so organization behaviour outside the
 * IGA interception points is byte-for-byte stock Keycloak.
 *
 * <h2>Priority pitfall (the Phase 7a wire-up fix)</h2>
 * Unlike Realm/User/Client/Group/Role caching — done by SEPARATE
 * {@code *CacheProviderFactory} provider types — KC's organization caching
 * lives on the same {@code OrganizationProviderFactory} SPI via
 * {@code InfinispanOrganizationProviderFactory.order() == 10} (KC 26.5.5,
 * {@code model/infinispan/.../organization/InfinispanOrganizationProviderFactory.java:80-82}).
 * The original {@code order() == 2} therefore lost to the Infinispan cache
 * factory and the IGA wrapper was never instantiated. Bumping to {@code 20}
 * wins. Trade-off: this replaces (not wraps) the Infinispan cache layer for
 * organizations — same trade-off all other Iga* providers make. The
 * Infinispan factory's {@code postInit} (idp/user-removed event listeners) is
 * still registered because {@code postInit} runs on every factory regardless
 * of which one is selected as the default
 * ({@code DefaultKeycloakSessionFactory#initializeProviders}).
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
        // Beat InfinispanOrganizationProviderFactory (order==10, KC 26.5.5
        // model/infinispan/.../organization/InfinispanOrganizationProviderFactory.java:80-82).
        // Unlike Realm/User/Client/Group/Role caching — which lives under
        // separate *CacheProviderFactory provider types so order==2 above the
        // stock JPA factory is enough — organization caching sits ON the same
        // OrganizationProviderFactory SPI at order==10. Anything <=10 loses
        // to the Infinispan cache factory and the IGA wrapper is never
        // instantiated, which was the latent wire-up defect Phase 7a fixes.
        // 20 leaves headroom for future Tide-side organization wrappers.
        return 20;
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
