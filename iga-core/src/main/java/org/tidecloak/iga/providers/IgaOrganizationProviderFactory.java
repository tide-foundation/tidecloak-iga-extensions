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
 * <h2>Priority pitfall</h2>
 * Unlike Realm/User/Client/Group/Role caching — done by SEPARATE
 * {@code *CacheProviderFactory} provider types — KC's organization caching
 * lives on the same {@code OrganizationProviderFactory} SPI via
 * {@code InfinispanOrganizationProviderFactory.order() == 10}.
 * An {@code order() == 2} therefore lost to the Infinispan cache
 * factory and the IGA wrapper was never instantiated. Bumping to {@code 20}
 * wins.
 *
 * <h2>Wrap the cache, don't replace it</h2>
 * Extending {@code JpaOrganizationProvider}
 * directly while winning {@code order()==20} also bypassed the Infinispan cache
 * layer entirely. Cache invalidations registered by KC's own
 * {@code InfinispanOrganizationProviderFactory.postInit} listeners
 * ({@code IdentityProviderUpdatedEvent}/{@code IdentityProviderRemovedEvent}/
 * {@code UserPreRemovedEvent}) had no reader and stale reads could leak after
 * IGA-mediated mutations — the per-org explicit eviction loop in
 * {@code TideAdminCompatResource.evictRealmCache} was the workaround. Instead
 * {@link IgaOrganizationProvider}
 * {@code extends InfinispanOrganizationProvider}, so the layering is now
 * IGA (top) → Infinispan cache (middle, via {@code super} calls) → JPA (bottom,
 * resolved by Infinispan's {@code getDelegate()} via
 * {@code session.getProvider(OrganizationProvider.class, "jpa")}). The factory
 * code does not change — it's still {@code order()==20}, still delegates
 * lifecycle to a {@code JpaOrganizationProviderFactory}. The Infinispan factory
 * is still in the SPI registry and its {@code postInit} listeners still fire
 * (see {@code DefaultKeycloakSessionFactory#initializeProviders}); its
 * listeners resolve {@code session.getProvider(OrganizationProvider.class,
 * "infinispan")} which sees a fresh {@link
 * org.keycloak.models.cache.infinispan.organization.InfinispanOrganizationProvider}
 * sharing the same {@code RealmCacheSession} as our subclass instance — so the
 * invalidations land on the same cache pane we read through.
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
        // Beat InfinispanOrganizationProviderFactory (order==10).
        // Unlike Realm/User/Client/Group/Role caching — which lives under
        // separate *CacheProviderFactory provider types so order==2 above the
        // stock JPA factory is enough — organization caching sits ON the same
        // OrganizationProviderFactory SPI at order==10. Anything <=10 loses
        // to the Infinispan cache factory and the IGA wrapper is never
        // instantiated.
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
