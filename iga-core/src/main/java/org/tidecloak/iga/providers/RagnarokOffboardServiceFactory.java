package org.tidecloak.iga.providers;

import org.keycloak.provider.ProviderFactory;

/**
 * Factory for {@link RagnarokOffboardService} implementations.
 *
 * <p><b>iga-core ships NO implementation of this factory</b> — ragnarok provides
 * the concrete factory and registers it in
 * {@code META-INF/services/org.tidecloak.iga.providers.RagnarokOffboardServiceFactory}.
 * iga-core only declares the type so the {@link RagnarokOffboardServiceSpi}
 * registration compiles and so {@code session.getProvider(RagnarokOffboardService.class)}
 * resolves (or returns {@code null} when ragnarok is absent).
 */
public interface RagnarokOffboardServiceFactory
        extends ProviderFactory<RagnarokOffboardService> {
}
