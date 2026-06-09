package org.tidecloak.iga.providers;

import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

/**
 * Keycloak SPI registration for the Ragnarok realm-offboard service, so it can be
 * resolved via {@code session.getProvider(RagnarokOffboardService.class)} from the
 * iga-core commit-replay path.
 *
 * <p>iga-core registers ONLY this {@link Spi} (in
 * {@code META-INF/services/org.keycloak.provider.Spi}) — it ships NO factory for
 * {@link RagnarokOffboardServiceFactory}. The implementing module (ragnarok)
 * provides the factory and its
 * {@code META-INF/services/org.tidecloak.iga.providers.RagnarokOffboardServiceFactory}
 * registration. Until ragnarok is deployed,
 * {@code session.getProvider(RagnarokOffboardService.class)} returns {@code null}
 * (no registered factory) — which the replay dispatcher treats as fail-closed.
 */
public class RagnarokOffboardServiceSpi implements Spi {

    public static final String SPI_NAME = "ragnarok-offboard-service";

    @Override
    public boolean isInternal() {
        return false;
    }

    @Override
    public String getName() {
        return SPI_NAME;
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return RagnarokOffboardService.class;
    }

    @Override
    @SuppressWarnings("rawtypes")
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return RagnarokOffboardServiceFactory.class;
    }
}
