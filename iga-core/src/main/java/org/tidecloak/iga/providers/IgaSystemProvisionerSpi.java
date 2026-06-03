package org.tidecloak.iga.providers;

import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

/**
 * Keycloak SPI registration for the tide-claims scope auto-provisioner, so it
 * can be resolved via {@code session.getProvider(IgaSystemProvisionerProvider.class)}
 * from outside the {@code iga-core} module (no Maven dependency required).
 */
public class IgaSystemProvisionerSpi implements Spi {

    public static final String SPI_NAME = "iga-system-provisioner";

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
        return IgaSystemProvisionerProvider.class;
    }

    @Override
    @SuppressWarnings("rawtypes")
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return IgaSystemProvisionerProviderFactory.class;
    }
}
