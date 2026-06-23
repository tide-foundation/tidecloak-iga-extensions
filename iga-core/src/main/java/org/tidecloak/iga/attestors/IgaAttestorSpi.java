package org.tidecloak.iga.attestors;

import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

/**
 * Keycloak SPI registration for pluggable IGA attestors.
 */
public class IgaAttestorSpi implements Spi {

    @Override
    public boolean isInternal() {
        return false;
    }

    @Override
    public String getName() {
        return "iga-attestor";
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return IgaAttestor.class;
    }

    @Override
    @SuppressWarnings("rawtypes")
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return IgaAttestorFactory.class;
    }
}
