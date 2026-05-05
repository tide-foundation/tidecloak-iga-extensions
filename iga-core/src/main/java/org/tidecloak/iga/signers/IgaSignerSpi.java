package org.tidecloak.iga.signers;

import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

/**
 * Keycloak SPI registration for pluggable IGA signers.
 */
public class IgaSignerSpi implements Spi {

    @Override
    public boolean isInternal() {
        return false;
    }

    @Override
    public String getName() {
        return "iga-signer";
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return IgaSigner.class;
    }

    @Override
    @SuppressWarnings("rawtypes")
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return IgaSignerFactory.class;
    }
}
