package org.tidecloak.iga.signing;

import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

/**
 * Keycloak SPI registration for the cross-module IdP-settings re-sign bridge.
 * The interface lives in iga-core; the implementation is contributed by
 * {@code tidecloak-key-provider}.
 */
public class IdpSettingsSignerSpi implements Spi {

    @Override
    public boolean isInternal() {
        return false;
    }

    @Override
    public String getName() {
        return "iga-idp-settings-signer";
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return IdpSettingsSigner.class;
    }

    @Override
    @SuppressWarnings("rawtypes")
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return IdpSettingsSignerFactory.class;
    }
}
