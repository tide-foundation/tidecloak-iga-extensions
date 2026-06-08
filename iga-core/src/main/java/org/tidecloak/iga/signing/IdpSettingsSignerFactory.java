package org.tidecloak.iga.signing;

import org.keycloak.provider.ProviderFactory;

/**
 * Factory for {@link IdpSettingsSigner} implementations. The concrete
 * implementation lives in {@code tidecloak-key-provider} (which can see
 * {@code VendorResource}); iga-core only declares the SPI contract.
 */
public interface IdpSettingsSignerFactory extends ProviderFactory<IdpSettingsSigner> {
}
