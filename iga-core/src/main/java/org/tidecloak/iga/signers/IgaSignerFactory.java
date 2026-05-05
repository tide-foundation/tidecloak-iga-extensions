package org.tidecloak.iga.signers;

import org.keycloak.provider.ProviderFactory;

/**
 * Factory for {@link IgaSigner} implementations.
 */
public interface IgaSignerFactory extends ProviderFactory<IgaSigner> {
}
