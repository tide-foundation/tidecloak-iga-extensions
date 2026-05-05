package org.tidecloak.iga.signers;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * Helper for resolving the configured {@link IgaSigner} for a realm.
 */
public final class IgaSigners {

    private IgaSigners() {
    }

    /**
     * Resolve the signer configured for the realm via realm attribute "iga.signer",
     * falling back to the default {@code "simple"} signer if the configured one is
     * missing or unset.
     *
     * @throws IllegalStateException if no IGA signer is registered at all
     */
    public static IgaSigner resolveSigner(KeycloakSession session, RealmModel realm) {
        String id = realm.getAttribute("iga.signer");
        if (id == null || id.isBlank()) {
            id = SimpleNameSigner.ID;
        }
        IgaSigner signer = session.getProvider(IgaSigner.class, id);
        if (signer == null) {
            // fallback to default if configured one is missing
            signer = session.getProvider(IgaSigner.class, SimpleNameSigner.ID);
        }
        if (signer == null) {
            throw new IllegalStateException("No IGA signer registered (id=" + id + ")");
        }
        return signer;
    }
}
