package org.tidecloak.iga.attestors;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * Helper for resolving the configured {@link IgaAttestor} for a realm.
 */
public final class IgaAttestors {

    private IgaAttestors() {
    }

    /**
     * Resolve the attestor configured for the realm via realm attribute "iga.attestor",
     * falling back to the default {@code "simple"} attestor if the configured one is
     * missing or unset.
     *
     * @throws IllegalStateException if no IGA attestor is registered at all
     */
    public static IgaAttestor resolveAttestor(KeycloakSession session, RealmModel realm) {
        String id = realm.getAttribute("iga.attestor");
        if (id == null || id.isBlank()) {
            id = SimpleNameAttestor.ID;
        }
        IgaAttestor attestor = session.getProvider(IgaAttestor.class, id);
        if (attestor == null) {
            // fallback to default if configured one is missing
            attestor = session.getProvider(IgaAttestor.class, SimpleNameAttestor.ID);
        }
        if (attestor == null) {
            throw new IllegalStateException("No IGA attestor registered (id=" + id + ")");
        }
        return attestor;
    }
}
