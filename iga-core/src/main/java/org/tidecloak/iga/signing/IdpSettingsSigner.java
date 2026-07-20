package org.tidecloak.iga.signing;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.Provider;

/**
 * Cross-module bridge that lets the IGA commit seam re-run the Tide
 * {@code signIdpSettings} ceremony AFTER a realm-config change-request commit
 * has altered a field that feeds the enclave-verified {@code VendorSettings}
 * (today: {@code registrationAllowed} -> {@code RegOn}).
 *
 * <h2>Why an SPI (and not a direct call / reflection)</h2>
 * The actual signing logic lives in {@code VendorResource.SignIdpSettings} in the
 * {@code tidecloak-key-provider} module ({@code tidecloak-idp-extensions}). That
 * module already depends on {@code iga-core} (compile-time), so iga-core CANNOT
 * depend back on it without a cycle. A Keycloak SPI inverts the dependency
 * cleanly: the INTERFACE lives here in iga-core (on everyone's classpath), the
 * IMPLEMENTATION lives in {@code tidecloak-key-provider} (which can see both this
 * interface and {@code VendorResource}), and the commit seam resolves it at
 * runtime via {@code session.getProvider(IdpSettingsSigner.class)}.
 *
 * <p>On a realm WITHOUT the Tide key stack (a plain Tideless realm), no provider
 * is registered, so {@code session.getProvider(IdpSettingsSigner.class)} returns
 * {@code null} and the hook is a clean no-op — matching the fact that such realms
 * have no signed settings to keep valid.
 *
 * <h2>Fail-closed contract</h2>
 * {@link #reSignIdpSettings} MUST throw (not swallow) when the re-sign cannot
 * complete (e.g. no active VRK / ORKs unreachable). The IGA commit seam runs this
 * inside the commit JPA transaction so a thrown exception rolls back the whole
 * commit, leaving the realm-config change UNapplied rather than applied with a
 * stale {@code settingsSig}. The realm-config commit already requires the ORKs
 * for its own Policy sign, so this adds no new dependency.
 */
public interface IdpSettingsSigner extends Provider {

    /**
     * Re-run the IdP-settings signing ceremony from the realm's CURRENT
     * (post-commit) state so the stored {@code settingsSig} matches the new
     * {@code VendorSettings} the enclave verifies.
     *
     * <p>Implementations resolve the {@code tide-vendor-key} component + the Tide
     * IDP + the active VRK/gVRK from the realm themselves (identical to the
     * {@code POST .../tide-vendor-key/sign-idp-settings} REST endpoint), so the
     * caller need only supply the session + realm.
     *
     * <p><b>Fail-closed:</b> throws {@link IdpSettingsSignException} when the
     * re-sign cannot complete (no active VRK, no component/IDP, ORKs unreachable).
     * The caller treats a thrown exception as a hard commit failure.
     *
     * @param session the commit session
     * @param realm   the realm whose IdP settings must be re-signed
     * @throws IdpSettingsSignException if the re-sign cannot complete (fail-closed)
     */
    void reSignIdpSettings(KeycloakSession session, RealmModel realm) throws IdpSettingsSignException;

    @Override
    default void close() {
    }
}
