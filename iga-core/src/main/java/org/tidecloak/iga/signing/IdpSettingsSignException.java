package org.tidecloak.iga.signing;

/**
 * Thrown by {@link IdpSettingsSigner#reSignIdpSettings} when the IdP-settings
 * re-sign cannot complete (no active VRK, missing {@code tide-vendor-key}
 * component / Tide IDP, or the ORK signing round-trip failed).
 *
 * <p>The IGA commit seam catches this and FAILS the commit (fail-closed), so a
 * realm-config change that would invalidate the enclave's signed settings is
 * never applied with a stale {@code settingsSig}.
 */
public class IdpSettingsSignException extends RuntimeException {

    public IdpSettingsSignException(String message) {
        super(message);
    }

    public IdpSettingsSignException(String message, Throwable cause) {
        super(message, cause);
    }
}
