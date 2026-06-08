package org.tidecloak.iga.signing;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;

import java.util.List;
import java.util.Map;

/**
 * Post-commit hook: re-run the Tide {@code signIdpSettings} ceremony when a
 * committed change request altered a realm-config field that feeds the
 * enclave-verified {@code VendorSettings}.
 *
 * <h2>Why this exists</h2>
 * The Heimdall enclave verifies a VVK signature ({@code settingsSig}) over
 * {@code VendorSettings = {RegOn, BackupOn, LogoURL, ImageURL}}, where
 * {@code RegOn = realm.isRegistrationAllowed()}
 * ({@code VendorResource.java:1077}). {@code signIdpSettings} runs only at
 * provisioning and VRK rotation. The IGA realm-config commit path
 * ({@code IgaReplayDispatcher.replaySetRealmConfig} ->
 * {@code realm.setRegistrationAllowed}) applies the change but never re-signs, so
 * toggling user registration flips {@code RegOn} and the stored
 * {@code settingsSig} goes stale — the enclave then throws "Signed Settings were
 * not able to be verified". This hook closes that gap by re-signing from the
 * now-updated realm state at commit time.
 *
 * <h2>Scope (narrow)</h2>
 * Fires ONLY for a {@code SET_REALM_CONFIG} CR whose rows include the
 * {@code setRegistrationAllowed} setter — the only {@code SET_REALM_CONFIG} setter
 * that maps to a signed {@code VendorSettings} field. {@code BackupOn} / {@code LogoURL}
 * / {@code ImageURL} are set through IDP / component endpoints that already re-sign,
 * so they never arrive as a {@code SET_REALM_CONFIG} CR. Any other realm-config CR
 * (e.g. {@code setVerifyEmail}) and non-config CRs do NOT trigger a re-sign, avoiding
 * needless ORK round-trips.
 *
 * <h2>Both commit lanes</h2>
 * This is invoked from the COMMON commit tail — the single-CR {@code commit(...)}
 * endpoint AND the bulk {@code processOneCr} loop (where {@code convergeAfterCommit}
 * also runs). The multiAdmin two-phase ceremony records approvals via
 * {@code approval-model} but still drives the final replay through the SAME
 * {@code commit(...)} endpoint, so neither lane bypasses this hook.
 *
 * <h2>Fail-closed</h2>
 * If a signer is registered (a Tide-provisioned realm) but the re-sign throws
 * (no active VRK / ORKs unreachable), the exception propagates so the commit JPA
 * transaction rolls back — the realm-config change is NOT applied with a stale
 * {@code settingsSig}. On a realm with no signer registered (plain Tideless), the
 * hook is a clean no-op (nothing to keep valid).
 */
public final class IgaIdpSettingsResign {

    private static final Logger log = Logger.getLogger(IgaIdpSettingsResign.class);

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<List<Map<String, Object>>> LIST_MAP_REF =
            new TypeReference<List<Map<String, Object>>>() {};

    /** Action type of a realm-config change request. */
    static final String ACTION_SET_REALM_CONFIG = "SET_REALM_CONFIG";

    /**
     * The only {@code SET_REALM_CONFIG} row {@code key} whose value feeds the
     * enclave-verified {@code VendorSettings.RegOn}
     * ({@code IgaReplayDispatcher.applyRealmConfig} case
     * {@code "setRegistrationAllowed" -> realm.setRegistrationAllowed(...)}).
     */
    static final String SIGNED_SETTING_KEY = "setRegistrationAllowed";

    private IgaIdpSettingsResign() {
    }

    /**
     * If {@code cr} changed a signed {@code VendorSettings} field, re-sign the
     * realm's IdP settings from current state. No-op otherwise.
     *
     * <p>Call this from the commit seam AFTER the realm-config replay has applied
     * (so {@code realm.isRegistrationAllowed()} already reflects the new value).
     *
     * @throws IdpSettingsSignException (fail-closed) when a signer is present but
     *         the re-sign cannot complete.
     */
    public static void maybeReSign(KeycloakSession session, RealmModel realm, IgaChangeRequestEntity cr) {
        if (!changesSignedSetting(cr)) {
            return;
        }

        IdpSettingsSigner signer = session.getProvider(IdpSettingsSigner.class);
        if (signer == null) {
            // No Tide key stack on this realm -> no signed settings to keep valid.
            // (A plain Tideless realm. The provider is contributed by
            // tidecloak-key-provider and only present where the crypto stack runs.)
            log.debugf("IGA idp-settings re-sign: CR %s changed %s but no IdpSettingsSigner "
                            + "is registered for realm %s — nothing to re-sign (no Tide key stack).",
                    cr.getId(), SIGNED_SETTING_KEY, realm.getName());
            return;
        }

        log.infof("IGA idp-settings re-sign: CR %s changed %s on realm %s — re-running "
                        + "signIdpSettings so the enclave's signed settings (RegOn=%s) stay valid.",
                cr.getId(), SIGNED_SETTING_KEY, realm.getName(), realm.isRegistrationAllowed());

        // Fail-closed: a thrown IdpSettingsSignException propagates out of the commit
        // seam, rolling back the commit tx rather than leaving a stale settingsSig.
        signer.reSignIdpSettings(session, realm);
    }

    /**
     * True iff {@code cr} is a {@code SET_REALM_CONFIG} change request whose rows
     * include the {@code setRegistrationAllowed} setter. Pure predicate — the
     * unit-testable scope gate.
     */
    static boolean changesSignedSetting(IgaChangeRequestEntity cr) {
        if (cr == null || !ACTION_SET_REALM_CONFIG.equals(cr.getActionType())) {
            return false;
        }
        List<Map<String, Object>> rows = parseRows(cr.getRowsJson());
        for (Map<String, Object> row : rows) {
            Object key = row.get("key");
            if (SIGNED_SETTING_KEY.equals(key)) {
                return true;
            }
        }
        return false;
    }

    private static List<Map<String, Object>> parseRows(String rowsJson) {
        if (rowsJson == null || rowsJson.isBlank()) {
            return List.of();
        }
        try {
            List<Map<String, Object>> rows = MAPPER.readValue(rowsJson, LIST_MAP_REF);
            return rows == null ? List.of() : rows;
        } catch (Exception e) {
            // A malformed payload cannot be proven to change a signed field; do not
            // re-sign on a parse failure (the replay itself would have failed first).
            log.warnf(e, "IGA idp-settings re-sign: could not parse ROWS_JSON for scope check — "
                    + "treating as no signed-field change.");
            return List.of();
        }
    }
}
