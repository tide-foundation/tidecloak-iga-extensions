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
 * ({@code VendorResource}). {@code signIdpSettings} runs only at
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
     * The client-settings CR action types whose commit can stale the VVK-signed
     * IdP-settings bundle. {@code SignIdpSettings} folds every realm client's web
     * origins into the signed draft (the {@code clientJsonUrls} segment) and emits a
     * per-origin {@code clientAuth:<clientId><origin>} signature, where a client's
     * origin set is derived from its web-origins, rootUrl/baseUrl/managementUrl and
     * redirect-URI origins ({@code VendorResource.getAllWebOriginsForClient}).
     * Committing any of these client CRs can therefore leave the stored
     * {@code clientAuth:*} signatures stale until the ceremony re-runs.
     *
     * <p>Kept in lockstep with the client-update capture in {@code IgaClientAdapter}
     * (iga-core 875888c6). NOTE: only {@code UPDATE_CLIENT_WEB_ORIGINS},
     * {@code UPDATE_CLIENT_REDIRECT_URIS} and (root/base/management-URL)
     * {@code UPDATE_CLIENT_PROPERTY} actually mutate a currently-signed field; the
     * attribute / protocol-mapper / scope-mapping types do not feed today's signed
     * draft. They are still included because the re-sign rebuilds the WHOLE bundle
     * from current realm state (idempotent), so triggering on the full client-CR
     * family is safe, matches the manual "re-sign settings" button admins run after
     * any client save, and stays correct if the signed draft is ever widened.
     *
     * <p>{@code CREATE_CLIENT} and {@code DELETE_CLIENT} are included because the
     * signed bundle's client-origin list is built from the set of live realm
     * clients: adding a client introduces a new {@code clientAuth:<clientId><origin>}
     * signature that must be minted, and removing one leaves the remaining bundle
     * needing a re-sign (the now-orphan {@code clientAuth:*} keys for the deleted
     * client are harmless and are not pruned). Their replay runs BEFORE the commit
     * tail's {@link #reSignForClientSettings}, so at re-sign time a created client
     * already exists and a deleted client is already gone, so the rebuild
     * reflects live state.
     */
    static final java.util.Set<String> CLIENT_SIGNED_ACTION_TYPES = java.util.Set.of(
            "CREATE_CLIENT",
            "DELETE_CLIENT",
            "SET_CLIENT_ATTRIBUTE",
            "REMOVE_CLIENT_ATTRIBUTE",
            "UPDATE_CLIENT_PROPERTY",
            "UPDATE_CLIENT_WEB_ORIGINS",
            "UPDATE_CLIENT_REDIRECT_URIS",
            "ADD_PROTOCOL_MAPPER",
            "UPDATE_PROTOCOL_MAPPER",
            "REMOVE_PROTOCOL_MAPPER",
            "SCOPE_MAPPING_ADD",
            "SCOPE_MAPPING_REMOVE");

    /**
     * True iff {@code cr} is one of the client-settings action types whose commit can
     * stale the signed IdP-settings bundle. Pure action-type predicate — no per-row
     * inspection is needed because the re-sign rebuilds the client-origin list
     * wholesale from current realm state. The commit seam uses this to decide whether
     * a committed batch needs a single coalesced re-sign.
     */
    public static boolean changesClientSignedSetting(IgaChangeRequestEntity cr) {
        return cr != null && CLIENT_SIGNED_ACTION_TYPES.contains(cr.getActionType());
    }

    /**
     * Unconditionally re-run the Tide {@code signIdpSettings} ceremony for
     * {@code realm} from current state. The caller has ALREADY decided a re-sign is
     * warranted (a client-settings CR committed in this batch — see
     * {@link #changesClientSignedSetting}). This is the once-per-batch coalesced
     * entry point, distinct from the per-CR RegOn {@link #maybeReSign} path: a client
     * save coalesces into up to ten per-action CRs, so the bulk commit lane calls
     * this EXACTLY ONCE after the batch drains rather than per CR (the single-CR
     * commit lane applies one CR, so it re-signs at most once there too).
     *
     * <p>No-op when no {@link IdpSettingsSigner} is registered (plain Tideless realm —
     * nothing signed to keep valid). Fail-closed when a signer IS present but the
     * re-sign throws: the exception propagates so the caller's commit tx rolls back
     * rather than leaving stale {@code clientAuth:*} signatures — the SAME contract as
     * {@link #maybeReSign} and {@code IgaToggleOnBackfill.convergeAfterCommit}.
     */
    public static void reSignForClientSettings(KeycloakSession session, RealmModel realm) {
        IdpSettingsSigner signer = session.getProvider(IdpSettingsSigner.class);
        if (signer == null) {
            log.debugf("IGA idp-settings re-sign: a client-settings CR committed on realm %s but no "
                            + "IdpSettingsSigner is registered — nothing to re-sign (no Tide key stack).",
                    realm.getName());
            return;
        }
        log.infof("IGA idp-settings re-sign: client-settings change committed on realm %s — re-running "
                        + "signIdpSettings once for the batch so the enclave-verified client-origin "
                        + "signatures stay valid.", realm.getName());
        // Fail-closed, exactly like maybeReSign: a thrown IdpSettingsSignException
        // propagates so the commit tx rolls back rather than committing with stale
        // client-origin signatures.
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
