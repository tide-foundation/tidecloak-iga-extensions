package org.tidecloak.iga.signing;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the IGA idp-settings re-sign hook scope predicate + dispatch.
 *
 * <p>The hook must fire ONLY for a {@code SET_REALM_CONFIG} CR whose rows include
 * {@code setRegistrationAllowed} (the only setter that feeds the enclave-verified
 * {@code VendorSettings.RegOn}), and must be fail-closed (a thrown signer
 * exception propagates so the caller's commit tx rolls back).
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class IgaIdpSettingsResignTest {

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock IdpSettingsSigner signer;

    private static IgaChangeRequestEntity cr(String actionType, String rowsJson) {
        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setId("cr-1");
        cr.setRealmId("realm-1");
        cr.setActionType(actionType);
        cr.setRowsJson(rowsJson);
        return cr;
    }

    // ---- scope predicate ------------------------------------------------

    @Test
    void predicateTrueForRegistrationAllowedRow() {
        IgaChangeRequestEntity c = cr("SET_REALM_CONFIG",
                "[{\"key\":\"setRegistrationAllowed\",\"value\":\"true\"}]");
        assertTrue(IgaIdpSettingsResign.changesSignedSetting(c));
    }

    @Test
    void predicateTrueWhenRegistrationAllowedAmongOtherRows() {
        IgaChangeRequestEntity c = cr("SET_REALM_CONFIG",
                "[{\"key\":\"setVerifyEmail\",\"value\":\"true\"},"
                        + "{\"key\":\"setRegistrationAllowed\",\"value\":\"false\"}]");
        assertTrue(IgaIdpSettingsResign.changesSignedSetting(c));
    }

    @Test
    void predicateFalseForVerifyEmailOnlyConfig() {
        IgaChangeRequestEntity c = cr("SET_REALM_CONFIG",
                "[{\"key\":\"setVerifyEmail\",\"value\":\"true\"}]");
        assertFalse(IgaIdpSettingsResign.changesSignedSetting(c));
    }

    @Test
    void predicateFalseForRemoveRealmAttribute() {
        IgaChangeRequestEntity c = cr("REMOVE_REALM_ATTRIBUTE",
                "[{\"key\":\"setRegistrationAllowed\",\"value\":\"true\"}]");
        // Even if a row literally said setRegistrationAllowed, a non-SET_REALM_CONFIG
        // action never feeds the realm-config replay -> must not trigger.
        assertFalse(IgaIdpSettingsResign.changesSignedSetting(c));
    }

    @Test
    void predicateFalseForGrantRoles() {
        IgaChangeRequestEntity c = cr("GRANT_ROLES",
                "[{\"USER_ID\":\"u1\",\"ROLE_ID\":\"r1\"}]");
        assertFalse(IgaIdpSettingsResign.changesSignedSetting(c));
    }

    @Test
    void predicateFalseForNullOrEmptyRows() {
        assertFalse(IgaIdpSettingsResign.changesSignedSetting(cr("SET_REALM_CONFIG", null)));
        assertFalse(IgaIdpSettingsResign.changesSignedSetting(cr("SET_REALM_CONFIG", "")));
        assertFalse(IgaIdpSettingsResign.changesSignedSetting(cr("SET_REALM_CONFIG", "[]")));
    }

    // ---- dispatch -------------------------------------------------------

    @Test
    void invokesSignerWithUpdatedRealmWhenSignedFieldChanged() {
        IgaChangeRequestEntity c = cr("SET_REALM_CONFIG",
                "[{\"key\":\"setRegistrationAllowed\",\"value\":\"true\"}]");
        when(session.getProvider(IdpSettingsSigner.class)).thenReturn(signer);

        IgaIdpSettingsResign.maybeReSign(session, realm, c);

        verify(signer, times(1)).reSignIdpSettings(session, realm);
    }

    @Test
    void doesNotInvokeSignerWhenNoSignedFieldChanged() {
        IgaChangeRequestEntity c = cr("SET_REALM_CONFIG",
                "[{\"key\":\"setVerifyEmail\",\"value\":\"true\"}]");

        IgaIdpSettingsResign.maybeReSign(session, realm, c);

        // Predicate short-circuits BEFORE the provider is even resolved.
        verify(session, never()).getProvider(IdpSettingsSigner.class);
        verify(signer, never()).reSignIdpSettings(session, realm);
    }

    @Test
    void noOpWhenNoSignerRegistered() {
        IgaChangeRequestEntity c = cr("SET_REALM_CONFIG",
                "[{\"key\":\"setRegistrationAllowed\",\"value\":\"true\"}]");
        when(session.getProvider(IdpSettingsSigner.class)).thenReturn(null);

        // A plain Tideless realm: predicate matches, but no signer -> clean no-op (no throw).
        IgaIdpSettingsResign.maybeReSign(session, realm, c);
    }

    @Test
    void failClosedPropagatesSignerException() {
        IgaChangeRequestEntity c = cr("SET_REALM_CONFIG",
                "[{\"key\":\"setRegistrationAllowed\",\"value\":\"true\"}]");
        when(session.getProvider(IdpSettingsSigner.class)).thenReturn(signer);
        IdpSettingsSignException boom =
                new IdpSettingsSignException("no active VRK");
        org.mockito.Mockito.doThrow(boom).when(signer).reSignIdpSettings(session, realm);

        // Fail-closed: the exception must propagate so the commit tx rolls back.
        IdpSettingsSignException thrown = assertThrows(IdpSettingsSignException.class,
                () -> IgaIdpSettingsResign.maybeReSign(session, realm, c));
        org.junit.jupiter.api.Assertions.assertSame(boom, thrown);
    }

    // ---- client-settings scope predicate --------------------------------

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {
            "SET_CLIENT_ATTRIBUTE", "REMOVE_CLIENT_ATTRIBUTE", "UPDATE_CLIENT_PROPERTY",
            "UPDATE_CLIENT_WEB_ORIGINS", "UPDATE_CLIENT_REDIRECT_URIS", "ADD_PROTOCOL_MAPPER",
            "UPDATE_PROTOCOL_MAPPER", "REMOVE_PROTOCOL_MAPPER", "SCOPE_MAPPING_ADD",
            "SCOPE_MAPPING_REMOVE"})
    void clientPredicateTrueForEveryCapturedClientActionType(String actionType) {
        // Rows are irrelevant to the client predicate (it is action-type only); the
        // re-sign rebuilds the client-origin list wholesale from realm state.
        assertTrue(IgaIdpSettingsResign.changesClientSignedSetting(cr(actionType, "[]")));
    }

    @Test
    void clientPredicateFalseForNonClientActions() {
        // RegOn realm-config is handled by the separate maybeReSign path, not the
        // client re-sign; CREATE_CLIENT is intentionally NOT in the captured set.
        assertFalse(IgaIdpSettingsResign.changesClientSignedSetting(
                cr("SET_REALM_CONFIG", "[{\"key\":\"setRegistrationAllowed\",\"value\":\"true\"}]")));
        assertFalse(IgaIdpSettingsResign.changesClientSignedSetting(cr("CREATE_CLIENT", "[]")));
        assertFalse(IgaIdpSettingsResign.changesClientSignedSetting(cr("GRANT_ROLES", "[]")));
        assertFalse(IgaIdpSettingsResign.changesClientSignedSetting(null));
    }

    // ---- client-settings dispatch ---------------------------------------

    @Test
    void reSignForClientSettingsInvokesSignerWhenRegistered() {
        when(session.getProvider(IdpSettingsSigner.class)).thenReturn(signer);

        IgaIdpSettingsResign.reSignForClientSettings(session, realm);

        verify(signer, times(1)).reSignIdpSettings(session, realm);
    }

    @Test
    void reSignForClientSettingsNoOpWhenNoSignerRegistered() {
        when(session.getProvider(IdpSettingsSigner.class)).thenReturn(null);

        // Plain Tideless realm: nothing signed to keep valid -> clean no-op (no throw).
        IgaIdpSettingsResign.reSignForClientSettings(session, realm);

        verify(signer, never()).reSignIdpSettings(session, realm);
    }

    @Test
    void reSignForClientSettingsFailClosedPropagatesSignerException() {
        when(session.getProvider(IdpSettingsSigner.class)).thenReturn(signer);
        IdpSettingsSignException boom = new IdpSettingsSignException("ORKs unreachable");
        org.mockito.Mockito.doThrow(boom).when(signer).reSignIdpSettings(session, realm);

        // Fail-closed: the exception must propagate so the commit tx rolls back rather
        // than leaving stale client-origin signatures.
        IdpSettingsSignException thrown = assertThrows(IdpSettingsSignException.class,
                () -> IgaIdpSettingsResign.reSignForClientSettings(session, realm));
        org.junit.jupiter.api.Assertions.assertSame(boom, thrown);
    }
}
