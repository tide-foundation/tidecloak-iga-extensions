package org.tidecloak.iga.providers;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ★ accept-unattested self-reg aud fix — the 1-arg {@code addUser} registration
 * default-role grant scoping.
 *
 * <p>Forensic bug: the {@code 24c74cd} {@code setEnabled}-based registration grant
 * never fires at runtime ({@code RegistrationUserCreation.success:159} calls
 * {@code setEnabled(true)} on the cache/storage-wrapped {@code UserModel} returned by
 * {@code profile.create()}, NOT the transient capture-mode {@code IgaUserAdapter}), so
 * the self-reg user is created ROLELESS → empty {@code resource_access} → no
 * {@code account} aud → the ORK TVE Stage-8 rejects "attested claim 'aud' is
 * suppressed in token".</p>
 *
 * <p>Working fix: grant default-roles RELIABLY at creation, in the registration
 * {@code IgaUserProvider.addUser(realm, username)} capture branch, by passing
 * {@code addDefaultRoles=true} to the 5-arg local-storage
 * {@code super.addUser(...)} — which grants {@code realm.getDefaultRole()} on the REAL
 * {@code JpaUser} (a plain {@code UserAdapter}, BEFORE the IGA capture wrap, so the
 * grant is NOT itself captured into a nested CR and it PERSISTS).</p>
 *
 * <p>SCOPE — the 1-arg overload is NOT registration-only. Live callers:
 * {@code DeclarativeUserProfileProvider} (registration + admin-create via
 * {@code profile.create()}), {@code ClientManager} (service-account),
 * {@code AbstractTokenExchangeProvider} (token-exchange),
 * {@code IdpCreateUserIfUniqueAuthenticator} (IdP broker), {@code ApplianceBootstrap}
 * (master — IGA-exempt). So the grant MUST be scoped to the self-registration flow
 * specifically: detect a {@code RegistrationUserCreation} frame anywhere in the live
 * stack. Admin-create ({@code UsersResource#createUser}) must NOT grant at creation —
 * its CR commits and {@code IgaReplayDispatcher.replayCreateUser} D3 grants
 * default-roles at replay; granting at creation too would double-grant.</p>
 *
 * <p>These tests pin the pure, frame-list-driven ★ F2 ALLOW-LIST classifier
 * {@link IgaUserProvider#isSelfEnrollmentFrame(java.util.List, boolean, boolean)}
 * (the live {@link StackWalker} cannot be mocked).</p>
 */
class IgaUserProviderRegistrationDefaultRolesTest {

    private static final String PROFILE_FACTORY =
            "org.keycloak.userprofile.DeclarativeUserProfileProvider$1";
    private static final String DEFAULT_PROFILE =
            "org.keycloak.userprofile.DefaultUserProfile";
    private static final String REGISTRATION =
            "org.keycloak.authentication.forms.RegistrationUserCreation";
    private static final String ADMIN_RESOURCE =
            "org.keycloak.services.resources.admin.UsersResource";

    // ═════════════════════════════════════════════════════════════════════════
    // ★ F2 ALLOW-LIST self-enrollment classifier (isSelfEnrollmentFrame).
    //
    // The former gate was a DENY-list (grant under RegOn for everything except
    // admin-create + service-account). That ALSO granted to token-exchange user
    // creation (AbstractTokenExchangeProvider) and EXTERNAL (non-Tide) IdP
    // first-login (IdpCreateUserIfUniqueAuthenticator) — non-self-reg paths that
    // then got admitted unsigned (the MF2 delivery vehicle). The allow-list grants
    // ONLY for the registration FORM or a POSITIVE Tide-broker enrollment.
    // ═════════════════════════════════════════════════════════════════════════

    private static final String IDP_CREATE_USER =
            "org.keycloak.authentication.authenticators.broker."
                    + "IdpCreateUserIfUniqueAuthenticator";
    private static final String TOKEN_EXCHANGE =
            "org.keycloak.protocol.oidc.tokenexchange.AbstractTokenExchangeProvider";
    private static final String CLIENT_MANAGER =
            "org.keycloak.services.managers.ClientManager";

    // ── RegOn OFF: never grant (open-registration posture is the gate) ───────

    @Test
    void regOnOff_registrationForm_doesNotGrant() {
        List<String> frames = List.of(
                PROFILE_FACTORY + "#apply",
                DEFAULT_PROFILE + "#create",
                REGISTRATION + "#success");
        assertFalse(IgaUserProvider.isSelfEnrollmentFrame(frames, false, false),
                "RegOn off → no default-role grant at creation even for the registration form");
    }

    @Test
    void regOnOff_tideBroker_doesNotGrant() {
        // Even a genuine Tide-broker enrollment must not grant when RegOn is off.
        assertFalse(IgaUserProvider.isSelfEnrollmentFrame(
                        List.of(IDP_CREATE_USER + "#authenticateImpl"), false, true),
                "RegOn off → no grant even for a Tide-broker enrollment");
    }

    // ── RegOn ON: ALLOW-LISTED self-enrollment grants ────────────────────────

    @Test
    void regOnOn_registrationForm_grants() {
        List<String> frames = List.of(
                PROFILE_FACTORY + "#apply",
                DEFAULT_PROFILE + "#create",
                REGISTRATION + "#success");
        assertTrue(IgaUserProvider.isSelfEnrollmentFrame(frames, true, false),
                "RegOn on + registration form → grant the realm default-role at creation");
    }

    @Test
    void regOnOn_tideBrokerEnrollment_grants() {
        // The genuine Tide-enrolled browser registration the user confirmed working
        // creates its user via the STOCK broker first-login authenticator brokered from
        // the Tide IdP. The frame is IdpCreateUserIfUniqueAuthenticator (shared with
        // external IdPs); the POSITIVE Tide-broker signal (IdP id = "tide") is what
        // distinguishes it and KEEPS it granting.
        List<String> frames = List.of(
                "org.keycloak.models.cache.infinispan.UserCacheSession#addUser",
                IDP_CREATE_USER + "#authenticateImpl");
        assertTrue(IgaUserProvider.isSelfEnrollmentFrame(frames, true, /*tideBroker=*/ true),
                "RegOn on + Tide-broker enrollment (IdP id = tide) → grant; this is the "
                        + "confirmed-working Tide self-registration flow and must NOT regress");
    }

    @Test
    void regOnOn_tideBrokerEnrollment_nullStack_grants() {
        // The Tide-broker signal is frame-independent (resolved from the auth-session
        // broker context), so it grants even when the stack is unavailable.
        assertTrue(IgaUserProvider.isSelfEnrollmentFrame(null, true, true),
                "RegOn on + Tide-broker enrollment → grant regardless of the stack");
    }

    // ── RegOn ON: NON-self-reg paths now EXCLUDED by the allow-list ──────────

    @Test
    void regOnOn_externalIdpFirstLogin_doesNotGrant() {
        // ★ F2 closed hole: external (non-Tide) IdP first-login reaches the 1-arg addUser
        // via the SAME IdpCreateUserIfUniqueAuthenticator frame, but with NO Tide-broker
        // context (tideBroker=false). The deny-list granted here (MF2 vehicle); the
        // allow-list must NOT.
        List<String> frames = List.of(
                "org.keycloak.models.cache.infinispan.UserCacheSession#addUser",
                IDP_CREATE_USER + "#authenticateImpl");
        assertFalse(IgaUserProvider.isSelfEnrollmentFrame(frames, true, /*tideBroker=*/ false),
                "RegOn on + EXTERNAL IdP first-login (no Tide broker context) must NOT grant "
                        + "default-roles — it was a non-self-reg admit-unsigned vehicle for MF2");
    }

    @Test
    void regOnOn_tokenExchange_doesNotGrant() {
        // ★ F2 closed hole: token-exchange user creation also reached the deny-list grant.
        List<String> frames = List.of(
                TOKEN_EXCHANGE + "#exchangeToIdentityToken");
        assertFalse(IgaUserProvider.isSelfEnrollmentFrame(frames, true, false),
                "RegOn on + token-exchange user creation must NOT grant default-roles "
                        + "(allow-list: not a recognised self-registration frame)");
    }

    @Test
    void regOnOn_adminCreate_excluded() {
        List<String> frames = List.of(
                PROFILE_FACTORY + "#apply",
                DEFAULT_PROFILE + "#create",
                ADMIN_RESOURCE + "#createUser");
        assertFalse(IgaUserProvider.isSelfEnrollmentFrame(frames, true, false),
                "admin-create (UsersResource#createUser) must NOT grant at creation even "
                        + "under RegOn — its CR commits and the D3 replay grant assigns roles");
    }

    @Test
    void regOnOn_serviceAccount_excluded() {
        List<String> frames = List.of(
                CLIENT_MANAGER + "#enableServiceAccount");
        assertFalse(IgaUserProvider.isSelfEnrollmentFrame(frames, true, false),
                "service-account user-create (ClientManager) must NOT get the realm "
                        + "default-role even under RegOn — internal, no account aud needed");
    }

    @Test
    void regOnOn_nullStack_noTideBroker_doesNotGrant() {
        // Allow-list: no recognised self-reg frame AND no Tide-broker signal → no grant
        // (a flip from the old deny-list null-stack default-to-grant).
        assertFalse(IgaUserProvider.isSelfEnrollmentFrame(null, true, false),
                "RegOn on + null stack + no Tide-broker signal → NO grant (allow-list)");
    }
}
