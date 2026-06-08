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
 * <p>These tests pin the pure, frame-list-driven classifier
 * {@link IgaUserProvider#isSelfRegistrationFrame} (the live {@link StackWalker}
 * cannot be mocked).</p>
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

    // ── REGISTRATION: grant default-roles ────────────────────────────────────

    @Test
    void selfRegistrationStack_grantsDefaultRoles() {
        // Live registration addUser stack (innermost first):
        //   addUser ← DeclarativeUserProfileProvider$1.apply ← DefaultUserProfile.create
        //   ← RegistrationUserCreation.success (:155 profile.create()).
        List<String> frames = List.of(
                PROFILE_FACTORY + "#apply",
                DEFAULT_PROFILE + "#create",
                REGISTRATION + "#success",
                "org.keycloak.authentication.DefaultAuthenticationFlow#processAction");

        assertTrue(IgaUserProvider.isSelfRegistrationFrame(frames),
                "a RegistrationUserCreation frame in the stack must scope the "
                        + "default-role grant ON (self-reg user holds default-roles → "
                        + "token carries the account aud)");
    }

    @Test
    void registrationFrameAnywhere_grantsDefaultRoles() {
        // Defensive: the match is presence-anywhere, not immediate-caller — the
        // profile factory sits between addUser and RegistrationUserCreation.
        List<String> frames = List.of(
                "org.keycloak.models.jpa.JpaUserProvider#addUser",
                PROFILE_FACTORY + "#apply",
                DEFAULT_PROFILE + "#create",
                REGISTRATION + "#success");
        assertTrue(IgaUserProvider.isSelfRegistrationFrame(frames));
    }

    // ── ADMIN-create: must NOT grant at creation ─────────────────────────────

    @Test
    void adminCreateStack_doesNotGrantDefaultRoles() {
        // Admin-create goes through the SAME 1-arg addUser via profile.create(),
        // but its entry frame is UsersResource#createUser, NOT RegistrationUserCreation.
        // Its CR commits and the D3 replay grant assigns default-roles; granting at
        // creation here would double-grant.
        List<String> frames = List.of(
                PROFILE_FACTORY + "#apply",
                DEFAULT_PROFILE + "#create",
                ADMIN_RESOURCE + "#createUser");

        assertFalse(IgaUserProvider.isSelfRegistrationFrame(frames),
                "admin-create (UsersResource#createUser) must NOT grant default-roles "
                        + "at creation — its CR commits and D3 replay grants them");
    }

    // ── OTHER internal callers: must NOT grant ───────────────────────────────

    @Test
    void serviceAccountCreate_doesNotGrantDefaultRoles() {
        List<String> frames = List.of(
                "org.keycloak.services.managers.ClientManager#enableServiceAccount");
        assertFalse(IgaUserProvider.isSelfRegistrationFrame(frames),
                "service-account user-create must NOT be classified as self-registration");
    }

    @Test
    void idpBrokerCreate_doesNotGrantDefaultRoles() {
        List<String> frames = List.of(
                "org.keycloak.authentication.authenticators.broker."
                        + "IdpCreateUserIfUniqueAuthenticator#authenticateImpl");
        assertFalse(IgaUserProvider.isSelfRegistrationFrame(frames),
                "IdP-broker first-login user-create must NOT be classified as self-registration");
    }

    @Test
    void tokenExchangeCreate_doesNotGrantDefaultRoles() {
        List<String> frames = List.of(
                "org.keycloak.protocol.oidc.tokenexchange."
                        + "AbstractTokenExchangeProvider#exchangeToIdentityToken");
        assertFalse(IgaUserProvider.isSelfRegistrationFrame(frames),
                "token-exchange user-create must NOT be classified as self-registration");
    }

    @Test
    void emptyOrNullStack_doesNotGrant() {
        assertFalse(IgaUserProvider.isSelfRegistrationFrame(List.of()),
                "an empty stack must NOT scope the grant on");
        assertFalse(IgaUserProvider.isSelfRegistrationFrame(null),
                "a null stack must NOT scope the grant on");
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Round 2 — PATH-ROBUST self-enrollment classifier
    // (shouldGrantDefaultRolesOnSelfCreate): RegOn-gated, admin/service-account
    // excluded, covers the Tide-enrolled broker/link-tide import that has NO
    // RegistrationUserCreation frame (the Round-1 gap).
    // ═════════════════════════════════════════════════════════════════════════

    private static final String USER_CACHE_SESSION =
            "org.keycloak.models.cache.infinispan.UserCacheSession";
    private static final String BROKER_FIRST_LOGIN =
            "org.keycloak.authentication.authenticators.broker."
                    + "IdpCreateUserIfUniqueAuthenticator";
    private static final String LINK_TIDE_ACTION =
            "org.tidecloak.idp.LinkTideAccountAction";
    private static final String CLIENT_MANAGER =
            "org.keycloak.services.managers.ClientManager";

    // ── RegOn OFF: never grant (open-registration posture is the gate) ───────

    @Test
    void regOnOff_registrationForm_doesNotGrant() {
        List<String> frames = List.of(
                PROFILE_FACTORY + "#apply",
                DEFAULT_PROFILE + "#create",
                REGISTRATION + "#success");
        assertFalse(IgaUserProvider.shouldGrantDefaultRolesOnSelfCreate(frames, false),
                "RegOn off → no default-role grant at creation even for the registration form");
    }

    @Test
    void regOnOff_brokerImport_doesNotGrant() {
        List<String> frames = List.of(
                "org.keycloak.models.jpa.JpaUserProvider#addUser",
                USER_CACHE_SESSION + "#addUser",
                LINK_TIDE_ACTION + "#authenticate");
        assertFalse(IgaUserProvider.shouldGrantDefaultRolesOnSelfCreate(frames, false),
                "RegOn off → no grant for the Tide-enrolled broker/link-tide import either");
    }

    // ── RegOn ON: genuine self-enrollment grants (BOTH paths) ────────────────

    @Test
    void regOnOn_registrationForm_grants() {
        List<String> frames = List.of(
                PROFILE_FACTORY + "#apply",
                DEFAULT_PROFILE + "#create",
                REGISTRATION + "#success");
        assertTrue(IgaUserProvider.shouldGrantDefaultRolesOnSelfCreate(frames, true),
                "RegOn on + registration form → grant the realm default-role at creation");
    }

    @Test
    void regOnOn_tideEnrolledBrokerImport_grants() {
        // THE Round-1 GAP: the Tide-enrolled link-tide/broker import arrives as
        // UserCacheSession#addUser with NO RegistrationUserCreation frame. The
        // Round-1 StackWalker gate (isSelfRegistrationFrame) returned false here →
        // roleless user → ORK "attested claim 'aud' is suppressed". The path-robust
        // gate MUST grant.
        List<String> frames = List.of(
                "org.keycloak.models.jpa.JpaUserProvider#addUser",
                USER_CACHE_SESSION + "#addUser",
                LINK_TIDE_ACTION + "#authenticate",
                "org.keycloak.authentication.DefaultAuthenticationFlow#processAction");
        assertFalse(IgaUserProvider.isSelfRegistrationFrame(frames),
                "sanity: the Tide-enrolled import has NO RegistrationUserCreation frame "
                        + "(this is exactly why the Round-1 narrow gate missed it)");
        assertTrue(IgaUserProvider.shouldGrantDefaultRolesOnSelfCreate(frames, true),
                "RegOn on + Tide-enrolled broker/link-tide import → grant the realm "
                        + "default-role at creation (path-robust fix)");
    }

    @Test
    void regOnOn_genericBrokerFirstLogin_grants() {
        List<String> frames = List.of(
                USER_CACHE_SESSION + "#addUser",
                BROKER_FIRST_LOGIN + "#authenticateImpl");
        assertTrue(IgaUserProvider.shouldGrantDefaultRolesOnSelfCreate(frames, true),
                "RegOn on + generic IdP-broker first-login self-enrollment → grant");
    }

    // ── RegOn ON: admin-create and service-account still EXCLUDED ────────────

    @Test
    void regOnOn_adminCreate_excluded() {
        List<String> frames = List.of(
                PROFILE_FACTORY + "#apply",
                DEFAULT_PROFILE + "#create",
                ADMIN_RESOURCE + "#createUser");
        assertFalse(IgaUserProvider.shouldGrantDefaultRolesOnSelfCreate(frames, true),
                "admin-create (UsersResource#createUser) must NOT grant at creation even "
                        + "under RegOn — its CR commits and the D3 replay grant assigns roles");
    }

    @Test
    void regOnOn_serviceAccount_excluded() {
        List<String> frames = List.of(
                CLIENT_MANAGER + "#enableServiceAccount");
        assertFalse(IgaUserProvider.shouldGrantDefaultRolesOnSelfCreate(frames, true),
                "service-account user-create (ClientManager) must NOT get the realm "
                        + "default-role even under RegOn — internal, no account aud needed");
    }

    @Test
    void regOnOn_nullStack_grantsByDefault() {
        // RegOn but no stack to inspect (degenerate/test path) → grant; admin and
        // service-account always carry their excluding frame on a live stack.
        assertTrue(IgaUserProvider.shouldGrantDefaultRolesOnSelfCreate(null, true),
                "RegOn on + null stack → default to granting (self-enrollment is the "
                        + "dominant RegOn create path)");
    }
}
