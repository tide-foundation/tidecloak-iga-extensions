package org.tidecloak.iga.providers;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ★ GOVERN SELF-REGISTRATION — the registration user-create terminal predicate.
 *
 * <p>Confirmed bug: self-registration's {@code RegistrationUserCreation.success}
 * (:155 {@code profile.create()}) creates the user via the 1-arg
 * {@code IgaUserProvider.addUser} capture seam, but the CREATE_USER CR was emitted
 * ONLY at {@code IgaUserAdapter.getId()} whose stack-walk predicate matched ONLY
 * {@code UsersResource#createUser}. Registration goes through the form action, never
 * that resource → no CR → the self-reg user committed UNGOVERNED
 * ({@code user_entity.attestation NULL}) → login fail-closes forever.</p>
 *
 * <p>Fix: a SECOND terminal seam recognizes the registration boundary —
 * {@code RegistrationUserCreation.success} calls {@code user.setEnabled(true)} DIRECTLY
 * at services :159 AFTER {@code profile.create()} returns the fully-built model, so a
 * capture-mode {@code setEnabled} whose IMMEDIATE caller is exactly
 * {@code org.keycloak.authentication.forms.RegistrationUserCreation#success} is the
 * deterministic, registration-SPECIFIC terminal. It fires the SAME persist-pending
 * CREATE_USER path as admin-create.</p>
 *
 * <p>These tests pin the pure classifier {@link IgaUserAdapter#classifyImmediateCaller}
 * (the live {@link StackWalker} cannot be mocked, so the skip/match decision is factored
 * into a frame-list-driven pure method). They prove the registration boundary is matched,
 * the admin boundary is unchanged, and replay/import/other internal creates are NOT
 * mis-classified as either terminal.</p>
 */
class IgaUserAdapterRegistrationTerminalTest {

    private static final String ADAPTER = "org.tidecloak.iga.providers.IgaUserAdapter";
    private static final String USER_ADAPTER = "org.keycloak.models.jpa.UserAdapter";
    private static final String ADMIN_RESOURCE =
            "org.keycloak.services.resources.admin.UsersResource";
    private static final String REGISTRATION =
            "org.keycloak.authentication.forms.RegistrationUserCreation";

    private static final String ADMIN_SENTINEL = "<UsersResource#createUser>";
    private static final String REGISTRATION_SENTINEL =
            "<RegistrationUserCreation#success>";

    // ── REGISTRATION boundary ────────────────────────────────────────────────

    @Test
    void registrationSuccess_isClassifiedAsRegistrationTerminal() {
        // Live registration setEnabled(:159) stack (innermost first): the predicate
        // runs inside IgaUserAdapter helpers; the genuine immediate caller of
        // setEnabled is RegistrationUserCreation#success (services :159).
        List<String> frames = List.of(
                ADAPTER + "#classifyImmediateCaller",
                ADAPTER + "#computeImmediateCaller",
                ADAPTER + "#calledDirectlyFromRegistrationSuccess",
                ADAPTER + "#setEnabled",
                REGISTRATION + "#success",            // ← the registration terminal
                "org.keycloak.authentication.DefaultAuthenticationFlow#processAction");

        assertEquals(REGISTRATION_SENTINEL,
                IgaUserAdapter.classifyImmediateCaller(frames),
                "setEnabled with immediate caller RegistrationUserCreation#success "
                        + "must classify as the REGISTRATION terminal");
    }

    @Test
    void registrationSuccess_isNotMisclassifiedAsAdmin() {
        List<String> frames = List.of(
                ADAPTER + "#setEnabled",
                REGISTRATION + "#success");
        // The registration sentinel is a DISTINCT identity from the admin sentinel.
        assertEquals(REGISTRATION_SENTINEL,
                IgaUserAdapter.classifyImmediateCaller(frames));
    }

    // ── ADMIN boundary (must be unchanged) ───────────────────────────────────

    @Test
    void adminCreateUser_isStillClassifiedAsAdminTerminal() {
        // Runtime-proven admin getId#7/#8: immediate caller UsersResource#createUser.
        List<String> frames = List.of(
                ADAPTER + "#classifyImmediateCaller",
                ADAPTER + "#computeImmediateCaller",
                ADAPTER + "#getId",
                ADMIN_RESOURCE + "#createUser");      // ← the admin terminal

        assertEquals(ADMIN_SENTINEL,
                IgaUserAdapter.classifyImmediateCaller(frames),
                "admin getId with immediate caller UsersResource#createUser must "
                        + "still classify as the ADMIN terminal (unchanged)");
    }

    // ── MID-BUILD / OTHER paths (must be NEITHER terminal) ───────────────────

    @Test
    void midBuildGetId_userCacheSession_isNeitherTerminal() {
        // Runtime-proven admin getId#1-#3: immediate caller UserCacheSession#addUser
        // (inside DefaultUserProfile#create) — must NOT emit.
        List<String> frames = List.of(
                ADAPTER + "#getId",
                "org.keycloak.models.cache.infinispan.UserCacheSession#addUser",
                "org.keycloak.userprofile.DefaultUserProfile#create");

        String kind = IgaUserAdapter.classifyImmediateCaller(frames);
        assertEquals("org.keycloak.models.cache.infinispan.UserCacheSession#addUser", kind,
                "a mid-build getId must resolve to its real (non-terminal) caller");
    }

    @Test
    void replayDispatcher_isNeitherTerminal() {
        // Replay sets IGA_REPLAY_ACTIVE; in practice captureMode is false so this
        // classifier is not even consulted. Belt+braces: even if a frame did appear,
        // the replay/import creators are NOT either terminal class.
        List<String> frames = List.of(
                ADAPTER + "#setEnabled",
                "org.keycloak.services.managers.RealmManager#createUser",
                "org.tidecloak.iga.replay.IgaReplayDispatcher#replayCreateUser");

        String kind = IgaUserAdapter.classifyImmediateCaller(frames);
        assertEquals("org.keycloak.services.managers.RealmManager#createUser", kind,
                "a replay create must NOT be classified as the registration or admin "
                        + "terminal");
    }

    @Test
    void partialImport_isNeitherTerminal() {
        List<String> frames = List.of(
                ADAPTER + "#setEnabled",
                "org.keycloak.exportimport.util.DefaultExportImportManager#createUser",
                "org.keycloak.services.resources.admin.PartialImportResource#partialImport");

        String kind = IgaUserAdapter.classifyImmediateCaller(frames);
        assertEquals("org.keycloak.exportimport.util.DefaultExportImportManager#createUser",
                kind,
                "a partialImport create must NOT be classified as either terminal");
    }

    // ── Skip-rule integrity (the predicate must skip its own + self-delegation) ─

    @Test
    void skipsOwnAndUserAdapterSelfDelegationFrames_beforeMatching() {
        // IgaUserAdapter frames + UserAdapter.{equals,hashCode,getId} self-delegations
        // must be skipped so the FIRST surviving frame is the genuine caller.
        List<String> frames = List.of(
                ADAPTER + "#classifyImmediateCaller",
                ADAPTER + "#computeImmediateCaller",
                ADAPTER + "#getId",
                USER_ADAPTER + "#getId",          // self-delegation, skipped
                USER_ADAPTER + "#equals",         // self-delegation, skipped
                USER_ADAPTER + "#hashCode",       // self-delegation, skipped
                "java.lang.StackWalker#walk",     // JDK machinery, skipped
                REGISTRATION + "#success");        // ← first surviving real frame

        assertEquals(REGISTRATION_SENTINEL,
                IgaUserAdapter.classifyImmediateCaller(frames),
                "self/self-delegation/StackWalker frames must be skipped before the "
                        + "registration terminal is matched");
    }

    @Test
    void userAdapterSetEnabled_isNotSkipped() {
        // Only equals/hashCode/getId are UserAdapter self-delegations. A real
        // UserAdapter#setEnabled frame (were it ever the caller) must NOT be skipped
        // — proves the skip list is narrow and can't accidentally swallow a setter.
        List<String> frames = List.of(
                ADAPTER + "#classifyImmediateCaller",
                USER_ADAPTER + "#setEnabled");
        assertEquals(USER_ADAPTER + "#setEnabled",
                IgaUserAdapter.classifyImmediateCaller(frames));
    }

    @Test
    void allFramesSkipped_yieldsNoneSentinel() {
        List<String> frames = List.of(
                ADAPTER + "#classifyImmediateCaller",
                ADAPTER + "#getId");
        assertEquals("<none>", IgaUserAdapter.classifyImmediateCaller(frames));
    }

    // ── REGISTRATION default-role grant scoping ──────────────────────────────
    //
    // ★ accept-unattested self-reg aud fix. The persist-pending emit grants the
    // realm default-role ONLY at the REGISTRATION terminal (the CR never commits
    // for accept-unattested self-reg, so the D3 replay grant never runs → without
    // this the user is ROLELESS → no `account` aud → TVE rejects "attested claim
    // 'aud' is suppressed"). The ADMIN terminal must NOT grant here — its CR
    // commits and IgaReplayDispatcher.replayCreateUser D3 grants default-roles,
    // so granting at the admin boundary would double-grant. isRegistrationTerminal
    // is the pure scoping predicate driving that decision.

    @Test
    void registrationTerminalLabel_triggersDefaultRoleGrant() {
        assertTrue(
                IgaUserAdapter.isRegistrationTerminal(
                        IgaUserAdapter.REGISTRATION_TERMINAL_LABEL),
                "the registration terminal label must trigger the default-role grant "
                        + "(self-reg user holds default-roles → token carries the account aud)");
    }

    @Test
    void adminTerminalLabel_doesNotTriggerDefaultRoleGrant() {
        assertFalse(
                IgaUserAdapter.isRegistrationTerminal(
                        IgaUserAdapter.ADMIN_TERMINAL_LABEL),
                "the admin terminal label must NOT grant here — admin-create's CR commits "
                        + "and the D3 replay grant assigns default-roles; granting here would "
                        + "double-grant and is out of scope");
    }

    @Test
    void unknownTerminalLabel_doesNotTriggerDefaultRoleGrant() {
        assertFalse(IgaUserAdapter.isRegistrationTerminal("SomethingElse#frame"),
                "only the exact registration terminal label may trigger the grant");
        assertFalse(IgaUserAdapter.isRegistrationTerminal(null),
                "a null terminal label must not trigger the grant");
    }

    // ── ACCEPT-UNATTESTED (RegOn) admit-vs-CR decision at the registration terminal ─
    //
    // ★ The real current-jar bug (live-reproduced on newrealm03): with RegOn ON, the
    // registration terminal fired the persist-pending CREATE_USER emit, which throws
    // IgaPendingApprovalException out of RegistrationUserCreation.success → registration
    // FAILED with REGISTER_ERROR / HTTP 400 (the user could not complete sign-up), even
    // though the default-role grant itself had landed. Fix: when the realm is
    // registrationAllowed (the producer admits the unsigned user_identity at login), the
    // registration terminal ADMITS the user (persist + local default-role, NO CR, NO
    // throw) instead of filing a pending CR. admitSelfRegWithoutCr is the pure decision.

    @Test
    void regOn_admitsSelfRegWithoutCr() {
        assertTrue(IgaUserAdapter.admitSelfRegWithoutCr(true),
                "registrationAllowed (RegOn / accept-unattested) → the registration "
                        + "terminal must ADMIT (persist + local default-role, no CREATE_USER "
                        + "CR, no throw) so sign-up completes and login admits the unsigned "
                        + "user_identity");
    }

    @Test
    void regOff_retainsPersistPendingCrLane() {
        assertFalse(IgaUserAdapter.admitSelfRegWithoutCr(false),
                "registration NOT allowed → no reachable self-registration; the "
                        + "persist-pending CREATE_USER CR lane is retained as the defensive "
                        + "default for that unreachable case");
    }
}
