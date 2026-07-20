package org.tidecloak.iga.replay;

import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * ★ ENROLL-BEFORE-COMMIT guard for {@link IgaReplayDispatcher#rebuildCreateUserFromRow}.
 *
 * <p>Confirmed bug: a post-flip CREATE_USER captures the user's pre-enrollment
 * representation (REP_JSON {@code attributes=null}). If the user is PERSISTED pre-commit
 * and ENROLLED via {@code LinkTideAccount} (adding {@code vuid}/{@code tideUserKey} under
 * {@code IGA_REPLAY_ACTIVE}, no re-sign) while the CREATE_USER CR is PENDING, the
 * phase-1 scratch-replay used to rebuild the user FROM the stale REP_JSON, dropping the
 * enrolled attributes. The quorum then signed {@code user_identity} over the PRE-enrollment
 * bytes, while the login emits {@code user_identity} over the user's CURRENT
 * (post-enrollment) attributes — a byte divergence that fails the batch Ed25519 verify.
 *
 * <p>The fix: when a LIVE persisted user with this id ALREADY exists (enroll-before-commit),
 * {@code rebuildCreateUserFromRow} must NOT recreate the user from the stale REP_JSON. It
 * returns early so the carrier enumerates {@code user_identity} over the live (post-enroll)
 * attributes — keeping phase-1 carrier bytes == commit live bytes == login emit bytes.
 *
 * <p>These tests assert the guard's TWO behaviours:
 * <ol>
 *   <li>live user present → no recreate ({@code RepresentationToModel.createUser} is NOT
 *       reached; {@code addUser} is NOT called) — the live (enrolled) attrs are preserved;</li>
 *   <li>live user absent (normal pre-enroll-then-commit / first-time create) → the existing
 *       REP_JSON rebuild path is unchanged (no regression).</li>
 * </ol>
 */
class RebuildCreateUserEnrollBeforeCommitTest {

    private static final String USER_ID = "ca42629c-b09b-46df-9858-d10c0488b77f";
    private static final String USERNAME = "test1";

    private static Map<String, Object> row(String repJson) {
        Map<String, Object> row = new HashMap<>();
        row.put("ID", USER_ID);
        row.put("USERNAME", USERNAME);
        if (repJson != null) {
            row.put("REP_JSON", repJson);
        }
        return row;
    }

    @Test
    void liveUserPresent_doesNotRecreateFromStaleRepJson() {
        RealmModel realm = mock(RealmModel.class);
        KeycloakSession session = mock(KeycloakSession.class);
        UserProvider users = mock(UserProvider.class);
        when(session.users()).thenReturn(users);

        // The pending CREATE_USER user was persisted pre-commit and ENROLLED: it exists
        // live with vuid/tideUserKey already on it.
        UserModel liveEnrolled = mock(UserModel.class);
        when(users.getUserById(eq(realm), eq(USER_ID))).thenReturn(liveEnrolled);

        // The captured REP_JSON is the STALE pre-enrollment snapshot (attributes=null) —
        // exactly the shape seen in the DB for a pending CREATE_USER CR.
        String staleRep = "{\"id\":\"" + USER_ID + "\",\"username\":\"" + USERNAME
                + "\",\"firstName\":\"test\",\"lastName\":\"aaa\",\"email\":\"test@tide.org\","
                + "\"emailVerified\":false,\"attributes\":null,\"enabled\":true}";

        assertDoesNotThrow(() ->
                IgaReplayDispatcher.rebuildCreateUserFromRow(session, realm, row(staleRep)));

        // ★ The guard fired: the stale REP_JSON was NOT used to recreate the user, so the
        // live (post-enrollment) attributes survive for the carrier/login to enumerate.
        // The bare-create safety net must also NOT be invoked.
        verify(users, never()).addUser(any(), anyString(), anyString(), anyBoolean(), anyBoolean());
        // getUserById was the guard check.
        verify(users).getUserById(eq(realm), eq(USER_ID));
    }

    @Test
    void liveUserAbsent_bareCreateRowUsesSafetyNet() {
        RealmModel realm = mock(RealmModel.class);
        KeycloakSession session = mock(KeycloakSession.class);
        UserProvider users = mock(UserProvider.class);
        when(session.users()).thenReturn(users);

        // No live user yet (normal first-time create / pre-enroll-then-commit order).
        when(users.getUserById(eq(realm), eq(USER_ID))).thenReturn(null);

        // A bare row (no REP_JSON) drives the safety-net addUser branch — proving the
        // guard did NOT short-circuit the normal create path when no live user exists.
        assertDoesNotThrow(() ->
                IgaReplayDispatcher.rebuildCreateUserFromRow(session, realm, row(null)));

        verify(users).addUser(eq(realm), eq(USER_ID), eq(USERNAME), eq(false), eq(false));
    }
}
