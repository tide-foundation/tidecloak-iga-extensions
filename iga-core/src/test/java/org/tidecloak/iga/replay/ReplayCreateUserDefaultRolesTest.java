package org.tidecloak.iga.replay;

import org.junit.jupiter.api.Test;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * ★ D3 — auto-assign the realm default-role + default groups at CREATE_USER COMMIT-replay so
 * the token the new user mints carries the default-role-derived claims.
 * {@code IgaReplayDispatcher.replayCreateUser} must, after the user is (re)established, call
 * {@code user.grantRole(realm.getDefaultRole())} and
 * {@code realm.getDefaultGroupsStream().forEach(user::joinGroup)} (mirroring stock KC
 * {@code JpaUserProvider.addUser}). It runs under {@code IGA_REPLAY_ACTIVE=true} (set by the
 * caller {@code replay()}), so the grant does NOT spawn a nested GRANT_ROLES/JOIN_GROUPS CR.
 *
 * <p>{@code replayCreateUser} is package-private-reachable only via reflection (private static);
 * this asserts the grant/join interactions on the live (post-rebuild) user mock.
 */
class ReplayCreateUserDefaultRolesTest {

    private static final String USER_ID = "d3-user-uuid";

    @Test
    void commitReplay_grantsDefaultRoleAndJoinsDefaultGroups() throws Exception {
        RealmModel realm = mock(RealmModel.class);
        KeycloakSession session = mock(KeycloakSession.class);
        UserProvider users = mock(UserProvider.class);
        when(session.users()).thenReturn(users);

        // The user already exists live (enroll-before-commit guard path → rebuildCreateUserFromRow
        // returns early without recreating); the D3 grant then runs over this live user.
        UserModel user = mock(UserModel.class);
        when(users.getUserById(eq(realm), eq(USER_ID))).thenReturn(user);

        RoleModel defaultRole = mock(RoleModel.class);
        when(realm.getDefaultRole()).thenReturn(defaultRole);
        GroupModel g1 = mock(GroupModel.class);
        GroupModel g2 = mock(GroupModel.class);
        when(realm.getDefaultGroupsStream()).thenReturn(Stream.of(g1, g2));

        // The UPDATE UserEntity attestation JPQL must not blow up.
        EntityManager em = mock(EntityManager.class);
        Query q = mock(Query.class);
        when(em.createQuery(anyString())).thenReturn(q);
        when(q.setParameter(anyString(), any())).thenReturn(q);
        when(q.executeUpdate()).thenReturn(1);

        Map<String, Object> row = new HashMap<>();
        row.put("ID", USER_ID);
        row.put("USERNAME", "d3user");
        List<Map<String, Object>> rows = new ArrayList<>();
        rows.add(row);

        Method m = IgaReplayDispatcher.class.getDeclaredMethod(
                "replayCreateUser", KeycloakSession.class, RealmModel.class,
                org.tidecloak.iga.entities.IgaChangeRequestEntity.class, List.class, String.class,
                EntityManager.class);
        m.setAccessible(true);

        assertDoesNotThrow(() -> {
            try {
                m.invoke(null, session, realm, null, rows, "SIG", em);
            } catch (java.lang.reflect.InvocationTargetException e) {
                if (e.getCause() instanceof RuntimeException re) throw re;
                throw new RuntimeException(e.getCause());
            }
        });

        // ★ D3: default-role granted + every default group joined on the live user.
        verify(user).grantRole(defaultRole);
        verify(user).joinGroup(g1);
        verify(user).joinGroup(g2);
    }
}
