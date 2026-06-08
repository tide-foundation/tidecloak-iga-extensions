package org.tidecloak.iga.services;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.tidecloak.iga.attestors.TideAttestor;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;

/**
 * firstAdmin baseline-config auto-commit sweep ({@link IgaFirstAdminAutoCommit}).
 *
 * <p>Covers: the allow-list classifier, the ADD_COMPOSITE default-role + MF2 gate,
 * and the two sweep gates (firstAdmin + VRK-active), plus the full sweep wiring over
 * an injected bulk engine.</p>
 */
class IgaFirstAdminAutoCommitTest {

    private static final String REALM = "myrealm";
    private static final String DEFAULT_ROLE_ID = "default-role-uuid";

    // ─────────────────────────────────────────────────────────────────────────
    // Pure allow-list classifier
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    void baselineConfigActions_areAllowListed() {
        // A representative sample of the baseline/default config action types.
        assertTrue(IgaFirstAdminAutoCommit.isBaselineConfigActionType("SET_REALM_ATTRIBUTE"));
        assertTrue(IgaFirstAdminAutoCommit.isBaselineConfigActionType("REMOVE_REALM_ATTRIBUTE"));
        assertTrue(IgaFirstAdminAutoCommit.isBaselineConfigActionType("REALM_DEFAULT_SCOPE_ADD"));
        assertTrue(IgaFirstAdminAutoCommit.isBaselineConfigActionType("CREATE_CLIENT_SCOPE"));
        assertTrue(IgaFirstAdminAutoCommit.isBaselineConfigActionType("CREATE_CLIENT"));
        assertTrue(IgaFirstAdminAutoCommit.isBaselineConfigActionType("CREATE_ROLE"));
        assertTrue(IgaFirstAdminAutoCommit.isBaselineConfigActionType("ADD_PROTOCOL_MAPPER"));
        assertTrue(IgaFirstAdminAutoCommit.isBaselineConfigActionType("SCOPE_ADD_ROLE"));
        assertTrue(IgaFirstAdminAutoCommit.isBaselineConfigActionType("ADD_REALM_DEFAULT_GROUP"));
        assertTrue(IgaFirstAdminAutoCommit.isBaselineConfigActionType("ADOPT_ROLE"));
        assertTrue(IgaFirstAdminAutoCommit.isBaselineConfigActionType("ADOPT_CLIENT_SCOPE_CLIENT"));
    }

    @Test
    void privilegedActions_areExcluded() {
        // user / grant / group-membership / org-membership — governed, stay PENDING.
        assertFalse(IgaFirstAdminAutoCommit.isBaselineConfigActionType("CREATE_USER"));
        assertFalse(IgaFirstAdminAutoCommit.isBaselineConfigActionType("GRANT_ROLES"));
        assertFalse(IgaFirstAdminAutoCommit.isBaselineConfigActionType("REVOKE_ROLES"));
        assertFalse(IgaFirstAdminAutoCommit.isBaselineConfigActionType("JOIN_GROUPS"));
        assertFalse(IgaFirstAdminAutoCommit.isBaselineConfigActionType("LEAVE_GROUPS"));
        assertFalse(IgaFirstAdminAutoCommit.isBaselineConfigActionType("ADD_ORG_MEMBER"));
    }

    @Test
    void unknownAction_isTreatedAsGoverned() {
        assertFalse(IgaFirstAdminAutoCommit.isBaselineConfigActionType("SOME_FUTURE_ACTION"));
        assertFalse(IgaFirstAdminAutoCommit.isBaselineConfigActionType(null));
        assertFalse(IgaFirstAdminAutoCommit.isBaselineConfigActionType(""));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ADD_COMPOSITE — default-role parent + MF2 gate
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    void addComposite_onDefaultRole_benign_isAutoCommittable() {
        KeycloakSession session = mock(KeycloakSession.class);
        RealmModel realm = defaultRoleRealm();
        IgaChangeRequestEntity cr = compositeCr(DEFAULT_ROLE_ID, "child-role-uuid");

        try (MockedStatic<DefaultRoleCompositeGuard> guard = mockStatic(DefaultRoleCompositeGuard.class)) {
            guard.when(() -> DefaultRoleCompositeGuard.isBenignDefaultRoleComposite(realm)).thenReturn(true);
            assertTrue(IgaFirstAdminAutoCommit.isAutoCommittable(session, realm, cr),
                    "a benign default-role composite is baseline config → auto-committable");
        }
    }

    @Test
    void addComposite_onDefaultRole_tainted_failsClosed_staysPending() {
        KeycloakSession session = mock(KeycloakSession.class);
        RealmModel realm = defaultRoleRealm();
        // a composite introducing realm-management / tide-realm-admin → MF2 fails closed.
        IgaChangeRequestEntity cr = compositeCr(DEFAULT_ROLE_ID, "tide-realm-admin-uuid");

        try (MockedStatic<DefaultRoleCompositeGuard> guard = mockStatic(DefaultRoleCompositeGuard.class)) {
            guard.when(() -> DefaultRoleCompositeGuard.isBenignDefaultRoleComposite(realm)).thenReturn(false);
            assertFalse(IgaFirstAdminAutoCommit.isAutoCommittable(session, realm, cr),
                    "a tainted default-role composite (realm-management/tide-realm-admin) must NOT be "
                            + "auto-committed even on the firstAdmin auto-path — MF2 fail-closed");
        }
    }

    @Test
    void addComposite_onNonDefaultRole_isNotBaselineConfig() {
        KeycloakSession session = mock(KeycloakSession.class);
        RealmModel realm = defaultRoleRealm();
        // parent is some OTHER role, not default-roles-<realm> → not baseline config.
        IgaChangeRequestEntity cr = compositeCr("some-other-parent-role-uuid", "child-uuid");

        // No need to mock the guard: the parent check short-circuits first.
        assertFalse(IgaFirstAdminAutoCommit.isAutoCommittable(session, realm, cr),
                "an ADD_COMPOSITE whose parent is not the realm default-role is not baseline config");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Sweep gates
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    void sweep_firstAdmin_vrkActive_committsBaselineConfig() {
        KeycloakSession session = mock(KeycloakSession.class);
        RealmModel realm = defaultRoleRealm();
        UserModel admin = mock(UserModel.class);

        List<IgaChangeRequestEntity> pending = new ArrayList<>();
        pending.add(simpleCr("c1", "SET_REALM_ATTRIBUTE"));
        pending.add(simpleCr("c2", "CREATE_CLIENT_SCOPE"));
        pending.add(simpleCr("c3", "CREATE_USER"));        // excluded
        pending.add(simpleCr("c4", "GRANT_ROLES"));        // excluded

        AtomicReference<List<String>> seenActionTypes = new AtomicReference<>();
        IgaFirstAdminAutoCommit.BulkEngine engine = actionTypeIn -> {
            seenActionTypes.set(actionTypeIn);
            // pretend the engine committed each requested action type once.
            List<Map<String, Object>> out = new ArrayList<>();
            for (String at : actionTypeIn) {
                out.add(Map.of("crId", at, "status", "COMMITTED"));
            }
            return out;
        };

        try (MockedStatic<TideAttestor> ta = mockStatic(TideAttestor.class)) {
            ta.when(() -> TideAttestor.isFirstAdminMode(session, realm)).thenReturn(true);
            ta.when(() -> TideAttestor.isRealSigningCapableRealm(realm)).thenReturn(true);

            IgaFirstAdminAutoCommit.SweepResult result =
                    IgaFirstAdminAutoCommit.sweep(session, realm, admin, pending, engine);

            assertTrue(result.ran, "firstAdmin + VRK active → sweep runs");
            assertEquals(2, result.eligible, "only the 2 baseline-config CRs are eligible");
            assertEquals(2, result.committed);
            // CREATE_USER / GRANT_ROLES must NOT appear in the bulk request.
            List<String> requested = seenActionTypes.get();
            assertTrue(requested.contains("SET_REALM_ATTRIBUTE"));
            assertTrue(requested.contains("CREATE_CLIENT_SCOPE"));
            assertFalse(requested.contains("CREATE_USER"));
            assertFalse(requested.contains("GRANT_ROLES"));
        }
    }

    @Test
    void sweep_multiAdmin_isNoOp() {
        KeycloakSession session = mock(KeycloakSession.class);
        RealmModel realm = defaultRoleRealm();
        UserModel admin = mock(UserModel.class);
        List<IgaChangeRequestEntity> pending = List.of(simpleCr("c1", "SET_REALM_ATTRIBUTE"));

        boolean[] engineCalled = {false};
        IgaFirstAdminAutoCommit.BulkEngine engine = at -> { engineCalled[0] = true; return List.of(); };

        try (MockedStatic<TideAttestor> ta = mockStatic(TideAttestor.class)) {
            ta.when(() -> TideAttestor.isFirstAdminMode(session, realm)).thenReturn(false); // multiAdmin
            // VRK-active is irrelevant once firstAdmin gate fails.

            IgaFirstAdminAutoCommit.SweepResult result =
                    IgaFirstAdminAutoCommit.sweep(session, realm, admin, pending, engine);

            assertFalse(result.ran, "multiAdmin → sweep is a no-op");
            assertEquals("NOT_FIRST_ADMIN", result.skipReason);
            assertFalse(engineCalled[0], "the bulk engine must not be invoked post-flip");
        }
    }

    @Test
    void sweep_vrkNotActive_isSkipped_noStubNoRollback() {
        KeycloakSession session = mock(KeycloakSession.class);
        RealmModel realm = defaultRoleRealm();
        UserModel admin = mock(UserModel.class);
        List<IgaChangeRequestEntity> pending = List.of(simpleCr("c1", "SET_REALM_ATTRIBUTE"));

        boolean[] engineCalled = {false};
        IgaFirstAdminAutoCommit.BulkEngine engine = at -> { engineCalled[0] = true; return List.of(); };

        try (MockedStatic<TideAttestor> ta = mockStatic(TideAttestor.class)) {
            ta.when(() -> TideAttestor.isFirstAdminMode(session, realm)).thenReturn(true);
            ta.when(() -> TideAttestor.isRealSigningCapableRealm(realm)).thenReturn(false); // VRK not active

            IgaFirstAdminAutoCommit.SweepResult result =
                    IgaFirstAdminAutoCommit.sweep(session, realm, admin, pending, engine);

            assertFalse(result.ran, "VRK not active → sweep skipped (CRs stay PENDING)");
            assertEquals("VRK_NOT_ACTIVE", result.skipReason);
            assertFalse(engineCalled[0], "no engine call → no stub stamps, no rollback mid-sweep");
        }
    }

    @Test
    void sweep_taintedDefaultRoleComposite_excludedFromBulkRequest() {
        KeycloakSession session = mock(KeycloakSession.class);
        RealmModel realm = defaultRoleRealm();
        UserModel admin = mock(UserModel.class);

        List<IgaChangeRequestEntity> pending = new ArrayList<>();
        pending.add(simpleCr("c1", "SET_REALM_ATTRIBUTE"));                 // baseline
        pending.add(compositeCr(DEFAULT_ROLE_ID, "tide-realm-admin-uuid")); // tainted default-role composite

        AtomicReference<List<String>> seen = new AtomicReference<>();
        IgaFirstAdminAutoCommit.BulkEngine engine = at -> {
            seen.set(at);
            List<Map<String, Object>> out = new ArrayList<>();
            for (String a : at) out.add(Map.of("crId", a, "status", "COMMITTED"));
            return out;
        };

        try (MockedStatic<TideAttestor> ta = mockStatic(TideAttestor.class);
             MockedStatic<DefaultRoleCompositeGuard> guard = mockStatic(DefaultRoleCompositeGuard.class)) {
            ta.when(() -> TideAttestor.isFirstAdminMode(session, realm)).thenReturn(true);
            ta.when(() -> TideAttestor.isRealSigningCapableRealm(realm)).thenReturn(true);
            guard.when(() -> DefaultRoleCompositeGuard.isBenignDefaultRoleComposite(realm)).thenReturn(false);

            IgaFirstAdminAutoCommit.SweepResult result =
                    IgaFirstAdminAutoCommit.sweep(session, realm, admin, pending, engine);

            assertTrue(result.ran);
            assertEquals(1, result.eligible, "only the realm-attribute CR is eligible; the tainted composite is held back");
            assertTrue(seen.get().contains("SET_REALM_ATTRIBUTE"));
            assertFalse(seen.get().contains("ADD_COMPOSITE"),
                    "the tainted default-role composite must never enter the auto-commit bulk request");
        }
    }

    @Test
    void sweep_noEligibleCrs_runsButCommitsNothing() {
        KeycloakSession session = mock(KeycloakSession.class);
        RealmModel realm = defaultRoleRealm();
        UserModel admin = mock(UserModel.class);
        // only governed actions pending.
        List<IgaChangeRequestEntity> pending = List.of(
                simpleCr("c1", "CREATE_USER"), simpleCr("c2", "GRANT_ROLES"));

        boolean[] engineCalled = {false};
        IgaFirstAdminAutoCommit.BulkEngine engine = at -> { engineCalled[0] = true; return List.of(); };

        try (MockedStatic<TideAttestor> ta = mockStatic(TideAttestor.class)) {
            ta.when(() -> TideAttestor.isFirstAdminMode(session, realm)).thenReturn(true);
            ta.when(() -> TideAttestor.isRealSigningCapableRealm(realm)).thenReturn(true);

            IgaFirstAdminAutoCommit.SweepResult result =
                    IgaFirstAdminAutoCommit.sweep(session, realm, admin, pending, engine);

            assertTrue(result.ran);
            assertEquals(0, result.eligible);
            assertFalse(engineCalled[0], "no eligible baseline CRs → engine not invoked");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // helpers
    // ─────────────────────────────────────────────────────────────────────────

    private static RealmModel defaultRoleRealm() {
        RealmModel realm = mock(RealmModel.class);
        lenient().when(realm.getName()).thenReturn(REALM);
        RoleModel defaultRole = mock(RoleModel.class);
        lenient().when(defaultRole.getId()).thenReturn(DEFAULT_ROLE_ID);
        lenient().when(realm.getDefaultRole()).thenReturn(defaultRole);
        return realm;
    }

    private static IgaChangeRequestEntity simpleCr(String id, String actionType) {
        IgaChangeRequestEntity cr = mock(IgaChangeRequestEntity.class);
        lenient().when(cr.getId()).thenReturn(id);
        lenient().when(cr.getActionType()).thenReturn(actionType);
        return cr;
    }

    private static IgaChangeRequestEntity compositeCr(String parentRoleId, String childRoleId) {
        IgaChangeRequestEntity cr = mock(IgaChangeRequestEntity.class);
        lenient().when(cr.getId()).thenReturn("composite-cr");
        lenient().when(cr.getActionType()).thenReturn("ADD_COMPOSITE");
        lenient().when(cr.getRowsJson()).thenReturn(
                "[{\"COMPOSITE\":\"" + parentRoleId + "\",\"CHILD_ROLE\":\"" + childRoleId + "\"}]");
        return cr;
    }
}
