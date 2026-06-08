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
        // The NARROWED baseline/default config action types: realm settings/config,
        // realm default groups, realm default scopes, default-role composite, and the
        // ADOPT_* family. (ADOPT auto-eligibility is further gated per-CR on the target
        // being a system/stock-default entity — see the ADOPT tests below.)
        assertTrue(IgaFirstAdminAutoCommit.isBaselineConfigActionType("SET_REALM_ATTRIBUTE"));
        assertTrue(IgaFirstAdminAutoCommit.isBaselineConfigActionType("REMOVE_REALM_ATTRIBUTE"));
        assertTrue(IgaFirstAdminAutoCommit.isBaselineConfigActionType("SET_REALM_CONFIG"));
        assertTrue(IgaFirstAdminAutoCommit.isBaselineConfigActionType("ADD_REALM_DEFAULT_GROUP"));
        assertTrue(IgaFirstAdminAutoCommit.isBaselineConfigActionType("REMOVE_REALM_DEFAULT_GROUP"));
        assertTrue(IgaFirstAdminAutoCommit.isBaselineConfigActionType("REALM_DEFAULT_SCOPE_ADD"));
        assertTrue(IgaFirstAdminAutoCommit.isBaselineConfigActionType("REALM_DEFAULT_SCOPE_REMOVE"));
        assertTrue(IgaFirstAdminAutoCommit.isBaselineConfigActionType("ADD_COMPOSITE"));
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

    /**
     * The NARROWED scope (user correction 2026-06-08): only realm DEFAULTS auto-sign.
     * Action types that create admin-authored custom entities (clients, roles, scopes,
     * groups, mappers, scope assignments) are NO LONGER on the allow-list — they must
     * stay MANUAL even during firstAdmin.
     */
    @Test
    void manuallyAddedEntityActions_areExcluded() {
        assertFalse(IgaFirstAdminAutoCommit.isBaselineConfigActionType("CREATE_CLIENT"),
                "manually-added client → manual");
        assertFalse(IgaFirstAdminAutoCommit.isBaselineConfigActionType("CREATE_ROLE"),
                "manually-added role → manual");
        assertFalse(IgaFirstAdminAutoCommit.isBaselineConfigActionType("CREATE_GROUP"),
                "manually-added group → manual");
        assertFalse(IgaFirstAdminAutoCommit.isBaselineConfigActionType("CREATE_CLIENT_SCOPE"),
                "manually-added client-scope → manual");
        assertFalse(IgaFirstAdminAutoCommit.isBaselineConfigActionType("ADD_PROTOCOL_MAPPER"),
                "manually-added protocol mapper → manual");
        assertFalse(IgaFirstAdminAutoCommit.isBaselineConfigActionType("ASSIGN_SCOPE"),
                "client scope assignment → manual");
        assertFalse(IgaFirstAdminAutoCommit.isBaselineConfigActionType("SCOPE_ADD_ROLE"),
                "scope→role → manual");
        assertFalse(IgaFirstAdminAutoCommit.isBaselineConfigActionType("SCOPE_MAPPING_ADD"),
                "scope-mapping → manual");
    }

    @Test
    void unknownAction_isTreatedAsGoverned() {
        assertFalse(IgaFirstAdminAutoCommit.isBaselineConfigActionType("SOME_FUTURE_ACTION"));
        assertFalse(IgaFirstAdminAutoCommit.isBaselineConfigActionType(null));
        assertFalse(IgaFirstAdminAutoCommit.isBaselineConfigActionType(""));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ADOPT_* — system/stock-default gate (ATTESTATION_ONLY marker)
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    void adopt_systemEntity_isAutoCommittable() {
        KeycloakSession session = mock(KeycloakSession.class);
        RealmModel realm = defaultRoleRealm();
        // The toggle-on scan marks a system/stock-default ADOPT CR with
        // ATTESTATION_ONLY=true in its ROWS_JSON (IgaSystemEntityFilter.shouldSkip).
        IgaChangeRequestEntity cr = adoptCr("ADOPT_CLIENT", true);
        assertTrue(IgaFirstAdminAutoCommit.isAutoCommittable(session, realm, cr),
                "an ADOPT CR targeting a system/stock-default entity is auto-committable");
    }

    @Test
    void adopt_manuallyAddedEntity_isNotAutoCommittable() {
        KeycloakSession session = mock(KeycloakSession.class);
        RealmModel realm = defaultRoleRealm();
        // An ADOPT CR for an admin-authored (non-system) entity carries NO
        // ATTESTATION_ONLY marker (it writes a quarantine sidecar instead) → manual.
        IgaChangeRequestEntity cr = adoptCr("ADOPT_CLIENT", false);
        assertFalse(IgaFirstAdminAutoCommit.isAutoCommittable(session, realm, cr),
                "an ADOPT CR targeting a manually-added (non-system) entity must NOT auto-commit");
    }

    @Test
    void adopt_edge_systemVsManual() {
        KeycloakSession session = mock(KeycloakSession.class);
        RealmModel realm = defaultRoleRealm();
        assertTrue(IgaFirstAdminAutoCommit.isAutoCommittable(session, realm,
                        adoptCr("ADOPT_PROTOCOL_MAPPER", true)),
                "system edge ADOPT (attestation-only) → auto");
        assertFalse(IgaFirstAdminAutoCommit.isAutoCommittable(session, realm,
                        adoptCr("ADOPT_PROTOCOL_MAPPER", false)),
                "manually-added edge ADOPT (no marker) → manual");
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
        pending.add(simpleCr("c1", "SET_REALM_ATTRIBUTE"));     // realm default → eligible
        pending.add(simpleCr("c2", "REALM_DEFAULT_SCOPE_ADD")); // realm default → eligible
        pending.add(simpleCr("c3", "CREATE_USER"));             // excluded
        pending.add(simpleCr("c4", "GRANT_ROLES"));             // excluded
        pending.add(simpleCr("c5", "CREATE_CLIENT_SCOPE"));     // excluded (manually-added)

        AtomicReference<List<String>> seenCrIds = new AtomicReference<>();
        IgaFirstAdminAutoCommit.BulkEngine engine = crIdIn -> {
            seenCrIds.set(crIdIn);
            // pretend the engine committed each requested CR id once.
            List<Map<String, Object>> out = new ArrayList<>();
            for (String id : crIdIn) {
                out.add(Map.of("crId", id, "status", "COMMITTED"));
            }
            return out;
        };

        try (MockedStatic<TideAttestor> ta = mockStatic(TideAttestor.class)) {
            ta.when(() -> TideAttestor.isFirstAdminMode(session, realm)).thenReturn(true);
            ta.when(() -> TideAttestor.isRealSigningCapableRealm(realm)).thenReturn(true);

            IgaFirstAdminAutoCommit.SweepResult result =
                    IgaFirstAdminAutoCommit.sweep(session, realm, admin, pending, engine);

            assertTrue(result.ran, "firstAdmin + VRK active → sweep runs");
            assertEquals(2, result.eligible, "only the 2 realm-default CRs are eligible");
            assertEquals(2, result.committed);
            // The sweep drives the engine by exact CR id, not action type.
            List<String> requested = seenCrIds.get();
            assertTrue(requested.contains("c1"));
            assertTrue(requested.contains("c2"));
            assertFalse(requested.contains("c3"), "CREATE_USER CR must not be swept");
            assertFalse(requested.contains("c4"), "GRANT_ROLES CR must not be swept");
            assertFalse(requested.contains("c5"), "manually-added CREATE_CLIENT_SCOPE CR must not be swept");
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
            // Engine is driven by CR id; the tainted composite's id ("composite-cr") must
            // never enter the bulk request.
            assertTrue(seen.get().contains("c1"));
            assertFalse(seen.get().contains("composite-cr"),
                    "the tainted default-role composite must never enter the auto-commit bulk request");
        }
    }

    @Test
    void sweep_manuallyAddedAndNonSystemAdopt_stayPending() {
        KeycloakSession session = mock(KeycloakSession.class);
        RealmModel realm = defaultRoleRealm();
        UserModel admin = mock(UserModel.class);

        List<IgaChangeRequestEntity> pending = new ArrayList<>();
        pending.add(simpleCr("c1", "SET_REALM_ATTRIBUTE"));            // realm default → AUTO
        pending.add(adoptCr("adopt-sys", "ADOPT_CLIENT", true));      // system entity → AUTO
        // The manually-added entities + non-system adopt — must NOT enter the bulk request.
        pending.add(simpleCr("c3", "CREATE_CLIENT"));                 // admin-authored client → manual
        pending.add(simpleCr("c4", "CREATE_ROLE"));                   // admin-authored role → manual
        pending.add(simpleCr("c5", "CREATE_CLIENT_SCOPE"));           // admin-authored scope → manual
        pending.add(simpleCr("c6", "CREATE_GROUP"));                  // admin-authored group → manual
        pending.add(simpleCr("c7", "ADD_PROTOCOL_MAPPER"));          // admin-authored mapper → manual
        pending.add(adoptCr("adopt-manual", "ADOPT_CLIENT", false));  // admin-authored adopt → manual

        AtomicReference<List<String>> seen = new AtomicReference<>();
        IgaFirstAdminAutoCommit.BulkEngine engine = crIdIn -> {
            seen.set(crIdIn);
            List<Map<String, Object>> out = new ArrayList<>();
            for (String id : crIdIn) out.add(Map.of("crId", id, "status", "COMMITTED"));
            return out;
        };

        try (MockedStatic<TideAttestor> ta = mockStatic(TideAttestor.class)) {
            ta.when(() -> TideAttestor.isFirstAdminMode(session, realm)).thenReturn(true);
            ta.when(() -> TideAttestor.isRealSigningCapableRealm(realm)).thenReturn(true);

            IgaFirstAdminAutoCommit.SweepResult result =
                    IgaFirstAdminAutoCommit.sweep(session, realm, admin, pending, engine);

            assertTrue(result.ran);
            assertEquals(2, result.eligible,
                    "only the realm-attribute CR + the SYSTEM ADOPT CR are eligible");
            List<String> requested = seen.get();
            assertTrue(requested.contains("c1"));
            assertTrue(requested.contains("adopt-sys"),
                    "the SYSTEM adopt CR IS swept (its target is a stock-default entity)");
            // The non-system adopt + every manually-added entity CR must never be requested.
            assertFalse(requested.contains("adopt-manual"),
                    "the non-system (admin-authored) ADOPT CR must stay manual");
            assertFalse(requested.contains("c3"));
            assertFalse(requested.contains("c4"));
            assertFalse(requested.contains("c5"));
            assertFalse(requested.contains("c6"));
            assertFalse(requested.contains("c7"));
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

    /**
     * An ADOPT CR whose ROWS_JSON carries (or omits) the {@code ATTESTATION_ONLY}
     * marker — the per-CR flag the toggle-on scan writes when (and only when) the
     * target entity is a system/stock-default per {@code IgaSystemEntityFilter}.
     */
    private static IgaChangeRequestEntity adoptCr(String actionType, boolean attestationOnly) {
        return adoptCr("adopt-cr-" + actionType + "-" + attestationOnly, actionType, attestationOnly);
    }

    private static IgaChangeRequestEntity adoptCr(String id, String actionType, boolean attestationOnly) {
        IgaChangeRequestEntity cr = mock(IgaChangeRequestEntity.class);
        lenient().when(cr.getId()).thenReturn(id);
        lenient().when(cr.getActionType()).thenReturn(actionType);
        lenient().when(cr.getRowsJson()).thenReturn(
                attestationOnly
                        ? "[{\"ID\":\"e1\",\"ATTESTATION_ONLY\":true}]"
                        : "[{\"ID\":\"e1\"}]");
        return cr;
    }
}
