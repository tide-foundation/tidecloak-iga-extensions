package org.tidecloak.iga.services;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;

/**
 * ★ MF2 (HIGH) — the benign default-role composite guard. The whole
 * accept-unattested self-reg model trusts {@code default-roles-<realm>} confers
 * only benign baseline; this guard validates it by walking the composite
 * transitively and fail-closing on any privileged child.
 */
class DefaultRoleCompositeGuardTest {

    private static final String REALM = "myrealm";
    private static final String DEFAULT_ROLES = "default-roles-" + REALM;

    // ─────────────────────────────────────────────────────────────────────────
    // Pure leaf classifier
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    void leaf_defaultRolesRoot_isBenign() {
        assertTrue(DefaultRoleCompositeGuard.isBenignChild(false, DEFAULT_ROLES, null, DEFAULT_ROLES));
    }

    @Test
    void leaf_stockDefaultRealmRoles_areBenign() {
        assertTrue(DefaultRoleCompositeGuard.isBenignChild(false, "offline_access", null, DEFAULT_ROLES));
        assertTrue(DefaultRoleCompositeGuard.isBenignChild(false, "uma_authorization", null, DEFAULT_ROLES));
    }

    @Test
    void leaf_accountBaselineClientRoles_areBenign() {
        assertTrue(DefaultRoleCompositeGuard.isBenignChild(true, "view-profile", "account", DEFAULT_ROLES));
        assertTrue(DefaultRoleCompositeGuard.isBenignChild(true, "manage-account", "account", DEFAULT_ROLES));
        assertTrue(DefaultRoleCompositeGuard.isBenignChild(true, "view-groups", "account-console", DEFAULT_ROLES));
    }

    @Test
    void leaf_realmManagementRoles_areTainted() {
        assertFalse(DefaultRoleCompositeGuard.isBenignChild(true, "manage-users", "realm-management", DEFAULT_ROLES));
        assertFalse(DefaultRoleCompositeGuard.isBenignChild(true, "realm-admin", "realm-management", DEFAULT_ROLES));
        assertFalse(DefaultRoleCompositeGuard.isBenignChild(true, "tide-realm-admin", "realm-management", DEFAULT_ROLES));
    }

    @Test
    void leaf_unknownRealmRole_isTainted() {
        // Allow-list: an operator-authored realm role we cannot classify is NOT benign.
        assertFalse(DefaultRoleCompositeGuard.isBenignChild(false, "admin", null, DEFAULT_ROLES));
        assertFalse(DefaultRoleCompositeGuard.isBenignChild(false, "some-custom-role", null, DEFAULT_ROLES));
    }

    @Test
    void leaf_accountNamedRoleUnderNonAccountClient_isTainted() {
        // A role NAMED like an account baseline role but owned by another client is tainted.
        assertFalse(DefaultRoleCompositeGuard.isBenignChild(true, "manage-account", "my-app", DEFAULT_ROLES));
        assertFalse(DefaultRoleCompositeGuard.isBenignChild(true, "view-profile", null, DEFAULT_ROLES));
    }

    @Test
    void leaf_nullName_isTainted() {
        assertFalse(DefaultRoleCompositeGuard.isBenignChild(false, null, null, DEFAULT_ROLES));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Realm composite walk
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    void nullRealm_isBenignVacuous() {
        assertTrue(DefaultRoleCompositeGuard.isBenignDefaultRoleComposite(null));
    }

    @Test
    void noDefaultRole_isBenignVacuous() {
        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn(REALM);
        when(realm.getDefaultRole()).thenReturn(null);
        assertTrue(DefaultRoleCompositeGuard.isBenignDefaultRoleComposite(realm));
    }

    @Test
    void benignComposite_passes() {
        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn(REALM);

        ClientModel account = clientMock("account");
        when(realm.getClientById("account-uuid")).thenReturn(account);

        RoleModel offlineAccess = realmRole("offline_access");
        RoleModel uma = realmRole("uma_authorization");
        RoleModel viewProfile = clientRole("view-profile", "account-uuid");
        RoleModel manageAccount = clientRole("manage-account", "account-uuid");

        RoleModel defaultRole = composite(DEFAULT_ROLES, false, null,
                offlineAccess, uma, viewProfile, manageAccount);
        when(realm.getDefaultRole()).thenReturn(defaultRole);

        assertTrue(DefaultRoleCompositeGuard.isBenignDefaultRoleComposite(realm),
                "a default-role composite of only offline_access/uma + account baseline "
                        + "roles must be benign — accept-unattested self-reg stays eligible");
    }

    @Test
    void taintedComposite_realmManagementChild_failsClosed() {
        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn(REALM);

        ClientModel realmMgmt = clientMock("realm-management");
        when(realm.getClientById("rm-uuid")).thenReturn(realmMgmt);

        RoleModel offlineAccess = realmRole("offline_access");
        RoleModel manageUsers = clientRole("manage-users", "rm-uuid"); // PRIVILEGED child

        RoleModel defaultRole = composite(DEFAULT_ROLES, false, null,
                offlineAccess, manageUsers);
        when(realm.getDefaultRole()).thenReturn(defaultRole);

        assertFalse(DefaultRoleCompositeGuard.isBenignDefaultRoleComposite(realm),
                "a realm-management:manage-users child on the default-role composite must "
                        + "fail the benign guard — it would confer manage-users to every "
                        + "unsigned self-registered user via composite expansion (invisible "
                        + "to the D1b user_role_mapping_set unit)");
    }

    @Test
    void taintedComposite_nestedPrivilegedChild_failsClosedTransitively() {
        // default-roles → benign-grouping (realm role) → realm-management:realm-admin
        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn(REALM);

        ClientModel realmMgmt = clientMock("realm-management");
        when(realm.getClientById("rm-uuid")).thenReturn(realmMgmt);

        RoleModel realmAdmin = clientRole("realm-admin", "rm-uuid"); // PRIVILEGED leaf
        // a nested realm role named like the default-roles root would be benign, but here
        // the nested grouping is offline_access (benign) which itself composites the
        // privileged leaf — proving the walk is transitive, not depth-1.
        RoleModel nested = composite("offline_access", false, null, realmAdmin);
        RoleModel defaultRole = composite(DEFAULT_ROLES, false, null, nested);
        when(realm.getDefaultRole()).thenReturn(defaultRole);

        assertFalse(DefaultRoleCompositeGuard.isBenignDefaultRoleComposite(realm),
                "a privileged role nested DEEP in the composite (not a direct child) must "
                        + "still be caught — the walk is transitive");
    }

    @Test
    void taintedComposite_unknownCustomRealmRole_failsClosed() {
        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn(REALM);

        RoleModel custom = realmRole("ops-superuser"); // not on the allowlist
        RoleModel defaultRole = composite(DEFAULT_ROLES, false, null, custom);
        when(realm.getDefaultRole()).thenReturn(defaultRole);

        assertFalse(DefaultRoleCompositeGuard.isBenignDefaultRoleComposite(realm),
                "an unknown operator-authored realm role on the default-role composite is "
                        + "tainted under the allow-list — we cannot positively classify it benign");
    }

    @Test
    void cyclicComposite_terminates() {
        // default-roles ←→ offline_access cycle: must not loop forever and must still pass
        // (both nodes are benign).
        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn(REALM);

        RoleModel offline = realmRole("offline_access");
        RoleModel defaultRole = realmRole(DEFAULT_ROLES);
        when(defaultRole.isComposite()).thenReturn(true);
        when(offline.isComposite()).thenReturn(true);
        when(defaultRole.getCompositesStream()).thenAnswer(inv -> Stream.of(offline));
        when(offline.getCompositesStream()).thenAnswer(inv -> Stream.of(defaultRole));
        when(realm.getDefaultRole()).thenReturn(defaultRole);

        assertTrue(DefaultRoleCompositeGuard.isBenignDefaultRoleComposite(realm),
                "a cyclic benign composite must terminate (cycle-safe) and pass");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // mock helpers
    // ─────────────────────────────────────────────────────────────────────────

    private static int idSeq = 0;

    private static ClientModel clientMock(String clientId) {
        ClientModel c = mock(ClientModel.class);
        lenient().when(c.getClientId()).thenReturn(clientId);
        return c;
    }

    private static RoleModel realmRole(String name) {
        return leafRole(name, false, null);
    }

    private static RoleModel clientRole(String name, String containerId) {
        return leafRole(name, true, containerId);
    }

    private static RoleModel leafRole(String name, boolean clientRole, String containerId) {
        RoleModel r = mock(RoleModel.class);
        lenient().when(r.getId()).thenReturn("role-" + (idSeq++) + "-" + name);
        lenient().when(r.getName()).thenReturn(name);
        lenient().when(r.isClientRole()).thenReturn(clientRole);
        lenient().when(r.getContainerId()).thenReturn(containerId);
        lenient().when(r.isComposite()).thenReturn(false);
        return r;
    }

    private static RoleModel composite(String name, boolean clientRole, String containerId,
                                       RoleModel... children) {
        RoleModel r = leafRole(name, clientRole, containerId);
        List<RoleModel> kids = new ArrayList<>(List.of(children));
        when(r.isComposite()).thenReturn(true);
        when(r.getCompositesStream()).thenAnswer(inv -> kids.stream());
        return r;
    }
}
