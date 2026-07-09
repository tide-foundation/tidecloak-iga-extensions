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
 * no realm-escalation privilege; this guard validates it by walking the
 * composite transitively and fail-closing on any PRIVILEGED child
 * (realm-management client roles + tide-realm-admin + bare admin realm-role
 * names). NON-privileged application roles ({@code appUser}, the self-scoped
 * {@code _tide_*} E2EE roles, custom app roles) are benign — they are exactly
 * the default baseline every user is meant to hold.
 */
class DefaultRoleCompositeGuardTest {

    private static final String REALM = "myrealm";
    private static final String DEFAULT_ROLES = "default-roles-" + REALM;

    // ─────────────────────────────────────────────────────────────────────────
    // Pure leaf classifier — BENIGN cases
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
    void leaf_applicationRealmRole_isBenign() {
        // appUser — the operator's application baseline realm role. It is NOT a
        // realm-escalation role, so it is benign. (Under the earlier allow-list this
        // was WRONGLY tainted, which created ROLELESS self-registrants — the bug.)
        assertTrue(DefaultRoleCompositeGuard.isBenignChild(false, "appUser", null, DEFAULT_ROLES));
        assertTrue(DefaultRoleCompositeGuard.isBenignChild(false, "some-custom-role", null, DEFAULT_ROLES));
    }

    @Test
    void leaf_tideSelfScopedE2EERoles_areBenign() {
        // _tide_dob.selfencrypt / .selfdecrypt — self-scoped E2EE roles, modelled either
        // as realm roles or as client roles under a non-realm-management client. Either
        // shape is NON-privileged and therefore benign.
        assertTrue(DefaultRoleCompositeGuard.isBenignChild(false, "_tide_dob.selfencrypt", null, DEFAULT_ROLES));
        assertTrue(DefaultRoleCompositeGuard.isBenignChild(false, "_tide_dob.selfdecrypt", null, DEFAULT_ROLES));
        assertTrue(DefaultRoleCompositeGuard.isBenignChild(true, "selfencrypt", "_tide_dob", DEFAULT_ROLES));
    }

    @Test
    void leaf_customAppClientRole_isBenign() {
        // A role under any client OTHER than realm-management is application-scoped, not
        // realm escalation — benign under the denylist. Even a role NAMED like an admin
        // action but owned by an application client is app-scoped, not realm control.
        assertTrue(DefaultRoleCompositeGuard.isBenignChild(true, "do-stuff", "my-app", DEFAULT_ROLES));
        assertTrue(DefaultRoleCompositeGuard.isBenignChild(true, "manage-account", "my-app", DEFAULT_ROLES));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Pure leaf classifier — PRIVILEGED (tainted) cases
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    void leaf_realmManagementRoles_areTainted() {
        // The ENTIRE realm-management client surface is privileged.
        assertFalse(DefaultRoleCompositeGuard.isBenignChild(true, "manage-users", "realm-management", DEFAULT_ROLES));
        assertFalse(DefaultRoleCompositeGuard.isBenignChild(true, "manage-realm", "realm-management", DEFAULT_ROLES));
        assertFalse(DefaultRoleCompositeGuard.isBenignChild(true, "realm-admin", "realm-management", DEFAULT_ROLES));
        assertFalse(DefaultRoleCompositeGuard.isBenignChild(true, "view-users", "realm-management", DEFAULT_ROLES));
        assertFalse(DefaultRoleCompositeGuard.isBenignChild(true, "impersonation", "realm-management", DEFAULT_ROLES));
    }

    @Test
    void leaf_tideRealmAdmin_isTaintedByName_anyContainer() {
        // tide-realm-admin is privileged wherever it lives (defense-in-depth): on
        // realm-management (its real home), on any other client, or as a realm role.
        assertFalse(DefaultRoleCompositeGuard.isBenignChild(true, "tide-realm-admin", "realm-management", DEFAULT_ROLES));
        assertFalse(DefaultRoleCompositeGuard.isBenignChild(true, "tide-realm-admin", "some-other-client", DEFAULT_ROLES));
        assertFalse(DefaultRoleCompositeGuard.isBenignChild(false, "tide-realm-admin", null, DEFAULT_ROLES));
    }

    @Test
    void leaf_privilegedRealmRoleNames_areTainted() {
        // Bare realm-role names that denote realm administration (defense-in-depth).
        assertFalse(DefaultRoleCompositeGuard.isBenignChild(false, "admin", null, DEFAULT_ROLES));
        assertFalse(DefaultRoleCompositeGuard.isBenignChild(false, "realm-admin", null, DEFAULT_ROLES));
        assertFalse(DefaultRoleCompositeGuard.isBenignChild(false, "create-realm", null, DEFAULT_ROLES));
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
    void benignComposite_stockOnly_passes() {
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

    /**
     * The exact staging default-role composite that the earlier allow-list wrongly
     * refused — { appUser, manage-account, view-profile, offline_access,
     * uma_authorization, _tide_dob.selfencrypt, _tide_dob.selfdecrypt } — must now be
     * BENIGN so the Tide self-registrant receives default-roles at creation.
     */
    @Test
    void reportedStagingDefaultComposite_isGrantable() {
        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn(REALM);

        ClientModel account = clientMock("account");
        when(realm.getClientById("account-uuid")).thenReturn(account);
        ClientModel tideDob = clientMock("_tide_dob");
        when(realm.getClientById("tidedob-uuid")).thenReturn(tideDob);

        RoleModel appUser = realmRole("appUser");
        RoleModel manageAccount = clientRole("manage-account", "account-uuid");
        RoleModel viewProfile = clientRole("view-profile", "account-uuid");
        RoleModel offlineAccess = realmRole("offline_access");
        RoleModel uma = realmRole("uma_authorization");
        RoleModel selfEncrypt = clientRole("selfencrypt", "tidedob-uuid");
        RoleModel selfDecrypt = clientRole("selfdecrypt", "tidedob-uuid");

        RoleModel defaultRole = composite(DEFAULT_ROLES, false, null,
                appUser, manageAccount, viewProfile, offlineAccess, uma, selfEncrypt, selfDecrypt);
        when(realm.getDefaultRole()).thenReturn(defaultRole);

        assertTrue(DefaultRoleCompositeGuard.isBenignDefaultRoleComposite(realm),
                "the standard staging default-role composite (appUser + account baseline + "
                        + "offline/uma + self-scoped _tide_* E2EE roles) contains NO "
                        + "realm-escalation role, so it must be grantable to a Tide "
                        + "self-registrant — the fix for the ROLELESS self-reg bug");
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

    /**
     * The staging-shape composite but TAINTED with a realm-management child — proves the
     * guard still refuses escalation even amid a legitimate benign baseline.
     */
    @Test
    void taintedComposite_stagingShapePlusTideRealmAdmin_failsClosed() {
        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn(REALM);

        ClientModel account = clientMock("account");
        when(realm.getClientById("account-uuid")).thenReturn(account);
        ClientModel realmMgmt = clientMock("realm-management");
        when(realm.getClientById("rm-uuid")).thenReturn(realmMgmt);

        RoleModel appUser = realmRole("appUser");
        RoleModel offlineAccess = realmRole("offline_access");
        RoleModel manageAccount = clientRole("manage-account", "account-uuid");
        RoleModel tideRealmAdmin = clientRole("tide-realm-admin", "rm-uuid"); // PRIVILEGED child

        RoleModel defaultRole = composite(DEFAULT_ROLES, false, null,
                appUser, offlineAccess, manageAccount, tideRealmAdmin);
        when(realm.getDefaultRole()).thenReturn(defaultRole);

        assertFalse(DefaultRoleCompositeGuard.isBenignDefaultRoleComposite(realm),
                "a tide-realm-admin child on an otherwise-benign default-role composite must "
                        + "still fail closed — the escalation vector stays shut");
    }

    @Test
    void taintedComposite_nestedPrivilegedChild_failsClosedTransitively() {
        // default-roles → benign-grouping (realm role) → realm-management:realm-admin
        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn(REALM);

        ClientModel realmMgmt = clientMock("realm-management");
        when(realm.getClientById("rm-uuid")).thenReturn(realmMgmt);

        RoleModel realmAdmin = clientRole("realm-admin", "rm-uuid"); // PRIVILEGED leaf
        // a nested benignly-named grouping role that itself composites the privileged leaf —
        // proving the walk is transitive, not depth-1.
        RoleModel nested = composite("appUser", false, null, realmAdmin);
        RoleModel defaultRole = composite(DEFAULT_ROLES, false, null, nested);
        when(realm.getDefaultRole()).thenReturn(defaultRole);

        assertFalse(DefaultRoleCompositeGuard.isBenignDefaultRoleComposite(realm),
                "a privileged role nested DEEP in the composite (hidden under a benignly-named "
                        + "grouping role) must still be caught — the walk is transitive");
    }

    @Test
    void benignComposite_unknownCustomRealmRole_passes() {
        // Policy flip vs the old allow-list: an unknown, NON-privileged operator-authored
        // realm role is now BENIGN (it confers no realm escalation). This is what lets the
        // operator's appUser / custom baseline roles ride the default composite.
        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn(REALM);

        RoleModel custom = realmRole("ops-report-viewer"); // non-privileged custom role
        RoleModel defaultRole = composite(DEFAULT_ROLES, false, null, custom);
        when(realm.getDefaultRole()).thenReturn(defaultRole);

        assertTrue(DefaultRoleCompositeGuard.isBenignDefaultRoleComposite(realm),
                "an unknown NON-privileged operator realm role on the default composite is "
                        + "benign under the denylist — only the realm-escalation surface is refused");
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
