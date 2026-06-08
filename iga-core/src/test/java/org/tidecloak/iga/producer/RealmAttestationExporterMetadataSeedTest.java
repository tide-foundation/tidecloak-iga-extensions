package org.tidecloak.iga.producer;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests the widened ROLE-METADATA seed
 * ({@link RealmAttestationExporter#metadataRoleSeed}) that drives
 * {@code role_definition} (U5) + {@code role_composite_children_set} (U11)
 * emission so the ORK can expand the composites it walks.
 *
 * <p>The seed is the UNION of the user's direct grants, every role mapped to a
 * group the user belongs to, the request client's own scope-mapping allowlist,
 * and each assigned client_scope's allowlist. Two scenarios are exercised:
 *
 * <ul>
 *   <li><b>(a)</b> a {@code full_scope_allowed=false} client whose scope-mapping
 *       allowlist contains a composite role the user does NOT directly hold — the
 *       allowlist composite must enter the metadata seed (so its U5/U11, and after
 *       transitive expansion its children's, get emitted).</li>
 *   <li><b>(a2)</b> a group-inherited composite role — a role mapped only to a
 *       group the user belongs to must enter the seed too.</li>
 * </ul>
 *
 * <p><b>Guardrail assertion:</b> the user's direct-grant list passed in
 * (the U8 {@code user_role_mapping_set} payload) is NOT mutated, and the only
 * roles the helper ADDS beyond the grants are metadata roles (allowlist / group),
 * never folded back into membership. Membership (U8/U9/U10) is produced elsewhere
 * from raw JPQL and is untouched by this helper.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class RealmAttestationExporterMetadataSeedTest {

    private static RoleModel role(String id) {
        RoleModel r = mock(RoleModel.class);
        when(r.getId()).thenReturn(id);
        return r;
    }

    private static GroupModel groupWithRoles(RoleModel... roles) {
        GroupModel g = mock(GroupModel.class);
        when(g.getRoleMappingsStream()).thenReturn(Stream.of(roles));
        return g;
    }

    /**
     * A group with a parent in its {@code getParent()} chain (top-level groups
     * return null). The role mappings stream is rebuildable on each access because
     * the ancestor walk reads {@code getRoleMappingsStream()} once per group.
     */
    private static GroupModel groupWithParentAndRoles(GroupModel parent, RoleModel... roles) {
        GroupModel g = mock(GroupModel.class);
        when(g.getRoleMappingsStream()).thenReturn(Stream.of(roles));
        when(g.getParent()).thenReturn(parent);
        return g;
    }

    private static ClientScopeModel scopeWithAllowlist(RoleModel... roles) {
        ClientScopeModel s = mock(ClientScopeModel.class);
        when(s.getScopeMappingsStream()).thenReturn(Stream.of(roles));
        return s;
    }

    private static UserModel userInGroups(GroupModel... groups) {
        UserModel u = mock(UserModel.class);
        when(u.getGroupsStream()).thenReturn(Stream.of(groups));
        return u;
    }

    private static final String GRANT_ROLE = "11111111-1111-1111-1111-111111111111";
    private static final String ALLOWLIST_COMPOSITE = "22222222-2222-2222-2222-222222222222";
    private static final String GROUP_COMPOSITE = "33333333-3333-3333-3333-333333333333";
    private static final String SCOPE_ALLOWLIST_ROLE = "44444444-4444-4444-4444-444444444444";
    private static final String ANCESTOR_A_COMPOSITE = "55555555-5555-5555-5555-555555555555";
    private static final String PARENT_B_ROLE = "66666666-6666-6666-6666-666666666666";
    private static final String SUBGROUP_C_ROLE = "77777777-7777-7777-7777-777777777777";
    private static final String DEFAULT_ROLE = "88888888-8888-8888-8888-888888888888";

    /**
     * (a): a client whose own SCOPE_MAPPING allowlist names a composite the user
     * does not directly hold widens the metadata seed to include that composite.
     */
    @Test
    void clientAllowlistCompositeEntersSeed() {
        List<String> userGrants = List.of(GRANT_ROLE);
        UserModel user = userInGroups(); // no groups

        Set<String> seed = RealmAttestationExporter.metadataRoleSeed(
                userGrants, user,
                List.of(ALLOWLIST_COMPOSITE),   // client SCOPE_MAPPING allowlist
                List.of(),                       // no assigned scopes
                null);                           // no realm default-role id

        assertTrue(seed.contains(GRANT_ROLE), "user's own grant is in the seed");
        assertTrue(seed.contains(ALLOWLIST_COMPOSITE),
                "allowlist composite the user does NOT hold must enter the metadata seed (a)");
    }

    /**
     * (a2): a composite role mapped only to a group the user belongs to (not a
     * direct grant) widens the metadata seed.
     */
    @Test
    void groupInheritedCompositeEntersSeed() {
        List<String> userGrants = List.of(GRANT_ROLE);
        UserModel user = userInGroups(groupWithRoles(role(GROUP_COMPOSITE)));

        Set<String> seed = RealmAttestationExporter.metadataRoleSeed(
                userGrants, user, List.of(), List.of(), null);

        assertTrue(seed.contains(GROUP_COMPOSITE),
                "group-mapped composite must enter the metadata seed (a2)");
    }

    /**
     * (a2, nested): the user is in subgroup C (child of B, child of A). A COMPOSITE
     * role sits on ANCESTOR group A. The ORK enumerates group roles
     * ancestor-inclusively (GroupAndAncestors ascends parent_group_id), so a role on
     * an ancestor of a joined group reaches the member. The metadata seed must walk
     * the same parent chain so that ancestor composite (and roles on every ancestor)
     * enter the seed — otherwise its U5/U11 are never emitted and the ORK can't
     * expand it → resource_access/realm_access under-reports (false reject).
     *
     * <p>GUARDRAIL: the user's direct-grant (U8) list is NOT mutated; the ancestor
     * roles are metadata-seed only, never folded into the user's held set.
     */
    @Test
    void ancestorGroupCompositeEntersSeedNestedGroups() {
        GroupModel groupA = groupWithRoles(role(ANCESTOR_A_COMPOSITE)); // top-level (getParent()==null)
        GroupModel groupB = groupWithParentAndRoles(groupA, role(PARENT_B_ROLE));
        GroupModel groupC = groupWithParentAndRoles(groupB, role(SUBGROUP_C_ROLE));

        List<String> userGrants = new ArrayList<>(List.of(GRANT_ROLE));
        UserModel user = userInGroups(groupC); // user is a DIRECT member of subgroup C only

        Set<String> seed = RealmAttestationExporter.metadataRoleSeed(
                userGrants, user, List.of(), List.of(), null);

        // The joined subgroup's role plus every ancestor group's roles enter the seed.
        assertTrue(seed.contains(SUBGROUP_C_ROLE), "joined subgroup C role in seed");
        assertTrue(seed.contains(PARENT_B_ROLE), "parent group B role in seed (ancestor-inclusive)");
        assertTrue(seed.contains(ANCESTOR_A_COMPOSITE),
                "ancestor group A composite must enter the metadata seed (nested ancestor walk)");
        assertTrue(seed.contains(GRANT_ROLE), "user's own direct grant still in seed");

        // GUARDRAIL: membership (U8 user_role_mapping_set payload) is unchanged — none of
        // the group/ancestor roles get folded into the user's held set.
        assertEquals(List.of(GRANT_ROLE), userGrants, "user-grant (U8) list must be unchanged");
        assertFalse(userGrants.contains(SUBGROUP_C_ROLE));
        assertFalse(userGrants.contains(PARENT_B_ROLE));
        assertFalse(userGrants.contains(ANCESTOR_A_COMPOSITE));
    }

    /**
     * Each assigned client_scope's CLIENT_SCOPE_ROLE_MAPPING allowlist also
     * contributes to the metadata seed.
     */
    @Test
    void assignedScopeAllowlistEntersSeed() {
        UserModel user = userInGroups();
        ClientScopeModel scope = scopeWithAllowlist(role(SCOPE_ALLOWLIST_ROLE));

        Set<String> seed = RealmAttestationExporter.metadataRoleSeed(
                List.of(GRANT_ROLE), user, List.of(), List.of(scope), null);

        assertTrue(seed.contains(SCOPE_ALLOWLIST_ROLE),
                "assigned scope allowlist role must enter the metadata seed");
    }

    /**
     * Full union, plus the GUARDRAIL: the input user-grant list (the U8 payload)
     * is NOT mutated by the helper — membership stays exactly the direct grants.
     */
    @Test
    void seedIsUnionAndDoesNotMutateMembership() {
        List<String> userGrants = new ArrayList<>(List.of(GRANT_ROLE));
        UserModel user = userInGroups(groupWithRoles(role(GROUP_COMPOSITE)));
        ClientScopeModel scope = scopeWithAllowlist(role(SCOPE_ALLOWLIST_ROLE));

        Set<String> seed = RealmAttestationExporter.metadataRoleSeed(
                userGrants, user, List.of(ALLOWLIST_COMPOSITE), List.of(scope), null);

        // Union of all four sources.
        assertTrue(seed.contains(GRANT_ROLE));
        assertTrue(seed.contains(ALLOWLIST_COMPOSITE));
        assertTrue(seed.contains(GROUP_COMPOSITE));
        assertTrue(seed.contains(SCOPE_ALLOWLIST_ROLE));
        assertEquals(4, seed.size());

        // GUARDRAIL: the user-membership list (U8 user_role_mapping_set payload) is
        // untouched — the helper never folds allowlist/group roles back into the
        // user's held set. Only the metadata closure widened.
        assertEquals(List.of(GRANT_ROLE), userGrants, "user-grant (U8) list must be unchanged");
        assertFalse(userGrants.contains(ALLOWLIST_COMPOSITE));
        assertFalse(userGrants.contains(GROUP_COMPOSITE));
        assertFalse(userGrants.contains(SCOPE_ALLOWLIST_ROLE));
    }

    /**
     * ★ THE aud FIX (default-roles METADATA seed).
     *
     * <p>After D1b excluded the realm default-role id from the per-user U8
     * {@code user_role_mapping_set} edge (and therefore from {@code userGrantRoleIds},
     * the first metadata-seed contributor), the login metadata seed no longer carried
     * the {@code default-roles-<realm>} composite id. So {@code transitiveRoleClosure}
     * stopped expanding it → no {@code role_definition} for its account/realm-management
     * children, no {@code role_composite_children_set} for the composite, and — fatally —
     * no {@code client_config} for the owning {@code account} client. The ORK
     * {@code AudienceResolveClaimMapper} then found {@code account}'s {@code client_config}
     * ABSENT from the login closure → "aud has no attested source" (Stage 8 reject).
     *
     * <p>The fix unions the realm default-role id into the METADATA seed (a fifth
     * contributor) — NOT into {@code userGrantRoleIds}/the U8 edge (the universal-inherit
     * on the ORK does the actual granting). This pins: the default-role id IS in the seed
     * (so the closure expands the default-roles composite), while the caller's
     * user-grant (U8) list stays excluded/unchanged (the sign-once invariant).
     */
    @Test
    void realmDefaultRoleIdEntersMetadataSeed_butNotTheU8GrantList() {
        // A default-roles-ONLY user: U8 user_role_mapping_set excludes the default-role id
        // (D1b), so userGrantRoleIds is EMPTY — exactly the failing case where the closure
        // previously dropped the account client_config.
        List<String> userGrants = new ArrayList<>(); // U8 excludes default-role (D1b)
        UserModel user = userInGroups();             // no groups

        Set<String> seed = RealmAttestationExporter.metadataRoleSeed(
                userGrants, user, List.of(), List.of(), DEFAULT_ROLE);

        // The aud fix: the realm default-role id MUST enter the metadata seed so
        // transitiveRoleClosure expands default-roles-<realm> → account client_config.
        assertTrue(seed.contains(DEFAULT_ROLE),
                "realm default-role id must enter the METADATA seed (drives default-roles "
                        + "composite expansion → account client_config → the aud fix)");

        // The sign-once invariant: the default-role id is NOT folded into the per-user U8
        // user_role_mapping_set payload — the universal-inherit grants it on the ORK.
        assertEquals(List.of(), userGrants,
                "U8 user_role_mapping_set (userGrantRoleIds) must STILL exclude the "
                        + "default-role edge — only the metadata closure gets it");
        assertFalse(userGrants.contains(DEFAULT_ROLE));
    }

    /**
     * Back-compat: a null default-role id (realm/default-role unresolvable) is a no-op —
     * the seed contains only the other contributors, exactly as before the aud fix.
     */
    @Test
    void nullDefaultRoleIdIsNoOp() {
        Set<String> seed = RealmAttestationExporter.metadataRoleSeed(
                List.of(GRANT_ROLE), userInGroups(), List.of(), List.of(), null);
        assertEquals(Set.of(GRANT_ROLE), seed);
    }
}
