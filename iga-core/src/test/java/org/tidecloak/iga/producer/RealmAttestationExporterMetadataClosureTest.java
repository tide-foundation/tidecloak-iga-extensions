package org.tidecloak.iga.producer;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.RoleProvider;
import org.keycloak.organization.OrganizationProvider;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.producer.units.AttestationUnit;
import org.tidecloak.iga.producer.units.AttestationUnitType;
import org.tidecloak.iga.producer.units.RoleCompositeChildrenSetUnit;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * ★ ROOT-CAUSE coverage for the full-realm-METADATA convergence
 * ({@link RealmAttestationExporter#exportRealmMetadata}).
 *
 * <p>The recurring failure: the convergence/backfill enumerated only the metadata a CURRENT
 * enabled user's token surfaces (per {@code (user, client)} {@link RealmAttestationExporter#export}).
 * A role NO current user holds — {@code tide-realm-admin}, {@code realm-admin}, the
 * {@code realm-management} composites — therefore never got its {@code role_definition}
 * (unit 4) / {@code role_composite_children_set} (unit 10) signed, so the moment a user was
 * granted {@code tide-realm-admin} (the multiAdmin flip) and logged in, the uniform read
 * fail-closed on the NULL composite.
 *
 * <p>{@code exportRealmMetadata} fixes this by enumerating EVERY realm role (realm + each
 * client's) membership-independently. These tests pin that:
 * <ol>
 *   <li>EVERY realm role and EVERY client role — including a composite
 *       {@code tide-realm-admin → realm-admin} that NO user holds — gets its
 *       {@code role_definition} emitted.</li>
 *   <li>ONLY roles that ARE real composites (have composite children) get a
 *       {@code role_composite_children_set} (unit 10): the composite
 *       {@code tide-realm-admin} does; the LEAF roles ({@code realm-admin},
 *       {@code plain-realm-role}, {@code client-role}) do NOT — a leaf has no
 *       {@code composite_role} row to sign, so emitting the unit would fail-close the
 *       login read on the structurally-NULL column.</li>
 *   <li>The composite's {@code role_composite_children_set} actually carries its child id
 *       (so the ORK can expand it), proving the composite metadata is real, not a stub.</li>
 *   <li>It is membership-INDEPENDENT: no {@code UserModel} is consulted — the closure comes
 *       purely from the realm's role/client/scope/group enumeration.</li>
 * </ol>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class RealmAttestationExporterMetadataClosureTest {

    private static final String REALM_ID = "realm-meta-uuid";

    // tide-realm-admin (composite) -> realm-admin (its child); NO user holds either.
    private static final String TIDE_REALM_ADMIN = "039f6de7-tide-realm-admin";
    private static final String REALM_ADMIN = "0f3187a3-realm-admin";
    private static final String PLAIN_REALM_ROLE = "11111111-plain-realm-role";
    private static final String CLIENT_ROLE = "22222222-client-role";
    private static final String CLIENT_UUID = "client-uuid-meta";

    private RoleModel role(String id, boolean clientRole, String containerId,
                           List<String> compositeChildIds) {
        RoleModel r = mock(RoleModel.class);
        when(r.getId()).thenReturn(id);
        when(r.getName()).thenReturn(id);
        when(r.isClientRole()).thenReturn(clientRole);
        when(r.getContainerId()).thenReturn(containerId);
        boolean composite = compositeChildIds != null && !compositeChildIds.isEmpty();
        when(r.isComposite()).thenReturn(composite);
        if (composite) {
            when(r.getCompositesStream()).thenAnswer(inv -> compositeChildIds.stream().map(cid -> {
                RoleModel child = mock(RoleModel.class);
                when(child.getId()).thenReturn(cid);
                return child;
            }));
        }
        return r;
    }

    /** A session whose JpaConnectionProvider returns an EM whose JPQL yields empty lists. */
    private KeycloakSession sessionWith(RealmModel realm, RoleModel... realmRoles) {
        KeycloakSession session = mock(KeycloakSession.class);
        KeycloakContext ctx = mock(KeycloakContext.class);
        when(session.getContext()).thenReturn(ctx);

        JpaConnectionProvider jpa = mock(JpaConnectionProvider.class);
        EntityManager em = mock(EntityManager.class);
        Query q = mock(Query.class, org.mockito.Answers.RETURNS_SELF);
        when(q.getResultList()).thenReturn(new ArrayList<>());
        when(em.createQuery(org.mockito.ArgumentMatchers.anyString())).thenReturn(q);
        when(jpa.getEntityManager()).thenReturn(em);
        when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa);

        RoleProvider roles = mock(RoleProvider.class);
        when(roles.getRealmRolesStream(realm)).thenAnswer(inv -> Stream.of(realmRoles));
        when(session.roles()).thenReturn(roles);

        // No orgs in this realm.
        OrganizationProvider orgs = mock(OrganizationProvider.class);
        when(orgs.getAllStream()).thenAnswer(inv -> Stream.empty());
        when(session.getProvider(OrganizationProvider.class)).thenReturn(orgs);
        return session;
    }

    @Test
    void everyRealmAndClientRole_getsDefinitionAndCompositeChildrenSet_membershipIndependent() {
        // Realm roles: a composite tide-realm-admin -> realm-admin (no user holds it),
        // plus realm-admin itself and a plain realm role.
        RoleModel tideRealmAdmin = role(TIDE_REALM_ADMIN, false, REALM_ID, List.of(REALM_ADMIN));
        RoleModel realmAdmin = role(REALM_ADMIN, false, REALM_ID, null);
        RoleModel plain = role(PLAIN_REALM_ROLE, false, REALM_ID, null);

        // One client owning one client role.
        RoleModel clientRole = role(CLIENT_ROLE, true, CLIENT_UUID, null);
        ClientModel client = mock(ClientModel.class);
        when(client.getId()).thenReturn(CLIENT_UUID);
        when(client.getClientId()).thenReturn("realm-management");
        when(client.getProtocol()).thenReturn("openid-connect");
        when(client.isFullScopeAllowed()).thenReturn(true);
        when(client.isServiceAccountsEnabled()).thenReturn(false);
        when(client.getWebOrigins()).thenReturn(new LinkedHashSet<>());
        when(client.getAttributes()).thenReturn(new java.util.LinkedHashMap<>());
        when(client.getRolesStream()).thenAnswer(inv -> Stream.of(clientRole));
        when(client.getProtocolMappersStream()).thenAnswer(inv -> Stream.empty());
        when(client.getScopeMappingsStream()).thenAnswer(inv -> Stream.empty());
        when(client.getClientScopes(org.mockito.ArgumentMatchers.anyBoolean()))
                .thenReturn(new java.util.LinkedHashMap<>());

        RealmModel realm = mock(RealmModel.class);
        when(realm.getId()).thenReturn(REALM_ID);
        when(realm.getName()).thenReturn("meta-realm");
        when(realm.getClientsStream()).thenAnswer(inv -> Stream.of(client));
        when(realm.getClientScopesStream()).thenAnswer(inv -> Stream.empty());
        when(realm.getGroupsStream()).thenAnswer(inv -> Stream.empty());
        when(realm.getDefaultGroupsStream()).thenAnswer(inv -> Stream.empty());
        // realm_config getters (RealmConfigUnit) — primitive returns default to 0/false.
        when(realm.getAttribute(org.mockito.ArgumentMatchers.anyString())).thenReturn(null);

        KeycloakSession session = sessionWith(realm, tideRealmAdmin, realmAdmin, plain);

        List<AttestationUnit> units = new RealmAttestationExporter().exportRealmMetadata(session, realm);

        // Collect (type, targetId) for assertions.
        Set<String> defTargets = new LinkedHashSet<>();
        Set<String> compositeTargets = new LinkedHashSet<>();
        RoleCompositeChildrenSetUnit tideAdminComposite = null;
        for (AttestationUnit u : units) {
            if (u.type() == AttestationUnitType.ROLE_DEFINITION) {
                defTargets.add(u.targetId());
            } else if (u.type() == AttestationUnitType.ROLE_COMPOSITE_CHILDREN_SET) {
                compositeTargets.add(u.targetId());
                if (TIDE_REALM_ADMIN.equals(u.targetId())) {
                    tideAdminComposite = (RoleCompositeChildrenSetUnit) u;
                }
            }
        }

        // (1) EVERY realm role AND the client role get a role_definition — incl. the roles
        //     NO user holds (tide-realm-admin, realm-admin). role_definition is keyed on
        //     keycloak_role.attestation which ALWAYS exists, so it is emitted for leaves too.
        for (String id : List.of(TIDE_REALM_ADMIN, REALM_ADMIN, PLAIN_REALM_ROLE, CLIENT_ROLE)) {
            assertTrue(defTargets.contains(id),
                    "role_definition must be emitted for " + id + " (membership-independent)");
        }

        // (1b) GATE: role_composite_children_set (unit 10) is emitted ONLY for the REAL
        //      composite (tide-realm-admin). The LEAF roles (realm-admin, plain-realm-role,
        //      client-role) have ZERO composite_role rows — emitting the unit for them would
        //      leave the convergence with no column to sign and fail-close every login.
        assertTrue(compositeTargets.contains(TIDE_REALM_ADMIN),
                "role_composite_children_set must be emitted for the composite tide-realm-admin");
        for (String leaf : List.of(REALM_ADMIN, PLAIN_REALM_ROLE, CLIENT_ROLE)) {
            assertTrue(!compositeTargets.contains(leaf),
                    "role_composite_children_set must NOT be emitted for leaf role " + leaf
                            + " (no composite_role row to sign → fail-close)");
        }

        // (2) the tide-realm-admin composite's children-set carries realm-admin — proving the
        //     composite metadata the ORK needs to expand is REAL, not a stub/NULL.
        assertTrue(tideAdminComposite != null,
                "tide-realm-admin must have a role_composite_children_set unit");
        @SuppressWarnings("unchecked")
        List<String> children =
                (List<String>) tideAdminComposite.payload().get("child_role_ids");
        assertTrue(children != null && children.contains(REALM_ADMIN),
                "tide-realm-admin -> realm-admin composite child must be signed so the multiAdmin "
                        + "flip login can expand it");

        // (3) realm-level units present (membership-independent realm metadata).
        boolean hasRealmConfig = units.stream()
                .anyMatch(u -> u.type() == AttestationUnitType.REALM_CONFIG);
        assertTrue(hasRealmConfig, "realm_config must be emitted by the metadata closure");
    }

    /**
     * Membership-independence: the metadata export consults NO {@code UserModel} / user
     * provider — the closure is identical whether or not any user holds the role. (Asserted
     * structurally: the method signature takes no user, and {@code session.users()} is never
     * stubbed yet the export completes and emits the un-held composite above.)
     */
    @Test
    void metadataExport_takesNoUser_andEmitsUnheldComposite() {
        RoleModel tideRealmAdmin = role(TIDE_REALM_ADMIN, false, REALM_ID, List.of(REALM_ADMIN));
        RealmModel realm = mock(RealmModel.class);
        when(realm.getId()).thenReturn(REALM_ID);
        when(realm.getName()).thenReturn("meta-realm-2");
        when(realm.getClientsStream()).thenAnswer(inv -> Stream.empty());
        when(realm.getClientScopesStream()).thenAnswer(inv -> Stream.empty());
        when(realm.getGroupsStream()).thenAnswer(inv -> Stream.empty());
        when(realm.getDefaultGroupsStream()).thenAnswer(inv -> Stream.empty());
        when(realm.getAttribute(org.mockito.ArgumentMatchers.anyString())).thenReturn(null);

        KeycloakSession session = sessionWith(realm, tideRealmAdmin);

        List<AttestationUnit> units = new RealmAttestationExporter().exportRealmMetadata(session, realm);

        long composite = units.stream()
                .filter(u -> u.type() == AttestationUnitType.ROLE_COMPOSITE_CHILDREN_SET
                        && TIDE_REALM_ADMIN.equals(u.targetId()))
                .count();
        assertEquals(1, composite,
                "the un-held tide-realm-admin composite is signed by the metadata closure "
                        + "without any user being consulted");
    }

    /**
     * ★ THE ROOT-CAUSE GATE — default-roles leaf-role scenario.
     *
     * <p>A {@code default-roles-<realm>} composite expands to leaf roles every user holds
     * ({@code offline_access}, {@code view-profile}, {@code manage-account-links}). Those
     * leaf roles have ZERO {@code composite_role} rows, so a
     * {@code role_composite_children_set} (unit 10) emitted for them is structurally
     * un-signable → the uniform login read fail-closed on the NULL column for EVERY login.
     *
     * <p>This pins the fix: the metadata closure emits unit 10 ONLY for the real composite
     * ({@code default-roles}), never for the leaf roles — while STILL emitting
     * {@code role_definition} (unit 4) for every leaf. A {@code default-roles} user login
     * therefore emits ZERO orphan leaf-role composite units → no fail-close.
     */
    @Test
    void defaultRolesLeafRoles_getNoCompositeChildrenSet_onlyDefinition_compositeStillEmitsUnit10() {
        final String DEFAULT_ROLES = "default-roles-meta-realm-uuid";
        final String OFFLINE_ACCESS = "offline_access-uuid";
        final String VIEW_PROFILE = "view-profile-uuid";
        final String MANAGE_ACCOUNT_LINKS = "manage-account-links-uuid";

        // default-roles is a REAL composite -> the three leaf roles. The leaves are NOT
        // composites (compositeChildIds == null -> isComposite()==false, no composite_role row).
        RoleModel defaultRoles = role(DEFAULT_ROLES, false, REALM_ID,
                List.of(OFFLINE_ACCESS, VIEW_PROFILE, MANAGE_ACCOUNT_LINKS));
        RoleModel offlineAccess = role(OFFLINE_ACCESS, false, REALM_ID, null);
        RoleModel viewProfile = role(VIEW_PROFILE, false, REALM_ID, null);
        RoleModel manageAccountLinks = role(MANAGE_ACCOUNT_LINKS, false, REALM_ID, null);

        RealmModel realm = mock(RealmModel.class);
        when(realm.getId()).thenReturn(REALM_ID);
        when(realm.getName()).thenReturn("default-roles-realm");
        when(realm.getClientsStream()).thenAnswer(inv -> Stream.empty());
        when(realm.getClientScopesStream()).thenAnswer(inv -> Stream.empty());
        when(realm.getGroupsStream()).thenAnswer(inv -> Stream.empty());
        when(realm.getDefaultGroupsStream()).thenAnswer(inv -> Stream.empty());
        when(realm.getAttribute(org.mockito.ArgumentMatchers.anyString())).thenReturn(null);

        KeycloakSession session = sessionWith(realm,
                defaultRoles, offlineAccess, viewProfile, manageAccountLinks);

        List<AttestationUnit> units = new RealmAttestationExporter().exportRealmMetadata(session, realm);

        Set<String> defTargets = new LinkedHashSet<>();
        Set<String> compositeTargets = new LinkedHashSet<>();
        for (AttestationUnit u : units) {
            if (u.type() == AttestationUnitType.ROLE_DEFINITION) {
                defTargets.add(u.targetId());
            } else if (u.type() == AttestationUnitType.ROLE_COMPOSITE_CHILDREN_SET) {
                compositeTargets.add(u.targetId());
            }
        }

        // role_definition (unit 4) for ALL roles incl. the leaves (keyed on the always-present
        // keycloak_role.attestation column).
        for (String id : List.of(DEFAULT_ROLES, OFFLINE_ACCESS, VIEW_PROFILE, MANAGE_ACCOUNT_LINKS)) {
            assertTrue(defTargets.contains(id),
                    "role_definition must STILL be emitted for " + id + " (only unit 10 is gated)");
        }

        // role_composite_children_set (unit 10): ONLY the real composite default-roles.
        assertTrue(compositeTargets.contains(DEFAULT_ROLES),
                "role_composite_children_set must be emitted for the real composite default-roles");
        for (String leaf : List.of(OFFLINE_ACCESS, VIEW_PROFILE, MANAGE_ACCOUNT_LINKS)) {
            assertTrue(!compositeTargets.contains(leaf),
                    "NO role_composite_children_set for leaf role " + leaf
                            + " — it has no composite_role row to sign (fail-close cause)");
        }
        // Exactly one unit-10 emitted in the whole closure (the composite), zero orphans.
        assertEquals(1, compositeTargets.size(),
                "exactly ONE role_composite_children_set (the composite) — zero orphan leaf units");
    }
}
