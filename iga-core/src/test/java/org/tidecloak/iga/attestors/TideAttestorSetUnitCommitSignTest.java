package org.tidecloak.iga.attestors;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.producer.RealmAttestationExporter;
import org.tidecloak.iga.producer.units.GroupRoleMappingSetUnit;
import org.tidecloak.iga.producer.units.RoleCompositeChildrenSetUnit;
import org.tidecloak.iga.producer.units.UserGroupMembershipSetUnit;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * PR-A coverage — the commit-time signer ({@link TideAttestor#buildUnitCbor}) MUST
 * produce the SAME producer-envelope CBOR the login/export path
 * ({@link RealmAttestationExporter}) emits over the POST-change owner set, so the ork
 * {@code TokenValidationEngine} re-derives byte-identical bytes and the VVK signature
 * verifies.
 *
 * <p>These tests assert byte-identity at the unit-CBOR level for the three SET units
 * wired in PR-A:
 * <ul>
 *   <li>{@code user_group_membership_set} (JOIN / LEAVE)</li>
 *   <li>{@code group_role_mapping_set} (GROUP_GRANT / REVOKE)</li>
 *   <li>{@code role_composite_children_set} (ADD / REMOVE_COMPOSITE)</li>
 * </ul>
 * plus the {@link TideAttestor#isProducerEnvelopeSignedAction} routing gate. The
 * commit builder reads the PRE-change set via the SAME shared
 * {@link RealmAttestationExporter} helper, applies the CR's add/remove delta, sorts to
 * the producer's {@code ORDER BY} order, and re-serializes — so the bytes equal the
 * producer's emission over the committed set, proving the no-hand-rolled-CBOR /
 * shared-builder contract.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TideAttestorSetUnitCommitSignTest {

    private static final String REALM_ID = "realm-uuid-set";
    private static final String USER_ID = "user-1";
    private static final String GROUP_ID = "group-1";
    private static final String PARENT_ROLE_ID = "parent-role-1";

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock JpaConnectionProvider jpa;
    @Mock EntityManager em;
    @Mock IgaChangeRequestEntity cr;

    private TideAttestor attestor;

    @BeforeEach
    void setUp() {
        when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa);
        when(jpa.getEntityManager()).thenReturn(em);
        when(realm.getId()).thenReturn(REALM_ID);
        when(realm.getName()).thenReturn("set-realm");
        attestor = new TideAttestor(session);
    }

    /** Stub em.createQuery(jpql).setParameter(...).getResultList() to return {@code ids}. */
    private void stubIdQuery(List<String> ids) {
        Query q = mock(Query.class);
        when(em.createQuery(anyString())).thenReturn(q);
        when(q.setParameter(anyString(), org.mockito.ArgumentMatchers.any())).thenReturn(q);
        when(q.getResultList()).thenReturn((List) ids);
    }

    // -------------------------------------------------------------------------
    // Routing gate
    // -------------------------------------------------------------------------

    @Test
    void routingGate_coversTemplateAndThreeSetUnits_excludesNodeAndDerived() {
        // The four producer-envelope-signed actions wired in PR-A (template + 3 set units,
        // both add and remove directions).
        for (String a : new String[]{"GRANT_ROLES",
                "JOIN_GROUPS", "LEAVE_GROUPS",
                "GROUP_GRANT_ROLES", "GROUP_REVOKE_ROLES",
                "ADD_COMPOSITE", "REMOVE_COMPOSITE"}) {
            assertTrue(TideAttestor.isProducerEnvelopeSignedAction(a),
                    a + " must route to the producer-envelope ceremony");
        }
        // Deferred to PR-A.2 — still the stub.
        for (String a : new String[]{"CREATE_CLIENT", "CREATE_ROLE", "CREATE_GROUP",
                "CREATE_USER", "CREATE_CLIENT_SCOPE", "CREATE_ORGANIZATION",
                "SET_REALM_CONFIG", "ASSIGN_SCOPE", "ADD_PROTOCOL_MAPPER", null}) {
            assertFalse(TideAttestor.isProducerEnvelopeSignedAction(a),
                    a + " must NOT route to the producer-envelope ceremony in PR-A");
        }
    }

    // -------------------------------------------------------------------------
    // user_group_membership_set (JOIN / LEAVE)
    // -------------------------------------------------------------------------

    @Test
    void userGroupMembershipSet_join_signsProducerEnvelopeBytes() {
        // Pre-change membership (raw stored set). The CR JOINs group "g-new".
        List<String> preSet = Arrays.asList("g-aaa", "g-ccc");
        stubIdQuery(preSet);
        when(cr.getActionType()).thenReturn("JOIN_GROUPS");
        when(cr.getEntityId()).thenReturn(USER_ID);
        when(cr.getRowsJson()).thenReturn(
                "[{\"USER\":\"" + USER_ID + "\",\"GROUP\":\"g-new\"}]");

        byte[] commitBytes = attestor.buildUserGroupMembershipSetUnitCbor(session, realm, cr);

        // Producer emission over the COMMITTED post-change set (sorted, as the producer's
        // ORDER BY m.groupId yields).
        List<String> committed = Arrays.asList("g-aaa", "g-ccc", "g-new");
        byte[] producerBytes =
                new UserGroupMembershipSetUnit(REALM_ID, USER_ID, committed).serialize();
        assertArrayEquals(producerBytes, commitBytes,
                "JOIN commit bytes must equal the producer's post-change membership-set envelope");
    }

    @Test
    void userGroupMembershipSet_leave_signsProducerEnvelopeBytes() {
        List<String> preSet = Arrays.asList("g-aaa", "g-bbb", "g-ccc");
        stubIdQuery(preSet);
        when(cr.getActionType()).thenReturn("LEAVE_GROUPS");
        when(cr.getEntityId()).thenReturn(USER_ID);
        when(cr.getRowsJson()).thenReturn(
                "[{\"USER\":\"" + USER_ID + "\",\"GROUP\":\"g-bbb\"}]");

        byte[] commitBytes = attestor.buildUserGroupMembershipSetUnitCbor(session, realm, cr);

        List<String> committed = Arrays.asList("g-aaa", "g-ccc");
        byte[] producerBytes =
                new UserGroupMembershipSetUnit(REALM_ID, USER_ID, committed).serialize();
        assertArrayEquals(producerBytes, commitBytes,
                "LEAVE commit bytes must equal the producer's post-change membership-set envelope");
    }

    // -------------------------------------------------------------------------
    // group_role_mapping_set (GROUP_GRANT / REVOKE)
    // -------------------------------------------------------------------------

    @Test
    void groupRoleMappingSet_grant_signsProducerEnvelopeBytes() {
        List<String> preSet = Arrays.asList("r-aaa");
        stubIdQuery(preSet);
        when(cr.getActionType()).thenReturn("GROUP_GRANT_ROLES");
        when(cr.getEntityId()).thenReturn(GROUP_ID);
        when(cr.getRowsJson()).thenReturn(
                "[{\"GROUP\":\"" + GROUP_ID + "\",\"ROLE\":\"r-zzz\"}]");

        byte[] commitBytes = attestor.buildGroupRoleMappingSetUnitCbor(session, realm, cr);

        List<String> committed = Arrays.asList("r-aaa", "r-zzz");
        byte[] producerBytes =
                new GroupRoleMappingSetUnit(REALM_ID, GROUP_ID, committed).serialize();
        assertArrayEquals(producerBytes, commitBytes,
                "GROUP_GRANT_ROLES commit bytes must equal the producer's post-change "
                        + "group-role-mapping-set envelope");
    }

    // -------------------------------------------------------------------------
    // role_composite_children_set (ADD / REMOVE_COMPOSITE)
    // -------------------------------------------------------------------------

    @Test
    void roleCompositeChildrenSet_add_signsProducerEnvelopeBytes() {
        // Pre-change composite children read live from the parent role model.
        RoleModel parent = mock(RoleModel.class);
        RoleModel childA = mock(RoleModel.class);
        RoleModel childC = mock(RoleModel.class);
        when(parent.getId()).thenReturn(PARENT_ROLE_ID);
        when(parent.isComposite()).thenReturn(true);
        when(childA.getId()).thenReturn("c-aaa");
        when(childC.getId()).thenReturn("c-ccc");
        when(parent.getCompositesStream()).thenReturn(Stream.of(childA, childC));
        when(realm.getRoleById(eq(PARENT_ROLE_ID))).thenReturn(parent);

        when(cr.getActionType()).thenReturn("ADD_COMPOSITE");
        when(cr.getEntityId()).thenReturn(PARENT_ROLE_ID);
        when(cr.getRowsJson()).thenReturn(
                "[{\"COMPOSITE\":\"" + PARENT_ROLE_ID + "\",\"CHILD_ROLE\":\"c-bbb\"}]");

        byte[] commitBytes = attestor.buildRoleCompositeChildrenSetUnitCbor(session, realm, cr);

        List<String> committed = Arrays.asList("c-aaa", "c-bbb", "c-ccc");
        byte[] producerBytes =
                new RoleCompositeChildrenSetUnit(REALM_ID, PARENT_ROLE_ID, committed).serialize();
        assertArrayEquals(producerBytes, commitBytes,
                "ADD_COMPOSITE commit bytes must equal the producer's post-change "
                        + "composite-children-set envelope");
    }
}
