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
import org.tidecloak.iga.entities.IgaAuthorizerEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.producer.units.RoleCompositeChildrenSetUnit;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import jakarta.persistence.TypedQuery;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * REPRODUCTION + fix coverage for the bulk-approve set-signature clobber that made a
 * production realm unable to mint tokens ({@code TideKey+SignatureException: Attested unit
 * signature validation failed}).
 *
 * <p>Two {@code ADD_COMPOSITE} change requests against the SAME parent role committed in one
 * bulk batch each signed their own {@code role_composite_children_set} PRE-replay, over
 * {@code pre-set + that CR's delta}, and each fanned that signature across the WHOLE owner set
 * ({@code UPDATE CompositeRoleEntity SET attestation WHERE parentRole.id = :owner}, with no member
 * predicate, no IS NULL guard). The surviving column therefore committed to a set the database
 * no longer held, and the ork re-derived the committed set at token issue and rejected it.
 *
 * <p>{@link TideAttestor#stampCoalescedSetUnits} is the fix: after every replay in the batch is
 * applied, each owner's set is re-derived from the committed model, signed ONCE, and stamped as
 * the LAST write for that owner. These tests assert the invariant the ork enforces:
 * <em>the signature stored on the owner set is the signature over the FULL committed set</em>,
 * for a two-CR batch (the repro), for a one-CR commit (the single-commit control), for
 * multi-owner grouping, and for the fail-closed post-stamp verification.
 *
 * <p><b>Harness boundary.</b> This module's tests are Mockito unit tests with no database and no
 * ork, so the batch is driven at the coalescing seam rather than through the REST bulk endpoint:
 * the replay/model writes the bulk loop performs are represented by the parent role's committed
 * composite children, and the signature is the realm's deterministic non-capable
 * {@code TIDE-FIRSTADMIN-v1:} stub rather than a real 64-byte VVK signature (a real ork ceremony
 * is not reachable from a unit test). The bytes SIGNED are the real producer envelope
 * ({@link RoleCompositeChildrenSetUnit#serialize()}), so the set-membership property the ork
 * verifies is exercised exactly.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TideAttestorSetUnitCoalescingTest {

    private static final String REALM_ID = "realm-uuid-coalesce";
    private static final String REALM_NAME = "coalesce-realm";
    private static final String DEFAULT_ROLE_ID = "default-roles-coalesce-realm-id";
    private static final String OTHER_PARENT_ID = "other-parent-role-id";

    private static final String PRE_CHILD = "c-aaa";
    private static final String CR1_CHILD = "c-bbb";
    private static final String CR2_CHILD = "c-ccc";

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock JpaConnectionProvider jpa;
    @Mock EntityManager em;

    /** parent role id -> the attestation currently stored on the owner's composite_role rows. */
    private final Map<String, String> attestationColumn = new HashMap<>();
    /** Every owner the fan-out UPDATE was issued for, in order. */
    private final List<String> stampedOwners = new ArrayList<>();
    /** parent role id -> the children the committed model holds for that parent. */
    private final Map<String, List<String>> committedChildren = new LinkedHashMap<>();
    /** When set, the column read returns this instead of what was stamped. */
    private String columnReadOverride;

    private TideAttestor attestor;

    @BeforeEach
    void setUp() {
        when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa);
        when(jpa.getEntityManager()).thenReturn(em);
        when(realm.getId()).thenReturn(REALM_ID);
        when(realm.getName()).thenReturn(REALM_NAME);
        // Tide discriminator with no authorizer row -> firstAdmin; no tide-vendor-key
        // component -> not real-signing-capable, so signing is the deterministic stub.
        when(realm.getAttribute("iga.attestor")).thenReturn(TideAttestor.ID);
        when(realm.getComponentsStream()).thenAnswer(inv -> Stream.empty());

        @SuppressWarnings("unchecked")
        TypedQuery<IgaAuthorizerEntity> authorizerQuery = mock(TypedQuery.class);
        when(em.createNamedQuery(eq("IgaAuthorizer.findByRealm"), eq(IgaAuthorizerEntity.class)))
                .thenReturn(authorizerQuery);
        when(authorizerQuery.setParameter(anyString(), any())).thenReturn(authorizerQuery);
        when(authorizerQuery.getResultStream()).thenAnswer(inv -> Stream.empty());

        wireCompositeRoleColumn();
        attestor = new TideAttestor(session);
    }

    /**
     * Back the {@code CompositeRoleEntity.attestation} column with an in-memory map so the
     * owner-keyed fan-out UPDATE and the {@code UnitColumnMapping} read the verification
     * performs operate on the same state a real batch would leave behind.
     */
    private void wireCompositeRoleColumn() {
        when(em.createQuery(anyString())).thenAnswer(inv -> {
            String jpql = inv.getArgument(0);
            Query q = mock(Query.class);
            Map<String, Object> params = new HashMap<>();
            when(q.setParameter(anyString(), any())).thenAnswer(p -> {
                params.put(p.getArgument(0), p.getArgument(1));
                return q;
            });
            when(q.setMaxResults(anyInt())).thenReturn(q);
            if (jpql.startsWith("UPDATE CompositeRoleEntity")) {
                when(q.executeUpdate()).thenAnswer(x -> {
                    String owner = (String) params.get("id");
                    attestationColumn.put(owner, (String) params.get("sig"));
                    stampedOwners.add(owner);
                    return 1;
                });
            } else if (jpql.startsWith("SELECT e.attestation FROM CompositeRoleEntity")) {
                when(q.getResultList()).thenAnswer(x -> {
                    String stored = columnReadOverride != null
                            ? columnReadOverride
                            : attestationColumn.get((String) params.get("id"));
                    return stored == null ? List.of() : List.of(stored);
                });
            } else {
                when(q.getResultList()).thenAnswer(x -> List.of());
            }
            return q;
        });
    }

    /** Register a parent role whose COMMITTED composite children are {@code childIds}. */
    private void committedParent(String parentRoleId, String... childIds) {
        committedChildren.put(parentRoleId, List.of(childIds));
        RoleModel parent = mock(RoleModel.class);
        when(parent.getId()).thenReturn(parentRoleId);
        when(parent.isComposite()).thenReturn(childIds.length > 0);
        when(parent.getCompositesStream()).thenAnswer(inv -> {
            List<RoleModel> children = new ArrayList<>();
            for (String childId : committedChildren.get(parentRoleId)) {
                RoleModel child = mock(RoleModel.class);
                when(child.getId()).thenReturn(childId);
                children.add(child);
            }
            return children.stream();
        });
        when(realm.getRoleById(eq(parentRoleId))).thenReturn(parent);
    }

    private IgaChangeRequestEntity addComposite(String crId, String parentRoleId, String childId) {
        IgaChangeRequestEntity cr = mock(IgaChangeRequestEntity.class);
        when(cr.getId()).thenReturn(crId);
        when(cr.getRealmId()).thenReturn(REALM_ID);
        when(cr.getActionType()).thenReturn("ADD_COMPOSITE");
        when(cr.getEntityId()).thenReturn(parentRoleId);
        when(cr.getRequestModel()).thenReturn(null);
        when(cr.getRowsJson()).thenReturn(
                "[{\"COMPOSITE\":\"" + parentRoleId + "\",\"CHILD_ROLE\":\"" + childId + "\"}]");
        return cr;
    }

    /** The stub signature the non-capable firstAdmin realm produces over a child set. */
    private static String expectedSig(String parentRoleId, String... childIds) {
        byte[] envelope =
                new RoleCompositeChildrenSetUnit(REALM_ID, parentRoleId, List.of(childIds)).serialize();
        try {
            return TideAttestor.FIRSTADMIN_SIG_PREFIX + Base64.getEncoder()
                    .encodeToString(MessageDigest.getInstance("SHA-256").digest(envelope));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // -------------------------------------------------------------------------
    // The reproduction
    // -------------------------------------------------------------------------

    @Test
    void twoCompositeCrsOnOneParent_leaveOneSignatureOverTheFullCommittedSet() {
        // The bulk batch: CR1 adds c-bbb and CR2 adds c-ccc to the SAME default-roles parent,
        // which already carried c-aaa. Both replays are applied, so the committed set is all
        // three children.
        committedParent(DEFAULT_ROLE_ID, PRE_CHILD, CR1_CHILD, CR2_CHILD);
        IgaChangeRequestEntity cr1 = addComposite("cr-1", DEFAULT_ROLE_ID, CR1_CHILD);
        IgaChangeRequestEntity cr2 = addComposite("cr-2", DEFAULT_ROLE_ID, CR2_CHILD);

        attestor.stampCoalescedSetUnits(session, realm, List.of(cr1, cr2));

        assertEquals(List.of(DEFAULT_ROLE_ID), stampedOwners,
                "the two CRs share one owner set, so exactly ONE fan-out must be issued "
                        + "(a per-CR stamp lets the last write clobber the first)");
        assertEquals(expectedSig(DEFAULT_ROLE_ID, PRE_CHILD, CR1_CHILD, CR2_CHILD),
                attestationColumn.get(DEFAULT_ROLE_ID),
                "the stored signature must cover the FULL committed child set, which is what "
                        + "the ork re-derives at token issue");
        assertNotEquals(expectedSig(DEFAULT_ROLE_ID, PRE_CHILD, CR1_CHILD),
                attestationColumn.get(DEFAULT_ROLE_ID),
                "a signature over pre-set + ONE CR's delta is the production failure; the DB "
                        + "holds three children, so a two-child signature fails ork verification");
        assertNotEquals(expectedSig(DEFAULT_ROLE_ID, PRE_CHILD, CR2_CHILD),
                attestationColumn.get(DEFAULT_ROLE_ID),
                "likewise for the other CR's partial set");
    }

    @Test
    void singleCompositeCr_control_signsTheCommittedSet() {
        // The single-commit control: one CR, one owner, signature over the committed set.
        committedParent(DEFAULT_ROLE_ID, PRE_CHILD, CR1_CHILD);
        IgaChangeRequestEntity cr1 = addComposite("cr-1", DEFAULT_ROLE_ID, CR1_CHILD);

        attestor.stampCoalescedSetUnits(session, realm, List.of(cr1));

        assertEquals(List.of(DEFAULT_ROLE_ID), stampedOwners);
        assertEquals(expectedSig(DEFAULT_ROLE_ID, PRE_CHILD, CR1_CHILD),
                attestationColumn.get(DEFAULT_ROLE_ID));
    }

    @Test
    void crsOnDifferentParents_stampOneSignaturePerOwner() {
        committedParent(DEFAULT_ROLE_ID, PRE_CHILD, CR1_CHILD);
        committedParent(OTHER_PARENT_ID, CR2_CHILD);
        IgaChangeRequestEntity cr1 = addComposite("cr-1", DEFAULT_ROLE_ID, CR1_CHILD);
        IgaChangeRequestEntity cr2 = addComposite("cr-2", OTHER_PARENT_ID, CR2_CHILD);

        attestor.stampCoalescedSetUnits(session, realm, List.of(cr1, cr2));

        assertEquals(List.of(DEFAULT_ROLE_ID, OTHER_PARENT_ID), stampedOwners,
                "grouping is per (unit type, owner); distinct owners each get their own stamp");
        assertEquals(expectedSig(DEFAULT_ROLE_ID, PRE_CHILD, CR1_CHILD),
                attestationColumn.get(DEFAULT_ROLE_ID));
        assertEquals(expectedSig(OTHER_PARENT_ID, CR2_CHILD),
                attestationColumn.get(OTHER_PARENT_ID));
    }

    @Test
    void nonEdgeActionTypes_touchNoOwnerSet() {
        committedParent(DEFAULT_ROLE_ID, PRE_CHILD);
        IgaChangeRequestEntity createRole = mock(IgaChangeRequestEntity.class);
        when(createRole.getId()).thenReturn("cr-create-role");
        when(createRole.getActionType()).thenReturn("CREATE_ROLE");

        attestor.stampCoalescedSetUnits(session, realm, List.of(createRole));

        assertTrue(stampedOwners.isEmpty(),
                "a CR that perturbs no per-(table, owner) set must not re-sign anything");
    }

    // -------------------------------------------------------------------------
    // The fail-closed post-stamp invariant
    // -------------------------------------------------------------------------

    @Test
    void clobberedColumn_failsClosedNamingUnitTypeAndOwner() {
        committedParent(DEFAULT_ROLE_ID, PRE_CHILD, CR1_CHILD, CR2_CHILD);
        IgaChangeRequestEntity cr1 = addComposite("cr-1", DEFAULT_ROLE_ID, CR1_CHILD);
        // Simulate a later owner-keyed fan-out replacing this commit's signature.
        columnReadOverride = expectedSig(DEFAULT_ROLE_ID, PRE_CHILD, CR1_CHILD);

        SetUnitAttestationException ex = assertThrows(SetUnitAttestationException.class,
                () -> attestor.stampCoalescedSetUnits(session, realm, List.of(cr1)));

        assertEquals("role_composite_children_set", ex.getUnitType());
        assertEquals(DEFAULT_ROLE_ID, ex.getTargetId());
        assertTrue(ex.getMessage().contains(REALM_NAME));
    }

    @Test
    void missingColumn_failsClosed() {
        committedParent(DEFAULT_ROLE_ID, PRE_CHILD, CR1_CHILD);
        IgaChangeRequestEntity cr1 = addComposite("cr-1", DEFAULT_ROLE_ID, CR1_CHILD);
        columnReadOverride = "";

        SetUnitAttestationException ex = assertThrows(SetUnitAttestationException.class,
                () -> attestor.stampCoalescedSetUnits(session, realm, List.of(cr1)));

        assertEquals("role_composite_children_set", ex.getUnitType());
        assertEquals(DEFAULT_ROLE_ID, ex.getTargetId());
    }
}
