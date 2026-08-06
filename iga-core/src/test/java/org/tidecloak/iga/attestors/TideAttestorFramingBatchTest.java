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
import org.tidecloak.iga.entities.IgaAuthorizationEntity;
import org.tidecloak.iga.entities.IgaAuthorizerEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.producer.units.AttestationUnit;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Coverage for the APPROVAL-time answer to the frozen-carrier hazard: framing a change
 * request's set units over its whole framing batch instead of over itself alone.
 *
 * <p>A multiAdmin approval carrier freezes the unit bytes the enclave framed. Framing each
 * change request as {@code pre-set + its own delta} therefore gave two change requests against
 * one owner two DIFFERENT projections of that owner, and whichever committed second left a
 * quorum signature over a set the database no longer held. Framing both over the state after
 * the whole group makes their bytes for that owner IDENTICAL, which is what these tests pin,
 * together with the batch bookkeeping (grouping, ordering, identity) and the byte-provenance
 * digest that fails a commit closed when the committed model does not re-derive the framed
 * bytes.
 *
 * <p><b>Harness boundary.</b> Mockito, no database and no ork, so:
 * <ul>
 *   <li>the post-batch model is represented directly (the parent role's committed composite
 *       children), rather than produced by the scratch replay that reaches it in production:
 *       {@code IgaScratchUnitBuilder} needs a real session factory and a real transaction;</li>
 *   <li>{@code isRealSigningCapable} cannot be made true from a unit test (it needs a
 *       provisioned tide-vendor-key component AND the THRESHOLD_T/N environment), so the
 *       CAPABILITY gate in front of the digest check is stack-only. The comparison itself is
 *       covered here through {@code requireFramedUnitHash}, which is the same call the gated
 *       path makes.</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TideAttestorFramingBatchTest {

    private static final String REALM_ID = "realm-framing-uuid";
    private static final String REALM_NAME = "framing-realm";
    private static final String PARENT_ID = "parent-role-id";
    private static final String OTHER_PARENT_ID = "other-parent-role-id";

    private static final String PRE_CHILD = "c-aaa";
    private static final String CR1_CHILD = "c-bbb";
    private static final String CR2_CHILD = "c-ccc";

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock JpaConnectionProvider jpa;
    @Mock EntityManager em;

    /** parent role id -> the children the committed model holds for that parent. */
    private final Map<String, List<String>> committedChildren = new LinkedHashMap<>();
    /** The PENDING edge change requests the pending-CR projection returns. */
    private final List<IgaChangeRequestEntity> pendingEdgeCrs = new ArrayList<>();
    /** Every change request the entity manager can resolve by id. */
    private final Map<String, IgaChangeRequestEntity> crsById = new LinkedHashMap<>();

    private TideAttestor attestor;

    @BeforeEach
    void setUp() {
        when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa);
        when(jpa.getEntityManager()).thenReturn(em);
        when(realm.getId()).thenReturn(REALM_ID);
        when(realm.getName()).thenReturn(REALM_NAME);
        when(realm.getAttribute("iga.attestor")).thenReturn(TideAttestor.ID);
        when(realm.getComponentsStream()).thenAnswer(inv -> Stream.empty());
        when(em.find(eq(IgaChangeRequestEntity.class), anyString()))
                .thenAnswer(inv -> crsById.get(inv.getArgument(1, String.class)));

        stubEmptyAuthorizerRows();
        stubEmptyAuthorizations();
        stubPendingEdgeCrProjection();
        stubPendingFramedCrProjection();
        attestor = new TideAttestor(session);
    }

    @SuppressWarnings("unchecked")
    private void stubEmptyAuthorizerRows() {
        TypedQuery<IgaAuthorizerEntity> q = mock(TypedQuery.class);
        when(em.createNamedQuery(eq("IgaAuthorizer.findByRealm"), eq(IgaAuthorizerEntity.class)))
                .thenReturn(q);
        when(q.setParameter(anyString(), any())).thenReturn(q);
        when(q.getResultStream()).thenAnswer(inv -> Stream.empty());
    }

    @SuppressWarnings("unchecked")
    private void stubEmptyAuthorizations() {
        TypedQuery<IgaAuthorizationEntity> q = mock(TypedQuery.class);
        when(em.createNamedQuery(eq("IgaAuthorization.findByChangeRequest"),
                eq(IgaAuthorizationEntity.class))).thenReturn(q);
        when(q.setParameter(anyString(), any())).thenReturn(q);
        when(q.getResultList()).thenAnswer(inv -> List.of());
    }

    /** {@code IgaChangeRequestService.listPendingByActionTypeIn} builds its JPQL inline. */
    @SuppressWarnings("unchecked")
    private void stubPendingEdgeCrProjection() {
        TypedQuery<IgaChangeRequestEntity> q = mock(TypedQuery.class);
        when(em.createQuery(anyString(), eq(IgaChangeRequestEntity.class))).thenReturn(q);
        when(q.setParameter(anyString(), any())).thenReturn(q);
        when(q.setMaxResults(anyInt())).thenReturn(q);
        when(q.getResultList()).thenAnswer(inv -> new ArrayList<>(pendingEdgeCrs));
    }

    @SuppressWarnings("unchecked")
    private void stubPendingFramedCrProjection() {
        TypedQuery<IgaChangeRequestEntity> q = mock(TypedQuery.class);
        when(em.createNamedQuery(eq("IgaChangeRequest.findPendingWithRequestBatch"),
                eq(IgaChangeRequestEntity.class))).thenReturn(q);
        when(q.setParameter(anyString(), any())).thenReturn(q);
        when(q.setMaxResults(anyInt())).thenReturn(q);
        when(q.getResultList()).thenAnswer(inv -> {
            List<IgaChangeRequestEntity> framed = new ArrayList<>();
            for (IgaChangeRequestEntity cr : crsById.values()) {
                if ("PENDING".equals(cr.getStatus()) && cr.getRequestBatch() != null) {
                    framed.add(cr);
                }
            }
            return framed;
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

    private IgaChangeRequestEntity addComposite(String crId, long createdAt, String parentRoleId,
                                               String childId) {
        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setId(crId);
        cr.setRealmId(REALM_ID);
        cr.setStatus("PENDING");
        cr.setActionType("ADD_COMPOSITE");
        cr.setEntityType("ROLE");
        cr.setEntityId(parentRoleId);
        cr.setCreatedAt(createdAt);
        cr.setRowsJson("[{\"COMPOSITE\":\"" + parentRoleId + "\",\"CHILD_ROLE\":\"" + childId + "\"}]");
        crsById.put(crId, cr);
        pendingEdgeCrs.add(cr);
        return cr;
    }

    /** The ordered unit CBOR this change request frames over the model as it currently stands. */
    private byte[][] framedCbor(IgaChangeRequestEntity cr) {
        List<AttestationUnit> units =
                attestor.buildAllCrUnits(session, realm, cr, /* modelAlreadyPostChange */ true);
        byte[][] out = new byte[units.size()][];
        for (int i = 0; i < units.size(); i++) {
            out[i] = units.get(i).serialize();
        }
        return out;
    }

    // -------------------------------------------------------------------------
    // Framing over the batch is what makes two change requests agree on the owner
    // -------------------------------------------------------------------------

    @Test
    void crsSharingAnOwner_frameIdenticalBytesOverThePostBatchModel() {
        // The state the batch scratch-replay reaches: BOTH deltas applied.
        committedParent(PARENT_ID, PRE_CHILD, CR1_CHILD, CR2_CHILD);
        IgaChangeRequestEntity cr1 = addComposite("cr-1", 1L, PARENT_ID, CR1_CHILD);
        IgaChangeRequestEntity cr2 = addComposite("cr-2", 2L, PARENT_ID, CR2_CHILD);

        byte[][] framed1 = framedCbor(cr1);
        byte[][] framed2 = framedCbor(cr2);

        assertEquals(1, framed1.length, "an ADD_COMPOSITE frames exactly its owner's child set");
        assertArrayEquals(framed1[0], framed2[0],
                "framed over the whole batch, both change requests describe the SAME owner set, "
                        + "so the bytes their carriers freeze are identical and either may be the "
                        + "one that stamps the column");
        assertEquals(TideAttestor.framedUnitsHash(framed1), TideAttestor.framedUnitsHash(framed2));
    }

    @Test
    void crsSharingAnOwner_frameDifferentBytesWhenFramedOverOnlyOneDelta() {
        // The production defect, reproduced at the framing input: the model carries only CR1's
        // delta, which is what per-change-request framing projected.
        committedParent(PARENT_ID, PRE_CHILD, CR1_CHILD);
        IgaChangeRequestEntity cr1 = addComposite("cr-1", 1L, PARENT_ID, CR1_CHILD);
        IgaChangeRequestEntity cr2 = addComposite("cr-2", 2L, PARENT_ID, CR2_CHILD);

        assertFalse(Arrays.equals(framedCbor(cr1)[0], framedCbor(cr2)[0]),
                "a projection that omits the sibling's delta is exactly the byte set the ork "
                        + "later fails to re-derive");
    }

    // -------------------------------------------------------------------------
    // Batch resolution, ordering and identity
    // -------------------------------------------------------------------------

    @Test
    void framingBatch_groupsEveryPendingCrOnTheSameOwner_inCommitOrder() {
        committedParent(PARENT_ID, PRE_CHILD, CR1_CHILD, CR2_CHILD);
        IgaChangeRequestEntity cr1 = addComposite("cr-1", 1L, PARENT_ID, CR1_CHILD);
        IgaChangeRequestEntity cr2 = addComposite("cr-2", 2L, PARENT_ID, CR2_CHILD);

        assertEquals(List.of("cr-1", "cr-2"),
                TideAttestor.framingBatchIds(attestor.resolveFramingBatch(session, realm, cr2)),
                "the batch is every pending change request on the owner, oldest first");
        assertEquals(TideAttestor.framingBatchIds(attestor.resolveFramingBatch(session, realm, cr1)),
                TideAttestor.framingBatchIds(attestor.resolveFramingBatch(session, realm, cr2)),
                "both members resolve the SAME batch, so both frame the same projection");
    }

    @Test
    void framingBatch_isJustTheChangeRequestWhenNothingSharesItsOwner() {
        committedParent(PARENT_ID, PRE_CHILD, CR1_CHILD);
        committedParent(OTHER_PARENT_ID, CR2_CHILD);
        IgaChangeRequestEntity cr1 = addComposite("cr-1", 1L, PARENT_ID, CR1_CHILD);
        addComposite("cr-2", 2L, OTHER_PARENT_ID, CR2_CHILD);

        assertEquals(List.of("cr-1"),
                TideAttestor.framingBatchIds(attestor.resolveFramingBatch(session, realm, cr1)),
                "distinct owner sets never contend, so the framing is unchanged from before");
    }

    @Test
    void framingBatch_isJustTheChangeRequestForANonEdgeAction() {
        IgaChangeRequestEntity createRole = new IgaChangeRequestEntity();
        createRole.setId("cr-create-role");
        createRole.setRealmId(REALM_ID);
        createRole.setStatus("PENDING");
        createRole.setActionType("CREATE_ROLE");

        assertEquals(List.of("cr-create-role"),
                TideAttestor.framingBatchIds(attestor.resolveFramingBatch(session, realm, createRole)));
    }

    @Test
    void framingBatchId_isDeterministicInTheMemberSetAndMovesWhenMembershipMoves() {
        String ab = TideAttestor.framingBatchId(REALM_ID, List.of("cr-1", "cr-2"));
        assertEquals(ab, TideAttestor.framingBatchId(REALM_ID, List.of("cr-2", "cr-1")),
                "the id must not depend on discovery order, so every member stamps the same value");
        assertNotEquals(ab, TideAttestor.framingBatchId(REALM_ID, List.of("cr-1", "cr-2", "cr-3")),
                "a group that gained a member is a different group");
        assertNotEquals(ab, TideAttestor.framingBatchId(REALM_ID, List.of("cr-1")),
                "a group that lost a member is a different group");
        assertNotEquals(ab, TideAttestor.framingBatchId("other-realm", List.of("cr-1", "cr-2")));
        assertNull(TideAttestor.framingBatchId(REALM_ID, List.of()));
    }

    // -------------------------------------------------------------------------
    // The byte-provenance digest
    // -------------------------------------------------------------------------

    @Test
    void framedUnitsHash_isSensitiveToContentAndToUnitBoundaries() {
        byte[][] ab = {"ab".getBytes(StandardCharsets.UTF_8), "c".getBytes(StandardCharsets.UTF_8)};
        byte[][] aBc = {"a".getBytes(StandardCharsets.UTF_8), "bc".getBytes(StandardCharsets.UTF_8)};
        assertNotEquals(TideAttestor.framedUnitsHash(ab), TideAttestor.framedUnitsHash(aBc),
                "the digest is length-prefixed per unit, so a different split of the same "
                        + "concatenation is a different framing");
        assertEquals(TideAttestor.framedUnitsHash(ab), TideAttestor.framedUnitsHash(
                new byte[][]{"ab".getBytes(StandardCharsets.UTF_8),
                        "c".getBytes(StandardCharsets.UTF_8)}));
        assertNull(TideAttestor.framedUnitsHash(new byte[0][]));
    }

    // -------------------------------------------------------------------------
    // WHEN the digest is verified. This is the regression guard for the placement
    // bug that blocked a dev realm: verifying a member right after its OWN replay
    // compares against pre + that member's delta, while its carrier described
    // pre + EVERY member's delta, so it mismatched by construction for every
    // member of a group except the one that replayed last.
    // -------------------------------------------------------------------------

    /**
     * The production verification pass with the realm CAPABILITY gate removed, which a unit
     * test cannot satisfy. Same predicate ({@link TideAttestor#hasAppliedFramingBasis}) and
     * same per-member action ({@link TideAttestor#requireFramedUnitHash}) as
     * {@code verifyFramedUnitsWithAppliedBasis}, so a placement regression fails here.
     */
    private void verifyPass(Set<String> verified, IgaChangeRequestEntity... members) {
        for (IgaChangeRequestEntity member : members) {
            if (verified.contains(member.getId())
                    || !TideAttestor.hasAppliedFramingBasis(em, member)) {
                continue;
            }
            TideAttestor.requireFramedUnitHash(member, member.getRequestUnitsHash(),
                    framedCbor(member));
            verified.add(member.getId());
        }
    }

    private void frameOverCurrentModel(IgaChangeRequestEntity cr, List<String> batch) {
        cr.setRequestBatchList(batch);
        cr.setRequestModel("carrier-" + cr.getId());
        cr.setRequestUnitsHash(TideAttestor.framedUnitsHash(framedCbor(cr)));
    }

    @Test
    void groupMemberDigest_isVerifiedOnlyAfterTheWHOLEGroupHasReplayed() {
        // Phase 1: both members framed over the post-batch model (pre + d1 + d2).
        committedParent(PARENT_ID, PRE_CHILD, CR1_CHILD, CR2_CHILD);
        IgaChangeRequestEntity cr1 = addComposite("cr-1", 1L, PARENT_ID, CR1_CHILD);
        IgaChangeRequestEntity cr2 = addComposite("cr-2", 2L, PARENT_ID, CR2_CHILD);
        frameOverCurrentModel(cr1, List.of("cr-1", "cr-2"));
        frameOverCurrentModel(cr2, List.of("cr-1", "cr-2"));

        // The drive begins against the pre-batch model.
        committedChildren.put(PARENT_ID, List.of(PRE_CHILD));
        Set<String> verified = new LinkedHashSet<>();

        // Step 1: cr-1 replays. The model is pre + d1, which is NOT what either carrier framed.
        committedChildren.put(PARENT_ID, List.of(PRE_CHILD, CR1_CHILD));
        cr1.setStatus("APPROVED");
        assertFalse(TideAttestor.hasAppliedFramingBasis(em, cr1),
                "cr-2 has not replayed, so the state cr-1's carrier describes is not reached yet");
        attestor.verifyFramedUnitsWithAppliedBasis(session, realm, List.of(cr1, cr2), verified);
        assertTrue(verified.isEmpty(),
                "nothing may be verified here: this is the placement that mismatched by "
                        + "construction and blocked every commit");
        assertThrows(FramingBatchException.class,
                () -> TideAttestor.requireFramedUnitHash(cr1, cr1.getRequestUnitsHash(),
                        framedCbor(cr1)),
                "verifying cr-1 after its OWN replay would fail, which is the bug this pins");

        // Step 2: cr-2 replays. The model is now pre + d1 + d2, exactly what both framed.
        committedChildren.put(PARENT_ID, List.of(PRE_CHILD, CR1_CHILD, CR2_CHILD));
        cr2.setStatus("APPROVED");
        verifyPass(verified, cr1, cr2);

        assertEquals(List.of("cr-1", "cr-2"), new ArrayList<>(verified),
                "both members verify against the post-group model, and both PASS");
        attestor.requireAllFramedUnitsVerified(List.of(cr1, cr2), verified);
    }

    @Test
    void memberFramedBeforeTheGroupGrew_isVerifiedAtItsOwnEarlierBasis() {
        // cr-1 was framed while it was alone and its batch was frozen by its first approval;
        // cr-2 arrived later and framed over both. Verifying everything at the END of the drive
        // would be past cr-1's basis, so the check must fire per member.
        committedParent(PARENT_ID, PRE_CHILD, CR1_CHILD);
        IgaChangeRequestEntity cr1 = addComposite("cr-1", 1L, PARENT_ID, CR1_CHILD);
        frameOverCurrentModel(cr1, List.of("cr-1"));

        committedParent(PARENT_ID, PRE_CHILD, CR1_CHILD, CR2_CHILD);
        IgaChangeRequestEntity cr2 = addComposite("cr-2", 2L, PARENT_ID, CR2_CHILD);
        frameOverCurrentModel(cr2, List.of("cr-1", "cr-2"));

        committedChildren.put(PARENT_ID, List.of(PRE_CHILD));
        Set<String> verified = new LinkedHashSet<>();

        // cr-1 replays: its basis is itself alone, so it verifies NOW and passes.
        committedChildren.put(PARENT_ID, List.of(PRE_CHILD, CR1_CHILD));
        cr1.setStatus("APPROVED");
        verifyPass(verified, cr1, cr2);
        assertEquals(List.of("cr-1"), new ArrayList<>(verified));

        // cr-2 replays: the model moves past cr-1's basis, and cr-2 verifies against it.
        committedChildren.put(PARENT_ID, List.of(PRE_CHILD, CR1_CHILD, CR2_CHILD));
        cr2.setStatus("APPROVED");
        verifyPass(verified, cr1, cr2);
        assertEquals(List.of("cr-1", "cr-2"), new ArrayList<>(verified));

        assertThrows(FramingBatchException.class,
                () -> TideAttestor.requireFramedUnitHash(cr1, cr1.getRequestUnitsHash(),
                        framedCbor(cr1)),
                "deferring cr-1 to the end of the drive would compare it against a model that "
                        + "has moved past what it framed");
    }

    @Test
    void aMemberThatNeverReachedItsBasis_failsClosedRatherThanCommittingUnverified() {
        committedParent(PARENT_ID, PRE_CHILD, CR1_CHILD, CR2_CHILD);
        IgaChangeRequestEntity cr1 = addComposite("cr-1", 1L, PARENT_ID, CR1_CHILD);
        IgaChangeRequestEntity cr2 = addComposite("cr-2", 2L, PARENT_ID, CR2_CHILD);
        frameOverCurrentModel(cr1, List.of("cr-1", "cr-2"));
        cr1.setStatus("APPROVED");

        FramingBatchException ex = assertThrows(FramingBatchException.class,
                () -> attestor.requireAllFramedUnitsVerified(List.of(cr1), new LinkedHashSet<>()));

        assertEquals(FramingBatchException.CODE_BATCH_BROKEN, ex.getCode());
        assertEquals("cr-1", ex.getChangeRequestId());
        assertEquals("PENDING", cr2.getStatus(), "cr-2 never applied, which is why cr-1 is unverifiable");
    }

    @Test
    void framedUnitHash_matchesWhenTheCommittedModelIsTheModelThatWasFramed() {
        committedParent(PARENT_ID, PRE_CHILD, CR1_CHILD, CR2_CHILD);
        IgaChangeRequestEntity cr1 = addComposite("cr-1", 1L, PARENT_ID, CR1_CHILD);
        String framed = TideAttestor.framedUnitsHash(framedCbor(cr1));

        TideAttestor.requireFramedUnitHash(cr1, framed, framedCbor(cr1));
    }

    @Test
    void framedUnitHash_failsClosedWhenTheCommittedModelMoved() {
        // Frame over the whole batch, then commit a model that only carries one delta, which is the
        // shape a partially applied batch would leave behind.
        committedParent(PARENT_ID, PRE_CHILD, CR1_CHILD, CR2_CHILD);
        IgaChangeRequestEntity cr1 = addComposite("cr-1", 1L, PARENT_ID, CR1_CHILD);
        String framed = TideAttestor.framedUnitsHash(framedCbor(cr1));

        committedChildren.put(PARENT_ID, List.of(PRE_CHILD, CR1_CHILD));
        FramingBatchException ex = assertThrows(FramingBatchException.class,
                () -> TideAttestor.requireFramedUnitHash(cr1, framed, framedCbor(cr1)));

        assertEquals(FramingBatchException.CODE_UNIT_HASH_MISMATCH, ex.getCode());
        assertEquals("cr-1", ex.getChangeRequestId());
        assertTrue(ex.getMessage().contains(framed),
                "the refusal names the digest the quorum actually signed");
    }

    // -------------------------------------------------------------------------
    // Denial invalidates the group
    // -------------------------------------------------------------------------

    @Test
    void denyingAMember_invalidatesEveryCarrierFramedWithIt() {
        committedParent(PARENT_ID, PRE_CHILD, CR1_CHILD, CR2_CHILD);
        IgaChangeRequestEntity cr1 = addComposite("cr-1", 1L, PARENT_ID, CR1_CHILD);
        IgaChangeRequestEntity cr2 = addComposite("cr-2", 2L, PARENT_ID, CR2_CHILD);
        for (IgaChangeRequestEntity member : List.of(cr1, cr2)) {
            member.setRequestModel("carrier-" + member.getId());
            member.setRequestBatchList(List.of("cr-1", "cr-2"));
            member.setRequestUnitsHash("digest");
        }
        // cr-1 is denied: cr-2's carrier now projects a set that will never exist.
        cr1.setStatus("DENIED");

        assertEquals(1, attestor.invalidateFramingBatchOf(session, realm, em, "cr-1"));

        assertNull(cr2.getRequestModel(), "the survivor must be re-approved, not committed as framed");
        assertNull(cr2.getRequestBatch());
        assertNull(cr2.getRequestUnitsHash());
    }

    // -------------------------------------------------------------------------
    // A frozen carrier whose basis has become unreachable, detected at APPROVAL
    // -------------------------------------------------------------------------

    @Test
    void accumulatedCarrier_isSoundWhileEveryMemberIsStillPendingOrApplied() {
        committedParent(PARENT_ID, PRE_CHILD, CR1_CHILD, CR2_CHILD);
        IgaChangeRequestEntity cr1 = addComposite("cr-1", 1L, PARENT_ID, CR1_CHILD);
        IgaChangeRequestEntity cr2 = addComposite("cr-2", 2L, PARENT_ID, CR2_CHILD);
        cr1.setRequestBatchList(List.of("cr-1", "cr-2"));

        assertTrue(attestor.unreachableFramingBasis(session, realm, cr1).isEmpty(),
                "both members are still pending, so the framed state is still reachable");

        cr2.setStatus("APPROVED");
        assertTrue(attestor.unreachableFramingBasis(session, realm, cr1).isEmpty(),
                "a member that has already applied is exactly what the framing assumed");
    }

    @Test
    void accumulatedCarrier_whoseMemberLeftThePool_isReportedUnreachable() {
        committedParent(PARENT_ID, PRE_CHILD, CR1_CHILD, CR2_CHILD);
        IgaChangeRequestEntity cr1 = addComposite("cr-1", 1L, PARENT_ID, CR1_CHILD);
        IgaChangeRequestEntity cr2 = addComposite("cr-2", 2L, PARENT_ID, CR2_CHILD);
        cr1.setRequestBatchList(List.of("cr-1", "cr-2"));
        cr2.setStatus("DENIED");

        assertEquals(List.of("cr-2"), attestor.unreachableFramingBasis(session, realm, cr1),
                "the denied member's delta will never apply, so the accumulated carrier can "
                        + "never satisfy its own digest and must be rebuilt while the enclave "
                        + "is open rather than failing at commit");
    }

    @Test
    void newcomerOnTheSameOwner_doesNotMakeAnApprovedCarrierUnreachable() {
        // The frozen-membership rule: a change request filed after the group was approved forms
        // its own superset batch and waits. It must NOT invalidate the approved carriers, which
        // would throw away the dokens the enclave already collected.
        committedParent(PARENT_ID, PRE_CHILD, CR1_CHILD, CR2_CHILD);
        IgaChangeRequestEntity cr1 = addComposite("cr-1", 1L, PARENT_ID, CR1_CHILD);
        IgaChangeRequestEntity cr2 = addComposite("cr-2", 2L, PARENT_ID, CR2_CHILD);
        cr1.setRequestBatchList(List.of("cr-1", "cr-2"));
        cr2.setRequestBatchList(List.of("cr-1", "cr-2"));

        IgaChangeRequestEntity cr3 = addComposite("cr-3", 3L, PARENT_ID, "c-ddd");

        assertTrue(attestor.unreachableFramingBasis(session, realm, cr1).isEmpty());
        assertEquals(List.of("cr-1", "cr-2", "cr-3"),
                TideAttestor.framingBatchIds(attestor.resolveFramingBatch(session, realm, cr3)),
                "the newcomer frames over the whole owner, including the members that commit "
                        + "before it");
    }

    @Test
    void denyingACrNothingWasFramedWith_invalidatesNothing() {
        committedParent(PARENT_ID, PRE_CHILD, CR1_CHILD);
        committedParent(OTHER_PARENT_ID, CR2_CHILD);
        IgaChangeRequestEntity cr1 = addComposite("cr-1", 1L, PARENT_ID, CR1_CHILD);
        IgaChangeRequestEntity cr2 = addComposite("cr-2", 2L, OTHER_PARENT_ID, CR2_CHILD);
        cr1.setRequestModel("carrier-1");
        cr1.setRequestBatchList(List.of("cr-1"));
        cr2.setRequestModel("carrier-2");
        cr2.setRequestBatchList(List.of("cr-2"));

        assertEquals(0, attestor.invalidateFramingBatchOf(session, realm, em, "cr-2"));
        assertEquals("carrier-1", cr1.getRequestModel(),
                "a change request on another owner was never framed against this one");
    }
}
