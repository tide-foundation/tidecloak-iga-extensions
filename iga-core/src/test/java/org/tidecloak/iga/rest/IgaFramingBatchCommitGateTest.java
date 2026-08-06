package org.tidecloak.iga.rest;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.attestors.FramingBatchException;
import org.tidecloak.iga.attestors.IgaAttestor;
import org.tidecloak.iga.attestors.TideAttestor;
import org.tidecloak.iga.entities.IgaAuthorizationEntity;
import org.tidecloak.iga.entities.IgaAuthorizerEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.entities.IgaRolePolicyEntity;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

/**
 * The commit-side half of framing batches: a group whose carriers were framed together must
 * apply together or not at all.
 *
 * <p>Phase 1 frames every member of the group over the state after ALL of them, so a member's
 * frozen bytes describe the post-group model. Committing one on its own would leave the owner
 * set carrying a quorum signature for a state the database does not hold: the same failure
 * the per-request framing produced, just relocated. These tests pin the two refusals that
 * prevent it, and the fact that an uncontested change request is untouched by any of it.
 *
 * <p><b>Harness boundary.</b> Mockito, no database and no ork, so the gate is exercised
 * directly rather than through a real commit: the SUCCESS path (the group actually applying in
 * one transaction) runs the whole replay pipeline per member and is stack-only.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class IgaFramingBatchCommitGateTest {

    private static final String REALM_ID = "realm-framing-gate-uuid";

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock(answer = Answers.RETURNS_DEEP_STUBS) AdminPermissionEvaluator auth;
    @Mock JpaConnectionProvider jpa;
    @Mock EntityManager em;

    private final Map<String, IgaChangeRequestEntity> crsById = new LinkedHashMap<>();
    private final Map<String, Integer> authCounts = new LinkedHashMap<>();

    private IgaAdminResource resource;

    @BeforeEach
    void setUp() {
        lenient().when(realm.getId()).thenReturn(REALM_ID);
        lenient().when(realm.getName()).thenReturn("framing-gate-realm");
        lenient().when(realm.getAttribute("iga.attestor")).thenReturn(TideAttestor.ID);
        lenient().when(realm.getComponentsStream()).thenAnswer(inv -> Stream.empty());
        lenient().when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa);
        lenient().when(jpa.getEntityManager()).thenReturn(em);
        lenient().when(session.getProvider(IgaAttestor.class, TideAttestor.ID))
                .thenReturn(new TideAttestor(session));
        lenient().when(em.find(eq(IgaChangeRequestEntity.class), anyString()))
                .thenAnswer(inv -> crsById.get(inv.getArgument(1, String.class)));

        stubMultiAdminAuthorizerRow();
        stubNoTideRealmAdminPolicy();
        stubAuthorizationCounts();
        stubPendingFramedCrProjection();

        resource = new IgaAdminResource(session, realm, auth);
    }

    @SuppressWarnings("unchecked")
    private void stubMultiAdminAuthorizerRow() {
        IgaAuthorizerEntity row = new IgaAuthorizerEntity();
        row.setRealmId(REALM_ID);
        row.setMode(TideAttestor.MODE_MULTI_ADMIN);
        TypedQuery<IgaAuthorizerEntity> q = mock(TypedQuery.class);
        lenient().when(em.createNamedQuery(eq("IgaAuthorizer.findByRealm"), eq(IgaAuthorizerEntity.class)))
                .thenReturn(q);
        lenient().when(q.setParameter(anyString(), any())).thenReturn(q);
        lenient().when(q.getResultStream()).thenAnswer(inv -> Stream.of(row));
    }

    @SuppressWarnings("unchecked")
    private void stubNoTideRealmAdminPolicy() {
        TypedQuery<IgaRolePolicyEntity> q = mock(TypedQuery.class);
        lenient().when(em.createNamedQuery(eq("IgaRolePolicy.findByRealmAndName"),
                eq(IgaRolePolicyEntity.class))).thenReturn(q);
        lenient().when(q.setParameter(anyString(), any())).thenReturn(q);
        lenient().when(q.getResultStream()).thenAnswer(inv -> Stream.empty());
    }

    /** Per-change-request approval rows, so a member can be held sub-quorum on purpose. */
    @SuppressWarnings("unchecked")
    private void stubAuthorizationCounts() {
        TypedQuery<IgaAuthorizationEntity> q = mock(TypedQuery.class);
        String[] boundCrId = new String[1];
        lenient().when(em.createNamedQuery(eq("IgaAuthorization.findByChangeRequest"),
                eq(IgaAuthorizationEntity.class))).thenReturn(q);
        lenient().when(q.setParameter(anyString(), any())).thenAnswer(inv -> {
            if ("changeRequestId".equals(inv.getArgument(0))) {
                boundCrId[0] = String.valueOf(inv.getArgument(1));
            }
            return q;
        });
        lenient().when(q.getResultList()).thenAnswer(inv -> {
            List<IgaAuthorizationEntity> rows = new ArrayList<>();
            for (int i = 0; i < authCounts.getOrDefault(boundCrId[0], 0); i++) {
                rows.add(new IgaAuthorizationEntity());
            }
            return rows;
        });
    }

    @SuppressWarnings("unchecked")
    private void stubPendingFramedCrProjection() {
        TypedQuery<IgaChangeRequestEntity> q = mock(TypedQuery.class);
        lenient().when(em.createNamedQuery(eq("IgaChangeRequest.findPendingWithRequestBatch"),
                eq(IgaChangeRequestEntity.class))).thenReturn(q);
        lenient().when(q.setParameter(anyString(), any())).thenReturn(q);
        lenient().when(q.setMaxResults(anyInt())).thenReturn(q);
        lenient().when(q.getResultList()).thenAnswer(inv -> {
            List<IgaChangeRequestEntity> framed = new ArrayList<>();
            for (IgaChangeRequestEntity cr : crsById.values()) {
                if ("PENDING".equals(cr.getStatus()) && cr.getRequestBatch() != null) {
                    framed.add(cr);
                }
            }
            return framed;
        });
    }

    private IgaChangeRequestEntity framedCr(String id, long createdAt, List<String> batch,
                                            int approvals) {
        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setId(id);
        cr.setRealmId(REALM_ID);
        cr.setStatus("PENDING");
        cr.setActionType("ADD_COMPOSITE");
        cr.setEntityType("ROLE");
        cr.setCreatedAt(createdAt);
        cr.setRowsJson("[]");
        cr.setRequestModel("carrier-" + id);
        cr.setRequestUnitsHash("digest-" + id);
        cr.setRequestBatchList(batch);
        crsById.put(id, cr);
        authCounts.put(id, approvals);
        return cr;
    }

    private Response commitFramingBatch(IgaChangeRequestEntity cr) throws Exception {
        Method m = IgaAdminResource.class.getDeclaredMethod("commitFramingBatch",
                IgaChangeRequestEntity.class, EntityManager.class, String.class);
        m.setAccessible(true);
        return (Response) m.invoke(resource, cr, em, cr.getId());
    }

    // -------------------------------------------------------------------------

    @Test
    @SuppressWarnings("unchecked")
    void partiallyResolvedBatch_isRefusedFailClosedAndTheGroupIsInvalidated() throws Exception {
        IgaChangeRequestEntity cr1 = framedCr("cr-1", 1L, List.of("cr-1", "cr-2"), 1);
        IgaChangeRequestEntity cr2 = framedCr("cr-2", 2L, List.of("cr-1", "cr-2"), 1);
        // cr-1 left the pool after the group was framed. cr-2's bytes assume it applied.
        cr1.setStatus("DENIED");

        Response resp = commitFramingBatch(cr2);

        assertNotNull(resp);
        assertEquals(409, resp.getStatus(),
                "a member that will never apply makes every carrier in the group unusable");
        Map<String, Object> body = (Map<String, Object>) resp.getEntity();
        assertEquals(FramingBatchException.CODE_BATCH_BROKEN, body.get("error"));
        assertEquals(List.of("cr-1"), body.get("brokenMembers"));
        assertNull(cr2.getRequestModel(), "the group's carriers are cleared so it is re-approved");
        assertNull(cr2.getRequestBatch());
        assertNull(cr2.getRequestUnitsHash());
    }

    @Test
    @SuppressWarnings("unchecked")
    void batchWithASubQuorumMember_waitsWithoutThrowingAwayTheCollectedApprovals()
            throws Exception {
        IgaChangeRequestEntity cr1 = framedCr("cr-1", 1L, List.of("cr-1", "cr-2"), 0);
        IgaChangeRequestEntity cr2 = framedCr("cr-2", 2L, List.of("cr-1", "cr-2"), 1);

        Response resp = commitFramingBatch(cr2);

        assertNotNull(resp);
        assertEquals(412, resp.getStatus(),
                "the group is intact, it is simply not fully approved yet");
        Map<String, Object> body = (Map<String, Object>) resp.getEntity();
        assertEquals("FRAMING_BATCH_NOT_READY", body.get("error"));
        assertEquals(List.of("cr-1", "cr-2"), body.get("batch"));
        List<Map<String, Object>> pendingMembers = (List<Map<String, Object>>) body.get("pendingMembers");
        assertEquals(1, pendingMembers.size());
        assertEquals("cr-1", pendingMembers.get(0).get("crId"));
        assertEquals("carrier-cr-2", cr2.getRequestModel(),
                "a wait must not discard the dokens the enclave already collected");
        assertEquals("carrier-cr-1", cr1.getRequestModel());
    }

    @Test
    void batchClosureFollowsCarriersFramedBeforeTheGroupGrew() throws Exception {
        // cr-1 was framed while it was alone; cr-2 arrived later and framed over both. Committing
        // cr-2 must therefore apply cr-1 first, so the closure names it even though cr-1's own
        // list does not.
        framedCr("cr-1", 1L, List.of("cr-1"), 0);
        IgaChangeRequestEntity cr2 = framedCr("cr-2", 2L, List.of("cr-1", "cr-2"), 1);

        Response resp = commitFramingBatch(cr2);

        Map<?, ?> body = (Map<?, ?>) resp.getEntity();
        assertEquals(List.of("cr-1", "cr-2"), body.get("batch"),
                "the closure is ordered oldest first, which is the order the batch was framed in");
    }

    @Test
    void uncontestedChangeRequest_isNotBatchedAtAll() throws Exception {
        IgaChangeRequestEntity cr = framedCr("cr-solo", 1L, List.of("cr-solo"), 1);

        assertNull(commitFramingBatch(cr),
                "a one-member framing batch runs the ordinary single-change-request pipeline");
    }

    @Test
    void legacyCarrierWithNoFramingBatch_isNotBatchedAtAll() throws Exception {
        IgaChangeRequestEntity cr = framedCr("cr-legacy", 1L, List.of(), 1);
        cr.setRequestBatch(null);

        assertNull(commitFramingBatch(cr),
                "a carrier that predates the framing batch keeps the legacy behaviour and is "
                        + "covered by the contested-owner backstop instead");
    }

    @Test
    @SuppressWarnings("unchecked")
    void alreadyAppliedMember_isNotTreatedAsBroken() throws Exception {
        IgaChangeRequestEntity cr1 = framedCr("cr-1", 1L, List.of("cr-1", "cr-2"), 1);
        // Held sub-quorum so the gate reports its decision instead of running the replay
        // pipeline, which needs the stack.
        framedCr("cr-2", 2L, List.of("cr-1", "cr-2"), 0);
        // cr-1 applied earlier in this same drain; the framing assumed exactly that.
        cr1.setStatus("APPROVED");

        Response resp = commitFramingBatch(crsById.get("cr-2"));

        assertEquals(412, resp.getStatus(),
                "an APPROVED member has applied, which is what the framing projected. It is not "
                        + "a broken group");
        Map<String, Object> body = (Map<String, Object>) resp.getEntity();
        assertEquals("FRAMING_BATCH_NOT_READY", body.get("error"));
        List<Map<String, Object>> pendingMembers = (List<Map<String, Object>>) body.get("pendingMembers");
        assertEquals(List.of("cr-2"), List.of(pendingMembers.get(0).get("crId")));
        assertEquals(1, pendingMembers.size());
    }
}
