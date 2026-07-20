package org.tidecloak.iga.rest;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.entities.IgaAuthorizerEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests the multiAdmin commit-ordering gate on the single-CR commit path
 * ({@code POST /iga/change-requests/{id}/commit}).
 *
 * <p>A {@code REGEN_ADMIN_POLICY} commit bumps {@code IGA_ROLE_POLICY.threshold}
 * 1->2, which would instantly re-gate any still-PENDING tide-realm-admin
 * GRANT/REVOKE assignment CR from 1/1 to 1/2 (stranding it). The guard refuses
 * to commit the policy CR while ANY tide-realm-admin assignment CR it covers is
 * still PENDING — forcing the grants to commit first (policy applies last).
 *
 * <p>The guard is COMMIT-ONLY: it lives in {@code commit(...)} after the
 * dependsOn gate, before {@code currentUser()}, and reuses the READ-ONLY
 * {@code resolvePolicyCrLinkage} (same source as {@code relatedPolicyCrId}). It
 * does NOT touch {@code dependsOn}/{@code computeBlockState}/{@code cr.blocked},
 * so the policy CR stays signable alongside the grants in one enclave session.
 *
 * <p>Discriminator: blocked -> 412 {@code PENDING_ADMIN_GRANTS}; not blocked ->
 * proceeds past the gate (here to the 401 no-admin branch, since no admin is
 * mocked).
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class IgaCommitRegenPolicyOrderingGateTest {

    private static final String REALM_ID = "realm-uuid-123";
    private static final String TIDE_ROLE_ID = "tide-realm-admin-role-uuid";
    private static final String POLICY_CR_ID = "policy-cr";

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock(answer = Answers.RETURNS_DEEP_STUBS) org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator auth;
    @Mock JpaConnectionProvider jpa;
    @Mock EntityManager em;

    private IgaAdminResource resource;

    @BeforeEach
    void setUp() {
        when(realm.getId()).thenReturn(REALM_ID);
        when(realm.getName()).thenReturn("test-realm");
        when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa);
        when(jpa.getEntityManager()).thenReturn(em);
        resource = new IgaAdminResource(session, realm, auth);

        // resolveMode(...) -> multiAdmin via the IgaAuthorizer.findByRealm named query.
        IgaAuthorizerEntity authorizer = mock(IgaAuthorizerEntity.class);
        when(authorizer.getMode()).thenReturn("multiAdmin");
        @SuppressWarnings("unchecked")
        TypedQuery<IgaAuthorizerEntity> authQ = mock(TypedQuery.class);
        when(em.createNamedQuery(eq("IgaAuthorizer.findByRealm"), eq(IgaAuthorizerEntity.class)))
                .thenReturn(authQ);
        when(authQ.setParameter(anyString(), any())).thenReturn(authQ);
        when(authQ.getResultStream()).thenAnswer(inv -> Stream.of(authorizer));

        // tideRealmAdminRoleId(realm) -> TIDE_ROLE_ID.
        ClientModel rm = mock(ClientModel.class);
        RoleModel tideRole = mock(RoleModel.class);
        when(realm.getClientByClientId("realm-management")).thenReturn(rm);
        when(rm.getRole("tide-realm-admin")).thenReturn(tideRole);
        when(tideRole.getId()).thenReturn(TIDE_ROLE_ID);
    }

    /** The REGEN_ADMIN_POLICY CR under commit. */
    private IgaChangeRequestEntity policyCr() {
        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setId(POLICY_CR_ID);
        cr.setRealmId(REALM_ID);
        cr.setStatus("PENDING");
        cr.setActionType("REGEN_ADMIN_POLICY");
        cr.setEntityType("ADMIN_POLICY");
        cr.setEntityId(TIDE_ROLE_ID);
        return cr;
    }

    private IgaChangeRequestEntity grantCr(String id, String action) {
        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setId(id);
        cr.setRealmId(REALM_ID);
        cr.setStatus("PENDING");
        cr.setActionType(action);
        cr.setEntityType("USER");
        cr.setRowsJson("[{\"ROLE_ID\":\"" + TIDE_ROLE_ID + "\"}]");
        return cr;
    }

    /** findPending(ADMIN_POLICY, roleId) via IgaChangeRequest.findPendingByEntity. */
    private void stubFindPendingPolicy(IgaChangeRequestEntity policy) {
        @SuppressWarnings("unchecked")
        TypedQuery<IgaChangeRequestEntity> q = mock(TypedQuery.class);
        when(em.createNamedQuery(eq("IgaChangeRequest.findPendingByEntity"), eq(IgaChangeRequestEntity.class)))
                .thenReturn(q);
        when(q.setParameter(anyString(), any())).thenReturn(q);
        when(q.getResultList()).thenReturn(policy == null ? List.of() : List.of(policy));
    }

    /** pendingTideRealmAdminAssignmentCrIds(...) -> GRANT/REVOKE findPendingByAction createQuery. */
    private void stubPendingAssignments(List<IgaChangeRequestEntity> grants,
                                        List<IgaChangeRequestEntity> revokes) {
        @SuppressWarnings("unchecked")
        TypedQuery<IgaChangeRequestEntity> grantQ = mock(TypedQuery.class);
        @SuppressWarnings("unchecked")
        TypedQuery<IgaChangeRequestEntity> revokeQ = mock(TypedQuery.class);
        // findPendingByAction issues a createQuery(jpql) with actionType bound; we
        // disambiguate GRANT vs REVOKE by the actionType parameter value.
        when(em.createQuery(contains("FROM IgaChangeRequestEntity"), eq(IgaChangeRequestEntity.class)))
                .thenReturn(grantQ);
        // Route per actionType: both query builders share the same JPQL, so we make
        // setParameter("actionType", ...) pick the result list.
        lenient().when(grantQ.setParameter(anyString(), any())).thenAnswer(inv -> {
            if ("actionType".equals(inv.getArgument(0))) {
                return "REVOKE_ROLES".equals(inv.getArgument(1)) ? revokeQ : grantQ;
            }
            return grantQ;
        });
        lenient().when(revokeQ.setParameter(anyString(), any())).thenReturn(revokeQ);
        when(grantQ.getResultList()).thenReturn(grants);
        when(revokeQ.getResultList()).thenReturn(revokes);
    }

    // ---------------------------------------------------------------------

    /**
     * Drive the shared {@code commitResolved(cr, em, id)} pipeline directly. The REGEN
     * ordering gate (and the dependency gate) live in {@code commitResolved}, which is run
     * by BOTH the legacy {@code commit()} endpoint AND the multiAdmin {@code /approve}
     * endpoint. Because this is a multiAdmin realm, the legacy {@code commit()} endpoint now
     * REFUSES the lane up-front (refuseLegacyLaneForMultiAdmin -> 409); the gate under test is
     * reached in production only via {@code /approve} -> {@code commitResolved}. We invoke
     * {@code commitResolved} directly so this test exercises the gate on its real path,
     * unobscured by the endpoint-level multiAdmin refusal.
     */
    private Response commitResolved(String id, IgaChangeRequestEntity cr) {
        try {
            java.lang.reflect.Method m = IgaAdminResource.class.getDeclaredMethod(
                    "commitResolved", IgaChangeRequestEntity.class, EntityManager.class, String.class);
            m.setAccessible(true);
            return (Response) m.invoke(resource, cr, em, id);
        } catch (java.lang.reflect.InvocationTargetException ite) {
            if (ite.getCause() instanceof RuntimeException re) throw re;
            throw new RuntimeException(ite.getCause());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void blockedWhenTideRealmAdminGrantStillPending() {
        IgaChangeRequestEntity policy = policyCr();
        when(em.find(IgaChangeRequestEntity.class, POLICY_CR_ID)).thenReturn(policy);
        stubFindPendingPolicy(policy);
        stubPendingAssignments(List.of(grantCr("grant-cr", "GRANT_ROLES")), List.of());

        Response resp = commitResolved(POLICY_CR_ID, policy);

        assertEquals(412, resp.getStatus());
        Map<String, Object> body = (Map<String, Object>) resp.getEntity();
        assertEquals("PENDING_ADMIN_GRANTS", body.get("error"));
        List<String> pending = (List<String>) body.get("pendingAssignmentCrIds");
        assertEquals(List.of("grant-cr"), pending);
    }

    @Test
    void notBlockedWhenAllGrantsCommitted() {
        // No pending assignment CRs -> empty linkage set -> guard is a no-op; commit
        // falls through past the dependency gate to the 401 no-admin branch.
        IgaChangeRequestEntity policy = policyCr();
        when(em.find(IgaChangeRequestEntity.class, POLICY_CR_ID)).thenReturn(policy);
        stubFindPendingPolicy(policy);
        stubPendingAssignments(List.of(), List.of());
        when(auth.adminAuth()).thenReturn(null);

        Response resp = commitResolved(POLICY_CR_ID, policy);

        if (resp.getStatus() == 412 && resp.getEntity() instanceof Map<?, ?> m) {
            assertNotEquals("PENDING_ADMIN_GRANTS", m.get("error"),
                    "all-committed grants must NOT block the policy commit");
        }
        assertEquals(401, resp.getStatus(),
                "with no pending grants + no admin, commit should fall through to 401, not 412");
    }

    @Test
    void grantCommitNeverBlockedByThisGuard() {
        // Committing a GRANT_ROLES CR itself is a non-REGEN action -> guard is a
        // no-op even if other grants are pending; falls through to the 401 branch.
        IgaChangeRequestEntity grant = grantCr("grant-cr", "GRANT_ROLES");
        when(em.find(IgaChangeRequestEntity.class, "grant-cr")).thenReturn(grant);
        when(auth.adminAuth()).thenReturn(null);

        Response resp = commitResolved("grant-cr", grant);

        if (resp.getStatus() == 412 && resp.getEntity() instanceof Map<?, ?> m) {
            assertNotEquals("PENDING_ADMIN_GRANTS", m.get("error"),
                    "a grant commit must never be blocked by the REGEN ordering guard");
        }
        assertEquals(401, resp.getStatus());
    }

    @Test
    void nonRegenCrUnaffected() {
        // A plain non-REGEN CR never even resolves linkage; falls through to 401.
        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setId("scope-cr");
        cr.setRealmId(REALM_ID);
        cr.setStatus("PENDING");
        cr.setActionType("REALM_DEFAULT_SCOPE_ADD");
        when(em.find(IgaChangeRequestEntity.class, "scope-cr")).thenReturn(cr);
        when(auth.adminAuth()).thenReturn(null);

        Response resp = commitResolved("scope-cr", cr);

        if (resp.getStatus() == 412 && resp.getEntity() instanceof Map<?, ?> m) {
            assertNotEquals("PENDING_ADMIN_GRANTS", m.get("error"));
        }
        assertEquals(401, resp.getStatus());
    }
}
