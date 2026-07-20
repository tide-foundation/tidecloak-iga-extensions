package org.tidecloak.iga.rest;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.cluster.ClusterProvider;
import org.keycloak.cluster.ExecutionResult;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Verifies the bulk-commit candidate ORDERING: all {@code REGEN_ADMIN_POLICY} CRs
 * must be committed LAST within a bulk-authorize batch, after every non-policy CR.
 *
 * <p>WHY: a REGEN_ADMIN_POLICY commit writes the NEW {@code IGA_ROLE_POLICY.threshold}.
 * The bulk commit gate reads the ENCODED threshold (commit 1b08bb0), so the moment the
 * policy CR commits and bumps the threshold (e.g. 1 -> 2), any still-PENDING grant CRs
 * re-gate upward (1/1 -> 1/2) and get stranded. Draining the grants first — under the
 * OLD encoded threshold — lets each commit with one signature, then the policy commits
 * last and bumps the threshold for FUTURE work only.
 *
 * <p>The bulk loop processes the (sorted) candidate list IN ORDER and {@code processOneCr}
 * calls {@code em.find(IgaChangeRequestEntity.class, crId)} as its first action. We make
 * every candidate non-PENDING so each {@code processOneCr} short-circuits right after that
 * find (SKIPPED/ALREADY_RESOLVED) — no replay needed — and we capture the find order. That
 * order IS the COMMIT order the loop would follow, so asserting REGEN_ADMIN_POLICY is found
 * LAST proves it would also be committed last.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class IgaBulkCommitOrderTest {

    private static final String REALM_ID = "realm-uuid-123";

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock(answer = Answers.RETURNS_DEEP_STUBS) AdminPermissionEvaluator auth;
    @Mock JpaConnectionProvider jpa;
    @Mock EntityManager em;

    private IgaAdminResource resource;

    @BeforeEach
    void setUp() {
        when(realm.getId()).thenReturn(REALM_ID);
        when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa);
        when(jpa.getEntityManager()).thenReturn(em);
        // bulkAuthorize's post-batch convergeAfterCommit block re-resolves the LIVE realm via
        // session.realms().getRealm(realmId) (added with the DELETE_REALM guard) and only runs
        // converge when it is non-null. These tests pin the sort/loop ORDERING, not converge, so
        // return a RealmProvider whose getRealm(...) is null → the converge block is skipped.
        org.keycloak.models.RealmProvider realmProvider = mock(org.keycloak.models.RealmProvider.class);
        when(session.realms()).thenReturn(realmProvider);
        resource = new IgaAdminResource(session, realm, auth);
    }

    private IgaChangeRequestEntity cr(String id, String actionType) {
        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setId(id);
        cr.setRealmId(REALM_ID);
        // Non-PENDING so processOneCr short-circuits to SKIPPED right after em.find,
        // exercising the real sort + loop ordering without standing up replay.
        cr.setStatus("APPROVED");
        cr.setActionType(actionType);
        return cr;
    }

    @SuppressWarnings("unchecked")
    private List<String> drainOrderFor(List<IgaChangeRequestEntity> listing) {
        // Capture the order processOneCr resolves CRs (its first action is em.find(crId)).
        List<String> findOrder = new ArrayList<>();
        for (IgaChangeRequestEntity c : listing) {
            when(em.find(IgaChangeRequestEntity.class, c.getId())).thenAnswer(inv -> {
                findOrder.add(c.getId());
                return c;
            });
        }

        UserModel admin = mock(UserModel.class);
        when(auth.adminAuth().getUser()).thenReturn(admin);

        // Run the cluster-locked callable inline.
        ClusterProvider cluster = mock(ClusterProvider.class);
        when(session.getProvider(ClusterProvider.class)).thenReturn(cluster);
        when(cluster.executeIfNotExecuted(anyString(), anyInt(), any(Callable.class)))
                .thenAnswer(inv -> {
                    Object result = ((Callable<Object>) inv.getArgument(2)).call();
                    return ExecutionResult.executed(result);
                });

        // service.listPendingByActionTypeIn -> the supplied listing.
        TypedQuery<IgaChangeRequestEntity> q = mock(TypedQuery.class);
        when(em.createQuery(anyString(), eq(IgaChangeRequestEntity.class))).thenReturn(q);
        when(q.setParameter(anyString(), any())).thenReturn(q);
        when(q.setMaxResults(anyInt())).thenReturn(q);
        when(q.getResultList()).thenReturn(listing);

        Response resp = resource.bulkAuthorize(Map.of("actionTypeIn",
                List.of("GRANT_ROLES", "REGEN_ADMIN_POLICY")));
        assertEquals(200, resp.getStatus(), "bulk returns 200 with per-CR outcomes");

        return findOrder;
    }

    @Test
    void regenAdminPolicyCommitsLast_evenWhenListedFirst() {
        // Listing order deliberately puts the policy CR in the MIDDLE: {grantA, regenPolicy, grantB}.
        // After the sort the commit order must be {grantA, grantB, regenPolicy} — policy strictly last.
        IgaChangeRequestEntity grantA = cr("grant-A", "GRANT_ROLES");
        IgaChangeRequestEntity regenPolicy = cr("regen-policy", "REGEN_ADMIN_POLICY");
        IgaChangeRequestEntity grantB = cr("grant-B", "GRANT_ROLES");

        List<String> order = drainOrderFor(List.of(grantA, regenPolicy, grantB));

        assertEquals(List.of("grant-A", "grant-B", "regen-policy"), order,
                "REGEN_ADMIN_POLICY must be committed LAST; grants keep their relative order");
        assertEquals("regen-policy", order.get(order.size() - 1),
                "the policy CR must be the final CR processed/committed");
    }

    @Test
    void regenAdminPolicyAlreadyLast_orderUnchanged() {
        // Stable sort: when the policy CR is already last, the grants keep their order.
        IgaChangeRequestEntity grantA = cr("grant-A", "GRANT_ROLES");
        IgaChangeRequestEntity grantB = cr("grant-B", "GRANT_ROLES");
        IgaChangeRequestEntity regenPolicy = cr("regen-policy", "REGEN_ADMIN_POLICY");

        List<String> order = drainOrderFor(List.of(grantA, grantB, regenPolicy));

        assertEquals(List.of("grant-A", "grant-B", "regen-policy"), order);
    }

    @Test
    void policyOnlyBatch_stillProcessed() {
        // A batch where the policy CR is the only candidate still drains normally.
        IgaChangeRequestEntity regenPolicy = cr("regen-policy", "REGEN_ADMIN_POLICY");

        List<String> order = drainOrderFor(List.of(regenPolicy));

        assertEquals(List.of("regen-policy"), order);
    }

    @Test
    void twoPolicies_bothLast_afterAllGrants() {
        // Multiple REGEN_ADMIN_POLICY CRs all sort to the end, after every grant,
        // and keep their own relative order (stable).
        IgaChangeRequestEntity regen1 = cr("regen-1", "REGEN_ADMIN_POLICY");
        IgaChangeRequestEntity grantA = cr("grant-A", "GRANT_ROLES");
        IgaChangeRequestEntity regen2 = cr("regen-2", "REGEN_ADMIN_POLICY");
        IgaChangeRequestEntity grantB = cr("grant-B", "GRANT_ROLES");

        List<String> order = drainOrderFor(List.of(regen1, grantA, regen2, grantB));

        assertEquals(List.of("grant-A", "grant-B", "regen-1", "regen-2"), order);
        // Both policy CRs come after every grant.
        int firstPolicyIdx = order.indexOf("regen-1");
        assertTrue(order.indexOf("grant-A") < firstPolicyIdx && order.indexOf("grant-B") < firstPolicyIdx,
                "every grant must be committed before any policy CR");
    }
}
