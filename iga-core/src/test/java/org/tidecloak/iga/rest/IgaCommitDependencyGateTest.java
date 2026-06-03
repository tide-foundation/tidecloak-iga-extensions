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

import java.util.List;
import java.util.Map;

import java.util.concurrent.Callable;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests the fail-closed dependency gate on the single-CR commit path
 * ({@code POST /iga/change-requests/{id}/commit}). A CR whose dependsOn set
 * contains a non-APPROVED prerequisite must be refused with
 * 412 {@code DEPENDENCY_NOT_MET} BEFORE any approver/threshold/replay work;
 * a CR whose prerequisites are all APPROVED must pass the gate.
 *
 * <p>The gate sits early in {@code commit(...)} (after the PENDING check,
 * before {@code currentUser()}), so we can assert its behaviour without
 * standing up the full replay: blocked -> 412 DEPENDENCY_NOT_MET; not blocked
 * -> proceeds past the gate (here, to the 401 no-admin branch, since we mock
 * no authenticated user). The discriminator is "did it 412 with
 * DEPENDENCY_NOT_MET or not".
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class IgaCommitDependencyGateTest {

    private static final String REALM_ID = "realm-uuid-123";

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    // Deep stubs so auth.realm().requireManageRealm() is a no-op (permission granted).
    @Mock(answer = Answers.RETURNS_DEEP_STUBS) AdminPermissionEvaluator auth;
    @Mock JpaConnectionProvider jpa;
    @Mock EntityManager em;

    private IgaAdminResource resource;

    @BeforeEach
    void setUp() {
        when(realm.getId()).thenReturn(REALM_ID);
        when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa);
        when(jpa.getEntityManager()).thenReturn(em);
        // requireManageRealm() is a void no-op on the mock (permission granted).
        resource = new IgaAdminResource(session, realm, auth);
    }

    private IgaChangeRequestEntity cr(String id, String status, List<String> dependsOn) {
        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setId(id);
        cr.setRealmId(REALM_ID);
        cr.setStatus(status);
        cr.setActionType("REALM_DEFAULT_SCOPE_ADD");
        cr.setDependsOnList(dependsOn);
        return cr;
    }

    @Test
    @SuppressWarnings("unchecked")
    void blockedWhenPrerequisitePending() {
        IgaChangeRequestEntity dependent = cr("dep-cr", "PENDING", List.of("prereq-cr"));
        IgaChangeRequestEntity prereq = cr("prereq-cr", "PENDING", null);
        prereq.setActionType("CREATE_CLIENT_SCOPE");
        when(em.find(IgaChangeRequestEntity.class, "dep-cr")).thenReturn(dependent);
        when(em.find(IgaChangeRequestEntity.class, "prereq-cr")).thenReturn(prereq);

        Response resp = resource.commit("dep-cr");

        assertEquals(412, resp.getStatus());
        Map<String, Object> body = (Map<String, Object>) resp.getEntity();
        assertEquals("DEPENDENCY_NOT_MET", body.get("error"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void blockedWhenPrerequisiteDenied() {
        // A DENIED prerequisite keeps the dependent blocked (fail-closed) rather
        // than wrongly unblocking it.
        IgaChangeRequestEntity dependent = cr("dep-cr", "PENDING", List.of("prereq-cr"));
        IgaChangeRequestEntity prereq = cr("prereq-cr", "DENIED", null);
        when(em.find(IgaChangeRequestEntity.class, "dep-cr")).thenReturn(dependent);
        when(em.find(IgaChangeRequestEntity.class, "prereq-cr")).thenReturn(prereq);

        Response resp = resource.commit("dep-cr");

        assertEquals(412, resp.getStatus());
        Map<String, Object> body = (Map<String, Object>) resp.getEntity();
        assertEquals("DEPENDENCY_NOT_MET", body.get("error"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void blockedWhenPrerequisiteMissing() {
        // A missing prerequisite CR (deleted/never existed) must keep the
        // dependent blocked, never silently unblock it.
        IgaChangeRequestEntity dependent = cr("dep-cr", "PENDING", List.of("ghost-cr"));
        when(em.find(IgaChangeRequestEntity.class, "dep-cr")).thenReturn(dependent);
        when(em.find(IgaChangeRequestEntity.class, "ghost-cr")).thenReturn(null);

        Response resp = resource.commit("dep-cr");

        assertEquals(412, resp.getStatus());
        Map<String, Object> body = (Map<String, Object>) resp.getEntity();
        assertEquals("DEPENDENCY_NOT_MET", body.get("error"));
    }

    @Test
    void notBlockedWhenPrerequisiteApproved() {
        // Prerequisite APPROVED -> the dependency gate passes. We then mock no
        // authenticated admin, so commit proceeds to the 401 branch — proving it
        // got PAST the dependency gate (not a 412 DEPENDENCY_NOT_MET).
        IgaChangeRequestEntity dependent = cr("dep-cr", "PENDING", List.of("prereq-cr"));
        IgaChangeRequestEntity prereq = cr("prereq-cr", "APPROVED", null);
        when(em.find(IgaChangeRequestEntity.class, "dep-cr")).thenReturn(dependent);
        when(em.find(IgaChangeRequestEntity.class, "prereq-cr")).thenReturn(prereq);
        // No authenticated admin -> currentUser() returns null, so commit falls
        // through to the 401 branch immediately AFTER passing the dependency
        // gate (overriding the deep-stub default non-null adminAuth()).
        when(auth.adminAuth()).thenReturn(null);

        Response resp = resource.commit("dep-cr");

        // Must NOT be a dependency rejection.
        if (resp.getStatus() == 412) {
            Object entity = resp.getEntity();
            if (entity instanceof Map<?, ?> m) {
                assertNotEquals("DEPENDENCY_NOT_MET", m.get("error"),
                        "APPROVED prerequisite must NOT block the dependent");
            }
        }
        assertEquals(401, resp.getStatus(),
                "with prereq APPROVED + no admin, commit should fall through to 401, not 412");
    }

    // ---------------------------------------------------------------------
    // Bulk path: the SAME fail-closed gate must hold a blocked CR as a
    // per-CR REJECTED/DEPENDENCY_NOT_MET (never committed in bulk).
    // ---------------------------------------------------------------------

    @Test
    @SuppressWarnings("unchecked")
    void bulkRejectsBlockedCrWithDependencyNotMet() {
        IgaChangeRequestEntity dependent = cr("dep-cr", "PENDING", List.of("prereq-cr"));
        IgaChangeRequestEntity prereq = cr("prereq-cr", "PENDING", null);
        when(em.find(IgaChangeRequestEntity.class, "dep-cr")).thenReturn(dependent);
        when(em.find(IgaChangeRequestEntity.class, "prereq-cr")).thenReturn(prereq);

        // Authenticated admin (deep-stub default returns non-null adminAuth()+user).
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

        // service.listPendingByActionTypeIn -> [dependent]. getService() builds a
        // real IgaChangeRequestService over the mocked em; stub its JPQL chain.
        TypedQuery<IgaChangeRequestEntity> q = mock(TypedQuery.class);
        when(em.createQuery(anyString(), eq(IgaChangeRequestEntity.class))).thenReturn(q);
        when(q.setParameter(anyString(), any())).thenReturn(q);
        when(q.setMaxResults(anyInt())).thenReturn(q);
        when(q.getResultList()).thenReturn(List.of(dependent));

        Response resp = resource.bulkAuthorize(Map.of("actionTypeIn", List.of("REALM_DEFAULT_SCOPE_ADD")));

        assertEquals(200, resp.getStatus(), "bulk returns 200 with per-CR outcomes");
        Map<String, Object> body = (Map<String, Object>) resp.getEntity();
        List<Map<String, Object>> results = (List<Map<String, Object>>) body.get("results");
        assertEquals(1, results.size());
        assertEquals("REJECTED", results.get(0).get("status"));
        assertEquals("DEPENDENCY_NOT_MET", results.get(0).get("error"));
    }
}
