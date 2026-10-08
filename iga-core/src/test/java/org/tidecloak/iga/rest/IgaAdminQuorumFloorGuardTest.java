package org.tidecloak.iga.rest;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
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
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.attestors.TideAttestor;
import org.tidecloak.iga.entities.IgaAuthorizerEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.entities.IgaRolePolicyEntity;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The tide-realm-admin quorum floor: a {@code REVOKE_ROLES} commit may not leave the realm with
 * fewer committed approvers than the threshold in force needs signatures.
 *
 * <p>WHY: the threshold gates every governed action in the realm, and it is enforced by every ORK
 * at PreSign against the signed M0 policy, so a realm holding a threshold its admin set can no
 * longer reach cannot be argued out of it locally. It cannot commit anything again, including the
 * {@code REGEN_ADMIN_POLICY} whose job is to lower the threshold. Realm
 * {@code tideqa-1790586762-1-local} reached exactly that state: one committed admin against an
 * encoded threshold of 2.
 *
 * <p>This is the mirror of the grant-side {@code TideRealmAdminGuard} lockout safeguard, and it
 * refuses rather than repairs, because by commit time there is nothing left to repair.
 *
 * <p>Discriminator: breached -> 412 {@code ADMIN_QUORUM_FLOOR}; safe -> proceeds past the gate
 * (here to the 401 no-admin branch, since no admin is mocked).
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class IgaAdminQuorumFloorGuardTest {

    private static final String REALM_ID = "realm-uuid-floor";
    private static final String TIDE_ROLE_ID = "tide-realm-admin-role-uuid";

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock(answer = Answers.RETURNS_DEEP_STUBS) org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator auth;
    @Mock JpaConnectionProvider jpa;
    @Mock EntityManager em;
    @Mock UserProvider users;
    @Mock RoleModel tideRole;

    private IgaAdminResource resource;

    @BeforeEach
    void setUp() {
        when(realm.getId()).thenReturn(REALM_ID);
        when(realm.getName()).thenReturn("floor-realm");
        when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa);
        when(jpa.getEntityManager()).thenReturn(em);
        IgaTestClusterLock.stubInlineClusterLock(session);
        resource = new IgaAdminResource(session, realm, auth);

        // resolveMode(...) -> multiAdmin.
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
        when(realm.getClientByClientId("realm-management")).thenReturn(rm);
        when(rm.getRole("tide-realm-admin")).thenReturn(tideRole);
        when(tideRole.getId()).thenReturn(TIDE_ROLE_ID);

        when(auth.adminAuth()).thenReturn(null);
    }

    /** Drive activeTideRealmAdminUserIds: {@code n} committed, enabled holders, ids admin-0..n-1. */
    @SuppressWarnings("unchecked")
    private void stubCommittedAdmins(int n) {
        List<String> ids = new ArrayList<>();
        List<UserModel> members = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            String uid = "admin-" + i;
            ids.add(uid);
            UserModel u = mock(UserModel.class);
            when(u.getId()).thenReturn(uid);
            when(u.isEnabled()).thenReturn(true);
            members.add(u);
        }
        Query jpql = mock(Query.class);
        when(em.createQuery(contains("UserRoleMappingEntity"))).thenReturn(jpql);
        when(jpql.setParameter(anyString(), any())).thenReturn(jpql);
        when(jpql.getResultList()).thenReturn((List) ids);
        when(session.users()).thenReturn(users);
        when(users.getRoleMembersStream(eq(realm), eq(tideRole))).thenAnswer(inv -> members.stream());
    }

    /** The in-force quorum: IGA_ROLE_POLICY.threshold. */
    @SuppressWarnings("unchecked")
    private void stubEncodedThreshold(int threshold) {
        IgaRolePolicyEntity policy = new IgaRolePolicyEntity();
        policy.setId("policy-row");
        policy.setRealmId(REALM_ID);
        policy.setName(TideAttestor.TIDE_REALM_ADMIN_POLICY_KEY);
        policy.setThreshold(threshold);
        TypedQuery<IgaRolePolicyEntity> q = mock(TypedQuery.class);
        when(em.createNamedQuery(eq("IgaRolePolicy.findByRealmAndName"), eq(IgaRolePolicyEntity.class)))
                .thenReturn(q);
        when(q.setParameter(anyString(), any())).thenReturn(q);
        when(q.getResultStream()).thenAnswer(inv -> Stream.of(policy));
    }

    /** A REVOKE_ROLES CR stripping tide-realm-admin from each of {@code userIds}. */
    private IgaChangeRequestEntity revokeCr(String id, String... userIds) {
        StringBuilder rows = new StringBuilder("[");
        for (int i = 0; i < userIds.length; i++) {
            if (i > 0) rows.append(',');
            rows.append("{\"USER_ID\":\"").append(userIds[i])
                .append("\",\"ROLE_ID\":\"").append(TIDE_ROLE_ID).append("\"}");
        }
        rows.append(']');
        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setId(id);
        cr.setRealmId(REALM_ID);
        cr.setStatus("PENDING");
        cr.setActionType("REVOKE_ROLES");
        cr.setEntityType("USER");
        cr.setEntityId(userIds.length > 0 ? userIds[0] : null);
        cr.setRowsJson(rows.toString());
        when(em.find(IgaChangeRequestEntity.class, id)).thenReturn(cr);
        return cr;
    }

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

    // ---------------------------------------------------------------------

    @Test
    @SuppressWarnings("unchecked")
    void refusesTheRevokeThatWouldStrandTheRealm() {
        // The live failure: 2 committed admins, threshold 2, revoking one leaves 1 approver against
        // a quorum of 2. Nothing in the realm could ever be committed again.
        stubCommittedAdmins(2);
        stubEncodedThreshold(2);
        IgaChangeRequestEntity cr = revokeCr("revoke-last-but-one", "admin-0");

        Response resp = commitResolved("revoke-last-but-one", cr);

        assertEquals(412, resp.getStatus());
        Map<String, Object> body = (Map<String, Object>) resp.getEntity();
        assertEquals("ADMIN_QUORUM_FLOOR", body.get("error"));
        assertEquals(2, body.get("committedAdmins"));
        assertEquals(1, body.get("committedAdminsAfter"));
        assertEquals(2, body.get("inForceThreshold"));
        // The operator has to be able to act on this without reading the source. Here the admin set
        // is ALREADY at the floor (2 admins, quorum 2), so telling them to revoke down to 2 would
        // be a no-op instruction; the only way forward is to lower the threshold first.
        String message = (String) body.get("message");
        assertTrue(message.contains("2 approvals"),
                "the message must name the quorum that cannot be reached: " + message);
        assertTrue(message.contains("threshold has to come down first"),
                "at the floor, the message must point at the threshold, not at more revokes: " + message);
    }

    @Test
    void allowsTheRevokeThatLeavesTheQuorumIntact() {
        // 3 committed admins, threshold 2: dropping to 2 still reaches quorum, so the guard is a
        // no-op and the commit falls through to the 401 no-admin branch.
        stubCommittedAdmins(3);
        stubEncodedThreshold(2);
        IgaChangeRequestEntity cr = revokeCr("revoke-safe", "admin-0");

        Response resp = commitResolved("revoke-safe", cr);

        if (resp.getStatus() == 412 && resp.getEntity() instanceof Map<?, ?> m) {
            assertNotEquals("ADMIN_QUORUM_FLOOR", m.get("error"),
                    "a revoke that leaves the quorum reachable must not be blocked");
        }
        assertEquals(401, resp.getStatus());
    }

    @Test
    @SuppressWarnings("unchecked")
    void countsTheWholeRevokeNotJustTheFirstRow() {
        // A batched revoke stripping 2 of 3 admins leaves 1 against a quorum of 2. Checking only
        // the first row would wave this through, which is how a one-shot shrink bricks a realm.
        stubCommittedAdmins(3);
        stubEncodedThreshold(2);
        IgaChangeRequestEntity cr = revokeCr("revoke-batch", "admin-0", "admin-1");

        Response resp = commitResolved("revoke-batch", cr);

        assertEquals(412, resp.getStatus());
        Map<String, Object> body = (Map<String, Object>) resp.getEntity();
        assertEquals("ADMIN_QUORUM_FLOOR", body.get("error"));
        assertEquals(1, body.get("committedAdminsAfter"));
        // Here there IS room to revoke (3 admins, quorum 2), so the message says how far.
        String message = (String) body.get("message");
        assertTrue(message.contains("rounds"),
                "with room to shrink, the message must say the shrink proceeds in rounds: " + message);
        assertTrue(message.contains("down to 2 admin(s)"),
                "the message must name how far this round may go: " + message);
    }

    @Test
    void duplicateRowsForOneUserCountOnce() {
        // 2 admins, threshold 1, and a CR carrying the same user twice. Counting rows instead of
        // distinct users would project 0 left and refuse a revoke that is perfectly safe.
        stubCommittedAdmins(2);
        stubEncodedThreshold(1);
        IgaChangeRequestEntity cr = revokeCr("revoke-dupe", "admin-0", "admin-0");

        Response resp = commitResolved("revoke-dupe", cr);

        if (resp.getStatus() == 412 && resp.getEntity() instanceof Map<?, ?> m) {
            assertNotEquals("ADMIN_QUORUM_FLOOR", m.get("error"),
                    "duplicate rows for one user must count once");
        }
        assertEquals(401, resp.getStatus());
    }

    @Test
    void ignoresRevokesOfOtherRoles() {
        // A revoke of some unrelated role never touches the approver set.
        stubCommittedAdmins(1);
        stubEncodedThreshold(2);
        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setId("revoke-other");
        cr.setRealmId(REALM_ID);
        cr.setStatus("PENDING");
        cr.setActionType("REVOKE_ROLES");
        cr.setEntityType("USER");
        cr.setRowsJson("[{\"USER_ID\":\"admin-0\",\"ROLE_ID\":\"some-other-role\"}]");
        when(em.find(IgaChangeRequestEntity.class, "revoke-other")).thenReturn(cr);

        Response resp = commitResolved("revoke-other", cr);

        if (resp.getStatus() == 412 && resp.getEntity() instanceof Map<?, ?> m) {
            assertNotEquals("ADMIN_QUORUM_FLOOR", m.get("error"));
        }
        assertEquals(401, resp.getStatus());
    }

    @Test
    void grantCommitIsUnaffected() {
        // The guard is revoke-only; a GRANT_ROLES commit never consults it.
        stubCommittedAdmins(1);
        stubEncodedThreshold(2);
        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setId("grant-cr");
        cr.setRealmId(REALM_ID);
        cr.setStatus("PENDING");
        cr.setActionType("GRANT_ROLES");
        cr.setEntityType("USER");
        cr.setRowsJson("[{\"USER_ID\":\"newbie\",\"ROLE_ID\":\"" + TIDE_ROLE_ID + "\"}]");
        when(em.find(IgaChangeRequestEntity.class, "grant-cr")).thenReturn(cr);

        Response resp = commitResolved("grant-cr", cr);

        if (resp.getStatus() == 412 && resp.getEntity() instanceof Map<?, ?> m) {
            assertNotEquals("ADMIN_QUORUM_FLOOR", m.get("error"));
        }
        assertEquals(401, resp.getStatus());
    }
}
