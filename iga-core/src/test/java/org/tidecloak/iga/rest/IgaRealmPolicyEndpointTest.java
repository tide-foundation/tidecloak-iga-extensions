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
import org.midgard.models.Policy.ApprovalType;
import org.midgard.models.Policy.ExecutionType;
import org.midgard.models.Policy.Policy;
import org.midgard.models.Policy.PolicyParameters;
import org.tidecloak.iga.attestors.TideAttestor;
import org.tidecloak.iga.entities.IgaRolePolicyEntity;

import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Coverage for the realm-level named-policy REST surface:
 * <ul>
 *   <li>LIST / GET-by-id / GET-by-name require ONLY authentication — they must NOT
 *       call {@code auth.realm().requireManageRealm()} (reaching this admin resource
 *       already implies a valid realm-admin token).</li>
 *   <li>The POST upsert and DELETE endpoints stay role-gated AND reject the reserved
 *       {@code tide-realm-admin} M0 policy name with 403 — only the M0 writer owns it.</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class IgaRealmPolicyEndpointTest {

    private static final String REALM_ID = "realm-uuid-pol";

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
        resource = new IgaAdminResource(session, realm, auth);
    }

    private void stubFindByRealm(IgaRolePolicyEntity... rows) {
        @SuppressWarnings("unchecked")
        TypedQuery<IgaRolePolicyEntity> q = mock(TypedQuery.class);
        when(em.createNamedQuery(eq("IgaRolePolicy.findByRealm"), eq(IgaRolePolicyEntity.class)))
                .thenReturn(q);
        when(q.setParameter(anyString(), any())).thenReturn(q);
        when(q.getResultList()).thenReturn(List.of(rows));
    }

    private void stubFindByRealmAndName(IgaRolePolicyEntity row) {
        @SuppressWarnings("unchecked")
        TypedQuery<IgaRolePolicyEntity> q = mock(TypedQuery.class);
        when(em.createNamedQuery(eq("IgaRolePolicy.findByRealmAndName"), eq(IgaRolePolicyEntity.class)))
                .thenReturn(q);
        when(q.setParameter(anyString(), any())).thenReturn(q);
        if (row == null) {
            when(q.getSingleResult()).thenThrow(new jakarta.persistence.NoResultException());
        } else {
            when(q.getSingleResult()).thenReturn(row);
        }
    }

    private IgaRolePolicyEntity row(String id, String name) {
        IgaRolePolicyEntity e = new IgaRolePolicyEntity();
        e.setId(id);
        e.setRealmId(REALM_ID);
        e.setName(name);
        e.setPolicy("body");
        e.setPolicySig("SIG");
        e.setCreatedAt(1L);
        return e;
    }

    // --- Read endpoints: authenticated-only (no requireManageRealm) ---

    @Test
    void list_doesNotRequireManageRealm() {
        stubFindByRealm(row("p1", "custom-a"));
        List<IgaRolePolicyRepresentation> out = resource.listRolePolicies();
        assertEquals(1, out.size());
        verify(auth, never()).realm();
    }

    @Test
    void getById_doesNotRequireManageRealm() {
        IgaRolePolicyEntity e = row("p1", "custom-a");
        when(em.find(eq(IgaRolePolicyEntity.class), eq("p1"))).thenReturn(e);
        Response resp = resource.getRolePolicy("p1");
        assertEquals(200, resp.getStatus());
        verify(auth, never()).realm();
    }

    @Test
    void getByName_doesNotRequireManageRealm() {
        stubFindByRealmAndName(row("p1", "custom-a"));
        Response resp = resource.getRolePolicyByName("custom-a");
        assertEquals(200, resp.getStatus());
        verify(auth, never()).realm();
    }

    // --- Write endpoints: role-gated + reserved-key immutability ---

    @Test
    void upsert_rejectsReservedKey_withForbidden() {
        IgaRolePolicyRepresentation rep = new IgaRolePolicyRepresentation();
        rep.setName(TideAttestor.TIDE_REALM_ADMIN_POLICY_KEY);
        rep.setPolicy("body");
        rep.setPolicySig("SIG");

        Response resp = resource.upsertRolePolicy(rep);

        assertEquals(403, resp.getStatus(), "operators may not create/upsert the reserved M0 key");
        verify(auth, atLeastOnce()).realm(); // still role-gated
        // No write happened.
        verify(em, never()).persist(any());
        verify(em, never()).merge(any());
    }

    /**
     * A real Base64 policy body. The upsert endpoint derives EXPIRY by parsing this, so a
     * placeholder string is no longer a valid policy to store.
     */
    private static String policyBody(Long expiry) {
        PolicyParameters params = new PolicyParameters();
        params.put("resource", "myclient");
        return Base64.getEncoder().encodeToString(
                new Policy("contract-1", new String[]{"m:1"}, "vuid-abc",
                        ApprovalType.EXPLICIT, ExecutionType.PUBLIC, params, expiry).ToBytes());
    }

    @Test
    void upsert_acceptsNonReservedName() {
        stubFindByRealmAndName(null); // no existing row -> INSERT path
        IgaRolePolicyRepresentation rep = new IgaRolePolicyRepresentation();
        rep.setName("custom-policy");
        rep.setPolicy(policyBody(null));
        rep.setPolicySig("SIG");

        Response resp = resource.upsertRolePolicy(rep);

        assertEquals(200, resp.getStatus());
        verify(em).persist(any(IgaRolePolicyEntity.class));
    }

    @Test
    void upsert_derivesExpiryFromTheSignedPolicy_notFromTheRequestBody() {
        // The column is a read-back of what POLICY already contains. Deriving it is what stops it
        // disagreeing with the bytes the ork will verify, so a caller-supplied value is ignored.
        stubFindByRealmAndName(null);
        long expiry = (System.currentTimeMillis() / 1000L) + 3600;
        IgaRolePolicyRepresentation rep = new IgaRolePolicyRepresentation();
        rep.setName("custom-policy");
        rep.setPolicy(policyBody(expiry));
        rep.setPolicySig("SIG");
        rep.setExpiry(1L); // a lie; the signed policy is the authority

        Response resp = resource.upsertRolePolicy(rep);

        assertEquals(200, resp.getStatus());
        verify(em).persist(argThat((IgaRolePolicyEntity e) ->
                e != null && Long.valueOf(expiry).equals(e.getExpiry())));
    }

    @Test
    void upsert_storesNoExpiryForAStandingPolicy() {
        stubFindByRealmAndName(null);
        IgaRolePolicyRepresentation rep = new IgaRolePolicyRepresentation();
        rep.setName("custom-policy");
        rep.setPolicy(policyBody(null));
        rep.setPolicySig("SIG");

        Response resp = resource.upsertRolePolicy(rep);

        assertEquals(200, resp.getStatus());
        verify(em).persist(argThat((IgaRolePolicyEntity e) -> e != null && e.getExpiry() == null));
    }

    @Test
    void upsert_refusesAnAlreadyExpiredPolicy() {
        // PolicySignRequest will not sign one and PolicyAuthorizationFlow will not honour it, so
        // storing it would only defer the failure to somewhere further from the cause.
        IgaRolePolicyRepresentation rep = new IgaRolePolicyRepresentation();
        rep.setName("custom-policy");
        rep.setPolicy(policyBody((System.currentTimeMillis() / 1000L) - 60));
        rep.setPolicySig("SIG");

        Response resp = resource.upsertRolePolicy(rep);

        assertEquals(400, resp.getStatus());
        verify(em, never()).persist(any());
        verify(em, never()).merge(any());
    }

    @Test
    void upsert_refusesAPolicyBodyItCannotParse() {
        // Storing it with a null expiry would hide a time-limited policy from anything that reads
        // the column, which is the failure this check exists to avoid.
        IgaRolePolicyRepresentation rep = new IgaRolePolicyRepresentation();
        rep.setName("custom-policy");
        rep.setPolicy("body");
        rep.setPolicySig("SIG");

        Response resp = resource.upsertRolePolicy(rep);

        assertEquals(400, resp.getStatus());
        verify(em, never()).persist(any());
    }

    @Test
    void deleteByName_rejectsReservedKey_withForbidden() {
        Response resp = resource.deleteRolePolicyByName(TideAttestor.TIDE_REALM_ADMIN_POLICY_KEY);
        assertEquals(403, resp.getStatus(), "the reserved M0 key may not be deleted via this surface");
        verify(em, never()).remove(any());
    }

    @Test
    void deleteById_rejectsReservedKeyRow_withForbidden() {
        IgaRolePolicyEntity reserved = row("m0", TideAttestor.TIDE_REALM_ADMIN_POLICY_KEY);
        when(em.find(eq(IgaRolePolicyEntity.class), eq("m0"))).thenReturn(reserved);
        Response resp = resource.deleteRolePolicy("m0");
        assertEquals(403, resp.getStatus(),
                "deleting the M0 policy row by id must be refused");
        verify(em, never()).remove(any());
    }

    @Test
    void deleteById_allowsNonReservedRow() {
        IgaRolePolicyEntity custom = row("c1", "custom-policy");
        when(em.find(eq(IgaRolePolicyEntity.class), eq("c1"))).thenReturn(custom);
        Response resp = resource.deleteRolePolicy("c1");
        assertEquals(204, resp.getStatus());
        verify(em).remove(custom);
    }

    @Test
    void reservedKeyConstant_isTideRealmAdmin() {
        assertNotNull(TideAttestor.TIDE_REALM_ADMIN_POLICY_KEY);
        assertEquals("tide-realm-admin", TideAttestor.TIDE_REALM_ADMIN_POLICY_KEY);
    }
}
