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
import org.tidecloak.iga.attestors.TideAttestor;
import org.tidecloak.iga.entities.IgaRolePolicyEntity;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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

    @Test
    void upsert_acceptsNonReservedName() {
        stubFindByRealmAndName(null); // no existing row -> INSERT path
        IgaRolePolicyRepresentation rep = new IgaRolePolicyRepresentation();
        rep.setName("custom-policy");
        rep.setPolicy("body");
        rep.setPolicySig("SIG");

        Response resp = resource.upsertRolePolicy(rep);

        assertEquals(200, resp.getStatus());
        verify(em).persist(any(IgaRolePolicyEntity.class));
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
