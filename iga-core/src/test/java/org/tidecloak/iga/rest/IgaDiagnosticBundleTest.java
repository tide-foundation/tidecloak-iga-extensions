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
import org.tidecloak.iga.attestors.IgaAttestor;
import org.tidecloak.iga.attestors.SimpleNameAttestor;
import org.tidecloak.iga.entities.IgaAuthorizationEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * GET /iga/change-requests/{id}/diagnostic-bundle (Schema 3 — CR dump only).
 * The endpoint returns a READ-ONLY diagnostic snapshot of a CR + its
 * authorizations + the effective threshold/approver-role; 404 for an unknown
 * id or a cross-realm id. requireManageRealm is enforced (deep-stub no-op).
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class IgaDiagnosticBundleTest {

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
        // simple attestor for getThreshold resolution.
        IgaAttestor simple = new SimpleNameAttestor(session);
        when(session.getProvider(eq(IgaAttestor.class), anyString())).thenReturn(simple);
        resource = new IgaAdminResource(session, realm, auth);
    }

    private IgaChangeRequestEntity cr() {
        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setId("cr-1");
        cr.setRealmId(REALM_ID);
        cr.setEntityType("CLIENT_SCOPE");
        cr.setEntityId("cs-uuid");
        cr.setActionType("CREATE_CLIENT_SCOPE");
        cr.setStatus("PENDING");
        cr.setRequestedBy("admin-uuid");
        cr.setCreatedAt(1700000000L);
        cr.setRowsJson("[{\"CLIENT_SCOPE_ID\":\"cs-uuid\",\"REP_JSON\":{\"name\":\"foo\"}}]");
        return cr;
    }

    @SuppressWarnings("unchecked")
    private void stubAuths(List<IgaAuthorizationEntity> rows) {
        TypedQuery<IgaAuthorizationEntity> q = mock(TypedQuery.class);
        when(em.createNamedQuery("IgaAuthorization.findByChangeRequest", IgaAuthorizationEntity.class))
                .thenReturn(q);
        when(q.setParameter(anyString(), any())).thenReturn(q);
        when(q.getResultList()).thenReturn(rows);
    }

    @Test
    @SuppressWarnings("unchecked")
    void returnsSchemaForKnownCr() {
        IgaChangeRequestEntity cr = cr();
        cr.setRequestModel("QkFTRTY0LUNBUlJJRVI=");
        when(em.find(IgaChangeRequestEntity.class, "cr-1")).thenReturn(cr);

        IgaAuthorizationEntity a = new IgaAuthorizationEntity();
        a.setAuthorizedBy("admin-uuid");
        a.setApproval("alice");
        a.setCreatedAt(1700000050L);
        stubAuths(List.of(a));

        // realm threshold default (no iga.threshold attr) -> 1.
        Response resp = resource.diagnosticBundle("cr-1");
        assertEquals(200, resp.getStatus());

        Map<String, Object> body = (Map<String, Object>) resp.getEntity();
        assertEquals("iga_cr_bundle", body.get("diag_kind"));
        assertEquals(1, body.get("schema_version"));
        assertEquals(REALM_ID, body.get("realm_id"));

        Map<String, Object> crMap = (Map<String, Object>) body.get("cr");
        assertEquals("cr-1", crMap.get("id"));
        assertEquals("CLIENT_SCOPE", crMap.get("entity_type"));
        assertEquals("cs-uuid", crMap.get("entity_id"));
        assertEquals("CREATE_CLIENT_SCOPE", crMap.get("action_type"));
        assertEquals("PENDING", crMap.get("status"));
        assertEquals("admin-uuid", crMap.get("requested_by"));
        assertEquals(1700000000L, crMap.get("created_at"));
        assertEquals(List.of(), crMap.get("depends_on"));
        assertEquals("QkFTRTY0LUNBUlJJRVI=", crMap.get("request_model"));
        // rows_json parsed into a tree (array preserved).
        assertNotNull(crMap.get("rows_json"));
        assertTrue(crMap.get("rows_json").toString().contains("cs-uuid"));

        List<Map<String, Object>> auths = (List<Map<String, Object>>) body.get("authorizations");
        assertEquals(1, auths.size());
        assertEquals("admin-uuid", auths.get(0).get("authorized_by"));
        assertEquals("alice", auths.get(0).get("approval"));
        assertEquals(1700000050L, auths.get(0).get("created_at"));

        assertEquals(1, body.get("threshold"));
        // No per-scope role + no realm iga.approverRole -> null.
        assertNull(body.get("approver_role"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void requestModelNullWhenAbsent() {
        IgaChangeRequestEntity cr = cr();   // requestModel left null
        when(em.find(IgaChangeRequestEntity.class, "cr-1")).thenReturn(cr);
        stubAuths(List.of());

        Response resp = resource.diagnosticBundle("cr-1");
        assertEquals(200, resp.getStatus());
        Map<String, Object> body = (Map<String, Object>) resp.getEntity();
        Map<String, Object> crMap = (Map<String, Object>) body.get("cr");
        assertNull(crMap.get("request_model"));
        assertTrue(((List<?>) body.get("authorizations")).isEmpty());
    }

    @Test
    @SuppressWarnings("unchecked")
    void approverRoleFromRealmDefault() {
        IgaChangeRequestEntity cr = cr();
        when(em.find(IgaChangeRequestEntity.class, "cr-1")).thenReturn(cr);
        stubAuths(List.of());
        // realm-level iga.approverRole (CREATE_CLIENT_SCOPE has empty per-scope set).
        when(realm.getAttribute("iga.approverRole")).thenReturn("realm-approver");

        Response resp = resource.diagnosticBundle("cr-1");
        Map<String, Object> body = (Map<String, Object>) resp.getEntity();
        assertEquals("realm-approver", body.get("approver_role"));
    }

    @Test
    void notFoundForUnknownId() {
        when(em.find(IgaChangeRequestEntity.class, "ghost")).thenReturn(null);
        Response resp = resource.diagnosticBundle("ghost");
        assertEquals(404, resp.getStatus());
    }

    @Test
    void notFoundForCrossRealmCr() {
        IgaChangeRequestEntity cr = cr();
        cr.setRealmId("some-other-realm");
        when(em.find(IgaChangeRequestEntity.class, "cr-1")).thenReturn(cr);
        Response resp = resource.diagnosticBundle("cr-1");
        assertEquals(404, resp.getStatus());
    }

    @Test
    void noPrivateKeyMaterialInDump() {
        // The dump must never carry anything key-shaped. request_model is the
        // public carrier; authorizations carry usernames/dokens. Assert no
        // sensitive key field names leak into the serialized body.
        IgaChangeRequestEntity cr = cr();
        cr.setRequestModel("QkFTRTY0");
        when(em.find(IgaChangeRequestEntity.class, "cr-1")).thenReturn(cr);
        stubAuths(List.of());

        Response resp = resource.diagnosticBundle("cr-1");
        String s = resp.getEntity().toString().toLowerCase();
        assertFalse(s.contains("eddsaprivatekey"), "no eddsaPrivateKey");
        assertFalse(s.contains("privatekey"), "no privateKey");
        assertFalse(s.contains("vrk_priv"), "no VRK private");
    }
}
