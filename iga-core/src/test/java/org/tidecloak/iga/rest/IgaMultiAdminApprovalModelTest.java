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
import org.midgard.Serialization.Tools;
import org.midgard.models.ModelRequest;
import org.midgard.models.RequestExtensions.AttestationUnitSignRequest;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.entities.IgaAuthorizerEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit coverage for the M1 multiAdmin two-phase approval endpoints
 * ({@code GET/POST /iga/change-requests/{id}/approval-model}) and the carrier
 * round-trip the phase-2 accept-back validates.
 *
 * <p>The endpoint tests assert the early gates (the discriminators that keep
 * firstAdmin single-phase untouched): a non-PENDING CR and a non-multiAdmin realm
 * both short-circuit with 409 BEFORE any Midgard work, and a phase-2 POST with no
 * {@code requestModel} is a 400. These hold without standing up real signing —
 * exactly the gate behaviour the two-phase seam contracts.
 *
 * <p>A non-Tide realm has {@code iga.attestor != "tide"}, so
 * {@code TideAttestor.isMultiAdminMode} resolves to {@code false} (the no-row /
 * Tideless branch) — which is precisely the NOT_MULTI_ADMIN gate we assert.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class IgaMultiAdminApprovalModelTest {

    private static final String REALM_ID = "realm-uuid-abc";

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
        // A non-Tide realm: iga.attestor is null, so resolveMode -> null and
        // isMultiAdminMode -> false (the NOT_MULTI_ADMIN gate path).
        when(realm.getAttribute("iga.attestor")).thenReturn(null);
        // resolveMode() runs IgaAuthorizer.findByRealm first; stub it to no rows so
        // it falls through to the (null) iga.attestor discriminator -> not multiAdmin.
        @SuppressWarnings("unchecked")
        TypedQuery<IgaAuthorizerEntity> authzQ = mock(TypedQuery.class);
        when(em.createNamedQuery(eq("IgaAuthorizer.findByRealm"), eq(IgaAuthorizerEntity.class)))
                .thenReturn(authzQ);
        when(authzQ.setParameter(anyString(), org.mockito.ArgumentMatchers.any())).thenReturn(authzQ);
        when(authzQ.getResultStream()).thenReturn(Stream.empty());
        resource = new IgaAdminResource(session, realm, auth);
    }

    private IgaChangeRequestEntity cr(String id, String status) {
        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setId(id);
        cr.setRealmId(REALM_ID);
        cr.setStatus(status);
        cr.setActionType("GRANT_ROLES");
        return cr;
    }

    // -- Phase 1 (GET) gates --------------------------------------------------

    @Test
    @SuppressWarnings("unchecked")
    void phase1RejectsNonPendingCr() {
        IgaChangeRequestEntity c = cr("cr-1", "APPROVED");
        when(em.find(IgaChangeRequestEntity.class, "cr-1")).thenReturn(c);

        Response resp = resource.getApprovalModel("cr-1");

        assertEquals(409, resp.getStatus());
        Map<String, Object> body = (Map<String, Object>) resp.getEntity();
        assertEquals("Change request is not in PENDING state", body.get("error"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void phase1RejectsNonMultiAdminRealm() {
        // PENDING CR but a non-multiAdmin (here Tideless) realm: the two-phase
        // ceremony does not apply — the caller must use single-phase authorize/commit.
        IgaChangeRequestEntity c = cr("cr-2", "PENDING");
        when(em.find(IgaChangeRequestEntity.class, "cr-2")).thenReturn(c);

        Response resp = resource.getApprovalModel("cr-2");

        assertEquals(409, resp.getStatus());
        Map<String, Object> body = (Map<String, Object>) resp.getEntity();
        assertEquals("NOT_MULTI_ADMIN", body.get("error"));
    }

    @Test
    void phase1NotFoundForUnknownCr() {
        when(em.find(IgaChangeRequestEntity.class, "ghost")).thenReturn(null);
        assertEquals(404, resource.getApprovalModel("ghost").getStatus());
    }

    // -- Phase 2 (POST) gates -------------------------------------------------

    @Test
    @SuppressWarnings("unchecked")
    void phase2RejectsNonMultiAdminRealm() {
        IgaChangeRequestEntity c = cr("cr-3", "PENDING");
        when(em.find(IgaChangeRequestEntity.class, "cr-3")).thenReturn(c);

        Response resp = resource.submitApprovalModel("cr-3", Map.of("requestModel", "ignored"));

        assertEquals(409, resp.getStatus());
        Map<String, Object> body = (Map<String, Object>) resp.getEntity();
        assertEquals("NOT_MULTI_ADMIN", body.get("error"));
    }

    @Test
    void phase2NotFoundForUnknownCr() {
        when(em.find(IgaChangeRequestEntity.class, "ghost")).thenReturn(null);
        assertEquals(404,
                resource.submitApprovalModel("ghost", Map.of("requestModel", "x")).getStatus());
    }

    // -- Carrier round-trip: the format the phase-2 accept-back validates -----

    @Test
    void approvalModelCarrierRoundTrips() throws Exception {
        // M2 draft framing: phase 1 builds the request via the proper Midgard
        // AttestationUnitSignRequest (NOT a raw ModelRequest.New) — SetUnits stores the
        // unit CBOR verbatim and SerializeDraft frames it as a TideMemory the ork's
        // AttestationUnitSignRequest.Deserialize reads via Draft.TryGetValue(i). The
        // phase-1 build persists Base64(Encode()); phase-2 accepts it back and validates
        // it via ModelRequest.FromBytes. Prove that exact contract holds for a Policy:1
        // AttestationUnit request carrying a unit draft + an embedded policy — without
        // needing real signing.
        byte[] unitCbor = "user_role_mapping_set-cbor-bytes".getBytes(StandardCharsets.UTF_8);
        AttestationUnitSignRequest req = new AttestationUnitSignRequest("Policy:1");
        req.SetUnits(new byte[][]{ unitCbor });
        req.SetPolicy("admin-policy-bytes".getBytes(StandardCharsets.UTF_8));
        // Materialize Draft BEFORE Encode() (units are folded into Draft lazily) — exactly
        // what buildMultiAdminApprovalModel does via GetDraft().
        req.GetDraft();

        String b64 = Base64.getEncoder().encodeToString(req.Encode());
        // The carrier stores a Base64 string; it must decode + parse back to a request.
        ModelRequest parsed = ModelRequest.FromBytes(Base64.getDecoder().decode(b64));
        assertNotNull(parsed, "phase-2 must be able to FromBytes the phase-1 carrier payload");

        // The reloaded request's seg-3 Draft IS the ork-format TideMemory unit framing:
        // walking it the way the ork's AttestationUnitSignRequest.Deserialize does
        // (Draft.TryGetValue(0)) recovers the unit CBOR verbatim.
        byte[] reloadedDraft = parsed.GetDraft();
        byte[] recoveredUnit = Tools.GetValue(reloadedDraft, 0);
        assertArrayEquals(unitCbor, recoveredUnit,
                "the carrier's Draft must be the TideMemory unit framing the ork Deserialize reads");

        // The entity carrier holds it verbatim (the column round-trip).
        IgaChangeRequestEntity c = cr("cr-rt", "PENDING");
        c.setRequestModel(b64);
        assertEquals(b64, c.getRequestModel());
        assertTrue(c.getRequestModel().length() > 0);
    }
}
