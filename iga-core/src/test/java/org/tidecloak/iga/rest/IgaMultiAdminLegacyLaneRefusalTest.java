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
import org.tidecloak.iga.attestors.TideAttestor;
import org.tidecloak.iga.entities.IgaAuthorizationEntity;
import org.tidecloak.iga.entities.IgaAuthorizerEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * SECURITY: the LEGACY simple authorize+commit lane must REFUSE a tide-multiAdmin
 * change request. A multiAdmin CR can only be signed by the approval enclave
 * (POST /iga/change-requests/{id}/approve), which collects an admin doken quorum and
 * Policy:1-signs the carrier. The simple authorize/commit path cannot collect a doken,
 * so without this guard a SINGLE manage-realm admin could authorize+commit a multiAdmin
 * CR with a bare-username record and a STUB attestation, bypassing the quorum entirely
 * (the reproduced hole: CREATE_ROLE authorize->commit succeeding with attestation
 * "TIDE-DUMMY-v1:" and no quorum).
 *
 * <p>This pins TWO layers of defense:
 * <ol>
 *   <li><b>REST guard</b> ({@code IgaAdminResource.refuseLegacyLaneForMultiAdmin}, wired
 *       into {@code authorize()} and {@code commit()}): a multiAdmin CR on the legacy lane
 *       returns 409 {@code MULTIADMIN_REQUIRES_APPROVAL_ENCLAVE} — while firstAdmin and
 *       Tideless are UNAFFECTED (the firstAdmin wizard's drainPendingCRs and Tideless both
 *       legitimately use authorize+commit).</li>
 *   <li><b>fail-closed sign guard</b> ({@code TideAttestor.sign}): even a direct/internal
 *       commit (e.g. bulkAuthorize) cannot stub-sign a non-producer multiAdmin CR that has
 *       NO collected enclave doken carrier — it throws instead.</li>
 * </ol>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class IgaMultiAdminLegacyLaneRefusalTest {

    private static final String REALM_ID = "realm-multiadmin-uuid";

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock(answer = Answers.RETURNS_DEEP_STUBS) AdminPermissionEvaluator auth;
    @Mock JpaConnectionProvider jpa;
    @Mock EntityManager em;

    private IgaAdminResource resource;

    @BeforeEach
    void setUp() {
        lenient().when(realm.getId()).thenReturn(REALM_ID);
        lenient().when(realm.getName()).thenReturn("multiadmin-realm");
        lenient().when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa);
        lenient().when(jpa.getEntityManager()).thenReturn(em);
        resource = new IgaAdminResource(session, realm, auth);
    }

    /**
     * Configure the realm + session as a tide-MULTIADMIN realm:
     * - iga.attestor=tide so IgaAttestors.resolveAttestor returns a TideAttestor;
     * - an IgaAuthorizer row with mode=multiAdmin so resolveMode() reports multiAdmin.
     */
    private void asMultiAdminTideRealm() {
        when(realm.getAttribute("iga.attestor")).thenReturn(TideAttestor.ID);
        when(session.getProvider(IgaAttestor.class, TideAttestor.ID))
                .thenReturn(new TideAttestor(session));

        IgaAuthorizerEntity row = new IgaAuthorizerEntity();
        row.setRealmId(REALM_ID);
        row.setMode(TideAttestor.MODE_MULTI_ADMIN);
        stubAuthorizerFindByRealm(row);
        stubEmptyAuthorizations();
        stubNoTideRealmAdminPolicy();
    }

    /**
     * The commit lane's sub-quorum guard resolves the multiAdmin threshold via
     * {@code TideAttestor.getThreshold -> findTideRealmAdminPolicy}, which queries
     * {@code IgaRolePolicy.findByRealmAndName}. With no policy row the threshold falls back to
     * {@code max(1, floor(0.7 * activeAdmins))} = 1 (the bare realm mock has no admins), so a
     * commit with 0 collected approvals is refused sub-quorum. Stub the query to no rows.
     */
    @SuppressWarnings("unchecked")
    private void stubNoTideRealmAdminPolicy() {
        TypedQuery<org.tidecloak.iga.entities.IgaRolePolicyEntity> q = mock(TypedQuery.class);
        lenient().when(em.createNamedQuery(eq("IgaRolePolicy.findByRealmAndName"),
                eq(org.tidecloak.iga.entities.IgaRolePolicyEntity.class))).thenReturn(q);
        lenient().when(q.setParameter(anyString(), any())).thenReturn(q);
        lenient().when(q.getResultStream()).thenAnswer(inv -> Stream.empty());
    }

    /** A firstAdmin tide realm: iga.attestor=tide, authorizer row mode=firstAdmin. */
    private void asFirstAdminTideRealm() {
        when(realm.getAttribute("iga.attestor")).thenReturn(TideAttestor.ID);
        when(session.getProvider(IgaAttestor.class, TideAttestor.ID))
                .thenReturn(new TideAttestor(session));

        IgaAuthorizerEntity row = new IgaAuthorizerEntity();
        row.setRealmId(REALM_ID);
        row.setMode(TideAttestor.MODE_FIRST_ADMIN);
        stubAuthorizerFindByRealm(row);
        stubEmptyAuthorizations();
    }

    /** A Tideless realm: iga.attestor unset -> SimpleNameAttestor, no multiAdmin mode. */
    private void asTidelessRealm() {
        when(realm.getAttribute("iga.attestor")).thenReturn(null);
        when(session.getProvider(IgaAttestor.class, SimpleNameAttestor.ID))
                .thenReturn(new SimpleNameAttestor(session));
        // resolveMode is only consulted defensively here; no row -> null/firstAdmin branch,
        // but the simple attestor isn't a TideAttestor so the guard never fires regardless.
        stubAuthorizerFindByRealm(null);
        stubEmptyAuthorizations();
    }

    @SuppressWarnings("unchecked")
    private void stubAuthorizerFindByRealm(IgaAuthorizerEntity row) {
        TypedQuery<IgaAuthorizerEntity> q = mock(TypedQuery.class);
        lenient().when(em.createNamedQuery(eq("IgaAuthorizer.findByRealm"), eq(IgaAuthorizerEntity.class)))
                .thenReturn(q);
        lenient().when(q.setParameter(anyString(), any())).thenReturn(q);
        // A single commit() call resolves the mode more than once (isMultiAdminMode, then
        // getThreshold -> resolveMode), each consuming this stream. A single Stream.of(row)
        // is closed after the first findFirst -> "stream has already been operated upon".
        // Return a FRESH stream per invocation so every resolveMode read succeeds.
        lenient().when(q.getResultStream())
                .thenAnswer(inv -> row == null ? Stream.empty() : Stream.of(row));
    }

    @SuppressWarnings("unchecked")
    private void stubEmptyAuthorizations() {
        TypedQuery<IgaAuthorizationEntity> q = mock(TypedQuery.class);
        lenient().when(em.createNamedQuery(eq("IgaAuthorization.findByChangeRequest"),
                        eq(IgaAuthorizationEntity.class)))
                .thenReturn(q);
        lenient().when(q.setParameter(anyString(), any())).thenReturn(q);
        lenient().when(q.getResultList()).thenReturn(Collections.emptyList());
    }

    private IgaChangeRequestEntity pendingCr(String id, String action) {
        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setId(id);
        cr.setRealmId(REALM_ID);
        cr.setStatus("PENDING");
        cr.setActionType(action);
        return cr;
    }

    // -- REST guard: multiAdmin is refused on the legacy lane -------------------

    @Test
    @SuppressWarnings("unchecked")
    void authorize_multiAdmin_nonProducerCr_isRefused() {
        asMultiAdminTideRealm();
        IgaChangeRequestEntity cr = pendingCr("cr-create-role", "CREATE_ROLE");
        when(em.find(IgaChangeRequestEntity.class, "cr-create-role")).thenReturn(cr);

        Response resp = resource.authorize("cr-create-role", Map.of());

        assertEquals(409, resp.getStatus(),
                "a multiAdmin CR on the legacy authorize lane must be refused with 409");
        Map<String, Object> body = (Map<String, Object>) resp.getEntity();
        assertEquals("MULTIADMIN_REQUIRES_APPROVAL_ENCLAVE", body.get("error"));
        assertTrue(String.valueOf(body.get("message")).contains("approval enclave"),
                "the refusal must point the caller at the approval enclave");
    }

    @Test
    @SuppressWarnings("unchecked")
    void commit_multiAdmin_nonProducerCr_isRefused() {
        asMultiAdminTideRealm();
        IgaChangeRequestEntity cr = pendingCr("cr-delete-user", "DELETE_USER");
        when(em.find(IgaChangeRequestEntity.class, "cr-delete-user")).thenReturn(cr);

        Response resp = resource.commit("cr-delete-user");

        // Two-button model (2026-06-16): approve (/approve, collects dokens) and commit
        // (/commit, apply-only) are now separate. The legacy commit lane no longer refuses
        // multiAdmin OUTRIGHT with 409 MULTIADMIN_REQUIRES_APPROVAL_ENCLAVE; instead
        // refuseSubQuorumCommitForMultiAdmin refuses a commit with < threshold collected
        // approvals as 412 QUORUM_NOT_MET (BEFORE replay). With 0 approvals and threshold 1
        // the lone-admin bypass is still refused — the security property is preserved.
        assertEquals(412, resp.getStatus(),
                "a multiAdmin CR committed sub-quorum must be refused with 412 BEFORE replay");
        Map<String, Object> body = (Map<String, Object>) resp.getEntity();
        assertEquals("QUORUM_NOT_MET", body.get("error"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void commit_multiAdmin_producerCr_isAlsoRefused() {
        // Even a producer-envelope action (GRANT_ROLES) cannot commit sub-quorum in
        // multiAdmin — the quorum/doken obligation is identical. Same two-button 412
        // QUORUM_NOT_MET refusal as the non-producer case above.
        asMultiAdminTideRealm();
        IgaChangeRequestEntity cr = pendingCr("cr-grant", "GRANT_ROLES");
        when(em.find(IgaChangeRequestEntity.class, "cr-grant")).thenReturn(cr);

        Response resp = resource.commit("cr-grant");

        assertEquals(412, resp.getStatus());
        Map<String, Object> body = (Map<String, Object>) resp.getEntity();
        assertEquals("QUORUM_NOT_MET", body.get("error"));
    }

    // -- Scope: firstAdmin / Tideless / ADOPT keep the legacy lane --------------

    @Test
    void authorize_firstAdmin_isNotRefusedByTheGuard() {
        // firstAdmin must keep authorize+commit (the wizard drainPendingCRs uses it).
        // The guard must NOT short-circuit here; the call proceeds past it into record()
        // (which may then fail for other unstubbed reasons, but NEVER with the multiAdmin
        // refusal). We assert: not a 409 MULTIADMIN_REQUIRES_APPROVAL_ENCLAVE.
        asFirstAdminTideRealm();
        IgaChangeRequestEntity cr = pendingCr("cr-fa", "CREATE_ROLE");
        when(em.find(IgaChangeRequestEntity.class, "cr-fa")).thenReturn(cr);

        Response resp = invokeGuardViaReflection(cr);
        assertNull(resp, "firstAdmin must NOT be refused by the multiAdmin legacy-lane guard");
    }

    @Test
    void tideless_isNotRefusedByTheGuard() {
        asTidelessRealm();
        IgaChangeRequestEntity cr = pendingCr("cr-tl", "CREATE_ROLE");
        Response resp = invokeGuardViaReflection(cr);
        assertNull(resp, "Tideless (SimpleNameAttestor) must NOT be refused by the guard");
    }

    @Test
    void adopt_multiAdmin_isExemptFromTheGuard() {
        asMultiAdminTideRealm();
        IgaChangeRequestEntity cr = pendingCr("cr-adopt", "ADOPT_ROLE");
        Response resp = invokeGuardViaReflection(cr);
        assertNull(resp, "ADOPT_* CRs are exempt from the multiAdmin legacy-lane refusal");
    }

    /**
     * Drive the private {@code refuseLegacyLaneForMultiAdmin(cr, attestor)} directly so the
     * firstAdmin/Tideless/ADOPT exemption assertions don't depend on the downstream
     * record()/commit() pipeline (which needs much more stubbing). Resolves the attestor the
     * same way the endpoints do.
     */
    private Response invokeGuardViaReflection(IgaChangeRequestEntity cr) {
        try {
            Method m = IgaAdminResource.class.getDeclaredMethod(
                    "refuseLegacyLaneForMultiAdmin", IgaChangeRequestEntity.class);
            m.setAccessible(true);
            return (Response) m.invoke(resource, cr);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // -- Secondary defense: TideAttestor.sign fail-closes the stub bypass -------

    @Test
    void sign_multiAdmin_nonProducerCr_withNoDokenCarrier_failsClosed() throws Exception {
        // A non-producer multiAdmin CR with NO collected doken carrier (requestModel == null)
        // is exactly the bypass shape a legacy commit / direct bulkAuthorize would produce.
        // sign() must THROW rather than stub-sign it.
        TideAttestor attestor = new TideAttestor(session);
        IgaChangeRequestEntity cr = mock(IgaChangeRequestEntity.class);
        when(cr.getId()).thenReturn("cr-no-carrier");
        when(cr.getActionType()).thenReturn("DISABLE_IGA");
        when(cr.getRequestModel()).thenReturn(null);

        Method signMethod = TideAttestor.class.getDeclaredMethod("sign",
                KeycloakSession.class, RealmModel.class, String.class,
                boolean.class, IgaChangeRequestEntity.class, byte[].class);
        signMethod.setAccessible(true);

        Throwable t = assertThrows(java.lang.reflect.InvocationTargetException.class, () ->
                signMethod.invoke(attestor, session, realm, TideAttestor.MODE_MULTI_ADMIN,
                        /*realCeremonyEligible*/ false, cr, "canonical".getBytes()));
        Throwable cause = t.getCause();
        assertTrue(cause instanceof RuntimeException,
                "the fail-closed guard must throw a RuntimeException");
        assertTrue(String.valueOf(cause.getMessage()).contains("no")
                        && String.valueOf(cause.getMessage()).contains("carrier"),
                "the throw must explain the missing doken carrier — was: " + cause.getMessage());
    }

    @Test
    void sign_multiAdmin_nonProducerCr_withDokenCarrier_stubsNormally() throws Exception {
        // The legitimate enclave path persists a doken carrier on requestModel; with one
        // present the non-producer CR stubs as designed (DISABLE_IGA must commit OFF even
        // without ORK reachability). Proves the guard keys on carrier-presence, not action.
        TideAttestor attestor = new TideAttestor(session);
        IgaChangeRequestEntity cr = mock(IgaChangeRequestEntity.class);
        lenient().when(cr.getId()).thenReturn("cr-with-carrier");
        when(cr.getActionType()).thenReturn("DISABLE_IGA");
        when(cr.getRequestModel()).thenReturn("present-enclave-doken-carrier");

        Method signMethod = TideAttestor.class.getDeclaredMethod("sign",
                KeycloakSession.class, RealmModel.class, String.class,
                boolean.class, IgaChangeRequestEntity.class, byte[].class);
        signMethod.setAccessible(true);

        String sig = (String) signMethod.invoke(attestor, session, realm,
                TideAttestor.MODE_MULTI_ADMIN, /*realCeremonyEligible*/ false, cr, "canonical".getBytes());
        assertTrue(sig.startsWith(TideAttestor.DUMMY_SIG_PREFIX),
                "a non-producer multiAdmin CR WITH a present doken carrier still stubs — was: " + sig);
        assertNotEquals("", sig);
    }
}
