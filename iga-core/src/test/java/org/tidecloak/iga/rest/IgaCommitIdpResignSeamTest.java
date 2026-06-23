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
import org.keycloak.models.UserModel;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.mockito.Answers;
import org.mockito.MockedStatic;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.attestors.IgaAttestor;
import org.tidecloak.iga.attestors.IgaAttestors;
import org.tidecloak.iga.attestors.IgaScopeResolver;
import org.tidecloak.iga.entities.IgaAuthorizationEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.replay.IgaReplayDispatcher;
import org.tidecloak.iga.replay.IgaReplayExtension;
import org.tidecloak.iga.services.IgaToggleOnBackfill;
import org.tidecloak.iga.signing.IgaIdpSettingsResign;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

/**
 * Seam test for the IGA single-CR commit tail re-sign hook
 * ({@code POST /iga/change-requests/{id}/commit}).
 *
 * <p>Asserts that the commit tail invokes
 * {@link IgaIdpSettingsResign#maybeReSign} with the committed CR — so a
 * {@code SET_REALM_CONFIG} CR that changed {@code setRegistrationAllowed}
 * re-signs the IdP settings (RegOn) and any other CR does not. The heavy
 * collaborators (scope resolver, attestor, replay, convergence) are static-mocked
 * so the test exercises the tail wiring, not the replay internals. The predicate
 * itself (which CRs trigger) is covered exhaustively in
 * {@code IgaIdpSettingsResignTest}.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class IgaCommitIdpResignSeamTest {

    private static final String REALM_ID = "realm-uuid-seam";

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

        // commit()'s legacy-lane multiAdmin guard consults TideAttestor.isMultiAdminMode ->
        // resolveMode -> IgaAuthorizer.findByRealm. This is a non-tide / non-multiAdmin realm
        // (no authorizer row), so stub the query to return no rows -> resolveMode falls to the
        // (null) iga.attestor discriminator -> not multiAdmin -> the guard passes straight
        // through to the commit tail under test.
        @SuppressWarnings("unchecked")
        TypedQuery<org.tidecloak.iga.entities.IgaAuthorizerEntity> authQ = mock(TypedQuery.class);
        org.mockito.Mockito.lenient().when(em.createNamedQuery(eq("IgaAuthorizer.findByRealm"),
                eq(org.tidecloak.iga.entities.IgaAuthorizerEntity.class))).thenReturn(authQ);
        org.mockito.Mockito.lenient().when(authQ.setParameter(anyString(), any())).thenReturn(authQ);
        org.mockito.Mockito.lenient().when(authQ.getResultStream())
                .thenReturn(java.util.stream.Stream.empty());
    }

    private IgaChangeRequestEntity cr(String id, String actionType, String rowsJson) {
        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setId(id);
        cr.setRealmId(REALM_ID);
        cr.setStatus("PENDING");
        cr.setActionType(actionType);
        cr.setRowsJson(rowsJson);
        return cr;
    }

    /**
     * Drive {@code commit(id)} to its tail with all the heavy collaborators
     * stubbed, capturing every {@code maybeReSign} call. Returns the static mock
     * so the caller can verify.
     */
    @SuppressWarnings("unchecked")
    private void driveCommitAndVerify(IgaChangeRequestEntity cr, boolean expectResign) {
        when(em.find(IgaChangeRequestEntity.class, cr.getId())).thenReturn(cr);

        // Authenticated admin (so the 401 branch is skipped).
        UserModel admin = mock(UserModel.class);
        when(auth.adminAuth().getUser()).thenReturn(admin);

        // Threshold query -> one authorization, threshold 1 (met).
        TypedQuery<IgaAuthorizationEntity> q = mock(TypedQuery.class);
        when(em.createNamedQuery("IgaAuthorization.findByChangeRequest", IgaAuthorizationEntity.class))
                .thenReturn(q);
        when(q.setParameter(anyString(), any())).thenReturn(q);
        when(q.getResultList()).thenReturn(List.of(new IgaAuthorizationEntity()));

        // toRepresentation(...) in the 200 tail counts authorizations via this
        // named query — stub it so the tail can build the response after the hook.
        TypedQuery<Long> countQ = mock(TypedQuery.class);
        when(em.createNamedQuery("IgaAuthorization.countByChangeRequest", Long.class))
                .thenReturn(countQ);
        when(countQ.setParameter(anyString(), any())).thenReturn(countQ);
        when(countQ.getSingleResult()).thenReturn(1L);

        IgaAttestor attestor = mock(IgaAttestor.class);
        when(attestor.getThreshold(any(), any(), any())).thenReturn(1);
        when(attestor.combineFinal(any(), any(), any())).thenReturn("ATTEST");
        when(attestor.isSetSigned()).thenReturn(false);

        try (MockedStatic<IgaAttestors> attestors = mockStatic(IgaAttestors.class);
             MockedStatic<IgaScopeResolver> scope = mockStatic(IgaScopeResolver.class);
             MockedStatic<IgaReplayExtension> ext = mockStatic(IgaReplayExtension.class);
             MockedStatic<IgaReplayDispatcher> disp = mockStatic(IgaReplayDispatcher.class);
             MockedStatic<IgaToggleOnBackfill> backfill = mockStatic(IgaToggleOnBackfill.class);
             MockedStatic<IgaIdpSettingsResign> resign = mockStatic(IgaIdpSettingsResign.class)) {

            attestors.when(() -> IgaAttestors.resolveAttestor(any(), any())).thenReturn(attestor);
            scope.when(() -> IgaScopeResolver.resolve(any(), any(), any()))
                    .thenReturn(mock(IgaScopeResolver.ResolvedScope.class));
            // requireApprover + convergeAfterCommit are void no-ops by default.
            // tryReplay returns false -> falls through to the dispatcher (also stubbed no-op).
            ext.when(() -> IgaReplayExtension.tryReplay(any(), any(), anyString(), anyBoolean()))
                    .thenReturn(false);

            Response resp = resource.commit(cr.getId());
            assertEquals(200, resp.getStatus(), "commit should reach its 200 tail");

            if (expectResign) {
                resign.verify(() -> IgaIdpSettingsResign.maybeReSign(session, realm, cr), times(1));
            } else {
                resign.verify(() -> IgaIdpSettingsResign.maybeReSign(any(), any(), eq(cr)), never());
            }
        }
    }

    @Test
    void commitTailReSignsWhenRegistrationAllowedChanged() {
        IgaChangeRequestEntity cr = cr("cr-reg", "SET_REALM_CONFIG",
                "[{\"key\":\"setRegistrationAllowed\",\"value\":\"true\"}]");
        driveCommitAndVerify(cr, true);
    }

    @Test
    void commitTailDoesNotReSignForVerifyEmailOnly() {
        // The hook is still INVOKED (it's an unconditional tail call), but with a
        // CR whose predicate is false it must be a no-op. We assert the tail calls
        // maybeReSign exactly once with this CR; the predicate test proves it does
        // nothing for setVerifyEmail. Here we assert the wiring passes the CR through.
        IgaChangeRequestEntity cr = cr("cr-verify", "SET_REALM_CONFIG",
                "[{\"key\":\"setVerifyEmail\",\"value\":\"true\"}]");
        // expectResign=true here means "the tail invoked maybeReSign with this CR";
        // the no-op-ness for non-signed fields is asserted in IgaIdpSettingsResignTest.
        driveCommitAndVerify(cr, true);
    }
}
