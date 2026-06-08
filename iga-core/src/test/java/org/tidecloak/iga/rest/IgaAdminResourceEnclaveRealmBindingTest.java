package org.tidecloak.iga.rest;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakSessionTask;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.entities.IgaAuthorizerEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Regression coverage for the swallowed "Session not bound to a realm" at approval-enclave open.
 *
 * <p>{@code IgaAdminResource.ensureThresholdPolicyCrForEnclave} runs the steady-state
 * multiAdmin threshold-policy ensure inside a FRESH {@code runJobInTransaction} session and
 * re-fetches the realm — but before the fix it never bound that realm onto the new session's
 * {@link KeycloakContext}. Downstream, {@code TideAttestor.countActiveTideRealmAdmins} →
 * {@code session.users().getRoleMembersStream} hits the KC 26.5.5 Infinispan
 * organization-provider guard, which reads {@code session.getContext().getRealm()} == null and
 * throws {@code IllegalArgumentException: Session not bound to a realm}. The wrapper's
 * best-effort try/catch swallowed it as a WARN, so the policy CR was never created.
 *
 * <p>This test drives the public {@code listChangeRequests("PENDING")} entry (the enclave-open
 * trigger), captures the nested {@code KeycloakSessionTask} by mocking the static
 * {@code KeycloakModelUtils.runJobInTransaction}, runs it with a controlled inner session, and
 * asserts {@code newSession.getContext().setRealm(newRealm)} is invoked BEFORE the ensure runs —
 * mirroring the {@code IgaAdoptScan} bind.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class IgaAdminResourceEnclaveRealmBindingTest {

    private static final String REALM_ID = "realm-uuid-enclave";

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock(answer = Answers.RETURNS_DEEP_STUBS) AdminPermissionEvaluator auth;
    @Mock JpaConnectionProvider jpa;
    @Mock EntityManager em;

    @Test
    void enclaveOpen_bindsRealmOnFreshJobSessionContext() {
        when(realm.getId()).thenReturn(REALM_ID);

        // Outer (request-thread) session: only getKeycloakSessionFactory() + the post-ensure
        // read are exercised. The post-ensure listing uses getProvider(JpaConnectionProvider).
        when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa);
        when(jpa.getEntityManager()).thenReturn(em);
        KeycloakSessionFactory factory = mock(KeycloakSessionFactory.class);
        when(session.getKeycloakSessionFactory()).thenReturn(factory);

        // The post-ensure PENDING listing (IgaChangeRequest.findPendingByRealm) returns nothing.
        @SuppressWarnings("unchecked")
        TypedQuery<IgaChangeRequestEntity> listQ = mock(TypedQuery.class);
        when(em.createNamedQuery(eq("IgaChangeRequest.findPendingByRealm"), eq(IgaChangeRequestEntity.class)))
                .thenReturn(listQ);
        when(listQ.setParameter(anyString(), any())).thenReturn(listQ);
        when(listQ.getResultList()).thenReturn(List.of());

        // The fresh job (inner) session the wrapper opens.
        KeycloakSession newSession = mock(KeycloakSession.class);

        // Stateful inner context: getRealm() is null until setRealm(x) is called, then x —
        // mirrors the real binding so an unbound-then-bound transition is observable.
        KeycloakContext newCtx = mock(KeycloakContext.class);
        AtomicReference<RealmModel> bound = new AtomicReference<>();
        org.mockito.Mockito.doAnswer(inv -> { bound.set(inv.getArgument(0)); return null; })
                .when(newCtx).setRealm(any());
        when(newCtx.getRealm()).thenAnswer(inv -> bound.get());
        when(newSession.getContext()).thenReturn(newCtx);

        // newSession.realms().getRealm(realmId) -> the re-fetched newRealm.
        RealmProvider newRealms = mock(RealmProvider.class);
        when(newSession.realms()).thenReturn(newRealms);
        RealmModel newRealm = mock(RealmModel.class);
        when(newRealm.getId()).thenReturn(REALM_ID);
        when(newRealm.getName()).thenReturn("enclave-realm");
        when(newRealms.getRealm(REALM_ID)).thenReturn(newRealm);

        // Inner EM: drive TideAttestor.ensureThresholdPolicyCrForEnclave to a cheap no-op via the
        // resolveMode short-circuit (IgaAuthorizer.findByRealm -> no rows + iga.attestor null ->
        // not multiAdmin -> ensure returns before any user-stream lookup). This keeps the test
        // focused on the realm-bind contract, not the projection arithmetic (covered elsewhere).
        JpaConnectionProvider newJpa = mock(JpaConnectionProvider.class);
        EntityManager newEm = mock(EntityManager.class);
        when(newSession.getProvider(JpaConnectionProvider.class)).thenReturn(newJpa);
        when(newJpa.getEntityManager()).thenReturn(newEm);
        when(newRealm.getAttribute("iga.attestor")).thenReturn(null);
        @SuppressWarnings("unchecked")
        TypedQuery<IgaAuthorizerEntity> authzQ = mock(TypedQuery.class);
        when(newEm.createNamedQuery(eq("IgaAuthorizer.findByRealm"), eq(IgaAuthorizerEntity.class)))
                .thenReturn(authzQ);
        when(authzQ.setParameter(anyString(), any())).thenReturn(authzQ);
        when(authzQ.getResultStream()).thenReturn(Stream.empty());

        IgaAdminResource resource = new IgaAdminResource(session, realm, auth);

        AtomicReference<RealmModel> boundWhenEnsureEntered = new AtomicReference<>();

        try (MockedStatic<KeycloakModelUtils> kmu = org.mockito.Mockito.mockStatic(KeycloakModelUtils.class)) {
            kmu.when(() -> KeycloakModelUtils.runJobInTransaction(eq(factory), any(KeycloakSessionTask.class)))
                    .thenAnswer(inv -> {
                        KeycloakSessionTask task = inv.getArgument(1);
                        // Precondition: the fresh session is unbound when the task starts.
                        org.junit.jupiter.api.Assertions.assertNull(newSession.getContext().getRealm(),
                                "fresh job session must start unbound");
                        task.run(newSession);
                        // Capture what was bound by the time the task finished.
                        boundWhenEnsureEntered.set(newSession.getContext().getRealm());
                        return null;
                    });

            List<?> out = resource.listChangeRequests("PENDING");
            assertNotNull(out, "listing must still return (ensure never poisons the read)");
        }

        // The wrapper bound the re-fetched realm onto the fresh job session's context.
        verify(newCtx).setRealm(newRealm);
        assertSame(newRealm, boundWhenEnsureEntered.get(),
                "newRealm must be bound on the fresh job session before the threshold ensure runs");
    }
}
