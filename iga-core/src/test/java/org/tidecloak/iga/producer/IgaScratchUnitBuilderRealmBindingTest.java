package org.tidecloak.iga.producer;

import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Test;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakSessionTask;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.mockito.MockedStatic;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.producer.units.AttestationUnit;
import org.tidecloak.iga.replay.IgaReplayDispatcher;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Regression coverage for the multiAdmin approval-model build bug
 * ("APPROVAL_MODEL_BUILD_FAILED: Session not bound to a realm").
 *
 * <p>{@code IgaScratchUnitBuilder.unitsFromScratchReplay} opens a nested
 * {@code runJobInTransaction} scratch session for the P4 scratch-replay-and-read.
 * Before the fix it never bound the realm context on that scratch session, so the
 * downstream enumeration's {@code session.users().getUserById(realm, id)} →
 * {@code validateUser} → {@code isReadOnlyOrganizationMember} →
 * {@code OrganizationProvider.getRealm()} read {@code scratch.getContext().getRealm()}
 * == null and threw {@code IllegalArgumentException: Session not bound to a realm}.
 *
 * <p>This test drives the nested {@code KeycloakSessionTask} (captured by mocking the
 * static {@code KeycloakModelUtils.runJobInTransaction}) with a controlled scratch
 * session and asserts that {@code scratch.getContext().setRealm(scratchRealm)} is
 * invoked BEFORE the enumerator runs — so an enumerator reading the bound realm
 * succeeds rather than throwing.
 */
class IgaScratchUnitBuilderRealmBindingTest {

    private static final String REALM_ID = "realm-uuid-scratch";

    @Test
    void bindsRealmContextOnScratchSessionBeforeEnumeration() {
        // The request-thread session/realm (only realm.getId() is read off it).
        RealmModel requestRealm = mock(RealmModel.class);
        when(requestRealm.getId()).thenReturn(REALM_ID);
        KeycloakSession requestSession = mock(KeycloakSession.class);
        KeycloakSessionFactory factory = mock(KeycloakSessionFactory.class);
        when(requestSession.getKeycloakSessionFactory()).thenReturn(factory);

        // The nested scratch session the job runs on.
        KeycloakSession scratch = mock(KeycloakSession.class);
        KeycloakContext scratchContext = mock(KeycloakContext.class);
        when(scratch.getContext()).thenReturn(scratchContext);
        // Make the mock context stateful: setRealm(x) -> getRealm() returns x. This mirrors
        // the real binding so the enumerator's getRealm() read observes what was bound.
        AtomicReference<RealmModel> boundRealm = new AtomicReference<>();
        org.mockito.Mockito.doAnswer(inv -> { boundRealm.set(inv.getArgument(0)); return null; })
                .when(scratchContext).setRealm(any());
        when(scratchContext.getRealm()).thenAnswer(inv -> boundRealm.get());
        RealmProvider scratchRealms = mock(RealmProvider.class);
        when(scratch.realms()).thenReturn(scratchRealms);
        RealmModel scratchRealm = mock(RealmModel.class);
        when(scratchRealm.getId()).thenReturn(REALM_ID);
        when(scratchRealms.getRealm(REALM_ID)).thenReturn(scratchRealm);

        // The finally block sets rollback-only and removes the replay flag.
        org.keycloak.models.KeycloakTransactionManager txMgr =
                mock(org.keycloak.models.KeycloakTransactionManager.class);
        when(scratch.getTransactionManager()).thenReturn(txMgr);

        JpaConnectionProvider jpa = mock(JpaConnectionProvider.class);
        EntityManager em = mock(EntityManager.class);
        when(scratch.getProvider(JpaConnectionProvider.class)).thenReturn(jpa);
        when(jpa.getEntityManager()).thenReturn(em);

        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setId("cr-scratch");
        cr.setRealmId(REALM_ID);
        cr.setActionType("GRANT_ROLES");

        // The enumerator stands in for enumerateLiveCrUnits: it reads the bound realm
        // off the scratch context (the exact read path that NPE'd) and would throw if
        // the realm were unbound. Records what it saw bound.
        AtomicReference<RealmModel> boundAtEnumerate = new AtomicReference<>();
        IgaScratchUnitBuilder.LiveUnitEnumerator enumerator =
                (s, r, e, c) -> {
                    boundAtEnumerate.set(s.getContext().getRealm());
                    if (s.getContext().getRealm() == null) {
                        throw new IllegalArgumentException("Session not bound to a realm");
                    }
                    return Collections.emptyList();
                };

        try (MockedStatic<KeycloakModelUtils> kmu = org.mockito.Mockito.mockStatic(KeycloakModelUtils.class);
             MockedStatic<IgaReplayDispatcher> replay = org.mockito.Mockito.mockStatic(IgaReplayDispatcher.class)) {

            // Make runJobInTransaction(factory, task) synchronously invoke the captured
            // task with our controlled scratch session.
            kmu.when(() -> KeycloakModelUtils.runJobInTransaction(eq(factory), any(KeycloakSessionTask.class)))
                    .thenAnswer(inv -> {
                        KeycloakSessionTask task = inv.getArgument(1);
                        task.run(scratch);
                        return null;
                    });

            // The dispatcher replay is exercised separately; here it is a no-op so the
            // test isolates the realm-binding behavior.
            replay.when(() -> IgaReplayDispatcher.replay(any(), any(), any(), anyBoolean()))
                    .thenAnswer(inv -> null);

            List<AttestationUnit> result = assertDoesNotThrow(() ->
                    IgaScratchUnitBuilder.unitsFromScratchReplay(
                            requestSession, requestRealm, cr, enumerator),
                    "unitsFromScratchReplay must not throw 'Session not bound to a realm'");
            assertNotNull(result);
        }

        // The realm context was bound to the scratch realm, and it was bound BEFORE the
        // enumerator ran (the enumerator observed it non-null).
        assertSame(scratchRealm, boundAtEnumerate.get(),
                "the enumerator must observe the scratch realm bound on the scratch session");

        // setRealm(scratchRealm) is invoked on the scratch context.
        verify(scratchContext).setRealm(scratchRealm);
    }
}
