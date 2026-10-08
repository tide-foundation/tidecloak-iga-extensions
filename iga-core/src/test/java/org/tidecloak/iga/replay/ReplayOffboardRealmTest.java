package org.tidecloak.iga.replay;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.persistence.EntityManager;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.providers.RagnarokOffboardException;
import org.tidecloak.iga.providers.RagnarokOffboardResult;
import org.tidecloak.iga.providers.RagnarokOffboardService;

/**
 * Governed Ragnarok realm offboard: {@code IgaReplayDispatcher.replayOffboardRealm}
 * looks up the {@link RagnarokOffboardService} SPI BY TYPE on the session and runs the
 * real teardown on commit — iga-core does NOT depend on ragnarok.
 *
 * <p>Contract pinned here:
 * <ul>
 *   <li>SPI present + carrier non-blank → {@code offboardRealm(session, realm, em, carrier)}
 *       is invoked exactly once, with the CR's accumulated {@code REQUEST_MODEL} carrier;</li>
 *   <li>SPI absent (ragnarok not deployed → {@code getProvider} returns {@code null}) →
 *       the replay THROWS (fail-closed): the replay tx rolls back, nothing is torn down,
 *       and the dispatcher tail that flips {@code STATUS=APPROVED} is never reached;</li>
 *   <li>carrier null/blank (no dokens collected) → fail-closed throw (never run
 *       Midgard.Offboard without admin-quorum dokens);</li>
 *   <li>a {@link RagnarokOffboardException} from the SPI is surfaced as an unchecked
 *       exception so the replay tx rolls back.</li>
 * </ul>
 */
class ReplayOffboardRealmTest {

    private static final String CARRIER = "BASE64-OFFBOARD1-DOKEN-CARRIER";

    private static Method replayOffboardRealm() throws Exception {
        Method m = IgaReplayDispatcher.class.getDeclaredMethod(
                "replayOffboardRealm", KeycloakSession.class, RealmModel.class,
                IgaChangeRequestEntity.class, EntityManager.class);
        m.setAccessible(true);
        return m;
    }

    private static IgaChangeRequestEntity crWithCarrier(String carrier) {
        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setActionType("OFFBOARD_REALM");
        cr.setRequestModel(carrier);
        return cr;
    }

    private static void invoke(KeycloakSession session, RealmModel realm, EntityManager em)
            throws Throwable {
        invoke(session, realm, crWithCarrier(CARRIER), em);
    }

    private static void invoke(KeycloakSession session, RealmModel realm,
                               IgaChangeRequestEntity cr, EntityManager em) throws Throwable {
        try {
            replayOffboardRealm().invoke(null, session, realm, cr, em);
        } catch (InvocationTargetException e) {
            throw e.getCause();
        }
    }

    private static KeycloakSession sessionWith(RealmModel realm, RagnarokOffboardService svc) {
        KeycloakSession session = mock(KeycloakSession.class);
        KeycloakContext ctx = mock(KeycloakContext.class);
        when(session.getContext()).thenReturn(ctx);
        // getProvider(RagnarokOffboardService.class) → svc (may be null = ragnarok absent)
        when(session.getProvider(RagnarokOffboardService.class)).thenReturn(svc);
        return session;
    }

    @Test
    void spiPresent_invokesOffboardRealmOnce() throws Throwable {
        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn("offboard-me");
        RagnarokOffboardService svc = mock(RagnarokOffboardService.class);
        when(svc.offboardRealm(any(), any(), any(), any()))
                .thenReturn(RagnarokOffboardResult.ok("torn down 3 things"));
        KeycloakSession session = sessionWith(realm, svc);
        EntityManager em = mock(EntityManager.class);
        // After the SPI teardown, replayOffboardRealm neutralizes the realm's IGA_AUTHORIZER
        // mode row(s) via em.createNamedQuery("IgaAuthorizer.findByRealm", ...).getResultList()
        // (so resolveMode falls to the Tideless branch post-offboard). The bare EntityManager
        // mock returns null for createNamedQuery → NPE; stub it to yield an empty result list.
        @SuppressWarnings("unchecked")
        jakarta.persistence.TypedQuery<org.tidecloak.iga.entities.IgaAuthorizerEntity> authQ =
                mock(jakarta.persistence.TypedQuery.class);
        when(em.createNamedQuery(eq("IgaAuthorizer.findByRealm"),
                eq(org.tidecloak.iga.entities.IgaAuthorizerEntity.class))).thenReturn(authQ);
        when(authQ.setParameter(org.mockito.ArgumentMatchers.anyString(), any())).thenReturn(authQ);
        when(authQ.getResultList()).thenReturn(java.util.Collections.emptyList());

        assertDoesNotThrow(() -> {
            try {
                invoke(session, realm, em);
            } catch (Throwable t) {
                throw new RuntimeException(t);
            }
        });

        // The accumulated CR carrier (REQUEST_MODEL) is handed to the SPI verbatim.
        verify(svc, times(1)).offboardRealm(eq(session), eq(realm), eq(em), eq(CARRIER));
    }

    @Test
    void carrierNullOrBlank_failsClosed_neverInvokesSpi() throws Throwable {
        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn("offboard-me");
        RagnarokOffboardService svc = mock(RagnarokOffboardService.class);
        KeycloakSession session = sessionWith(realm, svc);
        EntityManager em = mock(EntityManager.class);

        // No accumulated doken carrier on the CR → refuse to run Midgard.Offboard.
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> invoke(session, realm, crWithCarrier("   "), em));
        assertTrue(ex.getMessage().contains("doken carrier"),
                "fail-closed message must name the missing doken carrier — was: " + ex.getMessage());
        verify(svc, never()).offboardRealm(any(), any(), any(), any());
    }

    @Test
    void spiAbsent_failsClosed_throwsAndNeverFlipsStatus() throws Throwable {
        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn("offboard-me");
        // svc == null → ragnarok not deployed.
        KeycloakSession session = sessionWith(realm, null);
        EntityManager em = mock(EntityManager.class);

        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> invoke(session, realm, em));
        assertTrue(ex.getMessage().contains("RagnarokOffboardService"),
                "fail-closed message must name the missing SPI — was: " + ex.getMessage());

        // The dispatcher tail flips STATUS=APPROVED via em.find(...).setStatus, which can
        // only run if doReplay returns normally. The throw above proves it never returned,
        // so no APPROVED flip occurred. Belt-and-braces: the absent-SPI path never touches
        // the EM at all.
        verify(em, never()).find(any(), any());
    }

    @Test
    void spiThrows_offboardException_isSurfacedSoReplayTxRollsBack() throws Throwable {
        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn("offboard-me");
        RagnarokOffboardService svc = mock(RagnarokOffboardService.class);
        when(svc.offboardRealm(any(), any(), any(), any()))
                .thenThrow(new RagnarokOffboardException("teardown step 2 failed"));
        KeycloakSession session = sessionWith(realm, svc);
        EntityManager em = mock(EntityManager.class);

        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> invoke(session, realm, em));
        assertTrue(ex.getMessage().contains("ragnarok offboard failed"),
                "a failed teardown must surface a clear rollback message — was: " + ex.getMessage());
    }
}
