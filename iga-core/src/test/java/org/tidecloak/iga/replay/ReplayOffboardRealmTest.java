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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
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
 *   <li>SPI present → {@code offboardRealm(session, realm, em)} is invoked exactly once;</li>
 *   <li>SPI absent (ragnarok not deployed → {@code getProvider} returns {@code null}) →
 *       the replay THROWS (fail-closed): the replay tx rolls back, nothing is torn down,
 *       and the dispatcher tail that flips {@code STATUS=APPROVED} is never reached;</li>
 *   <li>a {@link RagnarokOffboardException} from the SPI is surfaced as an unchecked
 *       exception so the replay tx rolls back.</li>
 * </ul>
 */
class ReplayOffboardRealmTest {

    private static Method replayOffboardRealm() throws Exception {
        Method m = IgaReplayDispatcher.class.getDeclaredMethod(
                "replayOffboardRealm", KeycloakSession.class, RealmModel.class,
                List.class, EntityManager.class);
        m.setAccessible(true);
        return m;
    }

    private static void invoke(KeycloakSession session, RealmModel realm, EntityManager em)
            throws Throwable {
        try {
            replayOffboardRealm().invoke(null, session, realm, new ArrayList<Map<String, Object>>(), em);
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
        when(svc.offboardRealm(any(), any(), any()))
                .thenReturn(RagnarokOffboardResult.ok("torn down 3 things"));
        KeycloakSession session = sessionWith(realm, svc);
        EntityManager em = mock(EntityManager.class);

        assertDoesNotThrow(() -> {
            try {
                invoke(session, realm, em);
            } catch (Throwable t) {
                throw new RuntimeException(t);
            }
        });

        verify(svc, times(1)).offboardRealm(eq(session), eq(realm), eq(em));
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
        when(svc.offboardRealm(any(), any(), any()))
                .thenThrow(new RagnarokOffboardException("teardown step 2 failed"));
        KeycloakSession session = sessionWith(realm, svc);
        EntityManager em = mock(EntityManager.class);

        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> invoke(session, realm, em));
        assertTrue(ex.getMessage().contains("ragnarok offboard failed"),
                "a failed teardown must surface a clear rollback message — was: " + ex.getMessage());
    }
}
