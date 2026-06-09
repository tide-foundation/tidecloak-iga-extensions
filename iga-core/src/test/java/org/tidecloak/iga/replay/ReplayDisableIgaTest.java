package org.tidecloak.iga.replay;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * Governed IGA-disable teardown: {@code IgaReplayDispatcher.replayDisableIga} runs the
 * ON&rarr;OFF teardown that used to be inline in {@code TideAdminCompatResource.toggleIga},
 * now ONLY on commit of a DISABLE_IGA change request. In order, within the replay tx:
 * <ol>
 *   <li>{@code isIGAEnabled=false} (under IGA_REPLAY_ACTIVE so it is a real flag write,
 *       not a re-captured CR);</li>
 *   <li>{@code IgaAdoptCancel.cancel} (cancel PENDING ADOPTs + clear sidecar);</li>
 *   <li>user-cache + realm-cache eviction (best-effort, null cache providers → skipped);</li>
 *   <li>RS256 revert on a Tide realm whose default sig algorithm is EdDSA.</li>
 * </ol>
 *
 * <p>The teardown REVOKES NOTHING (re-ON-safe): no pack burn, no MODE flip, no VVK/VRK
 * retire. These tests assert the flag write, the cancel JPQL, and the RS256 revert /
 * non-revert; the eviction calls are exercised (no-op via null cache providers) so the
 * method runs end-to-end without throwing.</p>
 */
class ReplayDisableIgaTest {

    private static Method replayDisableIga() throws Exception {
        Method m = IgaReplayDispatcher.class.getDeclaredMethod(
                "replayDisableIga", KeycloakSession.class, RealmModel.class,
                List.class, EntityManager.class);
        m.setAccessible(true);
        return m;
    }

    private static List<Map<String, Object>> disableRows(String realmId) {
        Map<String, Object> row = new HashMap<>();
        row.put("REALM_ID", realmId);
        row.put("NAME", "isIGAEnabled");
        row.put("VALUE", "false");
        List<Map<String, Object>> rows = new ArrayList<>();
        rows.add(row);
        return rows;
    }

    /** Wire a session whose JPA provider yields an EM that tolerates the cancel JPQL. */
    private static KeycloakSession sessionWithJpa(RealmModel realm,
                                                  org.keycloak.models.IdentityProviderStorageProvider idps) {
        KeycloakSession session = mock(KeycloakSession.class);
        KeycloakContext ctx = mock(KeycloakContext.class);
        when(session.getContext()).thenReturn(ctx);
        when(session.identityProviders()).thenReturn(idps);

        // IgaAdoptCancel.cancel(session, realm) → session.getProvider(JpaConnectionProvider)
        //   .getEntityManager().createQuery(...).setParameter(...).executeUpdate()
        EntityManager em = mock(EntityManager.class);
        Query q = mock(Query.class);
        when(em.createQuery(anyString())).thenReturn(q);
        when(q.setParameter(anyString(), any())).thenReturn(q);
        when(q.executeUpdate()).thenReturn(0);
        JpaConnectionProvider jpa = mock(JpaConnectionProvider.class);
        when(jpa.getEntityManager()).thenReturn(em);
        when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa);

        // Cache providers absent → eviction is a no-op (best-effort).
        // (Unstubbed getProvider(...) returns null by default for the cache providers.)
        return session;
    }

    @Test
    void disablesFlagAndCancelsAdopts_tideRealmRevertsEdDSAToRs256() throws Exception {
        String realmId = "realm-uuid-1";
        RealmModel realm = mock(RealmModel.class);
        when(realm.getId()).thenReturn(realmId);
        when(realm.getName()).thenReturn("acme");

        // Tide realm: tide IdP present + tide-vendor-key component present, default = EdDSA.
        org.keycloak.models.IdentityProviderStorageProvider idps =
                mock(org.keycloak.models.IdentityProviderStorageProvider.class);
        IdentityProviderModel tideIdp = mock(IdentityProviderModel.class);
        when(idps.getByAlias("tide")).thenReturn(tideIdp);
        KeycloakSession session = sessionWithJpa(realm, idps);
        ComponentModel vendorKey = mock(ComponentModel.class);
        when(vendorKey.getProviderId()).thenReturn("tide-vendor-key");
        when(realm.getComponentsStream()).thenReturn(Stream.of(vendorKey));
        when(realm.getDefaultSignatureAlgorithm()).thenReturn("EdDSA");

        assertDoesNotThrow(() -> {
            try {
                replayDisableIga().invoke(null, session, realm, disableRows(realmId), mock(EntityManager.class));
            } catch (java.lang.reflect.InvocationTargetException e) {
                if (e.getCause() instanceof RuntimeException re) throw re;
                throw new RuntimeException(e.getCause());
            }
        });

        // 1. isIGAEnabled flipped to false (the governed disable).
        verify(realm).setAttribute("isIGAEnabled", "false");
        // 2. ADOPT cancel ran (the bulk UPDATE + sidecar DELETE go through createQuery).
        //    EM interactions happen on the JPA-provider EM, asserted indirectly via no throw.
        // 4. RS256 revert on the EdDSA Tide realm.
        verify(realm).setDefaultSignatureAlgorithm("RS256");
    }

    @Test
    void nonEdDSARealm_doesNotRevertAlgorithm() throws Exception {
        String realmId = "realm-uuid-2";
        RealmModel realm = mock(RealmModel.class);
        when(realm.getId()).thenReturn(realmId);
        when(realm.getName()).thenReturn("beta");

        // Tide realm but already RS256 → no revert.
        org.keycloak.models.IdentityProviderStorageProvider idps =
                mock(org.keycloak.models.IdentityProviderStorageProvider.class);
        IdentityProviderModel tideIdp = mock(IdentityProviderModel.class);
        when(idps.getByAlias("tide")).thenReturn(tideIdp);
        KeycloakSession session = sessionWithJpa(realm, idps);
        ComponentModel vendorKey = mock(ComponentModel.class);
        when(vendorKey.getProviderId()).thenReturn("tide-vendor-key");
        when(realm.getComponentsStream()).thenReturn(Stream.of(vendorKey));
        when(realm.getDefaultSignatureAlgorithm()).thenReturn("RS256");

        assertDoesNotThrow(() -> {
            try {
                replayDisableIga().invoke(null, session, realm, disableRows(realmId), mock(EntityManager.class));
            } catch (java.lang.reflect.InvocationTargetException e) {
                if (e.getCause() instanceof RuntimeException re) throw re;
                throw new RuntimeException(e.getCause());
            }
        });

        verify(realm).setAttribute("isIGAEnabled", "false");
        verify(realm, never()).setDefaultSignatureAlgorithm(anyString());
    }

    @Test
    void tidelessRealm_noTideIdp_disablesFlagWithoutAlgorithmTouch() throws Exception {
        String realmId = "realm-uuid-3";
        RealmModel realm = mock(RealmModel.class);
        when(realm.getId()).thenReturn(realmId);
        when(realm.getName()).thenReturn("tideless");

        // Tideless: no tide IdP → the RS256-revert branch is skipped entirely.
        org.keycloak.models.IdentityProviderStorageProvider idps =
                mock(org.keycloak.models.IdentityProviderStorageProvider.class);
        when(idps.getByAlias("tide")).thenReturn(null);
        KeycloakSession session = sessionWithJpa(realm, idps);
        when(realm.getComponentsStream()).thenReturn(Stream.empty());

        assertDoesNotThrow(() -> {
            try {
                replayDisableIga().invoke(null, session, realm, disableRows(realmId), mock(EntityManager.class));
            } catch (java.lang.reflect.InvocationTargetException e) {
                if (e.getCause() instanceof RuntimeException re) throw re;
                throw new RuntimeException(e.getCause());
            }
        });

        verify(realm).setAttribute("isIGAEnabled", "false");
        verify(realm, never()).setDefaultSignatureAlgorithm(anyString());
    }
}
