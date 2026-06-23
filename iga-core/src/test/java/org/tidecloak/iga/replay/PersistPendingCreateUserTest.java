package org.tidecloak.iga.replay;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import org.junit.jupiter.api.Test;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.mockito.ArgumentCaptor;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * ★ PERSIST-PENDING (enroll-before-commit) — commit-side FINALIZE.
 *
 * <p>Companion to {@link RebuildCreateUserEnrollBeforeCommitTest} (which covers the
 * scratch-replay short-circuit when a live enrolled user already exists). These tests
 * pin the OTHER half of the persist design: when a CREATE_USER CR commits, the finalize
 * must (a) stamp the user_identity producer column on UserEntity.attestation and
 * (b) CLEAR any IGA_UNSIGNED_ENTITY sidecar row the Tideless persist-pending path
 * registered for the user (keyed on the CR id) so the now-attested user is
 * un-quarantined.</p>
 *
 * <p>The login fail-closed guard (the OTHER quarantine mode, used by Tide realms) is
 * pinned in {@code IgaAttestationExporterReplayTest.uniformRead_failsClosed_*}: a NULL
 * user_identity column throws (no real token can mint pre-commit). Here we exercise the
 * commit-time DELETE-by-CR JPQL through the public {@link IgaReplayDispatcher#replay}
 * entry with a mocked EntityManager.</p>
 */
class PersistPendingCreateUserTest {

    private static final String REALM_ID = "realm-aaa";
    private static final String USER_ID = "ca42629c-b09b-46df-9858-d10c0488b77f";
    private static final String USERNAME = "pendinguser";
    private static final String CR_ID = "cr-create-user-1";
    private static final String SIG = "TIDE-FIRSTADMIN-v1:deadbeef";

    private static IgaChangeRequestEntity createUserCr() {
        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setId(CR_ID);
        cr.setRealmId(REALM_ID);
        cr.setEntityType("USER");
        cr.setEntityId(USER_ID);
        cr.setActionType("CREATE_USER");
        // REP_JSON absent → bare-create safety-net branch (no RepresentationToModel needed),
        // BUT we make a live user already exist so even the safety net is skipped (the
        // enroll-before-commit short-circuit). The finalize stamp + sidecar clear still run.
        cr.setRowsJson("[{\"ID\":\"" + USER_ID + "\",\"USERNAME\":\"" + USERNAME + "\"}]");
        cr.setStatus("PENDING");
        return cr;
    }

    private static KeycloakSession sessionWith(EntityManager em, UserModel liveUser) {
        KeycloakSession session = mock(KeycloakSession.class);

        RealmModel realm = mock(RealmModel.class);
        when(realm.getId()).thenReturn(REALM_ID);
        when(realm.getName()).thenReturn("pendingrealm");

        RealmProvider realms = mock(RealmProvider.class);
        when(realms.getRealm(REALM_ID)).thenReturn(realm);
        when(session.realms()).thenReturn(realms);

        UserProvider users = mock(UserProvider.class);
        when(users.getUserById(eq(realm), eq(USER_ID))).thenReturn(liveUser);
        when(session.users()).thenReturn(users);

        JpaConnectionProvider jpa = mock(JpaConnectionProvider.class);
        when(jpa.getEntityManager()).thenReturn(em);
        when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa);

        return session;
    }

    @Test
    void commitFinalize_stampsUserIdentityColumn_and_clearsSidecarByCrId() {
        EntityManager em = mock(EntityManager.class);
        Query stampQ = mock(Query.class);
        Query clearQ = mock(Query.class);

        // Route the two JPQL statements: the UserEntity attestation stamp (UPDATE) and
        // the sidecar clear (DELETE FROM IgaUnsignedEntityEntity ... WHERE adoptCrId).
        when(em.createQuery(anyString())).thenAnswer(inv -> {
            String jpql = inv.getArgument(0);
            if (jpql.contains("IgaUnsignedEntityEntity")) {
                return clearQ;
            }
            return stampQ;
        });
        when(stampQ.setParameter(anyString(), any())).thenReturn(stampQ);
        when(clearQ.setParameter(anyString(), any())).thenReturn(clearQ);

        // Live enrolled user already present → rebuildCreateUserFromRow short-circuits
        // (no addUser); the finalize stamp + sidecar clear still run.
        UserModel liveUser = mock(UserModel.class);
        KeycloakSession session = sessionWith(em, liveUser);

        IgaReplayDispatcher.replay(session, createUserCr(), SIG, /*setSigned*/ false);

        // (a) user_identity stamp: UPDATE UserEntity SET attestation=:sig WHERE id=:id
        ArgumentCaptor<String> jpqls = ArgumentCaptor.forClass(String.class);
        verify(em, atLeastOnce()).createQuery(jpqls.capture());
        List<String> all = jpqls.getAllValues();
        assertTrue(all.stream().anyMatch(s -> s.contains("UPDATE UserEntity")
                        && s.contains("attestation")),
                "finalize must stamp UserEntity.attestation (the user_identity column)");
        verify(stampQ).setParameter("sig", SIG);
        verify(stampQ).setParameter("id", USER_ID);

        // (b) sidecar clear keyed on the CR id (un-quarantine the finalized user).
        assertTrue(all.stream().anyMatch(s -> s.contains("DELETE")
                        && s.contains("IgaUnsignedEntityEntity")
                        && s.contains("adoptCrId")),
                "finalize must clear the IGA_UNSIGNED_ENTITY sidecar by the CREATE_USER CR id");
        verify(clearQ).setParameter("crId", CR_ID);
    }

    @Test
    void tidelessQuarantine_userSidecar_roundTrip_markIsUnsignedClear() {
        // Tideless persist-pending uses the IGA_UNSIGNED_ENTITY sidecar to hard-refuse
        // the user (isEnabled()=false via IgaQuarantineCache) until commit. Prove the
        // USER triple round-trips: markUnsigned inserts, isUnsigned probes true, the
        // CR-keyed clear DELETEs it.
        EntityManager em = mock(EntityManager.class);

        // markUnsigned: probe (find) returns null → persist a row.
        when(em.find(eq(org.tidecloak.iga.entities.IgaUnsignedEntityEntity.class), any()))
                .thenReturn(null);
        org.tidecloak.iga.services.IgaUnsignedEntityService.markUnsigned(
                em, REALM_ID, IgaReplayExtension.ENTITY_TYPE_USER, USER_ID, CR_ID);
        ArgumentCaptor<Object> persisted = ArgumentCaptor.forClass(Object.class);
        verify(em).persist(persisted.capture());
        Object p = persisted.getValue();
        assertTrue(p instanceof org.tidecloak.iga.entities.IgaUnsignedEntityEntity);
        org.tidecloak.iga.entities.IgaUnsignedEntityEntity row =
                (org.tidecloak.iga.entities.IgaUnsignedEntityEntity) p;
        assertEquals(REALM_ID, row.getRealmId());
        assertEquals(IgaReplayExtension.ENTITY_TYPE_USER, row.getEntityType());
        assertEquals(USER_ID, row.getEntityId());
        assertEquals(CR_ID, row.getAdoptCrId());

        // isUnsigned: now the find returns a row → quarantined.
        EntityManager em2 = mock(EntityManager.class);
        when(em2.find(eq(org.tidecloak.iga.entities.IgaUnsignedEntityEntity.class), any()))
                .thenReturn(row);
        assertTrue(org.tidecloak.iga.services.IgaUnsignedEntityService.isUnsigned(
                em2, REALM_ID, IgaReplayExtension.ENTITY_TYPE_USER, USER_ID),
                "a persisted pending user must read as unsigned (quarantined) in Tideless mode");

        // clearByAdoptCr: DELETE keyed on the CR id.
        EntityManager em3 = mock(EntityManager.class);
        Query del = mock(Query.class);
        when(em3.createQuery(anyString())).thenReturn(del);
        when(del.setParameter(anyString(), any())).thenReturn(del);
        when(del.executeUpdate()).thenReturn(1);
        org.tidecloak.iga.services.IgaUnsignedEntityService.clearByAdoptCr(em3, CR_ID);
        verify(del).setParameter("crId", CR_ID);
        verify(del).executeUpdate();
    }

    @Test
    void tideDiscriminator_isResolvedFromRealmAttribute() {
        // The persist path quarantines via the sidecar ONLY for Tideless realms
        // (iga.attestor != "tide"). For Tide realms the NULL user_identity column +
        // replayOrFailClosed is the guard and NO sidecar may be written (it would flip
        // isEnabled()=false and block the enrollment auth flow). Pin the discriminator
        // the create path keys on so a future refactor can't silently invert it.
        RealmModel tide = mock(RealmModel.class);
        when(tide.getAttribute("iga.attestor")).thenReturn("tide");
        RealmModel tideless = mock(RealmModel.class);
        when(tideless.getAttribute("iga.attestor")).thenReturn(null);

        assertEquals("tide",
                org.tidecloak.iga.attestors.TideAttestor.ID,
                "TideAttestor.ID is the discriminator value used by the create path");
        assertTrue("tide".equals(tide.getAttribute("iga.attestor")),
                "a Tide realm must report iga.attestor=tide → no sidecar quarantine");
        assertTrue(!"tide".equals(tideless.getAttribute("iga.attestor")),
                "a Tideless realm must NOT report iga.attestor=tide → sidecar quarantine");
    }
}
