package org.tidecloak.iga.attestors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.entities.IgaAuthorizerEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.replay.IgaReplayExtension;
import org.tidecloak.iga.services.IgaFirstAdminAutoCommit;

/**
 * OFFBOARD_REALM classification + min-admins threshold (governed Ragnarok offboard).
 *
 * <p>OFFBOARD_REALM mirrors DISABLE_IGA as a NON-producer realm-config action, but with
 * a stricter, irreversible-by-design commit gate:
 * <ul>
 *   <li>NON-producer → {@link TideAttestor#isProducerEnvelopeSignedAction} is false →
 *       the CR attestation stub-signs (no ORK Policy:1 round-trip);</li>
 *   <li>NOT on {@link IgaFirstAdminAutoCommit#BASELINE_CONFIG_ACTION_TYPES} → never
 *       firstAdmin auto-committed (explicit approval, even for firstAdmin);</li>
 *   <li>NOT an ADOPT action;</li>
 *   <li>{@link TideAttestor#getThreshold} for OFFBOARD_REALM =
 *       {@code max(normalQuorum, OFFBOARD_MIN_ADMINS)} — a minimum of 3 distinct admins
 *       by default, configurable via {@code iga.offboardMinAdmins}, even in firstAdmin
 *       mode (which would otherwise be 1-of-1).</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TideAttestorOffboardRealmTest {

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock JpaConnectionProvider jpa;
    @Mock EntityManager em;
    @Mock KeycloakContext ctx;

    private TideAttestor attestor;

    @BeforeEach
    void setUp() {
        lenient().when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa);
        lenient().when(jpa.getEntityManager()).thenReturn(em);
        lenient().when(session.getContext()).thenReturn(ctx);
        lenient().when(realm.getId()).thenReturn("realm-offboard");
        lenient().when(realm.getName()).thenReturn("offboard-realm");
        attestor = new TideAttestor(session);
    }

    private IgaChangeRequestEntity offboardCr() {
        IgaChangeRequestEntity cr = mock(IgaChangeRequestEntity.class);
        lenient().when(cr.getActionType()).thenReturn(TideAttestor.ACTION_OFFBOARD_REALM);
        return cr;
    }

    /** Stub resolveMode → firstAdmin via no authorizer row + iga.attestor=tide. */
    private void stubFirstAdminMode() {
        @SuppressWarnings("unchecked")
        TypedQuery<IgaAuthorizerEntity> q = mock(TypedQuery.class);
        lenient().when(em.createNamedQuery("IgaAuthorizer.findByRealm", IgaAuthorizerEntity.class))
                .thenReturn(q);
        lenient().when(q.setParameter(org.mockito.ArgumentMatchers.eq("realmId"),
                        org.mockito.ArgumentMatchers.any()))
                .thenReturn(q);
        // Fresh empty stream per call: resolveMode is invoked more than once in tests
        // that compare getThreshold against the offboardRealmThreshold helper, and a
        // Stream can only be consumed once.
        lenient().when(q.getResultStream()).thenAnswer(inv -> Stream.empty());
        lenient().when(realm.getAttribute("iga.attestor")).thenReturn(TideAttestor.ID);
    }

    @Test
    void offboardRealm_isNotProducerEnvelopeSigned() {
        assertFalse(TideAttestor.isProducerEnvelopeSignedAction(TideAttestor.ACTION_OFFBOARD_REALM),
                "OFFBOARD_REALM must NOT be producer-envelope signed → CR attestation stub-signs, "
                        + "no ORK Policy:1 round-trip");
    }

    @Test
    void offboardRealm_isNotBaselineAutoCommittable() {
        assertFalse(IgaFirstAdminAutoCommit.isBaselineConfigActionType(TideAttestor.ACTION_OFFBOARD_REALM),
                "OFFBOARD_REALM must NOT be on the firstAdmin baseline-config auto-commit allow-list "
                        + "— an irreversible offboard always needs explicit approval");
        assertFalse(IgaFirstAdminAutoCommit.BASELINE_CONFIG_ACTION_TYPES
                        .contains(TideAttestor.ACTION_OFFBOARD_REALM),
                "OFFBOARD_REALM must not be a member of BASELINE_CONFIG_ACTION_TYPES");
    }

    @Test
    void offboardRealm_isNotAdoptAction() {
        assertFalse(IgaReplayExtension.isAdoptAction(TideAttestor.ACTION_OFFBOARD_REALM),
                "OFFBOARD_REALM must NOT be an ADOPT action (no ADOPT threshold-1 short-circuit)");
    }

    @Test
    void getThreshold_firstAdminOffboard_requiresMinThreeNotOne() {
        // firstAdmin would normally be 1-of-1, but an offboard floors at min-admins (3).
        stubFirstAdminMode();
        int t = attestor.getThreshold(session, realm, offboardCr());
        assertEquals(TideAttestor.OFFBOARD_MIN_ADMINS_DEFAULT, t,
                "firstAdmin OFFBOARD_REALM must require the min-admins floor (3), not the firstAdmin 1-of-1");
    }

    @Test
    void getThreshold_offboard_honoursConfiguredMinAdminsOverride() {
        stubFirstAdminMode();
        when(realm.getAttribute(TideAttestor.ATTR_OFFBOARD_MIN_ADMINS)).thenReturn("5");
        int t = attestor.getThreshold(session, realm, offboardCr());
        assertEquals(5, t, "iga.offboardMinAdmins=5 must raise the offboard floor to 5");
    }

    @Test
    void getThreshold_offboard_invalidOverrideFallsBackToDefault() {
        stubFirstAdminMode();
        when(realm.getAttribute(TideAttestor.ATTR_OFFBOARD_MIN_ADMINS)).thenReturn("nope");
        int t = attestor.getThreshold(session, realm, offboardCr());
        assertEquals(TideAttestor.OFFBOARD_MIN_ADMINS_DEFAULT, t,
                "a non-numeric iga.offboardMinAdmins must fall back to the default (3), never weaken the gate");
    }

    @Test
    void getThreshold_offboard_belowOneOverrideFallsBackToDefault() {
        stubFirstAdminMode();
        when(realm.getAttribute(TideAttestor.ATTR_OFFBOARD_MIN_ADMINS)).thenReturn("0");
        int t = attestor.getThreshold(session, realm, offboardCr());
        assertEquals(TideAttestor.OFFBOARD_MIN_ADMINS_DEFAULT, t,
                "iga.offboardMinAdmins=0 must be ignored (floor never drops below the default 3)");
    }

    @Test
    void offboardRealmThreshold_publicPreflightHelper_matchesGetThreshold() {
        stubFirstAdminMode();
        int viaGate = attestor.getThreshold(session, realm, offboardCr());
        int viaHelper = attestor.offboardRealmThreshold(session, realm);
        assertEquals(viaGate, viaHelper,
                "offboardRealmThreshold (ragnarok pre-flight) must equal the getThreshold gate");
    }

    // -----------------------------------------------------------------------
    // Post-offboard Tideless cutover (IgaReplayDispatcher.replayOffboardRealm).
    //
    // After OFFBOARD_REALM commit the dispatcher flips iga.attestor -> "simple"
    // AND removes the realm's iga_authorizer mode row(s). These two tests pin the
    // exact seam the dispatcher controls: that BOTH steps are needed for the realm
    // to read as Tideless (the attribute flip alone is NOT decisive because
    // resolveMode reads the authorizer row first).
    // -----------------------------------------------------------------------

    /**
     * THE GOTCHA the dispatcher fix guards against: a multiAdmin ceremony realm
     * has a materialized IGA_AUTHORIZER row with MODE='multiAdmin'. Because
     * {@link TideAttestor#resolveMode} reads that row BEFORE the iga.attestor
     * attribute, merely flipping iga.attestor to "simple" does NOT make the realm
     * Tideless — resolveMode still returns multiAdmin, so the REST layer would keep
     * rejecting ordinary authorize/commit with MULTIADMIN_REQUIRES_APPROVAL_ENCLAVE.
     * This documents WHY replayOffboardRealm must also delete the authorizer row.
     */
    @Test
    void attributeFlipAlone_isNotDecisive_authorizerRowKeepsRealmMultiAdmin() {
        @SuppressWarnings("unchecked")
        TypedQuery<IgaAuthorizerEntity> q = mock(TypedQuery.class);
        lenient().when(em.createNamedQuery("IgaAuthorizer.findByRealm", IgaAuthorizerEntity.class))
                .thenReturn(q);
        lenient().when(q.setParameter(org.mockito.ArgumentMatchers.eq("realmId"),
                        org.mockito.ArgumentMatchers.any()))
                .thenReturn(q);
        // A materialized multiAdmin authorizer row still exists...
        IgaAuthorizerEntity row = new IgaAuthorizerEntity();
        row.setMode(TideAttestor.MODE_MULTI_ADMIN);
        lenient().when(q.getResultStream()).thenAnswer(inv -> Stream.of(row));
        // ...even though iga.attestor was already flipped to "simple".
        lenient().when(realm.getAttribute("iga.attestor")).thenReturn(SimpleNameAttestor.ID);

        assertEquals(TideAttestor.MODE_MULTI_ADMIN, TideAttestor.resolveMode(session, realm),
                "a left-behind authorizer row keeps resolveMode returning multiAdmin despite "
                        + "iga.attestor=simple — so the row MUST be cleared at offboard");
    }

    /**
     * The post-fix state: after replayOffboardRealm has flipped iga.attestor to
     * "simple" AND removed the authorizer row(s), resolveMode falls to its no-row
     * branch, reads iga.attestor (="simple", not "tide"), and returns null = Tideless.
     * isMultiAdminMode is then false, so the legacy authorize/commit lane is open and
     * the simple (attribute-based) attestor governs every subsequent CR.
     */
    @Test
    void afterFlipAndRowRemoval_realmResolvesTideless() {
        @SuppressWarnings("unchecked")
        TypedQuery<IgaAuthorizerEntity> q = mock(TypedQuery.class);
        lenient().when(em.createNamedQuery("IgaAuthorizer.findByRealm", IgaAuthorizerEntity.class))
                .thenReturn(q);
        lenient().when(q.setParameter(org.mockito.ArgumentMatchers.eq("realmId"),
                        org.mockito.ArgumentMatchers.any()))
                .thenReturn(q);
        // No authorizer row left (the dispatcher removed it)...
        lenient().when(q.getResultStream()).thenAnswer(inv -> Stream.empty());
        // ...and iga.attestor is "simple".
        lenient().when(realm.getAttribute("iga.attestor")).thenReturn(SimpleNameAttestor.ID);

        org.junit.jupiter.api.Assertions.assertNull(TideAttestor.resolveMode(session, realm),
                "with no authorizer row and iga.attestor=simple, resolveMode must return null (Tideless)");
        assertFalse(TideAttestor.isMultiAdminMode(session, realm),
                "a Tideless realm post-offboard must NOT report multiAdmin — the legacy "
                        + "authorize/commit lane stays open for SimpleNameAttestor governance");
    }
}
