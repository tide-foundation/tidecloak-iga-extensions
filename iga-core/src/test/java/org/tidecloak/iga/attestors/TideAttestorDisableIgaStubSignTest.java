package org.tidecloak.iga.attestors;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;

import jakarta.persistence.EntityManager;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * PROBLEM 1 — a {@code DISABLE_IGA} CR (and any other NON-producer-envelope realm-config CR:
 * {@code SET_REALM_ATTRIBUTE} / {@code SET_REALM_CONFIG} / {@code REMOVE_REALM_ATTRIBUTE}) must
 * commit as a STUB in multiAdmin mode — it must NOT be routed into
 * {@code signMultiAdminUnitViaPolicy} → {@code signMultiAdminUnitsViaPolicy} →
 * {@code ModelRequest.FromBytes(carrier)} (the producer {@code Policy:1} carrier sign).
 *
 * <p>The bug: the firstAdmin branch of {@code sign()} gated the real ceremony on
 * {@code realCeremonyEligible} ({@code isProducerEnvelopeSignedAction}), but the multiAdmin
 * branch did NOT — it called {@code signMultiAdminUnitViaPolicy} for ANY action whenever the
 * realm was real-signing-capable, so a DISABLE_IGA CR (which has no producer unit, only a
 * canonical-fallback carrier built at the enclave open) hit {@code ModelRequest.FromBytes},
 * which re-validated the carrier's expiry and threw {@code "Expiry cannot be in the past"}.
 *
 * <p>The fix gates the multiAdmin branch on {@code realCeremonyEligible} too. Because the gate
 * SHORT-CIRCUITS before the capability probe, a non-producer-envelope action NEVER reads the
 * carrier — regardless of capability — so it can never hit the carrier {@code FromBytes}. These
 * tests pin that contract deterministically (no ORK / no THRESHOLD env needed).
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TideAttestorDisableIgaStubSignTest {

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock JpaConnectionProvider jpa;
    @Mock EntityManager em;

    private TideAttestor attestor;
    private Method signMethod;

    @BeforeEach
    void setUp() throws Exception {
        lenient().when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa);
        lenient().when(jpa.getEntityManager()).thenReturn(em);
        lenient().when(realm.getId()).thenReturn("realm-disable-iga");
        lenient().when(realm.getName()).thenReturn("disable-realm");
        attestor = new TideAttestor(session);

        // private String sign(KeycloakSession, RealmModel, String mode,
        //                     boolean realCeremonyEligible, IgaChangeRequestEntity cr, byte[] canonical)
        signMethod = TideAttestor.class.getDeclaredMethod("sign",
                KeycloakSession.class, RealmModel.class, String.class,
                boolean.class, IgaChangeRequestEntity.class, byte[].class);
        signMethod.setAccessible(true);
    }

    private String invokeSign(String mode, boolean realCeremonyEligible,
                              IgaChangeRequestEntity cr, byte[] canonical) throws Exception {
        return (String) signMethod.invoke(attestor, session, realm, mode,
                realCeremonyEligible, cr, canonical);
    }

    /** The producer-envelope gate must NOT cover the realm-config / DISABLE_IGA actions. */
    @Test
    void realmConfigActions_areNotProducerEnvelopeSigned() {
        for (String a : new String[]{"DISABLE_IGA", "SET_REALM_ATTRIBUTE",
                "SET_REALM_CONFIG", "REMOVE_REALM_ATTRIBUTE"}) {
            assertFalse(TideAttestor.isProducerEnvelopeSignedAction(a),
                    a + " must NOT be producer-envelope signed → it commits as a stub, "
                            + "never via the Policy:1 carrier sign");
        }
    }

    /**
     * multiAdmin + a non-producer-envelope action (realCeremonyEligible=false) must return the
     * DUMMY stub WITHOUT ever reading the CR's carrier — proving it can never reach
     * signMultiAdminUnitsViaPolicy / ModelRequest.FromBytes (the "Expiry cannot be in the past"
     * crash site).
     *
     * <p>The load-bearing, ENV-INDEPENDENT distinguishing assertion: the fixed gate
     * {@code realCeremonyEligible && isRealSigningCapable(realm)} SHORT-CIRCUITS on
     * {@code realCeremonyEligible=false}, so {@code isRealSigningCapable} — and thus
     * {@code realm.getComponentsStream()} (its first probe) — is NEVER called. The OLD code
     * (no {@code realCeremonyEligible} gate) called {@code isRealSigningCapable} unconditionally,
     * so {@code getComponentsStream()} WOULD be invoked. Verifying it is never invoked therefore
     * fails on the old code and passes only with the fix, regardless of THRESHOLD env / ORK
     * availability. The poisoned carrier is a belt-and-braces guard against any FromBytes read.
     */
    @Test
    void multiAdmin_disableIga_returnsStub_andNeverProbesCapability() throws Exception {
        IgaChangeRequestEntity cr = mock(IgaChangeRequestEntity.class);
        when(cr.getId()).thenReturn("cr-disable");
        // A carrier that would THROW if ever parsed (not valid Base64 ModelRequest bytes).
        lenient().when(cr.getRequestModel()).thenReturn("!!!not-a-valid-carrier!!!");

        byte[] canonical = "disable-iga-canonical".getBytes();
        String sig = invokeSign(TideAttestor.MODE_MULTI_ADMIN, /*realCeremonyEligible*/ false,
                cr, canonical);

        assertTrue(sig.startsWith(TideAttestor.DUMMY_SIG_PREFIX),
                "a non-producer-envelope multiAdmin commit (DISABLE_IGA) must return the DUMMY "
                        + "stub, not a real Policy:1 carrier sig — was: " + sig);
        // Never reached the capability probe → never reached the carrier sign / FromBytes.
        verify(realm, never()).getComponentsStream();
        verify(cr, never()).getRequestModel();
    }

    /**
     * The SAME contract for the realm-config reference path (SET_REALM_ATTRIBUTE): a stub at
     * combineFinal time, carrier never read. (Its real realm_config producer column is signed
     * POST-replay in distributeMultiAdminUnitSigs, not here.)
     */
    @Test
    void multiAdmin_setRealmAttribute_returnsStub_andNeverProbesCapability() throws Exception {
        IgaChangeRequestEntity cr = mock(IgaChangeRequestEntity.class);
        when(cr.getId()).thenReturn("cr-set-realm-attr");
        lenient().when(cr.getRequestModel()).thenReturn("!!!not-a-valid-carrier!!!");

        String sig = invokeSign(TideAttestor.MODE_MULTI_ADMIN, /*realCeremonyEligible*/ false,
                cr, "realm-attr-canonical".getBytes());

        assertTrue(sig.startsWith(TideAttestor.DUMMY_SIG_PREFIX),
                "SET_REALM_ATTRIBUTE (the reference realm-config path) must also stub at "
                        + "combineFinal time, not hit the carrier sign — was: " + sig);
        verify(realm, never()).getComponentsStream();
        verify(cr, never()).getRequestModel();
    }

    /**
     * Positive control: a PRODUCER-envelope action (realCeremonyEligible=true) in multiAdmin DOES
     * probe capability ({@code getComponentsStream}) — proving the stub-routing above is the
     * {@code realCeremonyEligible} gate at work, not a blanket no-op. In the unit-test env the
     * realm is NOT capable (no THRESHOLD env / no vendor key), so it still returns a stub, but the
     * capability PROBE must have run.
     */
    @Test
    void multiAdmin_producerAction_probesCapability() throws Exception {
        IgaChangeRequestEntity cr = mock(IgaChangeRequestEntity.class);
        lenient().when(cr.getId()).thenReturn("cr-grant");
        lenient().when(cr.getActionType()).thenReturn("GRANT_ROLES");
        lenient().when(cr.getRequestModel()).thenReturn(null);
        // No vendor-key component → isRealSigningCapable returns false after probing the stream.
        when(realm.getComponentsStream()).thenReturn(java.util.stream.Stream.empty());

        String sig = invokeSign(TideAttestor.MODE_MULTI_ADMIN, /*realCeremonyEligible*/ true,
                cr, "grant-canonical".getBytes());

        assertTrue(sig.startsWith(TideAttestor.DUMMY_SIG_PREFIX),
                "a non-capable multiAdmin realm still stubs even for a producer action — was: " + sig);
        // The capability probe MUST have run for the producer-eligible action.
        verify(realm).getComponentsStream();
    }
}
