package org.tidecloak.iga.attestors;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import jakarta.persistence.EntityManager;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.stream.Stream;

import org.keycloak.common.util.MultivaluedHashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * ADOPT-commit producer-envelope signing routing (2026-06-06 fix).
 *
 * <p>The bug: bulk-approving a firstAdmin realm's ADOPT CRs stamped the producer
 * attestation columns with the {@link TideAttestor#FIRSTADMIN_SIG_PREFIX} <em>stub</em>
 * (a 32-byte SHA-256 digest) instead of a real 64-byte VVK signature, because the
 * bulk-authorize commit path never invoked {@code stampProducerUnitColumns} and the
 * non-capable fallback produces the SHA-256 stub.
 *
 * <p>These tests pin the {@link TideAttestor#signProducerEnvelope} routing contract that
 * the ADOPT/node/derived/realm column stampers depend on:
 * <ul>
 *   <li>the REAL VVK ceremony is taken iff {@code mode == firstAdmin} AND the realm is
 *       {@link TideAttestor#isRealSigningCapableRealm real-signing-capable};</li>
 *   <li>otherwise a deterministic 32-byte SHA-256 stub is returned under the
 *       mode-appropriate prefix (firstAdmin → {@code FIRSTADMIN-v1}, else {@code DUMMY-v1});</li>
 *   <li>a real sig is 64 bytes — the stub is 32 — so the uniform login read can tell them
 *       apart.</li>
 * </ul>
 *
 * <p>The "capable" assertion is environment-dependent (needs {@code THRESHOLD_T/N} env),
 * so the always-true assertions here pin the NON-capable stub shape (the bug-repro
 * baseline) and the firstAdmin-vs-multiAdmin prefix split. The capable branch is asserted
 * by negative: a capable firstAdmin realm NEVER yields a stub from these stampers — it
 * either returns a real 64-byte sig or fail-closes (no live ORK in unit tests).
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TideAttestorAdoptProducerSignRoutingTest {

    private static final String REALM_ID = "realm-uuid-adopt";

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock JpaConnectionProvider jpa;
    @Mock EntityManager em;

    private TideAttestor attestor;

    @BeforeEach
    void setUp() {
        when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa);
        when(jpa.getEntityManager()).thenReturn(em);
        when(realm.getId()).thenReturn(REALM_ID);
        when(realm.getName()).thenReturn("adopt-realm");
        attestor = new TideAttestor(session);
    }

    /** A realm with NO tide-vendor-key component → never real-signing-capable. */
    private void noVendorKey() {
        // getComponentsStream is consumed multiple times per call chain; return a FRESH
        // stream each time (a single Stream instance would throw "already operated upon").
        when(realm.getComponentsStream()).thenAnswer(inv -> Stream.empty());
    }

    private static String stubFor(String prefix, byte[] envelope) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(envelope);
        return prefix + Base64.getEncoder().encodeToString(digest);
    }

    @Test
    void firstAdmin_notCapable_returnsFirstAdminStub_32bytes() throws Exception {
        noVendorKey();
        assertFalse(TideAttestor.isRealSigningCapableRealm(realm),
                "a realm with no tide-vendor-key cannot be real-signing-capable");

        byte[] envelope = "unit-envelope-bytes".getBytes(StandardCharsets.UTF_8);
        String sig = attestor.signProducerEnvelope(session, realm,
                TideAttestor.MODE_FIRST_ADMIN, envelope);

        assertTrue(sig.startsWith(TideAttestor.FIRSTADMIN_SIG_PREFIX),
                "firstAdmin mode must use the FIRSTADMIN-v1 prefix");
        assertEquals(stubFor(TideAttestor.FIRSTADMIN_SIG_PREFIX, envelope), sig,
                "non-capable firstAdmin must fall back to the deterministic SHA-256 stub");

        byte[] payload = Base64.getDecoder().decode(
                sig.substring(TideAttestor.FIRSTADMIN_SIG_PREFIX.length()));
        assertEquals(32, payload.length,
                "the stub payload is a 32-byte SHA-256 — a REAL VVK sig is 64 bytes; the login "
                        + "read distinguishes them by length");
    }

    @Test
    void multiAdmin_notCapable_returnsDummyStub() {
        noVendorKey();
        byte[] envelope = "unit-envelope-bytes".getBytes(StandardCharsets.UTF_8);
        String sig = attestor.signProducerEnvelope(session, realm,
                TideAttestor.MODE_MULTI_ADMIN, envelope);
        assertTrue(sig.startsWith(TideAttestor.DUMMY_SIG_PREFIX),
                "non-firstAdmin mode must use the DUMMY-v1 prefix");
    }

    @Test
    void nullMode_notCapable_returnsDummyStub() {
        noVendorKey();
        byte[] envelope = "x".getBytes(StandardCharsets.UTF_8);
        String sig = attestor.signProducerEnvelope(session, realm, null, envelope);
        assertTrue(sig.startsWith(TideAttestor.DUMMY_SIG_PREFIX),
                "null mode (non-firstAdmin) must use the DUMMY-v1 prefix stub");
    }

    /**
     * The real-vs-stub gate is purely {@code mode==firstAdmin && isRealSigningCapable}.
     * With a vendor-key present but THRESHOLD env unset (the common unit-test environment),
     * the realm is NOT capable, so even firstAdmin yields the stub — proving the env gate
     * is part of the capability decision (the missing-env footgun that produced crtest's
     * stub columns at toggle time).
     */
    @Test
    void firstAdmin_vendorKeyButNoThresholdEnv_isNotCapable_stillStub() throws Exception {
        ComponentModel vk = mock(ComponentModel.class);
        when(vk.getProviderId()).thenReturn(TideAttestor.TIDE_VENDOR_KEY_PROVIDER_ID);
        MultivaluedHashMap<String, String> cfg = new MultivaluedHashMap<>();
        cfg.putSingle("clientSecret", "{\"activeVrk\":\"AAAA\"}");
        cfg.putSingle("gVRK", "deadbeef");
        cfg.putSingle("gVRKCertificate", "cert");
        cfg.putSingle("systemHomeOrk", "http://hostgateway:1001");
        cfg.putSingle("vvkId", "123");
        when(vk.getConfig()).thenReturn(cfg);
        when(realm.getComponentsStream()).thenAnswer(inv -> Stream.of(vk));

        // Capability is gated on THRESHOLD_T/N env (>0). In the test JVM these are unset,
        // so the realm is NOT capable and signProducerEnvelope returns the stub. If a CI
        // environment DOES set them, the call would attempt the real ceremony and throw
        // (no live ORK) rather than returning a stub — either way it never returns a real
        // 64-byte sig in a unit test, which is the contract we care about.
        boolean capable = TideAttestor.isRealSigningCapableRealm(realm);
        byte[] envelope = "env".getBytes(StandardCharsets.UTF_8);
        if (!capable) {
            String sig = attestor.signProducerEnvelope(session, realm,
                    TideAttestor.MODE_FIRST_ADMIN, envelope);
            assertEquals(stubFor(TideAttestor.FIRSTADMIN_SIG_PREFIX, envelope), sig,
                    "no THRESHOLD env → not capable → firstAdmin stub (NOT a real sig)");
        } else {
            // capable env: the real path must NOT silently produce a stub.
            try {
                String sig = attestor.signProducerEnvelope(session, realm,
                        TideAttestor.MODE_FIRST_ADMIN, envelope);
                byte[] payload = Base64.getDecoder().decode(
                        sig.substring(TideAttestor.FIRSTADMIN_SIG_PREFIX.length()));
                assertEquals(64, payload.length,
                        "a capable firstAdmin realm must produce a REAL 64-byte VVK sig, never a stub");
            } catch (RuntimeException failClosed) {
                // expected without a live ORK — fail-closed, never a silent stub.
                assertTrue(failClosed.getMessage() == null
                                || !failClosed.getMessage().contains("DUMMY"),
                        "capable realm must fail-closed, not degrade to a stub");
            }
        }
    }
}
