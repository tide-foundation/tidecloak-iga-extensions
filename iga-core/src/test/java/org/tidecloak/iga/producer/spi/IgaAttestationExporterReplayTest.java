package org.tidecloak.iga.producer.spi;

import org.junit.jupiter.api.Test;
import org.keycloak.tide.attestation.SignedUnit;
import org.tidecloak.iga.attestors.TideAttestor;
import org.tidecloak.iga.producer.units.AttestationUnit;
import org.tidecloak.iga.producer.units.AttestationUnitType;

import java.util.Base64;
import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Design B, Phase 1 — the login REPLAY contract for the {@code user_role_mapping_set}
 * unit. {@link IgaAttestationExporterProvider#decodeReplayableSig} is the pure decision
 * point {@code exportSignedAccessTokenUnits} uses to choose REPLAY-from-column vs
 * fresh re-sign for the URM-set unit, so it carries the full contract under test:
 *
 * <ul>
 *   <li>A real {@code TIDE-FIRSTADMIN-v1:}+base64(64-byte VVK sig) attestation →
 *       the DECODED 64-byte sig (replayed, not re-signed).</li>
 *   <li>The 32-byte firstAdmin STUB ({@code base64(sha256)}), a wrong prefix,
 *       garbage base64, blank and null → {@code null} (fall back to re-sign).</li>
 * </ul>
 */
class IgaAttestationExporterReplayTest {

    private static String prefixed(byte[] raw) {
        return TideAttestor.FIRSTADMIN_SIG_PREFIX + Base64.getEncoder().encodeToString(raw);
    }

    private static byte[] bytes(int len, int seed) {
        byte[] b = new byte[len];
        for (int i = 0; i < len; i++) {
            b[i] = (byte) (seed + i);
        }
        return b;
    }

    @Test
    void realFirstAdminSig_isReplayedAsDecoded64Bytes() {
        byte[] vvkSig = bytes(64, 7);                       // a bare 64-byte VVK sig
        String stored = prefixed(vvkSig);

        byte[] replayed = IgaAttestationExporterProvider.decodeReplayableSig(stored);

        assertArrayEquals(vvkSig, replayed,
                "a real TIDE-FIRSTADMIN-v1 + b64(64B) attestation must REPLAY the exact decoded 64-byte sig");
    }

    @Test
    void firstAdminStub_32Bytes_fallsBackToReSign() {
        // The stub is base64(sha256(canonical)) = 32 bytes under the SAME prefix.
        byte[] stub = bytes(32, 1);
        assertNull(IgaAttestationExporterProvider.decodeReplayableSig(prefixed(stub)),
                "the 32-byte firstAdmin STUB shares the prefix but must NOT be replayed (re-sign instead)");
    }

    @Test
    void wrongLength_fallsBackToReSign() {
        assertNull(IgaAttestationExporterProvider.decodeReplayableSig(prefixed(bytes(63, 1))));
        assertNull(IgaAttestationExporterProvider.decodeReplayableSig(prefixed(bytes(65, 1))));
    }

    @Test
    void wrongPrefix_fallsBackToReSign() {
        // The multiAdmin / dispatcher stub prefix is TIDE-DUMMY-v1: — not replayable here.
        String dummy = "TIDE-DUMMY-v1:" + Base64.getEncoder().encodeToString(bytes(64, 3));
        assertNull(IgaAttestationExporterProvider.decodeReplayableSig(dummy));
    }

    @Test
    void garbageBase64_fallsBackToReSign() {
        assertNull(IgaAttestationExporterProvider.decodeReplayableSig(
                TideAttestor.FIRSTADMIN_SIG_PREFIX + "!!!not-base64!!!"));
    }

    @Test
    void nullAndBlank_fallBackToReSign() {
        assertNull(IgaAttestationExporterProvider.decodeReplayableSig(null));
        assertNull(IgaAttestationExporterProvider.decodeReplayableSig(""));
        assertNull(IgaAttestationExporterProvider.decodeReplayableSig("   "));
    }

    // ---- PR-B: the UNIFORM read attaches the decoded sig OR fail-closes by unit ----

    private static AttestationUnit unit(AttestationUnitType type, String targetId) {
        return new AttestationUnit("realm-uuid", targetId) {
            @Override public AttestationUnitType type() { return type; }
            @Override public Map<String, Object> payload() { return Collections.emptyMap(); }
        };
    }

    @Test
    void uniformRead_attachesDecodedSig_whenColumnIsReal() {
        byte[] vvkSig = bytes(64, 9);
        AttestationUnit u = unit(AttestationUnitType.CLIENT_CONFIG, "client-uuid");

        SignedUnit signed = IgaAttestationExporterProvider.replayOrFailClosed(u, prefixed(vvkSig), "myrealm");

        assertNotNull(signed);
        assertArrayEquals(u.serialize(), signed.getEnvelope(),
                "the shipped envelope must be the verbatim producer serialize() bytes");
        assertArrayEquals(vvkSig, signed.getSignature(),
                "the shipped sig must be the decoded 64-byte VVK sig from the column");
    }

    @Test
    void uniformRead_failsClosed_namingUnitTypeAndTarget_onMissingSig() {
        AttestationUnit u = unit(AttestationUnitType.USER_ROLE_MAPPING_SET, "user-123");
        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> IgaAttestationExporterProvider.replayOrFailClosed(u, null, "myrealm"));
        assertTrue(ex.getMessage().contains("user_role_mapping_set"),
                "fail-closed error must name the unit type");
        assertTrue(ex.getMessage().contains("user-123"),
                "fail-closed error must name the target id");
        assertTrue(ex.getMessage().contains("myrealm"));
    }

    @Test
    void uniformRead_failsClosed_onStubAndWrongPrefix() {
        AttestationUnit u = unit(AttestationUnitType.REALM_CONFIG, "realm-uuid");
        // 32-byte firstAdmin stub
        assertThrows(RuntimeException.class,
                () -> IgaAttestationExporterProvider.replayOrFailClosed(u, prefixed(bytes(32, 1)), "r"));
        // wrong prefix (multiAdmin dummy)
        assertThrows(RuntimeException.class,
                () -> IgaAttestationExporterProvider.replayOrFailClosed(u,
                        "TIDE-DUMMY-v1:" + Base64.getEncoder().encodeToString(bytes(64, 2)), "r"));
    }

    // ---- Self-reg accept-unattested (phase 2/3): admit an UNSIGNED user_identity ----
    //
    // When the closure is default-roles-only on a registrationAllowed realm, the caller
    // (exportSignedAccessTokenUnits) passes admitUnsignedSelfReg=true for the user_identity
    // unit ONLY. A NULL/stub column then yields a SignedUnit marked isSelfRegUnsigned()=true
    // (null sig, verbatim envelope) instead of a fail-closed throw. Every OTHER unit type,
    // and the registration-off / privileged closures (admitUnsignedSelfReg=false), keep the
    // existing fail-closed throw. A signed user_identity always takes the signed lane.

    @Test
    void selfRegAdmit_userIdentity_nullColumn_admittedUnsigned_notThrown() {
        AttestationUnit u = unit(AttestationUnitType.USER_IDENTITY, "user-98bc3758");

        SignedUnit admitted = IgaAttestationExporterProvider.replayOrFailClosed(
                u, null, "selfregrealm", true);

        assertNotNull(admitted);
        assertTrue(admitted.isSelfRegUnsigned(),
                "a default-roles-only user_identity with a NULL column must be admitted UNSIGNED");
        assertNull(admitted.getSignature(),
                "a self-reg-admitted user_identity carries NO signature (slot-6 bundle, not the signed batch)");
        assertArrayEquals(u.serialize(), admitted.getEnvelope(),
                "the admitted envelope must be the verbatim producer serialize() bytes (the ORK re-derives it)");
    }

    @Test
    void selfRegAdmit_userIdentity_realSig_takesSignedLane() {
        byte[] vvkSig = bytes(64, 11);
        AttestationUnit u = unit(AttestationUnitType.USER_IDENTITY, "user-1");

        // Even with admitUnsignedSelfReg=true, a present replayable sig is shipped normally.
        SignedUnit signed = IgaAttestationExporterProvider.replayOrFailClosed(
                u, prefixed(vvkSig), "selfregrealm", true);

        assertFalse(signed.isSelfRegUnsigned(),
                "a signed user_identity must NOT be marked self-reg-unsigned");
        assertArrayEquals(vvkSig, signed.getSignature(),
                "a present 64-byte sig is replayed even when self-reg admit is enabled");
    }

    @Test
    void selfRegAdmit_disabled_stillFailsClosed_onNullColumn() {
        // Privileged / registration-off closure: caller passes admitUnsignedSelfReg=false,
        // so a NULL user_identity column STILL fail-closes exactly as today.
        AttestationUnit u = unit(AttestationUnitType.USER_IDENTITY, "user-priv");
        assertThrows(RuntimeException.class,
                () -> IgaAttestationExporterProvider.replayOrFailClosed(u, null, "r", false),
                "with self-reg admit OFF, a NULL user_identity must still fail closed");
        // and the 3-arg overload (no admit) is unchanged:
        assertThrows(RuntimeException.class,
                () -> IgaAttestationExporterProvider.replayOrFailClosed(u, null, "r"));
    }
}
