package org.tidecloak.iga.producer.spi;

import org.junit.jupiter.api.Test;
import org.tidecloak.iga.attestors.TideAttestor;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

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
}
