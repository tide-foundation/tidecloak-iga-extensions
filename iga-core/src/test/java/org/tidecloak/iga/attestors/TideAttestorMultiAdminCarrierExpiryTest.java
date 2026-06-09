package org.tidecloak.iga.attestors;

import org.junit.jupiter.api.Test;
import org.midgard.models.ModelRequest;
import org.midgard.models.RequestExtensions.AttestationUnitSignRequest;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PROBLEM 2 — the PERSISTED multiAdmin two-phase approval-model carrier
 * ({@code buildMultiAdminApprovalModel} / {@code buildPolicyResignApprovalModel}) must carry
 * a LONG expiry that covers a realistic multi-admin approval window (admins may sign hours or
 * days apart), so the carrier is NOT already EXPIRED when {@code signMultiAdminUnitsViaPolicy}
 * re-reads it via {@code ModelRequest.FromBytes} at commit.
 *
 * <p>The bug: the carrier's expiry was anchored to the FIRST admin's open with only a
 * ~180-second window ({@code FIRSTADMIN_SIGN_EXPIRY_SECONDS}); a real multi-admin approval
 * (admin1 signs, admin2 signs later, then commit) easily exceeds 3 minutes, so
 * {@code ModelRequest.FromBytes} → {@code SetCustomExpiry} threw
 * {@code "Expiry cannot be in the past"} at commit.
 *
 * <p>These tests pin the contract directly against the REAL Midgard {@code ModelRequest}
 * encode/FromBytes round-trip (no ORK needed): a carrier encoded with a 180-second expiry
 * is expired (and rejected) once that window lapses, while a carrier encoded with the new
 * {@code MULTIADMIN_APPROVAL_EXPIRY_SECONDS} bound survives FromBytes well past any 3-minute
 * approval delay. The expiry is set ONCE at the first phase-1 build and preserved verbatim by
 * the accumulation short-circuit, so a single long initial value is sufficient.
 */
class TideAttestorMultiAdminCarrierExpiryTest {

    /** Reflectively read the private static long constant under test. */
    private static long approvalExpirySeconds() throws Exception {
        Field f = TideAttestor.class.getDeclaredField("MULTIADMIN_APPROVAL_EXPIRY_SECONDS");
        f.setAccessible(true);
        return (long) f.get(null);
    }

    /** Encode a Policy:1 AttestationUnit carrier with an ABSOLUTE expiry of now+expirySeconds. */
    private static String encodeCarrier(long expirySeconds) throws Exception {
        AttestationUnitSignRequest req = new AttestationUnitSignRequest("Policy:1");
        req.SetUnits(new byte[][]{ "carrier-unit-cbor".getBytes(StandardCharsets.UTF_8) });
        req.SetPolicy("m0-admin-policy-bytes".getBytes(StandardCharsets.UTF_8));
        req.SetCustomExpiry((System.currentTimeMillis() / 1000) + expirySeconds);
        // Materialize the Draft (units folded in lazily) before Encode(), exactly as the
        // phase-1 builders do via GetDraft().
        req.GetDraft();
        return Base64.getEncoder().encodeToString(req.Encode());
    }

    @Test
    void expiryConstant_isAtLeastOneDay() throws Exception {
        long secs = approvalExpirySeconds();
        assertTrue(secs >= 24L * 60L * 60L,
                "the persisted multiAdmin approval-model carrier expiry must be a generous outer "
                        + "bound (>= 1 day) so a real multi-admin approval window never expires the "
                        + "carrier before commit — was " + secs + "s");
    }

    @Test
    void longExpiryCarrier_survivesFromBytes_pastA3MinuteApprovalDelay() throws Exception {
        // The carrier built at the FIRST admin's open with the NEW long bound.
        String carrier = encodeCarrier(approvalExpirySeconds());

        // Commit happens AFTER a realistic delay (the old 180s window would already be gone).
        // The absolute expiry is now+7d, so FromBytes at commit (here, immediately, but the
        // 7-day bound proves it holds well past any minutes-to-hours approval gap) must NOT throw.
        ModelRequest reloaded = assertDoesNotThrow(
                () -> ModelRequest.FromBytes(Base64.getDecoder().decode(carrier)),
                "a long-expiry carrier must re-read via ModelRequest.FromBytes at commit without "
                        + "throwing 'Expiry cannot be in the past'");
        assertNotNull(reloaded, "FromBytes must return the reloaded carrier");
    }

    @Test
    void shortExpiryCarrier_isRejectedOnceItsWindowLapses() throws Exception {
        // Reproduce the OLD bug deterministically: a carrier whose absolute expiry is already
        // in the past (the 180s window having lapsed by commit time) is rejected by FromBytes —
        // the exact "Expiry cannot be in the past" failure DISABLE_IGA / slow grant approvals hit.
        AttestationUnitSignRequest req = new AttestationUnitSignRequest("Policy:1");
        req.SetUnits(new byte[][]{ "carrier-unit-cbor".getBytes(StandardCharsets.UTF_8) });
        // Set a valid (future) expiry to build+encode, then rewrite the encoded segment-2 expiry
        // to a past timestamp to simulate the window having lapsed between build and commit.
        req.SetCustomExpiry((System.currentTimeMillis() / 1000) + 180L);
        req.GetDraft();
        byte[] encoded = req.Encode();

        // Overwrite the LE long at segment 2 (expiry) with a timestamp 60s in the PAST.
        byte[] tampered = withPastExpiry(encoded, (System.currentTimeMillis() / 1000) - 60L);

        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> ModelRequest.FromBytes(tampered),
                "a carrier whose expiry has lapsed must be rejected by FromBytes (the old bug)");
        assertTrue(String.valueOf(ex.getMessage()).contains("Expiry cannot be in the past"),
                "the rejection must be the 'Expiry cannot be in the past' contract — was: "
                        + ex.getMessage());
    }

    /**
     * Rewrite the TideMemory segment index 2 (the LE-long expiry) of an encoded ModelRequest to
     * {@code newExpiry}. Layout: [4B LE version][4B LE len0][data0]...; segment 2 is the third
     * length-prefixed block and is exactly 8 bytes (a LE long).
     */
    private static byte[] withPastExpiry(byte[] encoded, long newExpiry) {
        int pos = 4; // skip the 4-byte LE version header
        for (int seg = 0; seg < 2; seg++) {
            int len = leInt(encoded, pos);
            pos += 4 + len; // skip this segment's length prefix + data
        }
        int len2 = leInt(encoded, pos);
        if (len2 != Long.BYTES) {
            throw new IllegalStateException("segment 2 (expiry) expected 8 bytes, was " + len2);
        }
        byte[] out = encoded.clone();
        int dataStart = pos + 4;
        for (int i = 0; i < Long.BYTES; i++) {
            out[dataStart + i] = (byte) (newExpiry >>> (8 * i)); // little-endian
        }
        return out;
    }

    private static int leInt(byte[] b, int off) {
        return (b[off] & 0xFF)
                | ((b[off + 1] & 0xFF) << 8)
                | ((b[off + 2] & 0xFF) << 16)
                | ((b[off + 3] & 0xFF) << 24);
    }
}
