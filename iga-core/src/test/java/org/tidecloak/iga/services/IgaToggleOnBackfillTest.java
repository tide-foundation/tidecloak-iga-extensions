package org.tidecloak.iga.services;

import org.junit.jupiter.api.Test;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.tidecloak.iga.attestors.TideAttestor;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The toggle-on full-closure backfill's idempotency + maximal-scope decisions.
 *
 * <ul>
 *   <li>{@link IgaToggleOnBackfill#isRealReplayableSig} — only a
 *       {@code TIDE-FIRSTADMIN-v1:}+b64(64-byte) value is "real" (already covered →
 *       skip, never clobber); a NULL / blank / wrong-prefix / 32-byte STUB is NOT real
 *       (→ (re)sign). This is the exact discriminator the uniform login read uses, so
 *       the backfill never leaves a column the read would reject.</li>
 *   <li>{@link IgaToggleOnBackfill#maximalOptionalScopeString} — the union of every
 *       client's OPTIONAL scope names, so each export emits the maximal scope closure
 *       (any real login's requested scope is a subset).</li>
 * </ul>
 */
class IgaToggleOnBackfillTest {

    private static String prefixed(int len) {
        return TideAttestor.FIRSTADMIN_SIG_PREFIX + Base64.getEncoder().encodeToString(new byte[len]);
    }

    @Test
    void real64ByteSig_isAlreadyCovered_notReSigned() {
        assertTrue(IgaToggleOnBackfill.isRealReplayableSig(prefixed(64)),
                "a real 64-byte firstAdmin sig must be treated as already-covered (skip, never clobber)");
    }

    @Test
    void stubAndMissingAndWrong_areNotReal_soGetSigned() {
        assertFalse(IgaToggleOnBackfill.isRealReplayableSig(null));
        assertFalse(IgaToggleOnBackfill.isRealReplayableSig(""));
        assertFalse(IgaToggleOnBackfill.isRealReplayableSig("   "));
        assertFalse(IgaToggleOnBackfill.isRealReplayableSig(prefixed(32)),  // the 32B base64(sha256) STUB
                "the 32-byte firstAdmin stub must NOT count as real — it must be (re)signed");
        assertFalse(IgaToggleOnBackfill.isRealReplayableSig(prefixed(63)));
        assertFalse(IgaToggleOnBackfill.isRealReplayableSig(prefixed(65)));
        assertFalse(IgaToggleOnBackfill.isRealReplayableSig(
                "TIDE-DUMMY-v1:" + Base64.getEncoder().encodeToString(new byte[64])),
                "a wrong-prefix (multiAdmin dummy) value is not a replayable firstAdmin sig");
        assertFalse(IgaToggleOnBackfill.isRealReplayableSig(
                TideAttestor.FIRSTADMIN_SIG_PREFIX + "!!!not-base64!!!"));
    }

    @Test
    void backfillDiscriminator_isExactly_firstAdminPrefixPlus64Bytes() {
        // The backfill's "already covered" rule is identical to the login read's
        // "replayable" rule (TIDE-FIRSTADMIN-v1: + exactly 64 decoded bytes), so a
        // column the backfill leaves un-resigned is exactly one the login can replay.
        for (int len = 0; len <= 128; len++) {
            boolean expectReal = (len == 64);
            assertEquals(expectReal, IgaToggleOnBackfill.isRealReplayableSig(prefixed(len)),
                    "only a 64-byte prefixed sig is replayable/already-covered (len=" + len + ")");
        }
    }

    @Test
    void skippedResult_carriesReasonAndDidNotRun() {
        // The root cause of the first-time-tide login fail-close: backfill() returns a
        // Result.skipped("not_first_admin") when its firstAdmin gate (TideAttestor
        // .isFirstAdminMode, whose no-row branch keys on iga.attestor==tide) sees the
        // attestor as not-yet-tide — exactly what happens when the toggle's
        // iga.attestor=tide write is still uncommitted on the OUTER session and the
        // backfill runs in a nested job tx that reads stale DB state. A skipped pass
        // signs NOTHING, so the provisioning columns (realm_config etc.) stay NULL.
        // The TideAdminCompatResource fix re-asserts iga.attestor=tide on the reloaded
        // bfRealm inside the nested tx so the gate sees firstAdmin and ran==true.
        IgaToggleOnBackfill.Result skipped = IgaToggleOnBackfill.Result.skipped("not_first_admin");
        assertFalse(skipped.ran, "a gated-out backfill must report ran=false");
        assertEquals("not_first_admin", skipped.skipReason);
        assertEquals(0, skipped.unitsSigned, "a skipped pass signs zero units (columns stay NULL)");
        assertEquals(0, skipped.unitsSkipped);
        assertEquals(0, skipped.usersCovered);
        assertEquals(0, skipped.clientsCovered);
    }

    @Test
    void maximalScope_isUnionOfOptionalScopeNames() {
        ClientModel c1 = clientWithOptionalScopes("a", "b");
        ClientModel c2 = clientWithOptionalScopes("b", "c");   // "b" overlaps -> deduped
        String scope = IgaToggleOnBackfill.maximalOptionalScopeString(List.of(c1, c2));
        // order-insensitive set equality
        java.util.Set<String> names = new java.util.LinkedHashSet<>(List.of(scope.split("\\s+")));
        assertEquals(java.util.Set.of("a", "b", "c"), names,
                "maximal scope must be the deduped union of every client's optional scope names");
    }

    private static ClientModel clientWithOptionalScopes(String... names) {
        ClientModel c = mock(ClientModel.class);
        Map<String, ClientScopeModel> optional = new LinkedHashMap<>();
        for (String n : names) {
            ClientScopeModel s = mock(ClientScopeModel.class);
            when(s.getName()).thenReturn(n);
            optional.put(n, s);
        }
        when(c.getClientScopes(false)).thenReturn(optional);
        return c;
    }
}
