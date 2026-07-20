package org.tidecloak.iga.producer.spi;

import org.junit.jupiter.api.Test;
import org.tidecloak.iga.attestors.TideAttestor;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * ★ Design B P4 — the post-flip (multiAdmin) real-signing contract for the edge-set
 * units, asserted at the seam this PR fixes WITHOUT standing up real ORKs. (In the
 * {@code producer.spi} package so it can reach the package-private login-read predicate
 * {@link IgaAttestationExporterProvider#decodeReplayableSig}.)
 *
 * <p>The keystone P4 fix: the multiAdmin commit ({@code signMultiAdminUnitsViaPolicy})
 * stores a sig the UNIFORM login replays. The login read accepts ONLY
 * {@code TIDE-FIRSTADMIN-v1:}+base64(64-byte VVK sig) — the prefix is signer-agnostic
 * (it marks "a real replayable 64-byte VVK sig", whether the firstAdmin VRK pack or the
 * multiAdmin admin quorum produced it). So a post-flip multiAdmin column must be
 * byte-shape-identical to a pre-flip firstAdmin column.
 *
 * <p>{@code signMultiAdminUnitsViaPolicy} builds each per-unit value as
 * {@code FIRSTADMIN_SIG_PREFIX + resp.Signatures[i]}, where {@code resp.Signatures[i]} is
 * the Base64 of the ORK's 64-byte VVK sig (the SAME shape the firstAdmin path decodes then
 * re-Base64-encodes). These tests pin that wire-shape equality + the routing gate.
 */
class TideAttestorMultiAdminPostFlipSignTest {

    /** The exact string-composition signMultiAdminUnitsViaPolicy applies per unit. */
    private static String multiAdminColumnValue(String orkSignatureB64) {
        return TideAttestor.FIRSTADMIN_SIG_PREFIX + orkSignatureB64;
    }

    private static byte[] bytes(int len, int seed) {
        byte[] b = new byte[len];
        for (int i = 0; i < len; i++) b[i] = (byte) (seed + i);
        return b;
    }

    @Test
    void multiAdminColumnValue_isLoginReplayable_byteIdenticalToFirstAdmin() {
        // The ORK returns the 64-byte VVK sig Base64-encoded (resp.Signatures[i] is a String).
        byte[] vvkSig = bytes(64, 11);
        String orkSigB64 = Base64.getEncoder().encodeToString(vvkSig);

        // The multiAdmin commit stamps FIRSTADMIN_SIG_PREFIX + orkSigB64 into the column.
        String multiAdminColumn = multiAdminColumnValue(orkSigB64);

        // The uniform login read must REPLAY it as the exact 64-byte VVK sig — proving a
        // post-flip multiAdmin column is replayable, not a dead stub.
        byte[] replayed = IgaAttestationExporterProvider.decodeReplayableSig(multiAdminColumn);
        assertNotNull(replayed, "the multiAdmin commit column must be login-replayable");
        assertArrayEquals(vvkSig, replayed,
                "the multiAdmin column must replay the exact 64-byte VVK sig the ORK produced");

        // And it is byte-identical to what the firstAdmin path would stamp for the same sig.
        String firstAdminColumn = TideAttestor.FIRSTADMIN_SIG_PREFIX
                + Base64.getEncoder().encodeToString(vvkSig);
        assertEquals(firstAdminColumn, multiAdminColumn,
                "post-flip multiAdmin and pre-flip firstAdmin columns must be byte-identical "
                        + "(the prefix is signer-agnostic)");
    }

    @Test
    void multiAdminCommit_mustNotStoreTheDummyStubOrBareSig() {
        // The OLD (pre-P4) multiAdmin commit stored the bare ORK sig (no prefix) — and the
        // node/derived path stored the DUMMY_SIG_PREFIX SHA-256 stub — both NON-replayable.
        // Assert neither replays, so a regression back to either shape is caught.
        byte[] vvkSig = bytes(64, 3);
        String bareNoPrefix = Base64.getEncoder().encodeToString(vvkSig);
        assertNull(IgaAttestationExporterProvider.decodeReplayableSig(bareNoPrefix),
                "a bare sig with no prefix must NOT be login-replayable (the old multiAdmin bug)");

        String dummyStub = TideAttestor.DUMMY_SIG_PREFIX
                + Base64.getEncoder().encodeToString(bytes(32, 9)); // sha256 = 32 bytes
        assertNull(IgaAttestationExporterProvider.decodeReplayableSig(dummyStub),
                "the DUMMY_SIG_PREFIX stub must NOT be login-replayable");
    }

    /**
     * ★ P4 — the CREATE_* NODE unit (now framed onto the phase-1 carrier and distributed at
     * commit via {@code distributeMultiAdminUnitSigs}) is stamped with the SAME
     * {@code FIRSTADMIN_SIG_PREFIX}+b64(64B) shape — so a post-flip CREATE node column is
     * login-replayable, NOT a dead stub. (Distinct from the edge-set unit at index 0, this is
     * the node unit at index ≥1 in the carrier; both share the signer-agnostic replayable wire
     * shape.)
     */
    @Test
    void createNodeUnitColumn_isLoginReplayable_postFlip() {
        byte[] nodeVvkSig = bytes(64, 23); // the ORK's 64B VVK sig over the CREATE node unit
        String orkSigB64 = Base64.getEncoder().encodeToString(nodeVvkSig);

        // distributeMultiAdminUnitSigs stamps signMultiAdminUnitsViaPolicy's value verbatim:
        // FIRSTADMIN_SIG_PREFIX + b64(64B) — the same shape for EVERY framed unit (edge or
        // node), so the CREATE node column replays just like the edge column.
        String nodeColumn = multiAdminColumnValue(orkSigB64);

        byte[] replayed = IgaAttestationExporterProvider.decodeReplayableSig(nodeColumn);
        assertNotNull(replayed, "the post-flip CREATE node column must be login-replayable");
        assertArrayEquals(nodeVvkSig, replayed,
                "the CREATE node column must replay the exact 64-byte VVK sig the ORK produced");
    }

    /**
     * ★ P4 (generalized) — the SET_* / UPDATE_* live-entity node units, the DERIVED owner-sets,
     * and the REALM-scoped units are ALL now framed onto the phase-1 carrier (via the
     * scratch-replay-and-read in {@code IgaScratchUnitBuilder} + {@code enumerateLiveCrUnits})
     * and distributed at commit with the SAME {@code FIRSTADMIN_SIG_PREFIX}+b64(64B) shape — so
     * EVERY producer unit column is login-replayable post-flip, not just the edge + CREATE node.
     * This pins the wire-shape so a regression that re-routes any of them back through the
     * non-replayable {@code DUMMY_SIG_PREFIX} stub is caught.
     */
    @Test
    void setDerivedAndRealmUnitColumns_areLoginReplayable_postFlip() {
        // Representative sigs for a SET node (e.g. client_config from SET_CLIENT_ATTRIBUTE), a
        // derived set (e.g. client_scope_assignment_set from ASSIGN_SCOPE), and a realm unit
        // (e.g. realm_config from SET_REALM_ATTRIBUTE). All distributed via the same path.
        for (int seed : new int[]{31, 41, 53}) {
            byte[] vvkSig = bytes(64, seed);
            String column = multiAdminColumnValue(Base64.getEncoder().encodeToString(vvkSig));

            byte[] replayed = IgaAttestationExporterProvider.decodeReplayableSig(column);
            assertNotNull(replayed,
                    "the post-flip SET/derived/realm unit column must be login-replayable");
            assertArrayEquals(vvkSig, replayed,
                    "the column must replay the exact 64-byte VVK sig the ORK produced");
        }
    }
}
