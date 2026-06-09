package org.tidecloak.iga.replay;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import org.junit.jupiter.api.Test;
import org.tidecloak.iga.services.IgaFirstAdminAutoCommit;

/**
 * Contract guarantees for the governed {@code DISABLE_IGA} change request:
 * <ul>
 *   <li>It is NOT an ADOPT action, so {@code IgaReplayExtension.tryReplay} returns
 *       false and the commit routes it to {@code IgaReplayDispatcher.replay} (the
 *       dispatcher switch), NOT the ADOPT extension.</li>
 *   <li>It is NOT on the firstAdmin auto-commit allow-list — so even a firstAdmin
 *       must explicitly authorize+commit it (the toggle never auto-executes the
 *       disable).</li>
 *   <li>It is NOT a producer-envelope-signed action — so {@code combineFinal}
 *       produces a stub signature with no ORK/Policy:1 round-trip (OFF is never
 *       blocked by ORK reachability).</li>
 * </ul>
 */
class DisableIgaContractTest {

    @Test
    void disableIga_isNotAnAdoptAction() {
        assertFalse(IgaReplayExtension.isAdoptAction("DISABLE_IGA"),
                "DISABLE_IGA must route through the dispatcher, not the ADOPT extension");
    }

    @Test
    void disableIga_isNotAutoCommittableInFirstAdmin() {
        assertFalse(IgaFirstAdminAutoCommit.isBaselineConfigActionType("DISABLE_IGA"),
                "DISABLE_IGA must require explicit firstAdmin approval — never auto-committed");
    }

    @Test
    void disableIga_isNotProducerEnvelopeSigned_soCommitIsAStub() throws Exception {
        Method m = org.tidecloak.iga.attestors.TideAttestor.class
                .getDeclaredMethod("isProducerEnvelopeSignedAction", String.class);
        m.setAccessible(true);
        boolean producerSigned = (boolean) m.invoke(null, "DISABLE_IGA");
        assertFalse(producerSigned,
                "DISABLE_IGA must not be producer-envelope signed — its commit must be a stub (no ORK)");

        // Sanity: a real producer action IS signed, proving the probe works.
        assertTrue((boolean) m.invoke(null, "GRANT_ROLES"));
    }
}
