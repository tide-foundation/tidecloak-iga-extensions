package org.tidecloak.iga.providers;

/**
 * Outcome of a {@link RagnarokOffboardService#offboardRealm} run — a small,
 * dependency-free POJO so both the iga-core lookup side and the ragnarok
 * implementation side can produce/consume it WITHOUT either depending on the
 * other beyond this artifact.
 *
 * @param success   whether the offboard teardown completed (the SPI throws
 *                  {@link RagnarokOffboardException} on failure rather than
 *                  returning {@code success=false}, but the flag is kept for a
 *                  cheap success assertion at the call site).
 * @param summary   a human-readable one-line summary of what was torn down
 *                  (logged by the iga-core replay dispatcher).
 */
public record RagnarokOffboardResult(boolean success, String summary) {

    /** Convenience success factory. */
    public static RagnarokOffboardResult ok(String summary) {
        return new RagnarokOffboardResult(true, summary);
    }
}
