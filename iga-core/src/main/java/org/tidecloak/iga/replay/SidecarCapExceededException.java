package org.tidecloak.iga.replay;

/**
 * Thrown by {@link org.tidecloak.iga.services.IgaAdoptScan#scan} when, at scan
 * start, the realm's unattested-sidecar register already exceeds the configured
 * cap. The design refuses to start a toggle-on scan in that
 * state — the operator must drain (commit / cancel) sidecar rows before
 * enabling IGA. We surface this as a clean {@code 409 SIDECAR_CAP_EXCEEDED}
 * (rather than letting the scan run, timeout, or run out of memory) and roll
 * back the realm-attribute write so IGA stays OFF — clearer than half-enabling.
 *
 * <p>The cap is a hard-coded compile-time constant in {@link
 * org.tidecloak.iga.services.IgaAdoptScan}. It can be raised by editing that
 * constant; by design the cap is intentionally not a realm
 * attribute (so a misbehaving admin cannot lift it on their own realm). For
 * E2E only there is a system-property escape hatch documented on the constant.</p>
 *
 * <p>This is a sibling of {@link EntityVanishedException} — same typed signal
 * pattern so the calling endpoint can translate it into a structured response
 * with a single INFO log line, rather than dumping a stack at ERROR via the
 * generic uncaught-exception handler.</p>
 */
public final class SidecarCapExceededException extends RuntimeException {

    private final String realmId;
    private final long cap;
    private final long current;

    public SidecarCapExceededException(String realmId, long cap, long current) {
        super("IGA toggle-on refused: realm " + realmId + " sidecar size " + current
                + " exceeds cap " + cap);
        this.realmId = realmId;
        this.cap = cap;
        this.current = current;
    }

    public String getRealmId() {
        return realmId;
    }

    public long getCap() {
        return cap;
    }

    public long getCurrent() {
        return current;
    }
}
