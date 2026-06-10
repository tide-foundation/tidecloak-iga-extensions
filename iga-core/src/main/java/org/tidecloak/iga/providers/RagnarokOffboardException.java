package org.tidecloak.iga.providers;

/**
 * Thrown by {@link RagnarokOffboardService#offboardRealm} when the realm
 * teardown cannot be completed. Surfacing this out of the replay path rolls back
 * the replay transaction — nothing is torn down and the {@code OFFBOARD_REALM} CR
 * stays committable-retry (fail-closed: an offboard never "commits" without
 * actually offboarding).
 */
public class RagnarokOffboardException extends Exception {

    public RagnarokOffboardException(String message) {
        super(message);
    }

    public RagnarokOffboardException(String message, Throwable cause) {
        super(message, cause);
    }
}
