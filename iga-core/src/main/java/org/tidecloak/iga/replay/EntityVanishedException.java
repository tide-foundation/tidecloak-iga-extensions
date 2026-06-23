package org.tidecloak.iga.replay;

/**
 * Thrown by {@link IgaReplayExtension} when an ADOPT replay discovers that the
 * underlying entity (USER / ROLE / GROUP / CLIENT / CLIENT_SCOPE) referenced by
 * a pending change request no longer exists in the realm — i.e. it was deleted
 * out-of-band between ADOPT-create and ADOPT-commit.
 *
 * <p>This is a typed, structured signal rather than a raw {@code
 * IllegalStateException} so the commit endpoint can translate it into a clean
 * {@code 404 ENTITY_VANISHED} response (with the type/id/realm in the body) and
 * a single INFO log line, instead of letting it fall through to Keycloak's
 * generic uncaught-exception handler which would dump a full stack at ERROR
 * severity and return an opaque {@code 500 unknown_error}.</p>
 *
 * <p>The CR transaction is rolled back at the commit endpoint boundary, so the
 * CR remains in its prior state (PENDING) — the {@code APPROVED} flip in
 * {@link IgaReplayExtension#replayAdopt} only runs <em>after</em> the existence
 * check passes, so a thrown {@link EntityVanishedException} guarantees the CR
 * status is never touched.</p>
 */
public final class EntityVanishedException extends RuntimeException {

    private final String entityType;
    private final String entityId;
    private final String realmId;

    public EntityVanishedException(String entityType, String entityId, String realmId) {
        super("ADOPT replay: entity " + entityType + "/" + entityId
                + " no longer exists in realm " + realmId);
        this.entityType = entityType;
        this.entityId = entityId;
        this.realmId = realmId;
    }

    public String getEntityType() {
        return entityType;
    }

    public String getEntityId() {
        return entityId;
    }

    public String getRealmId() {
        return realmId;
    }
}
