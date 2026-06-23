package org.tidecloak.iga.providers;

/**
 * Thrown when a PENDING change request already exists for an entity.
 * The REST layer maps this to HTTP 409.
 */
public class IgaConflictException extends RuntimeException {

    private final String existingChangeRequestId;

    public IgaConflictException(String existingChangeRequestId) {
        super("A pending IGA change request already exists: " + existingChangeRequestId);
        this.existingChangeRequestId = existingChangeRequestId;
    }

    public String getExistingChangeRequestId() {
        return existingChangeRequestId;
    }
}
