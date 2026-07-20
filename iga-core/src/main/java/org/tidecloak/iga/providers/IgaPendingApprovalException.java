package org.tidecloak.iga.providers;

/**
 * Thrown by the IGA interception layer when an entity-create operation
 * has been recorded as a pending change request and should NOT proceed
 * to actually persist the entity. Mapped to HTTP 202 by
 * {@link org.tidecloak.iga.rest.IgaPendingApprovalExceptionMapper}.
 */
public class IgaPendingApprovalException extends RuntimeException {

    private final String changeRequestId;
    private final String actionType;
    private final String entityType;

    public IgaPendingApprovalException(String changeRequestId, String entityType, String actionType) {
        super(actionType + " on " + entityType + " is pending approval (change request " + changeRequestId + ")");
        this.changeRequestId = changeRequestId;
        this.entityType = entityType;
        this.actionType = actionType;
    }

    public String getChangeRequestId() { return changeRequestId; }
    public String getEntityType() { return entityType; }
    public String getActionType() { return actionType; }
}
