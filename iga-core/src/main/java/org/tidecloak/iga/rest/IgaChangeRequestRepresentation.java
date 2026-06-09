package org.tidecloak.iga.rest;

import java.util.List;
import java.util.Map;

/**
 * JSON representation of an IGA change request, returned by the REST API.
 */
public class IgaChangeRequestRepresentation {

    private String id;
    private String realmId;
    private String entityType;
    private String entityId;
    private String actionType;
    private List<Map<String, Object>> rows;
    private String status;
    private String requestedBy;
    private Long createdAt;
    private Long resolvedAt;
    private String resolvedBy;
    private long authorizationCount;
    private List<IgaCrAuthorizerRepresentation> authorizers;
    private boolean readyToCommit;
    private int threshold;
    private List<String> requiredApproverRoles;
    private String scopeMode;
    private List<String> dependsOn;
    private boolean blocked;
    private String blockedReason;
    private String relatedPolicyCrId;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getRealmId() { return realmId; }
    public void setRealmId(String realmId) { this.realmId = realmId; }

    public String getEntityType() { return entityType; }
    public void setEntityType(String entityType) { this.entityType = entityType; }

    public String getEntityId() { return entityId; }
    public void setEntityId(String entityId) { this.entityId = entityId; }

    public String getActionType() { return actionType; }
    public void setActionType(String actionType) { this.actionType = actionType; }

    public List<Map<String, Object>> getRows() { return rows; }
    public void setRows(List<Map<String, Object>> rows) { this.rows = rows; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getRequestedBy() { return requestedBy; }
    public void setRequestedBy(String requestedBy) { this.requestedBy = requestedBy; }

    public Long getCreatedAt() { return createdAt; }
    public void setCreatedAt(Long createdAt) { this.createdAt = createdAt; }

    public Long getResolvedAt() { return resolvedAt; }
    public void setResolvedAt(Long resolvedAt) { this.resolvedAt = resolvedAt; }

    public String getResolvedBy() { return resolvedBy; }
    public void setResolvedBy(String resolvedBy) { this.resolvedBy = resolvedBy; }

    public long getAuthorizationCount() { return authorizationCount; }
    public void setAuthorizationCount(long authorizationCount) { this.authorizationCount = authorizationCount; }

    public List<IgaCrAuthorizerRepresentation> getAuthorizers() { return authorizers; }
    public void setAuthorizers(List<IgaCrAuthorizerRepresentation> authorizers) { this.authorizers = authorizers; }

    public boolean isReadyToCommit() { return readyToCommit; }
    public void setReadyToCommit(boolean readyToCommit) { this.readyToCommit = readyToCommit; }

    public int getThreshold() { return threshold; }
    public void setThreshold(int threshold) { this.threshold = threshold; }

    public List<String> getRequiredApproverRoles() { return requiredApproverRoles; }
    public void setRequiredApproverRoles(List<String> requiredApproverRoles) { this.requiredApproverRoles = requiredApproverRoles; }

    public String getScopeMode() { return scopeMode; }
    public void setScopeMode(String scopeMode) { this.scopeMode = scopeMode; }

    public List<String> getDependsOn() { return dependsOn; }
    public void setDependsOn(List<String> dependsOn) { this.dependsOn = dependsOn; }

    public boolean isBlocked() { return blocked; }
    public void setBlocked(boolean blocked) { this.blocked = blocked; }

    public String getBlockedReason() { return blockedReason; }
    public void setBlockedReason(String blockedReason) { this.blockedReason = blockedReason; }

    public String getRelatedPolicyCrId() { return relatedPolicyCrId; }
    public void setRelatedPolicyCrId(String relatedPolicyCrId) { this.relatedPolicyCrId = relatedPolicyCrId; }
}
