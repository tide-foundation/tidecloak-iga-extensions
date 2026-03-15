package org.tidecloak.base.iga.interfaces.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;

import java.util.List;

public class RequestedChanges {
    @JsonProperty("action")
    protected  String action;

    @JsonProperty("changeSetType")
    protected ChangeSetType changeSetType;

    @JsonProperty("requestType")
    protected RequestType requestType;

    @JsonProperty("clientId")
    protected  String clientId;

    @JsonProperty("realmId")
    protected  String realmId;

    @JsonProperty("actionType")
    protected ActionType actionType;

    @JsonProperty("draftRecordId")
    protected String draftRecordId;

    @JsonProperty("userRecord")
    protected List<RequestChangesUserRecord> userRecord;

    @JsonProperty("status")
    protected DraftStatus status;

    @JsonProperty("deleteStatus")
    protected DraftStatus deleteStatus;

    @JsonProperty("requestedBy")
    protected String requestedBy;

    @JsonProperty("requestedByUsername")
    protected String requestedByUsername;

    @JsonProperty("approvalCount")
    protected int approvalCount;

    @JsonProperty("rejectionCount")
    protected int rejectionCount;

    @JsonProperty("approvedBy")
    protected List<String> approvedBy;

    @JsonProperty("deniedBy")
    protected List<String> deniedBy;

    @JsonProperty("commentCount")
    protected int commentCount;

    public RequestedChanges(String action, ChangeSetType changeSetType, RequestType requestType, String clientId, String realmId, ActionType actionType, String draftRecordId, List<RequestChangesUserRecord> userRecord, DraftStatus status, DraftStatus deleteStatus) {
        this.action = action;
        this.requestType = requestType;
        this.changeSetType = changeSetType;
        this.clientId = clientId;
        this.realmId = realmId;
        this.actionType = actionType;
        this.draftRecordId = draftRecordId;
        this.userRecord = userRecord;
        this.status = status;
        this.deleteStatus = deleteStatus;

    }

    public String getAction() {
        return action;
    }
    public RequestType getRequestType() {
        return requestType;
    }
    public ChangeSetType getChangeSetType() {
        return changeSetType;
    }
    public ActionType getActionType() {
        return actionType;
    }
    public String getDraftRecordId() {
        return draftRecordId;
    }
    public List<RequestChangesUserRecord> getUserRecord() {
        return userRecord;
    }
    public DraftStatus getStatus() {
        return status;
    }
    public DraftStatus getDeleteStatus() {
        return deleteStatus;
    }
    public void setAction(String action) {this.action = action; }
    public void setRequestType(RequestType requestType) {this.requestType = requestType; }
    public void setChangeSetType(ChangeSetType changeSetType) {this.changeSetType = changeSetType; }
    public void setActionType(ActionType actionType) {this.actionType = actionType; }
    public void setDraftRecordId(String draftRecordId) {
        this.draftRecordId = draftRecordId;
    }
    public void setUserRecord(List<RequestChangesUserRecord> userRecord) {
        this.userRecord = userRecord;
    }
    public void setStatus(DraftStatus draftStatus) {
        this.status = draftStatus;
    }
    public void setDeleteStatus(DraftStatus draftStatus) {
        this.deleteStatus = draftStatus;
    }

    public String getRequestedBy() { return requestedBy; }
    public void setRequestedBy(String requestedBy) { this.requestedBy = requestedBy; }
    public String getRequestedByUsername() { return requestedByUsername; }
    public void setRequestedByUsername(String requestedByUsername) { this.requestedByUsername = requestedByUsername; }

    public int getApprovalCount() { return approvalCount; }
    public void setApprovalCount(int approvalCount) { this.approvalCount = approvalCount; }
    public int getRejectionCount() { return rejectionCount; }
    public void setRejectionCount(int rejectionCount) { this.rejectionCount = rejectionCount; }
    public List<String> getApprovedBy() { return approvedBy; }
    public void setApprovedBy(List<String> approvedBy) { this.approvedBy = approvedBy; }
    public List<String> getDeniedBy() { return deniedBy; }
    public void setDeniedBy(List<String> deniedBy) { this.deniedBy = deniedBy; }
    public int getCommentCount() { return commentCount; }
    public void setCommentCount(int commentCount) { this.commentCount = commentCount; }

}
