package org.tidecloak.interfaces;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.tidecloak.enums.ActionType;
import org.tidecloak.enums.DraftStatus;

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


}
