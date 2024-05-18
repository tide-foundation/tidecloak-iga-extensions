package org.tidecloak.interfaces;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class RequestedChanges {
    @JsonProperty("changeSetType")
    protected ChangeSetType changeSetType;

    @JsonProperty("type")
    protected RequestType type;

    @JsonProperty("actionType")
    protected ActionType actionType;

    @JsonProperty("parentRecordId")
    protected String parentRecordId;

    @JsonProperty("userRecord")
    protected List<RequestChangesUserRecord> userRecord;

    @JsonProperty("description")
    protected String description;

    public RequestedChanges(ChangeSetType changeSetType, RequestType type, ActionType actionType, String parentRecordId, List<RequestChangesUserRecord> userRecord, String description) {
        this.type = type;
        this.changeSetType = changeSetType;
        this.actionType = actionType;
        this.parentRecordId = parentRecordId;
        this.userRecord = userRecord;
        this.description = description;
    }

    public String getParentRecordId() {
        return parentRecordId;
    }
    public ChangeSetType getChangeSetType() {
        return changeSetType;
    }
    public ActionType getActionType() {
        return actionType;
    }
    public List<RequestChangesUserRecord> getUserRecord() {
        return userRecord;
    }
    public String getDescription() {
        return description;
    }


    public void setParentRecordId(String parentRecordId) {
        this.parentRecordId = parentRecordId;
    }

    public void setUserRecord(List<RequestChangesUserRecord> userRecord) {
        this.userRecord = userRecord;
    }
    public void setDescription(String description) {
        this.description = description;
    }


}
