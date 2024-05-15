package org.tidecloak.interfaces;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class RequestedChanges {
    @JsonProperty("type")
    protected RequestType type;

    @JsonProperty("parentRecordId")
    protected String parentRecordId;

    @JsonProperty("userRecord")
    protected List<RequestChangesUserRecord> userRecord;

    @JsonProperty("description")
    protected String description;

    public RequestedChanges(RequestType type, String parentRecordId, List<RequestChangesUserRecord> userRecord, String description) {
        this.type = type;
        this.parentRecordId = parentRecordId;
        this.userRecord = userRecord;
        this.description = description;
    }

    public String getParentRecordId() {
        return parentRecordId;
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
