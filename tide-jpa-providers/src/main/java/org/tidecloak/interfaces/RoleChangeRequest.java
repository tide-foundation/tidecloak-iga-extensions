package org.tidecloak.interfaces;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class RoleChangeRequest  extends  RequestedChanges{
    @JsonProperty("role")
    protected String role;

    public RoleChangeRequest(String role, String action, ChangeSetType changeSetType, RequestType requestType, String clientId, ActionType actionType, String draftRecordId, List<RequestChangesUserRecord> userRecord, DraftStatus status) {
        super(action, changeSetType, requestType, clientId, actionType, draftRecordId, userRecord, status);
        this.role = role;
    }
}
