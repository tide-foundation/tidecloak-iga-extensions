package org.tidecloak.interfaces;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class CompositeRoleChangeRequest extends RequestedChanges{
    @JsonProperty("role")
    protected String role;

    @JsonProperty("compositeRole")
    protected String compositeRole;

    public CompositeRoleChangeRequest(String role, String compositeRole, String action, ChangeSetType changeSetType, RequestType requestType, String clientId, ActionType actionType, String draftRecordId, List<RequestChangesUserRecord> userRecord, DraftStatus status) {
        super(action, changeSetType, requestType, clientId, actionType, draftRecordId, userRecord, status);
        this.role = role;
        this.compositeRole = compositeRole;
    }
}
