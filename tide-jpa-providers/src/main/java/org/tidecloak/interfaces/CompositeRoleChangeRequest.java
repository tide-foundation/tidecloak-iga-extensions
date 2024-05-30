package org.tidecloak.interfaces;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class CompositeRoleChangeRequest extends RoleChangeRequest{
    @JsonProperty("compositeRole")
    protected String compositeRole;

    public CompositeRoleChangeRequest(String role, String compositeRole, String action, ChangeSetType changeSetType, RequestType requestType, String clientId, ActionType actionType, String draftRecordId, List<RequestChangesUserRecord> userRecord, DraftStatus status) {
        super(role, action, changeSetType, requestType, clientId, actionType, draftRecordId, userRecord, status);
        this.compositeRole = compositeRole;
    }
}
