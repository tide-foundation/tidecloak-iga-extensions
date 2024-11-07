package org.tidecloak.interfaces;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class CompositeRoleChangeRequest extends RoleChangeRequest{
    @JsonProperty("compositeRole")
    protected String compositeRole;

    public CompositeRoleChangeRequest(String role, String compositeRole, String action, ChangeSetType changeSetType, RequestType requestType, String clientId, String realmId, ActionType actionType, String draftRecordId, List<RequestChangesUserRecord> userRecord, DraftStatus status, DraftStatus deleteStatus) {
        super(role, action, changeSetType, requestType, clientId, realmId, actionType, draftRecordId, userRecord, status, deleteStatus);
        this.compositeRole = compositeRole;
    }
}
