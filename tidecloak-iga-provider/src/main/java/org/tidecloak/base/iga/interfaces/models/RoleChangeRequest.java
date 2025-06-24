package org.tidecloak.base.iga.interfaces.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;

import java.util.List;

public class RoleChangeRequest  extends  RequestedChanges{
    @JsonProperty("role")
    protected String role;

    public RoleChangeRequest(String role, String action, ChangeSetType changeSetType, RequestType requestType, String clientId, String realmId, ActionType actionType, String draftRecordId, List<RequestChangesUserRecord> userRecord, DraftStatus status, DraftStatus deleteStatus) {
        super(action, changeSetType, requestType, clientId, realmId, actionType, draftRecordId, userRecord, status, deleteStatus);
        this.role = role;
    }
}
