package org.tidecloak.base.iga.interfaces.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;

import java.util.List;

public class CompositeRoleChangeRequest extends RoleChangeRequest{
    @JsonProperty("compositeRole")
    protected String compositeRole;

    public CompositeRoleChangeRequest(String role, String compositeRole, String action, ChangeSetType changeSetType, RequestType requestType, String clientId, String realmId, ActionType actionType, String draftRecordId, List<RequestChangesUserRecord> userRecord, DraftStatus status, DraftStatus deleteStatus) {
        super(role, action, changeSetType, requestType, clientId, realmId, actionType, draftRecordId, userRecord, status, deleteStatus);
        this.compositeRole = compositeRole;
    }
}