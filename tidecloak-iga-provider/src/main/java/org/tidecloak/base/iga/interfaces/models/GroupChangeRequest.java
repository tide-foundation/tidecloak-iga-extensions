package org.tidecloak.base.iga.interfaces.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;

import java.util.List;

public class GroupChangeRequest extends RequestedChanges {
    @JsonProperty("groupName")
    protected String groupName;

    @JsonProperty("roleName")
    protected String roleName;

    @JsonProperty("userName")
    protected String userName;

    public GroupChangeRequest(String groupName, String roleName, String userName, String action, ChangeSetType changeSetType, RequestType requestType, String clientId, String realmId, ActionType actionType, String draftRecordId, List<RequestChangesUserRecord> userRecord, DraftStatus status) {
        super(action, changeSetType, requestType, clientId, realmId, actionType, draftRecordId, userRecord, status, DraftStatus.NULL);
        this.groupName = groupName;
        this.roleName = roleName;
        this.userName = userName;
    }
}
