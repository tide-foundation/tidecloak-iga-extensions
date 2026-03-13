package org.tidecloak.base.iga.ChangeSetProcessors.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;

public class WhatIfRequest {

    @JsonProperty("changeSetType")
    private ChangeSetType changeSetType;

    @JsonProperty("actionType")
    private ActionType actionType;

    @JsonProperty("userId")
    private String userId;

    @JsonProperty("clientId")
    private String clientId;

    @JsonProperty("roleId")
    private String roleId;

    @JsonProperty("compositeRoleId")
    private String compositeRoleId;

    @JsonProperty("childRoleId")
    private String childRoleId;

    @JsonProperty("groupId")
    private String groupId;

    public WhatIfRequest() {}

    public ChangeSetType getChangeSetType() {
        return changeSetType;
    }

    public void setChangeSetType(ChangeSetType changeSetType) {
        this.changeSetType = changeSetType;
    }

    public ActionType getActionType() {
        return actionType;
    }

    public void setActionType(ActionType actionType) {
        this.actionType = actionType;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getRoleId() {
        return roleId;
    }

    public void setRoleId(String roleId) {
        this.roleId = roleId;
    }

    public String getCompositeRoleId() {
        return compositeRoleId;
    }

    public void setCompositeRoleId(String compositeRoleId) {
        this.compositeRoleId = compositeRoleId;
    }

    public String getChildRoleId() {
        return childRoleId;
    }

    public void setChildRoleId(String childRoleId) {
        this.childRoleId = childRoleId;
    }

    public String getGroupId() {
        return groupId;
    }

    public void setGroupId(String groupId) {
        this.groupId = groupId;
    }
}
