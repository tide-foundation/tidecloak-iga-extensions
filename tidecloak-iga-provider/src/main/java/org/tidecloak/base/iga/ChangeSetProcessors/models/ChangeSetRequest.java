package org.tidecloak.base.iga.ChangeSetProcessors.models;
import org.tidecloak.shared.enums.ActionType;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.tidecloak.shared.enums.ChangeSetType;

import java.util.List;

public class ChangeSetRequest {

    @JsonProperty("changeSetId")
    protected String changeSetId;
    @JsonProperty("changeSetType")
    protected ChangeSetType changeSetType;
    @JsonProperty("actionType")
    protected ActionType actionType;
    @JsonProperty("policyRoleId")
    protected String policyRoleId;
    /** Ordered dynamic data array — each non-null element is assembled positionally into TideMemory. */
    @JsonProperty("dynamicData")
    protected List<String> dynamicData;

    public ChangeSetRequest() {}

    public ChangeSetRequest(String changeSetId, ChangeSetType changeSetType, ActionType actionType) {
        this.changeSetId = changeSetId;
        this.changeSetType = changeSetType;
        this.actionType = actionType;
    }

    public ChangeSetRequest(String changeSetId, ChangeSetType changeSetType, ActionType actionType, String policyRoleId) {
        this.changeSetId = changeSetId;
        this.changeSetType = changeSetType;
        this.actionType = actionType;
        this.policyRoleId = policyRoleId;
    }

    public ChangeSetType getType() {
        return changeSetType;
    }
    public String getChangeSetId() {
        return changeSetId;
    }
    public ActionType getActionType() {
        return actionType;
    }

    public void setType(ChangeSetType changeSetType) {
        this.changeSetType = changeSetType;
    }
    public void setChangeSetId(String changeSetId) {
        this.changeSetId = changeSetId;
    }
    public void setActionType(ActionType actionType) {
        this.actionType = actionType;
    }

    public String getPolicyRoleId() {
        return policyRoleId;
    }
    public void setPolicyRoleId(String policyRoleId) {
        this.policyRoleId = policyRoleId;
    }

    public List<String> getDynamicData() {
        return dynamicData;
    }
    public void setDynamicData(List<String> dynamicData) {
        this.dynamicData = dynamicData;
    }

}