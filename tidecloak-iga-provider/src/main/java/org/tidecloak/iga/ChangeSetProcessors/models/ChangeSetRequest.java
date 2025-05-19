package org.tidecloak.iga.ChangeSetProcessors.models;
import org.tidecloak.shared.enums.ActionType;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.tidecloak.shared.enums.ChangeSetType;

public class ChangeSetRequest {

    @JsonProperty("changeSetId")
    protected String changeSetId;
    @JsonProperty("changeSetType")
    protected ChangeSetType changeSetType;
    @JsonProperty("actionType")
    protected ActionType actionType;

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

}