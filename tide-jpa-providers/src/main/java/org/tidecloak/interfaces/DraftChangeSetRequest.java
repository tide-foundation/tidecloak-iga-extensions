package org.tidecloak.interfaces;

import com.fasterxml.jackson.annotation.JsonProperty;


public class DraftChangeSetRequest {

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
