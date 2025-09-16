//  (compat shim)
package org.tidecloak.base.iga.ChangeSetProcessors.models;

import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;

public class ChangeSetRequest {
    private String changeSetId;
    private ChangeSetType type;
    private ActionType actionType;

    public ChangeSetRequest(){}
    public ChangeSetRequest(String changeSetId, ChangeSetType type, ActionType actionType){
        this.changeSetId = changeSetId;
        this.type = type;
        this.actionType = actionType;
    }

    public String getChangeSetId() { return changeSetId; }
    public void setChangeSetId(String changeSetId) { this.changeSetId = changeSetId; }
    public ChangeSetType getType() { return type; }
    public void setType(ChangeSetType type) { this.type = type; }
    public ActionType getActionType() { return actionType; }
    public void setActionType(ActionType actionType) { this.actionType = actionType; }
}
