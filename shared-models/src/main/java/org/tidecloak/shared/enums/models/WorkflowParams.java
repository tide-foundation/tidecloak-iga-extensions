package org.tidecloak.shared.enums.models;

import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;

public class WorkflowParams {
    private final DraftStatus draftStatus;
    private final boolean isDelete;
    private final ActionType actionType;
    private final ChangeSetType changeSetType;
    private final String policyRoleId;

    // Constructor, getters, setters
    public WorkflowParams(DraftStatus draftStatus, boolean isDelete, ActionType actionType, ChangeSetType changeSetType) {
        this(draftStatus, isDelete, actionType, changeSetType, null);
    }

    public WorkflowParams(DraftStatus draftStatus, boolean isDelete, ActionType actionType, ChangeSetType changeSetType, String policyRoleId) {
        this.draftStatus = draftStatus;
        this.isDelete = isDelete;
        this.actionType = actionType;
        this.changeSetType = changeSetType;
        this.policyRoleId = policyRoleId;
    }

    public DraftStatus getDraftStatus() {
        return draftStatus;
    }

    public boolean isDelete() {
        return isDelete;
    }

    public ActionType getActionType() {
        return actionType;
    }

    public ChangeSetType getChangeSetType() {
        return changeSetType;
    }

    public String getPolicyRoleId() {
        return policyRoleId;
    }

}