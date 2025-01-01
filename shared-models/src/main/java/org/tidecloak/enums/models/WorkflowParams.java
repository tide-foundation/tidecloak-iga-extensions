package org.tidecloak.enums.models;

import org.tidecloak.enums.ActionType;
import org.tidecloak.enums.DraftStatus;

public class WorkflowParams {
    private DraftStatus draftStatus;
    private boolean isDelete;
    private ActionType actionType;

    // Constructor, getters, setters
    public WorkflowParams(DraftStatus draftStatus, boolean isDelete, ActionType actionType) {
        this.draftStatus = draftStatus;
        this.isDelete = isDelete;
        this.actionType = actionType;
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
}