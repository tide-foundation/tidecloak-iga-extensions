package org.tidecloak.base.iga.interfaces;

import org.keycloak.models.RoleModel;
import org.tidecloak.shared.enums.DraftStatus;

public class RoleModelExt {
    private RoleModel role;
    private DraftStatus draftStatus;


    public RoleModelExt(RoleModel role, DraftStatus draftStatus) {
        this.role = role;
        this.draftStatus = draftStatus;
    }

    public RoleModel getRole() {
        return this.role;
    }

    public void setRole(RoleModel role) {
        this.role = role;
    }

    public DraftStatus getDraftStatus() {
        return this.draftStatus;
    }

    public void setDraftStatus(DraftStatus draftStatus) {
        this.draftStatus = draftStatus;
    }

}
