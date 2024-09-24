package org.tidecloak.jpa.models;

import org.keycloak.admin.ui.rest.model.ClientRole;
import org.keycloak.models.RoleModel;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.tidecloak.interfaces.DraftStatus;

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
