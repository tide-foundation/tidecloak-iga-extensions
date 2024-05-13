package org.tidecloak.jpa.entities.drafting;

import org.keycloak.admin.ui.rest.model.ClientRole;
import org.tidecloak.interfaces.DraftStatus;

public class ClientRoleExt {
    private ClientRole clientRole;
    private DraftStatus draftStatus;


    public ClientRoleExt(ClientRole clientRole, DraftStatus draftStatus) {
        this.clientRole = clientRole;
        this.draftStatus = draftStatus;
    }

    public ClientRole getClient() {
        return this.clientRole;
    }

    public void setClient(ClientRole client) {
        this.clientRole = client;
    }

    public DraftStatus getDraftStatus() {
        return this.draftStatus;
    }

    public void setDraftStatus(DraftStatus draftStatus) {
        this.draftStatus = draftStatus;
    }

}
