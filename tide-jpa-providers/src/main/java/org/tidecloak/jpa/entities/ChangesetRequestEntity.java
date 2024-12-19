package org.tidecloak.jpa.entities;

import jakarta.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "CHANGESET_REQUEST")
public class ChangesetRequestEntity {

    @Id
    @Column(name = "CHANGESET_REQUEST_ID")
    private String changesetRequestId;

    @ElementCollection
    @CollectionTable(name = "ADMIN_AUTHORIZATIONS", joinColumns = @JoinColumn(name = "ID"))
    @Column(name = "ADMIN_AUTHORIZATION")
    protected List<String> adminAuthorizations = new ArrayList<>();

    @Column(name = "DRAFT_REQUEST")
    private String draftRequest;

    @Column(name = "TIMESTAMP")
    protected Long timestamp = System.currentTimeMillis();

    public String getChangesetRequestId() {
        return changesetRequestId;
    }

    public void setChangesetRequestId(String changesetRequestId) {
        this.changesetRequestId = changesetRequestId;
    }

    public List<String> getAdminAuthorizations() {
        return adminAuthorizations;
    }

    public void setAdminAuthorizations(List<String> adminAuthorizations) {
        this.adminAuthorizations = adminAuthorizations;
    }

    public void addAdminAuthorization(String adminAuthorizations) {
        this.adminAuthorizations.add(adminAuthorizations);
    }

    public String getDraftRequest() {
        return draftRequest;
    }

    public void setDraftRequest(String draftRequest) {
        this.draftRequest = draftRequest;
    }


    public Long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Long timestamp) {
        this.timestamp = timestamp;
    }
}
