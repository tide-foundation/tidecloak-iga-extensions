package org.tidecloak.jpa.entities;

import jakarta.persistence.*;
import org.tidecloak.shared.enums.ChangeSetType;

import java.util.ArrayList;
import java.util.List;
import java.io.Serializable;
@NamedQueries({
        @NamedQuery(
                name = "getAllChangeRequestsByRecordId",
                query = "SELECT c FROM ChangesetRequestEntity c WHERE c.changesetRequestId = :changesetRequestId"
        ),
})

@Entity
@Table(name = "CHANGESET_REQUEST")
@IdClass(ChangesetRequestEntity.Key.class)
public class ChangesetRequestEntity {

    @Id
    @Column(name = "CHANGESET_REQUEST_ID")
    private String changesetRequestId;

    @Id
    @Enumerated(EnumType.STRING)
    @Column(name = "CHANGE_SET_TYPE")
    protected ChangeSetType changesetType;

    @OneToMany(mappedBy = "changesetRequest", cascade = CascadeType.ALL, orphanRemoval = true)
    protected List<AdminAuthorizationEntity> adminAuthorizations = new ArrayList<>();

    @Column(name = "DRAFT_REQUEST")
    private String draftRequest;

    @Column(name = "TIMESTAMP")
    protected Long timestamp = System.currentTimeMillis() / 1000;

    public ChangeSetType getChangesetType() {
        return changesetType;
    }

    public void setChangesetType(ChangeSetType changesetType) {
        this.changesetType = changesetType;
    }

    public String getChangesetRequestId() {
        return changesetRequestId;
    }

    public void setChangesetRequestId(String changesetRequestId) {
        this.changesetRequestId = changesetRequestId;
    }

    public List<AdminAuthorizationEntity> getAdminAuthorizations() {
        return adminAuthorizations;
    }

    public void setAdminAuthorizations(List<AdminAuthorizationEntity> adminAuthorizations) {
        this.adminAuthorizations = adminAuthorizations;
    }

    public void addAdminAuthorization(AdminAuthorizationEntity adminAuthorizations) {
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

    public static class Key implements Serializable {

        protected String changesetRequestId;

        protected ChangeSetType changesetType;

        public Key() {
        }

        public Key(String changesetRequestId, ChangeSetType changesetType) {
            this.changesetRequestId = changesetRequestId;
            this.changesetType = changesetType;
        }

        public String getChangesetRequestId() {
            return changesetRequestId;
        }

        public ChangeSetType getChangeSetType() {
            return changesetType;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            ChangesetRequestEntity.Key key = (ChangesetRequestEntity.Key) o;

            if (!changesetType.equals(key.changesetType)) return false;
            if (!changesetRequestId.equals(key.changesetRequestId)) return false;

            return true;
        }

        @Override
        public int hashCode() {
            int result = changesetRequestId.hashCode();
            result = 31 * result + changesetType.hashCode();

            return result;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof ChangesetRequestEntity)) return false;

        ChangesetRequestEntity key = (ChangesetRequestEntity) o;

        if (!changesetType.equals(key.changesetType)) return false;
        if (!changesetRequestId.equals(key.changesetRequestId)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = changesetRequestId.hashCode();
        result = 31 * result + changesetType.hashCode();
        return result;
    }
}
