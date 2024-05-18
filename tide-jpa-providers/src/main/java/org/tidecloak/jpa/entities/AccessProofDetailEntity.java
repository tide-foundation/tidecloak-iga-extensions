package org.tidecloak.jpa.entities;

import jakarta.persistence.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.tidecloak.interfaces.ChangeSetType;

@NamedQueries({
        @NamedQuery(name="getProofDetailsForDraft", query="SELECT a FROM AccessProofDetailEntity a WHERE a.recordId = :recordId"),
        @NamedQuery(name="getProofDetailsForUserByClient", query="SELECT a FROM AccessProofDetailEntity a WHERE a.user = :user and a.clientId = :clientId ORDER BY a.createdTimestamp DESC"),
        @NamedQuery(name="getProofDetailsForUserByClientAndRecordId", query="SELECT a FROM AccessProofDetailEntity a WHERE a.user = :user and a.clientId = :clientId and a.recordId = :recordId ORDER BY a.createdTimestamp DESC"),
        @NamedQuery(name="getProofDetailsByClient", query="SELECT a FROM AccessProofDetailEntity a WHERE a.clientId = :clientId ORDER BY a.createdTimestamp DESC"),
        @NamedQuery(name="getProofDetailsForCompositeByClient", query="SELECT a FROM AccessProofDetailEntity a WHERE a.changesetType = :changesetType and a.clientId = :clientId ORDER BY a.createdTimestamp DESC"),
        @NamedQuery(
                name = "AccessProofDetailEntity.findLatestValidByUserAndClientAndType",
                query = "SELECT a FROM AccessProofDetailEntity a WHERE a.user = :user AND a.clientId = :clientId AND a.id NOT IN " +
                        "(SELECT d.recordId FROM AccessProofDetailDependencyEntity d WHERE d.forkedChangeSetType = :changesetType) " +
                        "ORDER BY a.createdTimestamp DESC"
        ),
        @NamedQuery(name="deleteProofRecordForUserAndClient", query="DELETE FROM AccessProofDetailEntity a WHERE a.recordId = :recordId and a.user  = :user AND a.clientId = :clientId"),
        @NamedQuery(name="deleteProofRecordForUser", query="DELETE FROM AccessProofDetailEntity a WHERE a.recordId = :recordId and a.user  = :user"),
        @NamedQuery(name="deleteProofRecords", query="DELETE FROM AccessProofDetailEntity a WHERE a.recordId = :recordId"),

})

@Entity
@Table(name = "ACCESS_PROOF_DETAIL")
public class AccessProofDetailEntity {

    @Id
    @Column(name="ID", length = 36)
    @Access(AccessType.PROPERTY) // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    protected String id;

    @Column(name = "RECORD_ID")
    protected String recordId;

    @Enumerated(EnumType.STRING)
    @Column(name = "CHANGE_SET_TYPE")
    protected ChangeSetType changesetType;

    @ManyToOne(fetch= FetchType.LAZY)
    @JoinColumn(name="USER_ID")
    protected UserEntity user;

    @Column(name = "CLIENT_ID")
    protected String clientId;

    @Column(name = "PROOF_DRAFT")
    protected String proofDraft;

    @Column(name = "CREATED_TIMESTAMP")
    protected Long createdTimestamp = System.currentTimeMillis();;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public UserEntity getUser() {
        return user;
    }

    public void setUser(UserEntity user) {
        this.user = user;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getRecordId() {
        return recordId;
    }

    public void setRecordId(String recordId) {
        this.recordId = recordId;
    }

    public ChangeSetType getChangesetType() {
        return changesetType;
    }

    public void setChangesetType(ChangeSetType changesetType) {
        this.changesetType = changesetType;
    }

    public String getProofDraft() {
        return proofDraft;
    }

    public void setProofDraft(String proofDraft) {
        this.proofDraft = proofDraft;
    }

    public Long getCreatedTimestamp() {
        return createdTimestamp;
    }

    public void setCreatedTimestamp(Long timestamp) {
        createdTimestamp = timestamp;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof AccessProofDetailEntity)) return false;

        AccessProofDetailEntity key = (AccessProofDetailEntity) o;

        if (!id.equals(key.id)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }

}
