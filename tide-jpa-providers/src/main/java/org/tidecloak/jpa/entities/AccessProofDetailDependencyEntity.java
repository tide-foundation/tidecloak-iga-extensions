package org.tidecloak.jpa.entities;


import jakarta.persistence.*;
import org.tidecloak.shared.enums.ChangeSetType;

import java.io.Serializable;

@NamedQueries({
        @NamedQuery(
                name = "AccessProofDetailDependencyEntity.findTideCompositeMappingByForkedDetails",
                query = "SELECT t FROM TideCompositeRoleMappingDraftEntity t WHERE t.composite.id IN " +
                        "(SELECT a.forkedRecordId FROM AccessProofDetailDependencyEntity a WHERE a.forkedChangeSetType = :changeSetType AND a.recordId = :recordId)" +
                        "ORDER BY t.createdTimestamp DESC"
        ),
})

@Entity
@Table(name = "ACCESS_PROOF_DETAIL_DEPENDENCY")
@IdClass(AccessProofDetailDependencyEntity.Key.class)
public class AccessProofDetailDependencyEntity {

    @Id
    @Column(name = "RECORD_ID")
    protected String recordId;

    @Id
    @Enumerated(EnumType.STRING)
    @Column(name = "CHANGE_SET_TYPE")
    protected ChangeSetType changeSetType;

    @Column(name = "FORKED_RECORD_ID")
    protected String forkedRecordId;

    @Enumerated(EnumType.STRING)
    @Column(name = "FORKED_CHANGE_SET_TYPE")
    protected ChangeSetType forkedChangeSetType;

//    @Column(name = "ROOT_NODE")
//    protected boolean root;

    public String getRecordId() {
        return recordId;
    }

    public void setRecordId(String recordId) {
        this.recordId = recordId;
    }

    public ChangeSetType getChangeSetType() {
        return changeSetType;
    }

    public void setChangesetType(ChangeSetType changeSetType) {
        this.changeSetType = changeSetType;
    }

    public String getForkedRecordId() {
        return forkedRecordId;
    }

    public void setForkedRecordId(String forkedRecordId) {
        this.forkedRecordId = forkedRecordId;
    }

    public ChangeSetType getForkedChangeSetType() {
        return forkedChangeSetType;
    }

    public void setForkedChangeSetType(ChangeSetType forkedChangeSetType) {
        this.forkedChangeSetType = forkedChangeSetType;
    }

//    public boolean isRoot() {
//        return root;
//    }
//
//    public void set(boolean isRoot) {
//        this.root = isRoot;
//    }

    public static class Key implements Serializable {

        protected String recordId;

        protected ChangeSetType changeSetType;

        public Key() {
        }

        public Key(String recordId, ChangeSetType changeSetType) {
            this.recordId = recordId;
            this.changeSetType = changeSetType;
        }

        public String getRecordId() {
            return recordId;
        }

        public ChangeSetType getChangeSetType() {
            return changeSetType;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            AccessProofDetailDependencyEntity.Key key = (AccessProofDetailDependencyEntity.Key) o;

            if (!changeSetType.equals(key.changeSetType)) return false;
            if (!recordId.equals(key.recordId)) return false;

            return true;
        }

        @Override
        public int hashCode() {
            int result = recordId.hashCode();
            result = 31 * result + changeSetType.hashCode();

            return result;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof AccessProofDetailDependencyEntity)) return false;

        AccessProofDetailDependencyEntity key = (AccessProofDetailDependencyEntity) o;

        if (!changeSetType.equals(key.changeSetType)) return false;
        if (!recordId.equals(key.recordId)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = recordId.hashCode();
        result = 31 * result + changeSetType.hashCode();
        return result;
    }


}
