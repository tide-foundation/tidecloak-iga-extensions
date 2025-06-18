package org.tidecloak.jpa.entities.drafting;

import jakarta.persistence.*;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.tidecloak.shared.enums.DraftStatus;


@NamedQueries({
        @NamedQuery(name="getCompositeRoleDraft", query="select r from TideCompositeRoleDraftEntity r where r.composite = :composite and r.draftStatus = :draftStatus"),
        @NamedQuery(name="deleteCompositeRole", query="delete from TideCompositeRoleDraftEntity r where r.composite = :composite"),
        @NamedQuery(name="DeleteAllCompositeRoleDraftsByRealm",
                query = "DELETE FROM TideCompositeRoleDraftEntity r " +
                        "WHERE r.composite IN (SELECT r FROM RoleEntity r WHERE r.realmId = :realmId)"
        ),
        @NamedQuery(name="DeleteAllCompositeRoleDraftsByRole",
                query = "DELETE FROM TideCompositeRoleDraftEntity r " +
                        "WHERE r.composite.id = :roleId"
        ),
        @NamedQuery(name="GetCompositeRoleDraftEntityByRequestId", query="SELECT m FROM TideCompositeRoleDraftEntity m where m.changeRequestId = :requestId")

})

@Entity
@Table(name="COMPOSITE_ROLE_DRAFT")
public class TideCompositeRoleDraftEntity {

    @Id
    @Column(name="ID", length = 36)
    @Access(AccessType.PROPERTY) // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    protected String id;

    @Column(name="CHANGE_REQUEST_ID", length = 36)
    protected String changeRequestId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "COMPOSITE", referencedColumnName = "ID")  // Ensure 'ID' is the correct primary key field name in RoleEntity
    private RoleEntity composite;

    @Enumerated(EnumType.STRING)
    @Column(name = "DELETE_STATUS")
    private DraftStatus deleteStatus;

    @Column(name = "TIMESTAMP")
    protected Long timestamp = System.currentTimeMillis();

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getChangeRequestId() {
        return changeRequestId;
    }

    public void setChangeRequestId(String changeRequestId) {
        this.changeRequestId = changeRequestId;
    }

    public RoleEntity getComposite() {
        return composite;
    }

    public void setComposite(RoleEntity composite) {
        this.composite = composite;
    }

    // Getters and setters for new fields
    public DraftStatus getDeleteStatus() {
        return deleteStatus;
    }

    public void setDeleteStatus(DraftStatus deleteStatus) {
        this.deleteStatus = deleteStatus;
    }

    public Long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Long timestamp) {
        this.timestamp = timestamp;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof TideCompositeRoleDraftEntity)) return false;

        TideCompositeRoleDraftEntity key = (TideCompositeRoleDraftEntity) o;

        if (!composite.equals(key.composite)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = composite.hashCode();
        return result;
    }
}
