package org.tidecloak.jpa.entities.drafting;

import jakarta.persistence.*;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.tidecloak.interfaces.ActionType;
import org.tidecloak.interfaces.DraftStatus;

@NamedQueries({
        @NamedQuery(name="getAllCompositeRoleMappingsByStatusAndRealmAndRecordId", query="select r from TideCompositeRoleMappingDraftEntity r where r.draftStatus = :draftStatus AND r.id = :changesetId AND r.composite IN ( SELECT u from RoleEntity u where u.realmId =:realmId ) "),
        @NamedQuery(name="getAllCompositeRoleMappingsByStatusAndRealm", query="select r from TideCompositeRoleMappingDraftEntity r where r.draftStatus = :draftStatus and r.composite IN ( SELECT u from RoleEntity u where u.realmId =:realmId ) "),
        @NamedQuery(name="getAllCompositeRoleMappingsByStatus", query="select r from TideCompositeRoleMappingDraftEntity r where r.draftStatus = :draftStatus"),
        @NamedQuery(name="getCompositeEntityByParent", query="select r from TideCompositeRoleMappingDraftEntity r where r.composite = :composite ORDER BY r.createdTimestamp DESC"),
        @NamedQuery(name="filterChildRoleByStatusAndParentAndAction", query="select r.childRole from TideCompositeRoleMappingDraftEntity r where r.composite = :composite and r.draftStatus = :draftStatus and r.actionType = :actionType"),
        @NamedQuery(name="filterChildRoleByStatusAndParent", query="select r.childRole from TideCompositeRoleMappingDraftEntity r where r.composite = :composite and r.draftStatus = :draftStatus"),
        @NamedQuery(name="getCompositeRoleMappingDraft", query="select r from TideCompositeRoleMappingDraftEntity r where r.composite = :composite and r.childRole = :childRole"),
        @NamedQuery(name="getCompositeRoleMappingDraftByStatus", query="select r from TideCompositeRoleMappingDraftEntity r where r.composite = :composite and r.childRole = :childRole and r.draftStatus = :draftStatus"),
        @NamedQuery(name="deleteCompositeRoleMapping", query="delete from TideCompositeRoleMappingDraftEntity r where r.composite = :composite"),
        @NamedQuery(
                name = "getRecordIdByChildAndComposite",
                query = "SELECT t FROM TideCompositeRoleMappingDraftEntity t WHERE t.composite = :composite and t.childRole = :childRole "
        )


})

@Entity
@Table(name="COMPOSITE_ROLE_MAPPING_DRAFT")
public class TideCompositeRoleMappingDraftEntity {


    @Id
    @Column(name="ID", length = 36)
    @Access(AccessType.PROPERTY) // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    protected String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "COMPOSITE", referencedColumnName = "ID")  // Ensure 'ID' is the correct primary key field name in RoleEntity
    private RoleEntity composite;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "CHILD_ROLE", referencedColumnName = "ID")
    private RoleEntity childRole;


    @Enumerated(EnumType.STRING)
    @Column(name = "DRAFT_STATUS")
    private DraftStatus draftStatus;

    @Enumerated(EnumType.STRING)
    @Column(name = "ACTION_TYPE")
    private ActionType actionType;

    @Column(name = "CREATED_TIMESTAMP")
    protected Long createdTimestamp;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public RoleEntity getComposite() {
        return composite;
    }

    public void setComposite(RoleEntity composite) {
        this.composite = composite;
    }

    public RoleEntity getChildRole() {
        return childRole;
    }

    public void setChildRole(RoleEntity childRole) {
        this.childRole = childRole;
    }

    // Getters and setters for new fields
    public DraftStatus getDraftStatus() {
        return draftStatus;
    }

    public void setDraftStatus(DraftStatus draftStatus) {
        this.draftStatus = draftStatus;
    }

    public ActionType getAction() {
        return actionType;
    }

    public void setAction(ActionType actionType) {
        this.actionType = actionType;
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
        if (!(o instanceof TideCompositeRoleMappingDraftEntity)) return false;

        TideCompositeRoleMappingDraftEntity key = (TideCompositeRoleMappingDraftEntity) o;

        if (!childRole.equals(key.childRole)) return false;
        if (!composite.equals(key.composite)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = composite.hashCode();
        result = 31 * result + childRole.hashCode();
        return result;
    }
}
