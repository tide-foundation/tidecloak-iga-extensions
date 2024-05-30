package org.tidecloak.jpa.entities.drafting;

import jakarta.persistence.*;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.tidecloak.interfaces.ActionType;
import org.tidecloak.interfaces.DraftStatus;

@NamedQueries({
        @NamedQuery(name="getRoleDraftByRole", query="SELECT r FROM TideRoleDraftEntity r WHERE r.role = :role"),
        @NamedQuery(name="getRoleDraftByRoleEntityAndDeleteStatus", query="SELECT r FROM TideRoleDraftEntity r WHERE r.role = :role And r.deleteStatus = :deleteStatus"),
        @NamedQuery(name="getRoleDraftByRoleAndDeleteStatus", query="SELECT r FROM TideRoleDraftEntity r WHERE r.id = :changesetId AND r.deleteStatus = :deleteStatus"),
        @NamedQuery(name="DeleteRoleDraftByRole", query="DELETE from TideRoleDraftEntity r WHERE r.id = :id"),
        @NamedQuery(name="getAllRolesByStatusAndRealm", query="select r from TideRoleDraftEntity r where r.deleteStatus = :deleteStatus and r.role IN ( SELECT u from RoleEntity u where u.realmId =:realmId ) "),
        @NamedQuery(
                name = "getAllRolesByRealmAndStatusNotEqualTo",
                query = "SELECT r FROM TideRoleDraftEntity r WHERE (r.deleteStatus != :deleteStatus OR r.deleteStatus IS NULL) AND r.role IN (SELECT u FROM RoleEntity u WHERE u.realmId = :realmId)"
        )



})

@Entity
@Table(name = "ROLE_DRAFT")
public class TideRoleDraftEntity {

    @Id
    @Column(name="ID", length = 36)
    @Access(AccessType.PROPERTY) // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    protected String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "ROLE", referencedColumnName = "ID")  // Ensure 'ID' is the correct primary key field name in RoleEntity
    private RoleEntity role;

    @Enumerated(EnumType.STRING)
    @Column(name = "DRAFT_STATUS")
    private DraftStatus draftStatus = DraftStatus.APPROVED; // we don't need to sign creations of roles. Only when its being deleted or assigned to a user

    @Enumerated(EnumType.STRING)
    @Column(name = "ACTION_TYPE")
    private ActionType actionType = ActionType.DELETE; // This table is to keep track of role deletions only atm.

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

    public RoleEntity getRole() {
        return role;
    }

    public void setRole(RoleEntity role) {
        this.role = role;
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

}
