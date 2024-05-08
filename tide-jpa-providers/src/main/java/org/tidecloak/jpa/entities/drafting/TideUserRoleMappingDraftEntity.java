package org.tidecloak.jpa.entities.drafting;

import jakarta.persistence.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.tidecloak.interfaces.ActionType;
import org.tidecloak.interfaces.DraftStatus;

import java.io.Serializable;

@NamedQueries({
        @NamedQuery(name="getUserRoleAssignmentDraftEntity", query="SELECT t FROM TideUserRoleMappingDraftEntity t WHERE t.user = :user and t.roleId = :roleId"),
        @NamedQuery(name="getUserRoleMappingDraftEntityByAction", query="SELECT m.roleId  FROM TideUserRoleMappingDraftEntity m WHERE m.user = :user and m.actionType = :actionType"),
        @NamedQuery(name="getUserRoleAssignmentDraftEntityByStatus", query="SELECT t FROM TideUserRoleMappingDraftEntity t WHERE t.user = :user and t.roleId = :roleId and draftStatus = :draftStatus"),
        @NamedQuery(name="getUserRoleAssignmentDraftEntityByStatusAndAction", query="SELECT t FROM TideUserRoleMappingDraftEntity t WHERE t.user = :user and t.roleId = :roleId and draftStatus = :draftStatus and actionType = :actionType"),
        @NamedQuery(name="getUserRoleMappingDraftEntityIdsByStatusAndAction", query="SELECT t.roleId FROM TideUserRoleMappingDraftEntity t WHERE t.user = :user and draftStatus = :draftStatus and actionType = :actionType"),
        @NamedQuery(name="filterUserRoleMappings", query="select m.roleId from TideUserRoleMappingDraftEntity m where m.user = :user and m.draftStatus = :draftStatus"),
        @NamedQuery(name="deleteUserRoleMappingDraftsByRealm", query="delete from TideUserRoleMappingDraftEntity mapping where mapping.user IN (select u from UserEntity u where u.realmId=:realmId)"),
        @NamedQuery(name="deleteUserRoleMappingDraftsByRealmAndLink", query="delete from TideUserRoleMappingDraftEntity mapping where mapping.user IN (select u from UserEntity u where u.realmId=:realmId and u.federationLink=:link)"),
        @NamedQuery(name="deleteUserRoleMappingDraftsByRole", query="delete from TideUserRoleMappingDraftEntity m where m.roleId = :roleId"),
        @NamedQuery(name="deleteUserRoleMappingDraftsByUser", query="delete from TideUserRoleMappingDraftEntity m where m.user = :user"),
})

@Entity
@Table(name = "USER_ROLE_MAPPING_DRAFT")
public class TideUserRoleMappingDraftEntity {

    @Id
    @Column(name="ID", length = 36)
    @Access(AccessType.PROPERTY) // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    protected String id;

    @ManyToOne(fetch= FetchType.LAZY)
    @JoinColumn(name="USER_ID")
    protected UserEntity user;

    @Column(name = "ROLE_ID")
    protected String roleId;

    @Enumerated(EnumType.STRING)
    @Column(name = "DRAFT_STATUS")
    private DraftStatus draftStatus = DraftStatus.DRAFT; // Default to DRAFT

    @Enumerated(EnumType.STRING)
    @Column(name = "ACTION_TYPE")
    private ActionType actionType = ActionType.CREATE; // Default to NONE

    @Column(name = "CHECKSUM")
    protected String checksum;

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

    public String getRoleId() {
        return roleId;
    }

    public void setRoleId(String roleId) {
        this.roleId = roleId;
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

    public String getChecksum() {
        return checksum;
    }

    public void setChecksum(String checksum) {
        this.checksum = checksum;
    }



    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof TideUserRoleMappingDraftEntity)) return false;

        TideUserRoleMappingDraftEntity key = (TideUserRoleMappingDraftEntity) o;

        if (!roleId.equals(key.roleId)) return false;
        if (!user.equals(key.user)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = user.hashCode();
        result = 31 * result + roleId.hashCode();
        return result;
    }

}

