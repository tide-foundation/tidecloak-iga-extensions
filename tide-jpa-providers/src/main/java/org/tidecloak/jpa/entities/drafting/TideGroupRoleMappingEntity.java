package org.tidecloak.jpa.entities.drafting;

import jakarta.persistence.*;
import org.keycloak.models.jpa.entities.GroupEntity;
import org.tidecloak.enums.ActionType;
import org.tidecloak.enums.DraftStatus;

@NamedQueries({
        @NamedQuery(name="groupRoleMappingDraftsByStatus", query="select m from TideGroupRoleMappingEntity m where m.group = :group and m.draftStatus = :draftStatus"),
        @NamedQuery(name="groupRoleMappingDraftsByStatusAndGroupAndRole", query="select m from TideGroupRoleMappingEntity m where m.group = :group and m.draftStatus = :draftStatus and m.roleId = :roleId"),
        @NamedQuery(name="groupRoleMappingDraftIdsByStatus", query="select m.roleId from TideGroupRoleMappingEntity m where m.group = :group and m.draftStatus = :draftStatus"),
        @NamedQuery(name="groupRoleMappingDraftIdsByStatusAndAction", query="select m.roleId from TideGroupRoleMappingEntity m where m.group = :group and m.draftStatus = :draftStatus and m.actionType = :actionType"),
        @NamedQuery(name="deleteGroupRoleMappingDraftsByRealm", query="delete from  TideGroupRoleMappingEntity mapping where mapping.group IN (select u from GroupEntity u where u.realm=:realm)"),
        @NamedQuery(name="deleteGroupRoleMappingDraftsByRole", query="delete from TideGroupRoleMappingEntity m where m.roleId = :roleId"),
        @NamedQuery(name="deleteGroupRoleMappingDraftsByGroup", query="delete from TideGroupRoleMappingEntity m where m.group = :group")

})

@Table(name="GROUP_ROLE_MAPPING_DRAFT")
@Entity
public class TideGroupRoleMappingEntity {

    @Id
    @Column(name="ID", length = 36)
    @Access(AccessType.PROPERTY) // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    protected String id;

    @ManyToOne(fetch= FetchType.LAZY)
    @JoinColumn(name="GROUP_ID")
    protected GroupEntity group;

    @Column(name = "ROLE_ID")
    protected String roleId;

    @Enumerated(EnumType.STRING)
    @Column(name = "DRAFT_STATUS")
    private DraftStatus draftStatus = DraftStatus.DRAFT; // Default to DRAFT

    @Enumerated(EnumType.STRING)
    @Column(name = "ACTION_TYPE")
    private ActionType actionType = ActionType.CREATE; // Default to NONE

    @Column(name = "CREATED_TIMESTAMP")
    protected Long createdTimestamp = System.currentTimeMillis();

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public GroupEntity getGroup() {
        return group;
    }

    public void setGroup(GroupEntity group) {
        this.group = group;
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
        if (!(o instanceof TideGroupRoleMappingEntity)) return false;

        TideGroupRoleMappingEntity key = (TideGroupRoleMappingEntity) o;

        if (!roleId.equals(key.roleId)) return false;
        if (!group.equals(key.group)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = group.hashCode();
        result = 31 * result + roleId.hashCode();
        return result;
    }
}
