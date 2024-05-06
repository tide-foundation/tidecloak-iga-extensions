package org.tidecloak.jpa.entities.drafting;

import jakarta.persistence.*;
import org.keycloak.models.jpa.entities.GroupEntity;
import org.keycloak.models.jpa.entities.GroupRoleMappingEntity;
import org.tidecloak.interfaces.ActionType;
import org.tidecloak.interfaces.DraftStatus;

import java.io.Serializable;

@NamedQueries({
        @NamedQuery(name="groupRoleMappingDraftsByStatus", query="select m from TideGroupRoleMappingEntity m where m.group = :group and m.draftStatus = :draftStatus"),
        @NamedQuery(name="groupRoleMappingDraftIdsByStatus", query="select m.roleId from TideGroupRoleMappingEntity m where m.group = :group and m.draftStatus = :draftStatus"),
        @NamedQuery(name="deleteGroupRoleMappingDraftsByRealm", query="delete from  TideGroupRoleMappingEntity mapping where mapping.group IN (select u from GroupEntity u where u.realm=:realm)"),
        @NamedQuery(name="deleteGroupRoleMappingDraftsByRole", query="delete from TideGroupRoleMappingEntity m where m.roleId = :roleId"),
        @NamedQuery(name="deleteGroupRoleMappingDraftsByGroup", query="delete from TideGroupRoleMappingEntity m where m.group = :group")

})

@Table(name="GROUP_ROLE_MAPPING_DRAFT")
@Entity
@IdClass(TideGroupRoleMappingEntity.Key.class)
public class TideGroupRoleMappingEntity {

    @Id
    @ManyToOne(fetch= FetchType.LAZY)
    @JoinColumn(name="GROUP_ID")
    protected GroupEntity group;

    @Id
    @Column(name = "ROLE_ID")
    protected String roleId;

    @Enumerated(EnumType.STRING)
    @Column(name = "DRAFT_STATUS")
    private DraftStatus draftStatus = DraftStatus.DRAFT; // Default to DRAFT

    @Enumerated(EnumType.STRING)
    @Column(name = "ACTION_TYPE")
    private ActionType actionType = ActionType.CREATE; // Default to NONE

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

    public static class Key implements Serializable {

        protected GroupEntity group;

        protected String roleId;

        public Key() {
        }

        public Key(GroupEntity group, String roleId) {
            this.group = group;
            this.roleId = roleId;
        }

        public GroupEntity getGroup() {
            return group;
        }

        public String getRoleId() {
            return roleId;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            TideGroupRoleMappingEntity.Key key = (TideGroupRoleMappingEntity.Key) o;

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
