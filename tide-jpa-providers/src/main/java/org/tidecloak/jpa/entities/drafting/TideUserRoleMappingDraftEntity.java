package org.tidecloak.jpa.entities.drafting;

import jakarta.persistence.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.tidecloak.interfaces.ActionType;
import org.tidecloak.interfaces.DraftStatus;

import java.io.Serializable;

@NamedQueries({
        @NamedQuery(name="getUserRoleAssignmentDraftEntity", query="SELECT t FROM TideUserRoleMappingDraftEntity t WHERE t.user = :user and t.roleId = :roleId"),
        @NamedQuery(name="filterUserRoleMappings", query="select m.roleId from TideUserRoleMappingDraftEntity m where m.user = :user and m.draftStatus = :draftStatus"),
        @NamedQuery(name="deleteUserRoleMappingDraftsByRealm", query="delete from TideUserRoleMappingDraftEntity mapping where mapping.user IN (select u from UserEntity u where u.realmId=:realmId)"),
        @NamedQuery(name="deleteUserRoleMappingDraftsByRealmAndLink", query="delete from TideUserRoleMappingDraftEntity mapping where mapping.user IN (select u from UserEntity u where u.realmId=:realmId and u.federationLink=:link)"),
        @NamedQuery(name="deleteUserRoleMappingDraftsByRole", query="delete from TideUserRoleMappingDraftEntity m where m.roleId = :roleId"),
        @NamedQuery(name="deleteUserRoleMappingDraftsByUser", query="delete from TideUserRoleMappingDraftEntity m where m.user = :user"),
})

@Entity
@Table(name = "USER_ROLE_MAPPING_DRAFT")
@IdClass(TideUserRoleMappingDraftEntity.Key.class)
public class TideUserRoleMappingDraftEntity {

    @Id
    @ManyToOne(fetch= FetchType.LAZY)
    @JoinColumn(name="USER_ID")
    protected UserEntity user;

    @Id
    @Column(name = "ROLE_ID")
    protected String roleId;

    @Enumerated(EnumType.STRING)
    @Column(name = "DRAFT_STATUS")
    private DraftStatus draftStatus = DraftStatus.DRAFT; // Default to DRAFT

    @Enumerated(EnumType.STRING)
    @Column(name = "ACTION_TYPE")
    private ActionType actionType = ActionType.CREATE; // Default to NONE

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

    public static class Key implements Serializable {

        protected UserEntity user;

        protected String roleId;

        public Key() {
        }

        public Key(UserEntity user, String roleId) {
            this.user = user;
            this.roleId = roleId;
        }

        public UserEntity getUser() {
            return user;
        }

        public String getRoleId() {
            return roleId;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            TideUserRoleMappingDraftEntity.Key key = (TideUserRoleMappingDraftEntity.Key) o;

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

