package org.tidecloak.jpa.entities.drafting;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.DraftStatus;

@NamedQueries({

        @NamedQuery(
                name = "getUserRoleAssignmentDraftEntityByStatuses",
                query = "SELECT t FROM TideUserRoleMappingDraftEntity t " +
                        "WHERE t.user = :user " +
                        "AND t.roleId = :roleId " +
                        "AND t.draftStatus IN :draftStatuses"
        ),

        @NamedQuery(
                name = "getUserRoleAssignmentDraftEntityByDeleteStatuses",
                query = "SELECT t FROM TideUserRoleMappingDraftEntity t " +
                        "WHERE t.user = :user " +
                        "AND t.roleId = :roleId " +
                        "AND t.deleteStatus IN :deleteStatuses"
        ),

        @NamedQuery(
                name = "getUserRoleAssignmentDraftEntityByStatusAndUserId",
                query = "SELECT t FROM TideUserRoleMappingDraftEntity t " +
                        "WHERE t.user.id = :userId " +
                        "AND t.roleId = :roleId " +
                        "AND t.draftStatus = :draftStatus"
        ),

        @NamedQuery(
                name = "getUserRoleMappingsByStatusAndRole",
                query = "SELECT m FROM TideUserRoleMappingDraftEntity m " +
                        "WHERE m.draftStatus = :draftStatus " +
                        "AND m.roleId = :roleId"
        ),

        @NamedQuery(
                name = "getUserRoleMappingsByStatusAndRealmAndRequestId",
                query = "SELECT m FROM TideUserRoleMappingDraftEntity m " +
                        "WHERE m.draftStatus = :draftStatus " +
                        "AND m.changeRequestId = :changeRequestId " +
                        "AND m.user IN (SELECT u FROM UserEntity u WHERE u.realmId = :realmId)"
        ),

        @NamedQuery(
                name = "getUserRoleMappingsByDeleteStatusAndRealmAndRequestId",
                query = "SELECT m FROM TideUserRoleMappingDraftEntity m " +
                        "WHERE m.deleteStatus = :deleteStatus " +
                        "AND m.changeRequestId = :changeRequestId " +
                        "AND m.user IN (SELECT u FROM UserEntity u WHERE u.realmId = :realmId)"
        ),

        @NamedQuery(
                name = "getAllUserRoleMappingsByStatusAndRealm",
                query = "SELECT m FROM TideUserRoleMappingDraftEntity m " +
                        "WHERE m.draftStatus = :draftStatus " +
                        "AND m.user IN (SELECT u FROM UserEntity u WHERE u.realmId = :realmId)"
        ),

        @NamedQuery(
                name = "getAllUserRoleMappingsByRealmAndStatusNotEqualTo",
                query = "SELECT m FROM TideUserRoleMappingDraftEntity m " +
                        "WHERE m.draftStatus <> :draftStatus " +
                        "AND m.user IN (SELECT u FROM UserEntity u WHERE u.realmId = :realmId)"
        ),

        @NamedQuery(
                name = "getAllUserRoleMappingsByStatus",
                query = "SELECT m FROM TideUserRoleMappingDraftEntity m " +
                        "WHERE m.draftStatus = :draftStatus"
        ),

        @NamedQuery(
                name = "getAllUserRoleMappingsByStatusNotEqualTo",
                query = "SELECT m FROM TideUserRoleMappingDraftEntity m " +
                        "WHERE m.draftStatus <> :draftStatus"
        ),

        @NamedQuery(
                name = "getUserRoleMappingStatus",
                query = "SELECT m FROM TideUserRoleMappingDraftEntity m " +
                        "WHERE m.user = :user"
        ),

        @NamedQuery(
                name = "getUserRoleAssignmentDraftEntity",
                query = "SELECT t FROM TideUserRoleMappingDraftEntity t " +
                        "WHERE t.user = :user " +
                        "AND t.roleId = :roleId"
        ),

        @NamedQuery(
                name = "getUserRoleMappingDraftEntityByAction",
                query = "SELECT m.roleId FROM TideUserRoleMappingDraftEntity m " +
                        "WHERE m.user = :user " +
                        "AND m.actionType = :actionType"
        ),

        @NamedQuery(
                name = "getUserRoleAssignmentDraftEntityByStatusNotEqualTo",
                query = "SELECT t FROM TideUserRoleMappingDraftEntity t " +
                        "WHERE t.user = :user " +
                        "AND t.roleId = :roleId " +
                        "AND t.draftStatus <> :draftStatus"
        ),

        @NamedQuery(
                name = "getUserRoleAssignmentDraftEntityByStatus",
                query = "SELECT t FROM TideUserRoleMappingDraftEntity t " +
                        "WHERE t.user = :user " +
                        "AND t.roleId = :roleId " +
                        "AND t.draftStatus = :draftStatus"
        ),

        @NamedQuery(
                name = "getUserRoleAssignmentDraftEntityByStatusAndAction",
                query = "SELECT t FROM TideUserRoleMappingDraftEntity t " +
                        "WHERE t.user = :user " +
                        "AND t.roleId = :roleId " +
                        "AND t.draftStatus = :draftStatus " +
                        "AND t.actionType = :actionType"
        ),

        @NamedQuery(
                name = "getUserRoleMappingDraftEntityIdsByStatusAndAction",
                query = "SELECT t.roleId FROM TideUserRoleMappingDraftEntity t " +
                        "WHERE t.user = :user " +
                        "AND t.draftStatus = :draftStatus " +
                        "AND t.actionType = :actionType"
        ),

        @NamedQuery(
                name = "getUserRoleMappingDraftEntityIdsByStatus",
                query = "SELECT t.roleId FROM TideUserRoleMappingDraftEntity t " +
                        "WHERE t.user = :user " +
                        "AND t.draftStatus = :draftStatus"
        ),

        @NamedQuery(
                name = "filterUserRoleMappings",
                query = "SELECT m.roleId FROM TideUserRoleMappingDraftEntity m " +
                        "WHERE m.user = :user " +
                        "AND m.draftStatus = :draftStatus"
        ),

        @NamedQuery(
                name = "deleteUserRoleMappingDraftsByRealm",
                query = "DELETE FROM TideUserRoleMappingDraftEntity m " +
                        "WHERE m.user IN (SELECT u FROM UserEntity u WHERE u.realmId = :realmId)"
        ),

        @NamedQuery(
                name = "deleteUserRoleMappingDraftsByRealmAndLink",
                query = "DELETE FROM TideUserRoleMappingDraftEntity m " +
                        "WHERE m.user IN (SELECT u FROM UserEntity u WHERE u.realmId = :realmId AND u.federationLink = :link)"
        ),

        @NamedQuery(
                name = "deleteUserRoleMappingDraftsByRole",
                query = "DELETE FROM TideUserRoleMappingDraftEntity m " +
                        "WHERE m.roleId = :roleId"
        ),

        @NamedQuery(
                name = "deleteUserRoleMappingDraftsByRoleAndUser",
                query = "DELETE FROM TideUserRoleMappingDraftEntity m " +
                        "WHERE m.roleId = :roleId " +
                        "AND m.user = :user"
        ),

        @NamedQuery(
                name = "deleteUserRoleMappingDraftsByUser",
                query = "DELETE FROM TideUserRoleMappingDraftEntity m " +
                        "WHERE m.user = :user"
        ),

        @NamedQuery(
                name = "getUserRoleMappingDraftsByRole",
                query = "SELECT t.id FROM TideUserRoleMappingDraftEntity t " +
                        "WHERE t.roleId = :roleId"
        ),

        @NamedQuery(
                name = "getUserRoleMappingDraftsByRoleAndStatusNotEqualTo",
                query = "SELECT t FROM TideUserRoleMappingDraftEntity t " +
                        "WHERE t.roleId = :roleId " +
                        "AND t.draftStatus <> :draftStatus"
        ),

        @NamedQuery(
                name = "getUserRoleMappingsByUserAndClientId",
                query = "SELECT m FROM TideUserRoleMappingDraftEntity m " +
                        "WHERE m.user = :user " +
                        "AND m.roleId IN (" +
                        "SELECT r.id FROM RoleEntity r " +
                        "WHERE r.clientRole = true AND r.clientId = :clientId" +
                        ")"
        ),

        @NamedQuery(
                name = "getAllPendingUserRoleMappingsByRealm",
                query = "SELECT m FROM TideUserRoleMappingDraftEntity m " +
                        "WHERE (m.draftStatus <> :draftStatus OR " +
                        "(m.draftStatus = :draftStatus AND m.deleteStatus <> :deleteStatus)) " +
                        "AND m.user IN (SELECT u FROM UserEntity u WHERE u.realmId = :realmId)"
        ),

        @NamedQuery(
                name = "DeleteAllUserRoleMappingDraftsByRealm",
                query = "DELETE FROM TideUserRoleMappingDraftEntity m " +
                        "WHERE m.user IN (SELECT u FROM UserEntity u WHERE u.realmId = :realmId)"
        ),

        @NamedQuery(
                name = "DeleteAllUserRoleMappingDraftsByRole",
                query = "DELETE FROM TideUserRoleMappingDraftEntity m " +
                        "WHERE m.roleId = :roleId"
        ),

        @NamedQuery(
                name = "GetUserRoleMappingDraftEntityByRequestId",
                query = "SELECT m FROM TideUserRoleMappingDraftEntity m " +
                        "WHERE m.changeRequestId = :requestId"
        ),

        @NamedQuery(
                name = "getUserRoleMappingsByUserAndClientIdAndRequestId",
                query = "SELECT m FROM TideUserRoleMappingDraftEntity m " +
                        "WHERE m.changeRequestId = :requestId " +
                        "AND m.user = :user " +
                        "AND m.roleId IN (" +
                        "SELECT r.id FROM RoleEntity r " +
                        "WHERE r.clientRole = true AND r.clientId = :clientId" +
                        ")"
        )

})
//where mapping.user IN (select u from UserEntity u where u.realmId=:realmId)")
@Entity
@Table(name = "USER_ROLE_MAPPING_DRAFT")
public class TideUserRoleMappingDraftEntity {

    @Id
    @Column(name="ID", length = 36)
    @Access(AccessType.PROPERTY) // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    protected String id;

    @Column(name="CHANGE_REQUEST_ID", length = 36)
    protected String changeRequestId;

    @ManyToOne(fetch= FetchType.LAZY)
    @JoinColumn(name="USER_ID")
    @JsonIgnoreProperties({"credentials", "federatedIdentities", "attributes"})
    protected UserEntity user;

    @Column(name = "ROLE_ID")
    protected String roleId;

    @Enumerated(EnumType.STRING)
    @Column(name = "DRAFT_STATUS")
    private DraftStatus draftStatus = DraftStatus.DRAFT; // Default to DRAFT

    @Enumerated(EnumType.STRING)
    @Column(name = "ACTION_TYPE")
    private ActionType actionType = ActionType.CREATE; // Default to NONE

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

