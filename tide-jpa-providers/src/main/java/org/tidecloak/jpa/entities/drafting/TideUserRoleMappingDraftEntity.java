package org.tidecloak.jpa.entities.drafting;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.DraftStatus;

@NamedQueries({
        @NamedQuery(
                name = "getUserRoleAssignmentDraftEntityByStatuses",
                query = "SELECT t FROM TideUserRoleMappingDraftEntity t WHERE t.user = :user AND t.roleId = :roleId AND t.draftStatus IN :draftStatuses"
        ),
        @NamedQuery(
                name = "getUserRoleAssignmentDraftEntityByDeleteStatuses",
                query = "SELECT t FROM TideUserRoleMappingDraftEntity t WHERE t.user = :user AND t.roleId = :roleId AND t.deleteStatus IN :draftStatuses"
        ),
        @NamedQuery(name="getUserRoleAssignmentDraftEntityByStatusAndUserId", query="SELECT t FROM TideUserRoleMappingDraftEntity t WHERE t.user.id = :userId and t.roleId = :roleId and draftStatus = :draftStatus"),
        @NamedQuery(name="getUserRoleMappingsByStatusAndRole", query="select m from TideUserRoleMappingDraftEntity m where m.draftStatus = :draftStatus AND m.roleId = : roleId"),
        @NamedQuery(name="getUserRoleMappingsByStatusAndRealmAndRecordId", query="select m from TideUserRoleMappingDraftEntity m where m.draftStatus = :draftStatus AND m.id = :changesetId AND m.user IN (select u from UserEntity u where u.realmId= :realmId)"),
        @NamedQuery(name="getUserRoleMappingsByDeleteStatusAndRealmAndRecordId", query="select m from TideUserRoleMappingDraftEntity m where m.deleteStatus = :deleteStatus AND m.id = :changesetId AND m.user IN (select u from UserEntity u where u.realmId= :realmId)"),
        @NamedQuery(name="getAllUserRoleMappingsByStatusAndRealm", query="select m from TideUserRoleMappingDraftEntity m where m.draftStatus = :draftStatus AND m.user IN (select u from UserEntity u where u.realmId= :realmId)"),
        @NamedQuery(name="getAllUserRoleMappingsByRealmAndStatusNotEqualTo", query="select m from TideUserRoleMappingDraftEntity m where m.draftStatus != :draftStatus AND m.user IN (select u from UserEntity u where u.realmId= :realmId)"),
        @NamedQuery(name="getAllUserRoleMappingsByStatus", query="select m from TideUserRoleMappingDraftEntity m where m.draftStatus = :draftStatus"),
        @NamedQuery(name="getAllUserRoleMappingsByStatusNotEqualTo", query="select m from TideUserRoleMappingDraftEntity m where m.draftStatus != :draftStatus"),
        @NamedQuery(name="getUserRoleMappingStatus", query="select m from TideUserRoleMappingDraftEntity m where m.user = :user"),
        @NamedQuery(name="getUserRoleAssignmentDraftEntity", query="SELECT t FROM TideUserRoleMappingDraftEntity t WHERE t.user = :user and t.roleId = :roleId"),
        @NamedQuery(name="getUserRoleMappingDraftEntityByAction", query="SELECT m.roleId  FROM TideUserRoleMappingDraftEntity m WHERE m.user = :user and m.actionType = :actionType"),
        @NamedQuery(name="getUserRoleAssignmentDraftEntityByStatusNotEqualTo", query="SELECT t FROM TideUserRoleMappingDraftEntity t WHERE t.user = :user and t.roleId = :roleId and draftStatus != :draftStatus"),
        @NamedQuery(name="getUserRoleAssignmentDraftEntityByStatus", query="SELECT t FROM TideUserRoleMappingDraftEntity t WHERE t.user = :user and t.roleId = :roleId and draftStatus = :draftStatus"),
        @NamedQuery(name="getUserRoleAssignmentDraftEntityByStatusAndAction", query="SELECT t FROM TideUserRoleMappingDraftEntity t WHERE t.user = :user and t.roleId = :roleId and draftStatus = :draftStatus and actionType = :actionType"),
        @NamedQuery(name="getUserRoleMappingDraftEntityIdsByStatusAndAction", query="SELECT t.roleId FROM TideUserRoleMappingDraftEntity t WHERE t.user = :user and draftStatus = :draftStatus and actionType = :actionType"),
        @NamedQuery(name="getUserRoleMappingDraftEntityIdsByStatus", query="SELECT t.roleId FROM TideUserRoleMappingDraftEntity t WHERE t.user = :user and draftStatus = :draftStatus"),
        @NamedQuery(name="filterUserRoleMappings", query="select m.roleId from TideUserRoleMappingDraftEntity m where m.user = :user and m.draftStatus = :draftStatus"),
        @NamedQuery(name="deleteUserRoleMappingDraftsByRealm", query="delete from TideUserRoleMappingDraftEntity mapping where mapping.user IN (select u from UserEntity u where u.realmId=:realmId)"),
        @NamedQuery(name="deleteUserRoleMappingDraftsByRealmAndLink", query="delete from TideUserRoleMappingDraftEntity mapping where mapping.user IN (select u from UserEntity u where u.realmId=:realmId and u.federationLink=:link)"),
        @NamedQuery(name="deleteUserRoleMappingDraftsByRole", query="delete from TideUserRoleMappingDraftEntity m where m.roleId = :roleId"),
        @NamedQuery(name="deleteUserRoleMappingDraftsByRoleAndUser", query="delete from TideUserRoleMappingDraftEntity m where m.roleId = :roleId and m.user = :user"),
        @NamedQuery(name="deleteUserRoleMappingDraftsByUser", query="delete from TideUserRoleMappingDraftEntity m where m.user = :user"),
        @NamedQuery(name="getUserRoleMappingDraftsByRole", query="SELECT t.id FROM TideUserRoleMappingDraftEntity t WHERE t.roleId = :roleId"),
        @NamedQuery(
                name = "getUserRoleMappingDraftsByRoleAndStatusNotEqualTo",
                query = "SELECT t FROM TideUserRoleMappingDraftEntity t WHERE t.roleId = :roleId AND t.draftStatus != :draftStatus"
        ),
        @NamedQuery(
                name = "getUserRoleMappingsByUserAndClientId",
                query = "SELECT m FROM TideUserRoleMappingDraftEntity m " +
                        "WHERE m.user =:user AND m.roleId IN (" +
                        "   SELECT r.id FROM RoleEntity r " +
                        "   WHERE r.clientRole = true AND r.clientId = :clientId" +
                        ")"
        ),
        @NamedQuery(name="getAllPendingUserRoleMappingsByRealm",
                query = "SELECT m FROM TideUserRoleMappingDraftEntity m " +
                        "WHERE (m.draftStatus != :draftStatus OR " +
                        "(m.draftStatus = :draftStatus AND m.deleteStatus != :deleteStatus)) " +
                        "AND m.user IN (SELECT u FROM UserEntity u WHERE u.realmId = :realmId)"
        ),

        @NamedQuery(name="DeleteAllUserRoleMappingDraftsByRealm",
                query = "DELETE FROM TideUserRoleMappingDraftEntity r " +
                        "WHERE r.user IN (SELECT u FROM UserEntity u WHERE u.realmId = :realmId)"
        ),

        @NamedQuery(name="DeleteAllUserRoleMappingDraftsByRole",
                query = "DELETE FROM TideUserRoleMappingDraftEntity r " +
                        "WHERE r.roleId = :roleId"
        ),
        @NamedQuery(name="GetUserRoleMappingDraftEntityByRequestId", query="SELECT m FROM TideUserRoleMappingDraftEntity m where m.changeRequestId = :requestId"),
        @NamedQuery(name="getAllPreApprovedUserRoleMappingsByRealm",
                query = "SELECT m FROM TideUserRoleMappingDraftEntity m " +
                        "WHERE (m.draftStatus NOT IN :draftStatus OR " +
                        "(m.draftStatus = :activeStatus AND m.deleteStatus NOT IN :draftStatus)) " +
                        "AND m.user IN (SELECT u FROM UserEntity u WHERE u.realmId = :realmId)"
        ),


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
