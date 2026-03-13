package org.tidecloak.jpa.entities.drafting;

import jakarta.persistence.*;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.DraftStatus;

@NamedQueries({
        @NamedQuery(name="GetGroupMoveDraftEntityByRequestId", query="SELECT m FROM TideGroupMoveDraftEntity m where m.changeRequestId = :requestId"),
        @NamedQuery(name="getAllPendingGroupMoveDraftsByRealm", query="select m from TideGroupMoveDraftEntity m where m.draftStatus <> :draftStatus and m.groupId IN (select g.id from GroupEntity g where g.realm=:realmId)"),
        @NamedQuery(name="deleteGroupMoveDraftsByGroup", query="delete from TideGroupMoveDraftEntity m where m.groupId = :groupId"),
        @NamedQuery(name="deleteGroupMoveDraftsByRealm", query="delete from TideGroupMoveDraftEntity m where m.groupId IN (select g.id from GroupEntity g where g.realm=:realmId)")
})

@Table(name="GROUP_MOVE_DRAFT")
@Entity
public class TideGroupMoveDraftEntity {

    @Id
    @Column(name="ID", length = 36)
    @Access(AccessType.PROPERTY)
    protected String id;

    @Column(name="CHANGE_REQUEST_ID", length = 36)
    protected String changeRequestId;

    @Column(name = "GROUP_ID", length = 36)
    protected String groupId;

    @Column(name = "OLD_PARENT_ID", length = 36)
    protected String oldParentId;

    @Column(name = "NEW_PARENT_ID", length = 36)
    protected String newParentId;

    @Enumerated(EnumType.STRING)
    @Column(name = "DRAFT_STATUS")
    private DraftStatus draftStatus = DraftStatus.DRAFT;

    @Enumerated(EnumType.STRING)
    @Column(name = "ACTION_TYPE")
    private ActionType actionType = ActionType.CREATE;

    @Column(name = "CREATED_TIMESTAMP")
    protected Long createdTimestamp = System.currentTimeMillis();

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

    public String getGroupId() {
        return groupId;
    }

    public void setGroupId(String groupId) {
        this.groupId = groupId;
    }

    public String getOldParentId() {
        return oldParentId;
    }

    public void setOldParentId(String oldParentId) {
        this.oldParentId = oldParentId;
    }

    public String getNewParentId() {
        return newParentId;
    }

    public void setNewParentId(String newParentId) {
        this.newParentId = newParentId;
    }

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
        if (!(o instanceof TideGroupMoveDraftEntity)) return false;

        TideGroupMoveDraftEntity key = (TideGroupMoveDraftEntity) o;

        if (!groupId.equals(key.groupId)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        return groupId.hashCode();
    }
}
