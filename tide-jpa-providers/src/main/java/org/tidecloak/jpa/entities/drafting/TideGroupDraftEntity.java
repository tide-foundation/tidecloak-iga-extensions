package org.tidecloak.jpa.entities.drafting;


import jakarta.persistence.*;
import org.hibernate.annotations.Nationalized;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.DraftStatus;

@NamedQueries({
        @NamedQuery(name="getGroupByStatus", query="select m from TideGroupDraftEntity m where m.group = :group and m.draftStatus = :draftStatus"),
        @NamedQuery(name="deleteGroupDraftByRole", query="delete from TideGroupDraftEntity m where m.id = :roleId"),
        @NamedQuery(name="GetGroupDraftEntityByRequestId", query="SELECT m FROM TideGroupDraftEntity m where m.changeRequestId = :requestId")

})

@Entity
@Table(name="KEYCLOAK_GROUP_DRAFT",
        uniqueConstraints = { @UniqueConstraint(columnNames = {"REALM_ID", "PARENT_GROUP", "NAME"})}
)
public class TideGroupDraftEntity {

    @Id
    @Column(name="ID", length = 36)
    @Access(AccessType.PROPERTY) // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    protected String id;

    @Column(name="CHANGE_REQUEST_ID", length = 36)
    protected String changeRequestId;

    @Nationalized
    @Column(name = "NAME")
    protected String name;

    @Column(name = "PARENT_GROUP")
    private String parentId;

    @Column(name = "REALM_ID")
    private String realm;

    @Enumerated(EnumType.STRING)
    @Column(name = "DRAFT_STATUS")
    private DraftStatus draftStatus = DraftStatus.DRAFT; // Default to DRAFT

    @Enumerated(EnumType.STRING)
    @Column(name = "ACTION_TYPE")
    private ActionType actionType = ActionType.CREATE; // Default to NONE

    @Column(name = "CREATED_TIMESTAMP")
    protected Long createdTimestamp;

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

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public String getParentId() {
        return parentId;
    }

    public void setParentId(String parentId) {
        this.parentId = parentId;
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
        if (!(o instanceof TideGroupDraftEntity)) return false;

        TideGroupDraftEntity that = (TideGroupDraftEntity) o;

        if (!id.equals(that.id)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }

}
