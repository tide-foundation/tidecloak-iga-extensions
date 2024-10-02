package org.tidecloak.jpa.entities.drafting;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.keycloak.models.jpa.entities.UserEntity;

import jakarta.persistence.*;
import org.tidecloak.interfaces.ActionType;
import org.tidecloak.interfaces.DraftStatus;


@NamedQueries({
        @NamedQuery(name="getTideUserDraftEntityByDraftStatusAndId", query="SELECT t FROM TideUserDraftEntity t WHERE t.id = :changesetId AND t.draftStatus = :draftStatus"),
        @NamedQuery(name="getTideUserDraftEntity", query="SELECT t FROM TideUserDraftEntity t WHERE t.user = :user"),
        @NamedQuery(name="deleteUserDrafts", query="delete from TideUserDraftEntity m where m.user = :user"),
        @NamedQuery(name="DeleteAllTideUserDraftEntityByRealm",
                query = "DELETE FROM TideUserDraftEntity r " +
                        "WHERE r.user IN (SELECT u FROM UserEntity u WHERE u.realmId = :realmId)"
        ),
})

@Entity
@Table(name = "USER_ENTITY_DRAFT")
public class TideUserDraftEntity {

    @Id
    @Column(name="ID", length = 36)
    @Access(AccessType.PROPERTY) // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    protected String id; // Primary key for TideUserDraftEntity

    @ManyToOne(fetch= FetchType.LAZY)
    @JoinColumn(name="USER_ID")
    @JsonIgnoreProperties({"credentials", "federatedIdentities"})
    protected UserEntity user;

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

    public UserEntity getUser() {
        return user;
    }

    public void setUser(UserEntity user) {
        this.user = user;
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

