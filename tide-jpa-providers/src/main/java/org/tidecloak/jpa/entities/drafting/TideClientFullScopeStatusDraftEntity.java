package org.tidecloak.jpa.entities.drafting;

import jakarta.persistence.*;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.tidecloak.interfaces.ActionType;
import org.tidecloak.interfaces.DraftStatus;


@NamedQueries({
        @NamedQuery(name="getClientFullScopeStatusDraftByIdAndDraftStatus", query="SELECT t FROM TideClientFullScopeStatusDraftEntity t WHERE t.id = :changesetId AND t.draftStatus = :draftStatus"),
        @NamedQuery(name="getClientFullScopeStatus", query="SELECT t FROM TideClientFullScopeStatusDraftEntity t WHERE t.client = :client"),

})


@Entity
@Table(name="CLIENT_FULL_SCOPE_STATUS_DRAFT")
public class TideClientFullScopeStatusDraftEntity {

    @Id
    @Column(name="ID", length = 36)
    @Access(AccessType.PROPERTY) // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    private String id;

    @OneToOne(fetch = FetchType.LAZY)  // Defining the relationship
    @JoinColumn(name = "CLIENT", referencedColumnName = "ID")  // Ensure 'ID' is the correct primary key field name in ClientEntity
    private ClientEntity client;

    @Enumerated(EnumType.STRING)
    @Column(name = "DRAFT_STATUS")
    private DraftStatus draftStatus = DraftStatus.APPROVED;

    @Enumerated(EnumType.STRING)
    @Column(name = "ACTION_TYPE")
    private ActionType actionType;

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

    public ClientEntity getClient() {
        return client;
    }

    public void setClient(ClientEntity client) {
        this.client = client;
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
