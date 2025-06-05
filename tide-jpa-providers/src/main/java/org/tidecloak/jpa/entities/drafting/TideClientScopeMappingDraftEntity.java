package org.tidecloak.jpa.entities.drafting;


import jakarta.persistence.*;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.DraftStatus;

@NamedQueries({
        @NamedQuery(name="tideClientScopeClientMappingIdsByClient", query="select m.clientScopeId from TideClientScopeMappingDraftEntity m where m.clientId = :clientId AND m.clientScopeId = :clientScopeId AND draftStatus = :draftStatus"),
        @NamedQuery(name="deleteTideClientScopeClientMapping", query="delete from TideClientScopeMappingDraftEntity where clientId = :clientId and clientScopeId = :clientScopeId"),
        @NamedQuery(name="deleteTideClientScopeClientMappingByClient", query="delete from TideClientScopeMappingDraftEntity where clientId = :clientId"),
        @NamedQuery(name="deleteTideClientScopeClientMappingByRealm",
                query = "DELETE FROM TideClientScopeMappingDraftEntity r " +
                        "WHERE r.clientId IN (SELECT c.id FROM ClientEntity c WHERE c.realmId = :realmId)"
        ),
        @NamedQuery(name="GetClientScopeMappingDraftEntityByRequestId", query="SELECT m FROM TideClientScopeMappingDraftEntity m where m.changeRequestId = :requestId")

})

@Entity
@Table(name="CLIENT_SCOPE_CLIENT_DRAFT")
public class TideClientScopeMappingDraftEntity {

    @Id
    @Column(name="ID", length = 36)
    @Access(AccessType.PROPERTY) // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    protected String id;

    @Column(name="CHANGE_REQUEST_ID", length = 36)
    protected String changeRequestId;

    @Column(name = "SCOPE_ID")
    protected String clientScopeId;

    @Column(name="CLIENT_ID")
    protected String clientId;

    @Column(name="DEFAULT_SCOPE")
    protected boolean defaultScope;

    @Enumerated(EnumType.STRING)
    @Column(name = "DRAFT_STATUS")
    private DraftStatus draftStatus;

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

    public String getChangeRequestId() {
        return changeRequestId;
    }

    public void setChangeRequestId(String changeRequestId) {
        this.changeRequestId = changeRequestId;
    }

    public String getClientScopeId() {
        return clientScopeId;
    }

    public void setClientScopeId(String clientScopeId) {
        this.clientScopeId = clientScopeId;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public boolean isDefaultScope() {
        return defaultScope;
    }

    public void setDefaultScope(boolean defaultScope) {
        this.defaultScope = defaultScope;
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
