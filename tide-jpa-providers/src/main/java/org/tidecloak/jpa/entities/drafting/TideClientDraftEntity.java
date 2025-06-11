package org.tidecloak.jpa.entities.drafting;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.shared.enums.ActionType;


@NamedQueries({
        @NamedQuery(
                name = "getClientFullScopeStatusDraftThatDoesNotHaveStatus",
                query = "SELECT t FROM TideClientDraftEntity t " +
                        "WHERE ((t.fullScopeEnabled = :status) " +
                        "AND (t.fullScopeDisabled != : status2 AND t.fullScopeDisabled != :status)) " +
                        "OR ((t.fullScopeDisabled = :status) " +
                        "AND (t.fullScopeEnabled != : status2 AND t.fullScopeEnabled != :status))"
        ),
        @NamedQuery(name="getClientFullScopeStatusDraftByIdAndFullScopeEnabled", query="SELECT t FROM TideClientDraftEntity t WHERE t.id = :changesetId AND t.fullScopeEnabled = :fullScopeEnabled"),
        @NamedQuery(name="getClientFullScopeStatusDraftByIdAndFullScopeDisabled", query="SELECT t FROM TideClientDraftEntity t WHERE t.id = :changesetId AND t.fullScopeDisabled = :fullScopeDisabled"),
        @NamedQuery(name="getClientFullScopeStatus", query="SELECT t FROM TideClientDraftEntity t WHERE t.client = :client"),
        @NamedQuery(name="getClientDraftById", query="SELECT t FROM TideClientDraftEntity t WHERE t.id = :changesetId"),
        @NamedQuery(name="getClientFullScopeStatusByFullScopeEnabledStatus", query="SELECT t FROM TideClientDraftEntity t WHERE t.client = :client AND t.fullScopeEnabled = :fullScopeEnabled"),
        @NamedQuery(name="getClientFullScopeStatusByFullScopeDisabledStatus", query="SELECT t FROM TideClientDraftEntity t WHERE t.client = :client AND t.fullScopeDisabled = :fullScopeDisabled"),
        @NamedQuery(name="deleteClientFullScopeStatusByRealm",
                query = "DELETE FROM TideClientDraftEntity r " +
                        "WHERE r.client.id IN (SELECT c.id FROM ClientEntity c WHERE c.realmId = :realmId)"
        ),
        @NamedQuery(name="deleteClient",
                query = "DELETE FROM TideClientDraftEntity r " +
                        "WHERE r.client =: client"
        ),
        @NamedQuery(name="getClientDraftDetails", query="SELECT t FROM TideClientDraftEntity t WHERE t.client = :client"),
        @NamedQuery(
                name = "TideClientDraftEntity.findDraftsNotInAccessProof",
                query = "SELECT t FROM TideClientDraftEntity t " +
                        "WHERE (t.draftStatus = :draftStatus) " +
                        "AND (t.client.id IN (SELECT c.id FROM ClientEntity c WHERE c.realmId = :realmId)) " +
                        "AND NOT EXISTS ( " +
                        "   SELECT a FROM AccessProofDetailEntity a " +
                        "   WHERE a.changeRequestKey.mappingId = t.id" +
                        ")"
        ),
        @NamedQuery(
                name = "getClientDraftsWithNullScopes",
                query = "SELECT t FROM TideClientDraftEntity t WHERE t.fullScopeEnabled IS NULL OR t.fullScopeDisabled IS NULL"
        ),
        @NamedQuery(name="GetClientDraftEntityByRequestId", query="SELECT m FROM TideClientDraftEntity m where m.changeRequestId = :requestId")
})


@Entity
@Table(name="CLIENT_DRAFT")
public class TideClientDraftEntity {

    @Id
    @Column(name="ID", length = 36)
    @Access(AccessType.PROPERTY) // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    private String id;

    @Column(name="CHANGE_REQUEST_ID", length = 36)
    protected String changeRequestId;

    @OneToOne(fetch = FetchType.LAZY)  // Defining the relationship
    @JoinColumn(name = "CLIENT", referencedColumnName = "ID")  // Ensure 'ID' is the correct primary key field name in ClientEntity
    @JsonIgnore
    private ClientEntity client;

    @Column(name="DEFAULT_USER_CONTEXT")
    protected String defaultUserContext;
    @Column(name="DEFAULT_USER_CONTEXT_SIG")
    protected String defaultUserContextSig;

    @Enumerated(EnumType.STRING)
    @Column(name = "FULL_SCOPE_ENABLED")
    private DraftStatus fullScopeEnabled; // by default, clients are full-scoped

    @Enumerated(EnumType.STRING)
    @Column(name = "FULL_SCOPE_DISABLED")
    private DraftStatus fullScopeDisabled;

    @Enumerated(EnumType.STRING)
    @Column(name = "ACTION_TYPE")
    private ActionType actionType;

    @Enumerated(EnumType.STRING)
    @Column(name = "DRAFT_STATUS")
    private DraftStatus draftStatus = DraftStatus.DRAFT; // Default to DRAFT

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

    public ClientEntity getClient() {
        return client;
    }

    public void setClient(ClientEntity client) {
        this.client = client;
    }

    // Getters and setters for new fields

    public DraftStatus getFullScopeEnabled() {
        return fullScopeEnabled;
    }

    public void setFullScopeEnabled(DraftStatus fullScopeEnabled) {
        this.fullScopeEnabled = fullScopeEnabled;
    }

    public DraftStatus getFullScopeDisabled() {
        return fullScopeDisabled;
    }

    public void setFullScopeDisabled(DraftStatus fullScopeDisabled) {
        this.fullScopeDisabled = fullScopeDisabled;
    }

    public ActionType getAction() {
        return actionType;
    }

    public void setAction(ActionType actionType) {
        this.actionType = actionType;
    }

    public Long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Long timestamp) {
        this.timestamp = timestamp;
    }

    public String getDefaultUserContext() {
        return defaultUserContext;
    }

    public void setDefaultUserContext(String defaultUserContext) {
        this.defaultUserContext = defaultUserContext;
    }

    public String getDefaultUserContextSig() {
        return defaultUserContextSig;
    }

    public void setDefaultUserContextSig(String defaultUserContextSig) {
        this.defaultUserContextSig = defaultUserContextSig;
    }

    public DraftStatus getDraftStatus() {
        return draftStatus;
    }

    public void setDraftStatus(DraftStatus draftStatus) {
        this.draftStatus = draftStatus;
    }

}
