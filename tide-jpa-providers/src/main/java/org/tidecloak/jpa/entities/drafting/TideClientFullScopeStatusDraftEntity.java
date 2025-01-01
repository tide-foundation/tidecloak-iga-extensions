package org.tidecloak.jpa.entities.drafting;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.tidecloak.enums.DraftStatus;
import org.tidecloak.enums.ActionType;


@NamedQueries({
        @NamedQuery(
                name = "getClientFullScopeStatusDraftThatDoesNotHaveStatus",
                query = "SELECT t FROM TideClientFullScopeStatusDraftEntity t " +
                        "WHERE ((t.fullScopeEnabled = :status) " +
                        "AND (t.fullScopeDisabled != : status2 AND t.fullScopeDisabled != :status)) " +
                        "OR ((t.fullScopeDisabled = :status) " +
                        "AND (t.fullScopeEnabled != : status2 AND t.fullScopeEnabled != :status))"
        ),
        @NamedQuery(name="getClientFullScopeStatusDraftByIdAndFullScopeEnabled", query="SELECT t FROM TideClientFullScopeStatusDraftEntity t WHERE t.id = :changesetId AND t.fullScopeEnabled = :fullScopeEnabled"),
        @NamedQuery(name="getClientFullScopeStatusDraftByIdAndFullScopeDisabled", query="SELECT t FROM TideClientFullScopeStatusDraftEntity t WHERE t.id = :changesetId AND t.fullScopeDisabled = :fullScopeDisabled"),
        @NamedQuery(name="getClientFullScopeStatus", query="SELECT t FROM TideClientFullScopeStatusDraftEntity t WHERE t.client = :client"),
        @NamedQuery(name="getClientFullScopeStatusByFullScopeEnabledStatus", query="SELECT t FROM TideClientFullScopeStatusDraftEntity t WHERE t.client = :client AND t.fullScopeEnabled = :fullScopeEnabled"),
        @NamedQuery(name="getClientFullScopeStatusByFullScopeDisabledStatus", query="SELECT t FROM TideClientFullScopeStatusDraftEntity t WHERE t.client = :client AND t.fullScopeDisabled = :fullScopeDisabled"),
        @NamedQuery(name="deleteClientFullScopeStatusByRealm",
                query = "DELETE FROM TideClientFullScopeStatusDraftEntity r " +
                        "WHERE r.client.id IN (SELECT c.id FROM ClientEntity c WHERE c.realmId = :realmId)"
        ),
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
    @JsonIgnore
    private ClientEntity client;

    @Enumerated(EnumType.STRING)
    @Column(name = "FULL_SCOPE_ENABLED")
    private DraftStatus fullScopeEnabled; // by default, clients are full-scoped

    @Enumerated(EnumType.STRING)
    @Column(name = "FULL_SCOPE_DISABLED")
    private DraftStatus fullScopeDisabled;

    @Enumerated(EnumType.STRING)
    @Column(name = "ACTION_TYPE")
    private ActionType actionType;

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

}
