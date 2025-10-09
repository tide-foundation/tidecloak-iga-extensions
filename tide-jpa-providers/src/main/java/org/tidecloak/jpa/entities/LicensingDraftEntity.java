package org.tidecloak.jpa.entities;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.DraftStatus;

@NamedQueries({
        // select all drafts for a realm
        @NamedQuery(
                name  = "LicensingDraft.findByRealm",
                query = "SELECT o FROM LicensingDraftEntity o WHERE o.realmId = :realmId"
        ),
        // count drafts for a realm
        @NamedQuery(
                name  = "LicensingDraft.countByRealm",
                query = "SELECT COUNT(o) FROM LicensingDraftEntity o WHERE o.realmId = :realmId"
        ),
        // delete all drafts for a realm
        @NamedQuery(
                name  = "LicensingDraft.deleteByRealm",
                query = "DELETE FROM LicensingDraftEntity o WHERE o.realmId = :realmId"
        ),
        // select all drafts for a realm with a particular status
        @NamedQuery(
                name  = "LicensingDraft.findByRealmAndStatus",
                query = "SELECT o FROM LicensingDraftEntity o "
                        + "WHERE o.realmId = :realmId AND o.draftStatus = :status"
        ),
        @NamedQuery(
                name  = "LicensingDraft.findByChangeRequestId",
                query = "SELECT o FROM LicensingDraftEntity o WHERE o.changeRequestId = :changeRequestId"
        ),
        @NamedQuery(
                name  = "LicensingDraft.findByRealmAndStatusNotEqual",
                query = "SELECT o FROM LicensingDraftEntity o "
                        + "WHERE o.realmId = :realmId "
                        + "  AND o.draftStatus <> :status"
        )
})

@Entity
@Table(name="LICENSING_DRAFT")
public class LicensingDraftEntity {

    @Id
    @Column(name="ID", length = 36)
    @Access(AccessType.PROPERTY) // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    protected String id;

    @Column(name="CHANGE_REQUEST_ID", length = 36)
    protected String changeRequestId;

    @Column(name="REALM_ID")
    protected String realmId;

    @Enumerated(EnumType.STRING)
    @Column(name = "DRAFT_STATUS")
    private DraftStatus draftStatus;

    @Column(name = "SIGNATURE")
    private String signature;

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

    public String getChangeRequestId() {
        return changeRequestId;
    }

    public void setChangeRequestId(String changeRequestId) {
        this.changeRequestId = changeRequestId;
    }
    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(String realmId) {
        this.realmId = realmId;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
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

    public Long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Long timestamp) {
        this.timestamp = timestamp;
    }

}
