package org.tidecloak.iga.entities;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.Table;

@Entity
@Table(name = "IGA_LICENSING_DRAFT")
@NamedQueries({
    @NamedQuery(
        name = "IgaLicensingDraft.findByRealm",
        query = "SELECT d FROM IgaLicensingDraftEntity d WHERE d.realmId = :realmId ORDER BY d.createdAt DESC"
    ),
    @NamedQuery(
        name = "IgaLicensingDraft.findById",
        query = "SELECT d FROM IgaLicensingDraftEntity d WHERE d.id = :id"
    ),
    @NamedQuery(
        name = "IgaLicensingDraft.findByChangeRequestId",
        query = "SELECT d FROM IgaLicensingDraftEntity d WHERE d.changeRequest.id = :crId"
    ),
    @NamedQuery(
        name = "IgaLicensingDraft.deleteByRealm",
        query = "DELETE FROM IgaLicensingDraftEntity d WHERE d.realmId = :realmId"
    )
})
public class IgaLicensingDraftEntity {

    @Id
    @Column(name = "ID", length = 36)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "CHANGE_REQUEST_ID")
    private IgaChangeRequestEntity changeRequest;

    @Column(name = "REALM_ID", length = 36, nullable = false)
    private String realmId;

    @Column(name = "ACTION_TYPE", length = 64, nullable = false)
    private String actionType;

    @Column(name = "SIGNATURE", columnDefinition = "TEXT")
    private String signature;

    @Column(name = "CREATED_AT", nullable = false)
    private long createdAt;

    @Column(name = "UPDATED_AT")
    private Long updatedAt;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public IgaChangeRequestEntity getChangeRequest() { return changeRequest; }
    public void setChangeRequest(IgaChangeRequestEntity changeRequest) { this.changeRequest = changeRequest; }

    public String getRealmId() { return realmId; }
    public void setRealmId(String realmId) { this.realmId = realmId; }

    public String getActionType() { return actionType; }
    public void setActionType(String actionType) { this.actionType = actionType; }

    public String getSignature() { return signature; }
    public void setSignature(String signature) { this.signature = signature; }

    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }

    public Long getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Long updatedAt) { this.updatedAt = updatedAt; }
}
