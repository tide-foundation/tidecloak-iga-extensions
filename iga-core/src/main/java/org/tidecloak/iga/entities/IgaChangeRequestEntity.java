package org.tidecloak.iga.entities;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;

import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "IGA_CHANGE_REQUEST")
@NamedQueries({
    @NamedQuery(
        name = "IgaChangeRequest.findPendingByEntity",
        query = "SELECT cr FROM IgaChangeRequestEntity cr WHERE cr.realmId = :realmId AND cr.entityType = :entityType AND cr.entityId = :entityId AND cr.status = 'PENDING'"
    ),
    @NamedQuery(
        name = "IgaChangeRequest.findPendingByRealm",
        query = "SELECT cr FROM IgaChangeRequestEntity cr WHERE cr.realmId = :realmId AND cr.status = 'PENDING' ORDER BY cr.createdAt DESC"
    ),
    @NamedQuery(
        name = "IgaChangeRequest.countPendingByEntity",
        query = "SELECT COUNT(cr) FROM IgaChangeRequestEntity cr WHERE cr.entityType = :entityType AND cr.entityId = :entityId AND cr.status = 'PENDING'"
    ),
    @NamedQuery(
        name = "IgaChangeRequest.deleteByRealm",
        query = "DELETE FROM IgaChangeRequestEntity cr WHERE cr.realmId = :realmId"
    )
})
public class IgaChangeRequestEntity {

    @Id
    @Column(name = "ID", length = 36)
    private String id;

    @Column(name = "REALM_ID", length = 36, nullable = false)
    private String realmId;

    @Column(name = "ENTITY_TYPE", length = 50, nullable = false)
    private String entityType;

    @Column(name = "ENTITY_ID", length = 36, nullable = false)
    private String entityId;

    @Column(name = "ACTION_TYPE", length = 50, nullable = false)
    private String actionType;

    @Column(name = "ROWS_JSON", columnDefinition = "TEXT", nullable = false)
    private String rowsJson;

    @Column(name = "STATUS", length = 20, nullable = false)
    private String status;

    @Column(name = "REQUESTED_BY", length = 36)
    private String requestedBy;

    @Column(name = "CREATED_AT", nullable = false)
    private Long createdAt;

    @Column(name = "RESOLVED_AT")
    private Long resolvedAt;

    @Column(name = "RESOLVED_BY", length = 36)
    private String resolvedBy;

    @OneToMany(mappedBy = "changeRequest", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<IgaAuthorizationEntity> authorizations = new ArrayList<>();

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getRealmId() { return realmId; }
    public void setRealmId(String realmId) { this.realmId = realmId; }

    public String getEntityType() { return entityType; }
    public void setEntityType(String entityType) { this.entityType = entityType; }

    public String getEntityId() { return entityId; }
    public void setEntityId(String entityId) { this.entityId = entityId; }

    public String getActionType() { return actionType; }
    public void setActionType(String actionType) { this.actionType = actionType; }

    public String getRowsJson() { return rowsJson; }
    public void setRowsJson(String rowsJson) { this.rowsJson = rowsJson; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getRequestedBy() { return requestedBy; }
    public void setRequestedBy(String requestedBy) { this.requestedBy = requestedBy; }

    public Long getCreatedAt() { return createdAt; }
    public void setCreatedAt(Long createdAt) { this.createdAt = createdAt; }

    public Long getResolvedAt() { return resolvedAt; }
    public void setResolvedAt(Long resolvedAt) { this.resolvedAt = resolvedAt; }

    public String getResolvedBy() { return resolvedBy; }
    public void setResolvedBy(String resolvedBy) { this.resolvedBy = resolvedBy; }

    public List<IgaAuthorizationEntity> getAuthorizations() { return authorizations; }
    public void setAuthorizations(List<IgaAuthorizationEntity> authorizations) { this.authorizations = authorizations; }
}
