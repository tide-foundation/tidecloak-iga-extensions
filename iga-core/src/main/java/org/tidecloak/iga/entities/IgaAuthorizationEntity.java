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
@Table(name = "IGA_AUTHORIZATION")
@NamedQueries({
    @NamedQuery(
        name = "IgaAuthorization.findByChangeRequest",
        query = "SELECT a FROM IgaAuthorizationEntity a WHERE a.changeRequest.id = :changeRequestId ORDER BY a.createdAt"
    ),
    @NamedQuery(
        name = "IgaAuthorization.countByChangeRequest",
        query = "SELECT COUNT(a) FROM IgaAuthorizationEntity a WHERE a.changeRequest.id = :changeRequestId"
    ),
    @NamedQuery(
        name = "IgaAuthorization.deleteByChangeRequest",
        query = "DELETE FROM IgaAuthorizationEntity a WHERE a.changeRequest.id = :changeRequestId"
    )
})
public class IgaAuthorizationEntity {

    @Id
    @Column(name = "ID", length = 36)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "CHANGE_REQUEST_ID")
    private IgaChangeRequestEntity changeRequest;

    @Column(name = "AUTHORIZED_BY", length = 36, nullable = false)
    private String authorizedBy;

    @Column(name = "PARTIAL_SIG", columnDefinition = "TEXT")
    private String partialSig;

    @Column(name = "CREATED_AT", nullable = false)
    private Long createdAt;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public IgaChangeRequestEntity getChangeRequest() { return changeRequest; }
    public void setChangeRequest(IgaChangeRequestEntity changeRequest) { this.changeRequest = changeRequest; }

    public String getAuthorizedBy() { return authorizedBy; }
    public void setAuthorizedBy(String authorizedBy) { this.authorizedBy = authorizedBy; }

    public String getPartialSig() { return partialSig; }
    public void setPartialSig(String partialSig) { this.partialSig = partialSig; }

    public Long getCreatedAt() { return createdAt; }
    public void setCreatedAt(Long createdAt) { this.createdAt = createdAt; }
}
