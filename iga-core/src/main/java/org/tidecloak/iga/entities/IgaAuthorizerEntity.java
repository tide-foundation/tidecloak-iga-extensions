package org.tidecloak.iga.entities;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.Table;

@Entity
@Table(name = "IGA_AUTHORIZER")
@NamedQueries({
    @NamedQuery(
        name = "IgaAuthorizer.findByRealm",
        query = "SELECT a FROM IgaAuthorizerEntity a WHERE a.realmId = :realmId"
    ),
    @NamedQuery(
        name = "IgaAuthorizer.findByProviderId",
        query = "SELECT a FROM IgaAuthorizerEntity a WHERE a.providerId = :providerId"
    ),
    @NamedQuery(
        name = "IgaAuthorizer.findByRealmAndType",
        query = "SELECT a FROM IgaAuthorizerEntity a WHERE a.realmId = :realmId AND a.type = :type"
    ),
    @NamedQuery(
        name = "IgaAuthorizer.findById",
        query = "SELECT a FROM IgaAuthorizerEntity a WHERE a.id = :id"
    ),
    @NamedQuery(
        name = "IgaAuthorizer.deleteById",
        query = "DELETE FROM IgaAuthorizerEntity a WHERE a.id = :id"
    )
})
public class IgaAuthorizerEntity {

    @Id
    @Column(name = "ID", length = 36)
    private String id;

    @Column(name = "REALM_ID", length = 36, nullable = false)
    private String realmId;

    @Column(name = "PROVIDER_ID", length = 36, nullable = false)
    private String providerId;

    @Column(name = "TYPE", length = 64, nullable = false)
    private String type;

    @Column(name = "AUTHORIZER", columnDefinition = "TEXT", nullable = false)
    private String authorizer;

    @Column(name = "AUTHORIZER_CERTIFICATE", columnDefinition = "TEXT", nullable = false)
    private String authorizerCertificate;

    @Column(name = "CREATED_AT", nullable = false)
    private Long createdAt;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getRealmId() { return realmId; }
    public void setRealmId(String realmId) { this.realmId = realmId; }

    public String getProviderId() { return providerId; }
    public void setProviderId(String providerId) { this.providerId = providerId; }

    public String getType() { return type; }
    public void setType(String type) { this.type = type; }

    public String getAuthorizer() { return authorizer; }
    public void setAuthorizer(String authorizer) { this.authorizer = authorizer; }

    public String getAuthorizerCertificate() { return authorizerCertificate; }
    public void setAuthorizerCertificate(String authorizerCertificate) { this.authorizerCertificate = authorizerCertificate; }

    public Long getCreatedAt() { return createdAt; }
    public void setCreatedAt(Long createdAt) { this.createdAt = createdAt; }
}
