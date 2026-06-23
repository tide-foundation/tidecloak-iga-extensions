package org.tidecloak.iga.rest;

/**
 * JSON representation of an IGA authorizer (admin signer registry entry).
 */
public class IgaAuthorizerRepresentation {

    private String id;
    private String realmId;
    private String providerId;
    private String type;
    private String authorizer;
    private String authorizerCertificate;
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
