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
@Table(name = "IGA_SERVER_CERT_DRAFT")
@NamedQueries({
    @NamedQuery(
        name = "IgaServerCertDraft.findByRealm",
        query = "SELECT d FROM IgaServerCertDraftEntity d WHERE d.realmId = :realmId ORDER BY d.createdAt DESC"
    ),
    @NamedQuery(
        name = "IgaServerCertDraft.findByRealmAndInstance",
        query = "SELECT d FROM IgaServerCertDraftEntity d WHERE d.realmId = :realmId AND d.instanceId = :instanceId ORDER BY d.createdAt DESC"
    ),
    @NamedQuery(
        name = "IgaServerCertDraft.findById",
        query = "SELECT d FROM IgaServerCertDraftEntity d WHERE d.id = :id"
    ),
    @NamedQuery(
        name = "IgaServerCertDraft.findByChangeRequestId",
        query = "SELECT d FROM IgaServerCertDraftEntity d WHERE d.changeRequest.id = :crId"
    ),
    @NamedQuery(
        name = "IgaServerCertDraft.findActive",
        query = "SELECT d FROM IgaServerCertDraftEntity d WHERE d.realmId = :realmId AND d.revoked = false AND d.certificate IS NOT NULL ORDER BY d.createdAt DESC"
    ),
    @NamedQuery(
        name = "IgaServerCertDraft.deleteByRealm",
        query = "DELETE FROM IgaServerCertDraftEntity d WHERE d.realmId = :realmId"
    )
})
public class IgaServerCertDraftEntity {

    @Id
    @Column(name = "ID", length = 36)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "CHANGE_REQUEST_ID")
    private IgaChangeRequestEntity changeRequest;

    @Column(name = "REALM_ID", length = 36, nullable = false)
    private String realmId;

    @Column(name = "CLIENT_ID", length = 255, nullable = false)
    private String clientId;

    @Column(name = "INSTANCE_ID", length = 255, nullable = false)
    private String instanceId;

    @Column(name = "SPIFFE_ID", length = 512)
    private String spiffeId;

    @Column(name = "PUBLIC_KEY", columnDefinition = "TEXT", nullable = false)
    private String publicKey;

    @Column(name = "PUBLIC_KEY_FINGERPRINT", length = 255)
    private String publicKeyFingerprint;

    @Column(name = "REQUESTED_LIFETIME")
    private Long requestedLifetime;

    @Column(name = "CERTIFICATE", columnDefinition = "TEXT")
    private String certificate;

    @Column(name = "TRUST_BUNDLE", columnDefinition = "TEXT")
    private String trustBundle;

    @Column(name = "SIGNED_POLICY", columnDefinition = "TEXT")
    private String signedPolicy;

    @Column(name = "REVOKED", nullable = false)
    private boolean revoked = false;

    @Column(name = "REVOKED_AT")
    private Long revokedAt;

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

    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }

    public String getInstanceId() { return instanceId; }
    public void setInstanceId(String instanceId) { this.instanceId = instanceId; }

    public String getSpiffeId() { return spiffeId; }
    public void setSpiffeId(String spiffeId) { this.spiffeId = spiffeId; }

    public String getPublicKey() { return publicKey; }
    public void setPublicKey(String publicKey) { this.publicKey = publicKey; }

    public String getPublicKeyFingerprint() { return publicKeyFingerprint; }
    public void setPublicKeyFingerprint(String publicKeyFingerprint) { this.publicKeyFingerprint = publicKeyFingerprint; }

    public Long getRequestedLifetime() { return requestedLifetime; }
    public void setRequestedLifetime(Long requestedLifetime) { this.requestedLifetime = requestedLifetime; }

    public String getCertificate() { return certificate; }
    public void setCertificate(String certificate) { this.certificate = certificate; }

    public String getTrustBundle() { return trustBundle; }
    public void setTrustBundle(String trustBundle) { this.trustBundle = trustBundle; }

    public String getSignedPolicy() { return signedPolicy; }
    public void setSignedPolicy(String signedPolicy) { this.signedPolicy = signedPolicy; }

    public boolean isRevoked() { return revoked; }
    public void setRevoked(boolean revoked) { this.revoked = revoked; }

    public Long getRevokedAt() { return revokedAt; }
    public void setRevokedAt(Long revokedAt) { this.revokedAt = revokedAt; }

    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }

    public Long getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Long updatedAt) { this.updatedAt = updatedAt; }
}
