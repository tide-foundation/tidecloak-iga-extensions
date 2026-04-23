package org.tidecloak.jpa.entities;

import jakarta.persistence.*;
import org.tidecloak.shared.enums.DraftStatus;

@NamedQueries({
        @NamedQuery(
                name = "getServerCertDraftById",
                query = "SELECT s FROM ServerCertDraftEntity s WHERE s.id = :changesetId"
        ),
        @NamedQuery(
                name = "getServerCertDraftByRequestId",
                query = "SELECT s FROM ServerCertDraftEntity s WHERE s.changeRequestId = :requestId"
        ),
        @NamedQuery(
                name = "getServerCertDraftsByRealm",
                query = "SELECT s FROM ServerCertDraftEntity s WHERE s.realmId = :realmId AND s.draftStatus = :draftStatus"
        ),
        @NamedQuery(
                name = "getServerCertDraftsByRealmNotStatus",
                query = "SELECT s FROM ServerCertDraftEntity s WHERE s.realmId = :realmId AND s.draftStatus != :draftStatus"
        ),
        @NamedQuery(
                name = "getServerCertByInstanceId",
                query = "SELECT s FROM ServerCertDraftEntity s WHERE s.realmId = :realmId AND s.instanceId = :instanceId"
        ),
        @NamedQuery(
                name = "getApprovedServerCertByClientAndInstance",
                query = "SELECT s FROM ServerCertDraftEntity s WHERE s.realmId = :realmId AND s.clientId = :clientId AND s.instanceId = :instanceId AND s.draftStatus = :draftStatus"
        ),
        @NamedQuery(
                name = "deleteServerCertDraftsByRealm",
                query = "DELETE FROM ServerCertDraftEntity s WHERE s.realmId = :realmId"
        )
})

@Entity
@Table(name = "SERVER_CERT_DRAFT")
public class ServerCertDraftEntity {

    @Id
    @Column(name = "ID", length = 36)
    @Access(AccessType.PROPERTY)
    private String id;

    @Column(name = "CHANGE_REQUEST_ID", length = 36)
    private String changeRequestId;

    @Column(name = "REALM_ID", length = 36)
    private String realmId;

    @Column(name = "CLIENT_ID")
    private String clientId;

    @Column(name = "INSTANCE_ID")
    private String instanceId;

    @Column(name = "SPIFFE_ID")
    private String spiffeId;

    @Column(name = "PUBLIC_KEY", length = 4096)
    private String publicKey;

    @Column(name = "PUBLIC_KEY_FINGERPRINT")
    private String publicKeyFingerprint;

    @Column(name = "REQUESTED_LIFETIME")
    private Long requestedLifetime;

    @Column(name = "CERTIFICATE", length = 8192)
    private String certificate;

    @Column(name = "TRUST_BUNDLE", length = 8192)
    private String trustBundle;

    @Enumerated(EnumType.STRING)
    @Column(name = "DRAFT_STATUS")
    private DraftStatus draftStatus = DraftStatus.DRAFT;

    @Column(name = "TIMESTAMP")
    private Long timestamp = System.currentTimeMillis();

    @Column(name = "SIGNED_POLICY", length = 8192)
    private String signedPolicy;

    @Column(name = "REVOKED")
    private Boolean revoked = false;

    @Column(name = "REVOKED_AT")
    private Long revokedAt;

    // Getters and setters

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getChangeRequestId() { return changeRequestId; }
    public void setChangeRequestId(String changeRequestId) { this.changeRequestId = changeRequestId; }

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

    public DraftStatus getDraftStatus() { return draftStatus; }
    public void setDraftStatus(DraftStatus draftStatus) { this.draftStatus = draftStatus; }

    public Long getTimestamp() { return timestamp; }
    public void setTimestamp(Long timestamp) { this.timestamp = timestamp; }

    public Boolean getRevoked() { return revoked; }
    public void setRevoked(Boolean revoked) { this.revoked = revoked; }

    public String getSignedPolicy() { return signedPolicy; }
    public void setSignedPolicy(String signedPolicy) { this.signedPolicy = signedPolicy; }

    public Long getRevokedAt() { return revokedAt; }
    public void setRevokedAt(Long revokedAt) { this.revokedAt = revokedAt; }
}
