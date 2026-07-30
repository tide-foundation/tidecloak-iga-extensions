package org.tidecloak.iga.rest;

/**
 * JSON representation of an IGA server-cert draft — the sidecar to a
 * REQUEST_SERVER_CERT change request, holding workload TLS / SPIFFE cert data.
 */
public class IgaServerCertDraftRepresentation {

    private String id;
    private String changeRequestId;
    private String realmId;
    private String clientId;
    private String instanceId;
    private String spiffeId;
    private String publicKey;
    private String publicKeyFingerprint;
    private Long requestedLifetime;
    private String certificate;
    private String trustBundle;
    private String signedPolicy;
    private boolean revoked;
    private Long revokedAt;
    private Long createdAt;
    private Long updatedAt;

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

    public String getSignedPolicy() { return signedPolicy; }
    public void setSignedPolicy(String signedPolicy) { this.signedPolicy = signedPolicy; }

    /**
     * Read-only alias of {@link #getSignedPolicy()} exposed under the source branch's
     * field name. The {@code signedPolicy} column stores the ORK-signed workload public
     * key ({@code base64(pubKey) + "." + base64(vvkSig)}), surfaced to admin listings as
     * {@code signedPublicKey} for parity with the {@code add-server-identity} branch.
     */
    public String getSignedPublicKey() { return signedPolicy; }

    public boolean isRevoked() { return revoked; }
    public void setRevoked(boolean revoked) { this.revoked = revoked; }

    public Long getRevokedAt() { return revokedAt; }
    public void setRevokedAt(Long revokedAt) { this.revokedAt = revokedAt; }

    public Long getCreatedAt() { return createdAt; }
    public void setCreatedAt(Long createdAt) { this.createdAt = createdAt; }

    public Long getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Long updatedAt) { this.updatedAt = updatedAt; }
}
