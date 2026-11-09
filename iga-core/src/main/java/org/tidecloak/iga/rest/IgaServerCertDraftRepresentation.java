package org.tidecloak.iga.rest;

/**
 * JSON representation of an IGA server-cert draft — the sidecar to a
 * REQUEST_SERVER_CERT change request, holding workload TLS cert data.
 */
public class IgaServerCertDraftRepresentation {

    private String id;
    private String changeRequestId;
    private String realmId;
    private String clientId;
    private String publicKey;
    private String publicKeyFingerprint;
    private String csr;
    private String serialNumber;
    private String certificate;
    private Long notBefore;
    private Long notAfter;
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

    public String getPublicKey() { return publicKey; }
    public void setPublicKey(String publicKey) { this.publicKey = publicKey; }

    public String getPublicKeyFingerprint() { return publicKeyFingerprint; }
    public void setPublicKeyFingerprint(String publicKeyFingerprint) { this.publicKeyFingerprint = publicKeyFingerprint; }

    public String getCsr() { return csr; }
    public void setCsr(String csr) { this.csr = csr; }

    public String getSerialNumber() { return serialNumber; }
    public void setSerialNumber(String serialNumber) { this.serialNumber = serialNumber; }

    public String getCertificate() { return certificate; }
    public void setCertificate(String certificate) { this.certificate = certificate; }

    public Long getNotBefore() { return notBefore; }
    public void setNotBefore(Long notBefore) { this.notBefore = notBefore; }

    public Long getNotAfter() { return notAfter; }
    public void setNotAfter(Long notAfter) { this.notAfter = notAfter; }

    public boolean isRevoked() { return revoked; }
    public void setRevoked(boolean revoked) { this.revoked = revoked; }

    public Long getRevokedAt() { return revokedAt; }
    public void setRevokedAt(Long revokedAt) { this.revokedAt = revokedAt; }

    public Long getCreatedAt() { return createdAt; }
    public void setCreatedAt(Long createdAt) { this.createdAt = createdAt; }

    public Long getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Long updatedAt) { this.updatedAt = updatedAt; }
}
