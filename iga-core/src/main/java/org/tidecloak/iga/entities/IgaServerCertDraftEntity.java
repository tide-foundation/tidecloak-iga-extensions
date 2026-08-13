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

/**
 * Sidecar to a REQUEST_SERVER_CERT change request: the workload's certificate request and, once
 * the CR commits, the certificates the ORK cohort issued for it.
 *
 * <h2>Lifecycle</h2>
 * <ol>
 *   <li>{@code POST /tide-server-identity/request} stores the CSR + its derived fingerprint and
 *       serial, with a PENDING parent CR. No certificate yet.</li>
 *   <li>The admin quorum approves the CR.</li>
 *   <li>Commit signs {@code ResourceIdentity:1}; the ORK returns the TBS bytes it built, which are
 *       assembled, VALIDATED against this row's CSR, and stored below.</li>
 * </ol>
 *
 * <p>The CSR is retained after issuance because it is the only record of what was actually
 * requested — validation compares the issued certificate's subject public key against it, and
 * keeping it makes that check reproducible after the fact.
 */
@Entity
@Table(name = "IGA_SERVER_CERT_DRAFT")
@NamedQueries({
    @NamedQuery(
        name = "IgaServerCertDraft.findByRealm",
        query = "SELECT d FROM IgaServerCertDraftEntity d WHERE d.realmId = :realmId ORDER BY d.createdAt DESC"
    ),
    @NamedQuery(
        name = "IgaServerCertDraft.findByRealmAndFingerprint",
        query = "SELECT d FROM IgaServerCertDraftEntity d WHERE d.realmId = :realmId AND d.publicKeyFingerprint = :fingerprint ORDER BY d.createdAt DESC"
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

    /** Human clientId, taken from the CSR's subject CN. */
    @Column(name = "CLIENT_ID", length = 255, nullable = false)
    private String clientId;

    /** The workload's PKCS#10 CSR exactly as submitted, base64url DER. */
    @Column(name = "CSR", columnDefinition = "TEXT", nullable = false)
    private String csr;

    /**
     * DER SubjectPublicKeyInfo from the CSR, base64url. Kept alongside the CSR so validation and
     * the status lookup do not have to re-parse PKCS#10 on every read.
     */
    @Column(name = "PUBLIC_KEY", columnDefinition = "TEXT", nullable = false)
    private String publicKey;

    /** {@code SHA256:<base64url>} over the SPKI — the dedup key and the /status lookup key. */
    @Column(name = "PUBLIC_KEY_FINGERPRINT", length = 255)
    private String publicKeyFingerprint;

    /**
     * The certificate serial sent to the ORK, hex. Generated at request time so the value the
     * cohort signs is fixed before the approval window opens, and so the issued certificate can be
     * matched back to this row.
     */
    @Column(name = "SERIAL_NUMBER", length = 64)
    private String serialNumber;

    /** Issued resource-identity (workload mTLS client) certificate, PEM. */
    @Column(name = "CERTIFICATE", columnDefinition = "TEXT")
    private String certificate;

    /** notBefore of the issued resource certificate, epoch millis — read back from the cert. */
    @Column(name = "NOT_BEFORE")
    private Long notBefore;

    /** notAfter of the issued resource certificate, epoch millis — drives expiry on /status. */
    @Column(name = "NOT_AFTER")
    private Long notAfter;

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

    public String getCsr() { return csr; }
    public void setCsr(String csr) { this.csr = csr; }

    public String getPublicKey() { return publicKey; }
    public void setPublicKey(String publicKey) { this.publicKey = publicKey; }

    public String getPublicKeyFingerprint() { return publicKeyFingerprint; }
    public void setPublicKeyFingerprint(String publicKeyFingerprint) { this.publicKeyFingerprint = publicKeyFingerprint; }

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

    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }

    public Long getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Long updatedAt) { this.updatedAt = updatedAt; }
}
