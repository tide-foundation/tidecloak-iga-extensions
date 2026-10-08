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
 * The realm-wide certificates issued by the ORK cohort: the P-256 realm server certificate and
 * the Ed25519 realm root CA.
 *
 * <h2>Why this is separate from IGA_SERVER_CERT_DRAFT</h2>
 * {@link IgaServerCertDraftEntity} is one row per <em>client</em> enrolment — per (client, keypair)
 * — and its certificate belongs to that one workload. Both certificates here are realm-scoped: the
 * root CA is the realm's trust anchor (re-signed from the same gVVK on every round, so it is the
 * same certificate for every workload in the realm), and the server certificate is Tidecloak's own
 * TLS identity. Carrying them on each client row duplicated them across the realm and left no way
 * to tell which copy was current after a rotation, so they live here instead, one row per issuance.
 *
 * <h2>The two certificates</h2>
 * <ul>
 *   <li><b>Realm server certificate</b> — P-256, over a keypair Tidecloak holds. It has a CSR,
 *       because Tidecloak proves possession of that key the same way a workload does; the
 *       {@code server*} columns mirror the CSR-side columns on the per-client draft.</li>
 *   <li><b>Realm root CA</b> — Ed25519 over the threshold gVVK, which Tidecloak never holds. There
 *       is no CSR and no locally-generated serial: the cohort derives the serial from the gVVK SPKI
 *       so every ORK produces identical bytes. Only the issued certificate comes back.</li>
 * </ul>
 * Their validity windows are tracked separately — a root CA outlives the leaf it anchors, so
 * collapsing them onto one pair of columns would report the wrong expiry for one of the two.
 *
 * <p>Rotation is a new row, not an update: the newest non-revoked row with the certificate set is
 * the current one ({@code IgaRealmCert.findCurrent}), and history is retained for auditing which
 * anchor a certificate was issued under.
 */
@Entity
@Table(name = "IGA_REALM_CERT")
@NamedQueries({
    @NamedQuery(
        name = "IgaRealmCert.findByRealm",
        query = "SELECT c FROM IgaRealmCertEntity c WHERE c.realmId = :realmId ORDER BY c.createdAt DESC"
    ),
    @NamedQuery(
        name = "IgaRealmCert.findById",
        query = "SELECT c FROM IgaRealmCertEntity c WHERE c.id = :id"
    ),
    @NamedQuery(
        name = "IgaRealmCert.findByChangeRequestId",
        query = "SELECT c FROM IgaRealmCertEntity c WHERE c.changeRequest.id = :crId"
    ),
    // Newest first: index 0 of the result is the realm's current certificate pair.
    @NamedQuery(
        name = "IgaRealmCert.findCurrent",
        query = "SELECT c FROM IgaRealmCertEntity c WHERE c.realmId = :realmId AND c.revoked = false "
                + "AND c.serverCertificate IS NOT NULL ORDER BY c.createdAt DESC"
    ),
    @NamedQuery(
        name = "IgaRealmCert.deleteByRealm",
        query = "DELETE FROM IgaRealmCertEntity c WHERE c.realmId = :realmId"
    )
})
public class IgaRealmCertEntity {

    @Id
    @Column(name = "ID", length = 36)
    private String id;

    /** The change request whose approval authorised this issuance. */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "CHANGE_REQUEST_ID")
    private IgaChangeRequestEntity changeRequest;

    @Column(name = "REALM_ID", length = 36, nullable = false)
    private String realmId;

    // ---------------------------------------------------------------------
    // Realm server certificate — P-256, Tidecloak's own keypair
    // ---------------------------------------------------------------------

    /** Tidecloak's PKCS#10 request for the realm server certificate, base64url DER. */
    @Column(name = "SERVER_CSR", columnDefinition = "TEXT")
    private String serverCsr;

    /** DER SubjectPublicKeyInfo of the P-256 key from {@link #serverCsr}, base64url. */
    @Column(name = "SERVER_PUBLIC_KEY", columnDefinition = "TEXT")
    private String serverPublicKey;

    /** {@code SHA256:<base64url>} over the server SPKI. */
    @Column(name = "SERVER_PUBLIC_KEY_FINGERPRINT", length = 255)
    private String serverPublicKeyFingerprint;

    /** Serial sent to the ORK for the server certificate, hex — fixed before approval opens. */
    @Column(name = "SERVER_SERIAL_NUMBER", length = 64)
    private String serverSerialNumber;

    /** The issued P-256 realm server certificate, PEM. Null until the CR commits. */
    @Column(name = "SERVER_CERTIFICATE", columnDefinition = "TEXT")
    private String serverCertificate;

    /** notBefore of the server certificate, epoch millis — read back from the cert. */
    @Column(name = "SERVER_NOT_BEFORE")
    private Long serverNotBefore;

    /** notAfter of the server certificate, epoch millis. */
    @Column(name = "SERVER_NOT_AFTER")
    private Long serverNotAfter;

    // ---------------------------------------------------------------------
    // Realm root CA — Ed25519 over the threshold gVVK
    // ---------------------------------------------------------------------

    /** The issued Ed25519 realm root CA, PEM — the trust anchor workloads verify peers against. */
    @Column(name = "ROOT_CA_CERTIFICATE", columnDefinition = "TEXT")
    private String rootCaCertificate;

    /** Serial of the root CA, hex. Cohort-derived from the gVVK SPKI, not generated here. */
    @Column(name = "ROOT_CA_SERIAL_NUMBER", length = 64)
    private String rootCaSerialNumber;

    /** notBefore of the root CA, epoch millis. */
    @Column(name = "ROOT_CA_NOT_BEFORE")
    private Long rootCaNotBefore;

    /** notAfter of the root CA, epoch millis. Typically well beyond the server certificate's. */
    @Column(name = "ROOT_CA_NOT_AFTER")
    private Long rootCaNotAfter;

    // ---------------------------------------------------------------------

    /** Revokes the row as a unit — the server certificate and its anchor are issued together. */
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

    public String getServerCsr() { return serverCsr; }
    public void setServerCsr(String serverCsr) { this.serverCsr = serverCsr; }

    public String getServerPublicKey() { return serverPublicKey; }
    public void setServerPublicKey(String serverPublicKey) { this.serverPublicKey = serverPublicKey; }

    public String getServerPublicKeyFingerprint() { return serverPublicKeyFingerprint; }
    public void setServerPublicKeyFingerprint(String serverPublicKeyFingerprint) { this.serverPublicKeyFingerprint = serverPublicKeyFingerprint; }

    public String getServerSerialNumber() { return serverSerialNumber; }
    public void setServerSerialNumber(String serverSerialNumber) { this.serverSerialNumber = serverSerialNumber; }

    public String getServerCertificate() { return serverCertificate; }
    public void setServerCertificate(String serverCertificate) { this.serverCertificate = serverCertificate; }

    public Long getServerNotBefore() { return serverNotBefore; }
    public void setServerNotBefore(Long serverNotBefore) { this.serverNotBefore = serverNotBefore; }

    public Long getServerNotAfter() { return serverNotAfter; }
    public void setServerNotAfter(Long serverNotAfter) { this.serverNotAfter = serverNotAfter; }

    public String getRootCaCertificate() { return rootCaCertificate; }
    public void setRootCaCertificate(String rootCaCertificate) { this.rootCaCertificate = rootCaCertificate; }

    public String getRootCaSerialNumber() { return rootCaSerialNumber; }
    public void setRootCaSerialNumber(String rootCaSerialNumber) { this.rootCaSerialNumber = rootCaSerialNumber; }

    public Long getRootCaNotBefore() { return rootCaNotBefore; }
    public void setRootCaNotBefore(Long rootCaNotBefore) { this.rootCaNotBefore = rootCaNotBefore; }

    public Long getRootCaNotAfter() { return rootCaNotAfter; }
    public void setRootCaNotAfter(Long rootCaNotAfter) { this.rootCaNotAfter = rootCaNotAfter; }

    public boolean isRevoked() { return revoked; }
    public void setRevoked(boolean revoked) { this.revoked = revoked; }

    public Long getRevokedAt() { return revokedAt; }
    public void setRevokedAt(Long revokedAt) { this.revokedAt = revokedAt; }

    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }

    public Long getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Long updatedAt) { this.updatedAt = updatedAt; }
}
