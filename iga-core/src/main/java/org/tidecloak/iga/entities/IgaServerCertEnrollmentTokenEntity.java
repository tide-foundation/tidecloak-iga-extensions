package org.tidecloak.iga.entities;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.Table;

/**
 * One-time enrollment token gating the public server-identity request endpoint
 * ({@code /realms/{realm}/tide-server-identity/request}). An admin mints a token via
 * {@code POST /admin/realms/{realm}/iga/server-certs/enrollment-token}; the plaintext is
 * returned ONCE and never stored (only its SHA-256 hex hash lives here). The workload
 * presents the plaintext as an {@code Authorization: Bearer} header on its request, which
 * is validated-and-consumed atomically (single-use).
 *
 * Re-mint supersedes: minting a new token for a (realm, client) invalidates any prior
 * unconsumed token for that client.
 */
@Entity
@Table(name = "IGA_SERVER_CERT_ENROLLMENT_TOKEN")
@NamedQueries({
    @NamedQuery(
        name = "IgaServerCertEnrollmentToken.findByHash",
        query = "SELECT t FROM IgaServerCertEnrollmentTokenEntity t WHERE t.realmId = :realmId AND t.tokenHash = :tokenHash"
    )
})
public class IgaServerCertEnrollmentTokenEntity {

    @Id
    @Column(name = "ID", length = 36)
    private String id;

    @Column(name = "REALM_ID", length = 36, nullable = false)
    private String realmId;

    @Column(name = "CLIENT_ID", length = 255, nullable = false)
    private String clientId;

    /** SHA-256 hex of the plaintext token. The plaintext itself is never persisted. */
    @Column(name = "TOKEN_HASH", length = 64, nullable = false)
    private String tokenHash;

    @Column(name = "CREATED_AT", nullable = false)
    private long createdAt;

    @Column(name = "EXPIRES_AT", nullable = false)
    private long expiresAt;

    @Column(name = "CONSUMED_AT")
    private Long consumedAt;

    @Column(name = "CREATED_BY", length = 36)
    private String createdBy;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getRealmId() { return realmId; }
    public void setRealmId(String realmId) { this.realmId = realmId; }

    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }

    public String getTokenHash() { return tokenHash; }
    public void setTokenHash(String tokenHash) { this.tokenHash = tokenHash; }

    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }

    public long getExpiresAt() { return expiresAt; }
    public void setExpiresAt(long expiresAt) { this.expiresAt = expiresAt; }

    public Long getConsumedAt() { return consumedAt; }
    public void setConsumedAt(Long consumedAt) { this.consumedAt = consumedAt; }

    public String getCreatedBy() { return createdBy; }
    public void setCreatedBy(String createdBy) { this.createdBy = createdBy; }
}
