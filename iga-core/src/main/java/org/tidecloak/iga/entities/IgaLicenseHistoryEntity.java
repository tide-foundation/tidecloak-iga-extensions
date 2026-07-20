package org.tidecloak.iga.entities;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.Table;

/**
 * Append-only audit log of every issued license. Pairs with
 * {@link IgaLicensingDraftEntity} on issuance.
 */
@Entity
@Table(name = "IGA_LICENSE_HISTORY")
@NamedQueries({
    @NamedQuery(
        name = "IgaLicenseHistory.findByRealm",
        query = "SELECT h FROM IgaLicenseHistoryEntity h WHERE h.realmId = :realmId ORDER BY h.createdAt DESC"
    ),
    @NamedQuery(
        name = "IgaLicenseHistory.findByProvider",
        query = "SELECT h FROM IgaLicenseHistoryEntity h WHERE h.providerId = :providerId ORDER BY h.createdAt DESC"
    ),
    @NamedQuery(
        name = "IgaLicenseHistory.findLatestByGvrk",
        query = "SELECT h FROM IgaLicenseHistoryEntity h WHERE h.gvrk = :gvrk ORDER BY h.createdAt DESC"
    ),
    @NamedQuery(
        name = "IgaLicenseHistory.findById",
        query = "SELECT h FROM IgaLicenseHistoryEntity h WHERE h.id = :id"
    ),
    @NamedQuery(
        name = "IgaLicenseHistory.deleteByRealm",
        query = "DELETE FROM IgaLicenseHistoryEntity h WHERE h.realmId = :realmId"
    )
})
public class IgaLicenseHistoryEntity {

    @Id
    @Column(name = "ID", length = 36)
    private String id;

    @Column(name = "REALM_ID", length = 36, nullable = false)
    private String realmId;

    /** References Keycloak COMPONENT.id; no DB FK. */
    @Column(name = "PROVIDER_ID", length = 36, nullable = false)
    private String providerId;

    @Column(name = "VRK", columnDefinition = "TEXT", nullable = false)
    private String vrk;

    @Column(name = "GVRK", columnDefinition = "TEXT", nullable = false)
    private String gvrk;

    @Column(name = "GVRK_CERTIFICATE", columnDefinition = "TEXT")
    private String gvrkCertificate;

    @Column(name = "VVK_ID", length = 256)
    private String vvkId;

    @Column(name = "CUSTOMER_ID", length = 256)
    private String customerId;

    @Column(name = "VENDOR_ID", length = 256)
    private String vendorId;

    @Column(name = "PAYER_PUB", length = 512)
    private String payerPub;

    @Column(name = "WALLET_ID", length = 512)
    private String walletId;

    @Column(name = "EXPIRY")
    private Long expiry;

    @Column(name = "CREATED_AT", nullable = false)
    private long createdAt;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getRealmId() { return realmId; }
    public void setRealmId(String realmId) { this.realmId = realmId; }

    public String getProviderId() { return providerId; }
    public void setProviderId(String providerId) { this.providerId = providerId; }

    public String getVrk() { return vrk; }
    public void setVrk(String vrk) { this.vrk = vrk; }

    public String getGvrk() { return gvrk; }
    public void setGvrk(String gvrk) { this.gvrk = gvrk; }

    public String getGvrkCertificate() { return gvrkCertificate; }
    public void setGvrkCertificate(String gvrkCertificate) { this.gvrkCertificate = gvrkCertificate; }

    public String getVvkId() { return vvkId; }
    public void setVvkId(String vvkId) { this.vvkId = vvkId; }

    public String getCustomerId() { return customerId; }
    public void setCustomerId(String customerId) { this.customerId = customerId; }

    public String getVendorId() { return vendorId; }
    public void setVendorId(String vendorId) { this.vendorId = vendorId; }

    public String getPayerPub() { return payerPub; }
    public void setPayerPub(String payerPub) { this.payerPub = payerPub; }

    public String getWalletId() { return walletId; }
    public void setWalletId(String walletId) { this.walletId = walletId; }

    public Long getExpiry() { return expiry; }
    public void setExpiry(Long expiry) { this.expiry = expiry; }

    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }
}
