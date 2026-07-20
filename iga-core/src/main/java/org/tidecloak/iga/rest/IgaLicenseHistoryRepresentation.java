package org.tidecloak.iga.rest;

/**
 * JSON representation of an IGA_LICENSE_HISTORY row — an append-only record
 * of an issued license.
 */
public class IgaLicenseHistoryRepresentation {

    private String id;
    private String realmId;
    private String providerId;
    private String vrk;
    private String gvrk;
    private String gvrkCertificate;
    private String vvkId;
    private String customerId;
    private String vendorId;
    private String payerPub;
    private String walletId;
    private Long expiry;
    private Long createdAt;

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

    public Long getCreatedAt() { return createdAt; }
    public void setCreatedAt(Long createdAt) { this.createdAt = createdAt; }
}
