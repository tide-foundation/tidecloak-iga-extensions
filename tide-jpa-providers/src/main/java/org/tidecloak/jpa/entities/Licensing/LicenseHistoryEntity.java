package org.tidecloak.jpa.entities.Licensing;

import jakarta.persistence.*;
import org.keycloak.models.jpa.entities.ComponentEntity;

@Entity
@Table(name="LICENSE_HISTORY")
@NamedQueries({
        @NamedQuery(
                name = "getLicenseHistoryForKey",
                query = "SELECT l FROM LicenseHistoryEntity l WHERE l.componentEntity = :componentEntity"
        ),
        @NamedQuery(
                name = "LicenseHistory.findByGvrk",
                query = "SELECT l FROM LicenseHistoryEntity l WHERE l.GVRK = :gvrk ORDER BY l.expiry DESC"
        ),
        @NamedQuery(
                name = "LicenseHistory.findLatestByGvrk",
                query = "SELECT l FROM LicenseHistoryEntity l WHERE l.GVRK = :gvrk ORDER BY l.expiry DESC"
        )
})
public class LicenseHistoryEntity {


    @Id
    @Column(name="ID", length = 36)
    @Access(AccessType.PROPERTY) // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    protected String id;

    @ManyToOne
    @JoinColumn(name = "PROVIDER_ID", referencedColumnName = "ID")
    protected ComponentEntity componentEntity;

    @Column(name = "VRK")
    protected String VRK;

    @Column(name = "GVRK")
    protected String GVRK;

    @Column(name = "GVRK_CERTIFICATE")
    protected String GVRKCertificate;

    @Column(name = "VVK_ID", length = 256)
    protected String vvkId;

    @Column(name = "CUSTOMER_ID", length = 256)
    protected String customerId;

    @Column(name = "VENDOR_ID", length = 256)
    protected String vendorId;

    @Column(name = "PAYER_PUB", length = 512)
    protected String payerPub;

    @Column(name = "EXPIRY")
    protected Long expiry;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public ComponentEntity getComponentEntity() {
        return componentEntity;
    }

    public void setComponentEntity(ComponentEntity componentEntity) {
        this.componentEntity = componentEntity;
    }

    public String getVRK() {
        return VRK;
    }

    public void setVRK(String VRK) {
        this.VRK = VRK;
    }

    public String getGVRK() {
        return GVRK;
    }

    public void setGVRK(String GVRK) {
        this.GVRK = GVRK;
    }

    public String getGVRKCertificate() {
        return GVRKCertificate;
    }

    public void setGVRKCertificate(String GVRKCertificate) {
        this.GVRKCertificate = GVRKCertificate;
    }

    public String getVvkId() {
        return vvkId;
    }

    public void setVvkId(String vvkId) {
        this.vvkId = vvkId;
    }

    public String getCustomerId() {
        return customerId;
    }

    public void setCustomerId(String customerId) {
        this.customerId = customerId;
    }

    public String getVendorId() {
        return vendorId;
    }

    public void setVendorId(String vendorId) {
        this.vendorId = vendorId;
    }

    public String getPayerPub() {
        return payerPub;
    }

    public void setPayerPub(String payerPub) {
        this.payerPub = payerPub;
    }
    public Long getExpiry() {
        return expiry;
    }

    public void setExpiry(Long expiry) {
        this.expiry = expiry;
    }
}
