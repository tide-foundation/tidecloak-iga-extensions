package org.tidecloak.iga.entities;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

@Entity
@Table(name = "IGA_FORSETI_CONTRACT",
        uniqueConstraints = @UniqueConstraint(
                name = "UQ_IGA_FORSETI_CONTRACT_REALM_HASH",
                columnNames = {"REALM_ID", "CONTRACT_HASH"}))
@NamedQueries({
    @NamedQuery(
        name = "IgaForsetiContract.findByRealm",
        query = "SELECT c FROM IgaForsetiContractEntity c WHERE c.realmId = :realmId ORDER BY c.createdAt DESC"
    ),
    @NamedQuery(
        name = "IgaForsetiContract.findByRealmAndHash",
        query = "SELECT c FROM IgaForsetiContractEntity c WHERE c.realmId = :realmId AND c.contractHash = :hash"
    ),
    @NamedQuery(
        name = "IgaForsetiContract.findById",
        query = "SELECT c FROM IgaForsetiContractEntity c WHERE c.id = :id"
    ),
    @NamedQuery(
        name = "IgaForsetiContract.deleteById",
        query = "DELETE FROM IgaForsetiContractEntity c WHERE c.id = :id"
    ),
    @NamedQuery(
        name = "IgaForsetiContract.deleteByRealm",
        query = "DELETE FROM IgaForsetiContractEntity c WHERE c.realmId = :realmId"
    )
})
public class IgaForsetiContractEntity {

    @Id
    @Column(name = "ID", length = 36)
    private String id;

    @Column(name = "REALM_ID", length = 36, nullable = false)
    private String realmId;

    @Column(name = "CONTRACT_HASH", length = 128, nullable = false)
    private String contractHash;

    @Column(name = "CONTRACT_CODE", columnDefinition = "TEXT", nullable = false)
    private String contractCode;

    @Column(name = "NAME", length = 255)
    private String name;

    @Column(name = "CREATED_AT", nullable = false)
    private Long createdAt;

    @Column(name = "UPDATED_AT")
    private Long updatedAt;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getRealmId() { return realmId; }
    public void setRealmId(String realmId) { this.realmId = realmId; }

    public String getContractHash() { return contractHash; }
    public void setContractHash(String contractHash) { this.contractHash = contractHash; }

    public String getContractCode() { return contractCode; }
    public void setContractCode(String contractCode) { this.contractCode = contractCode; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public Long getCreatedAt() { return createdAt; }
    public void setCreatedAt(Long createdAt) { this.createdAt = createdAt; }

    public Long getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Long updatedAt) { this.updatedAt = updatedAt; }
}
