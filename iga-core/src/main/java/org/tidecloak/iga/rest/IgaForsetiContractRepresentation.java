package org.tidecloak.iga.rest;

/**
 * JSON representation of an IGA Forseti policy contract — a row in the
 * realm-scoped library of policy source code.
 */
public class IgaForsetiContractRepresentation {

    private String id;
    private String realmId;
    private String contractHash;
    private String contractCode;
    private String name;
    private Long createdAt;
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
