package org.tidecloak.jpa.entities;

import jakarta.persistence.*;

@NamedQueries({
        @NamedQuery(
                name = "getForsetiContractsByRealm",
                query = "SELECT c FROM ForsetiContractEntity c WHERE c.realmId = :realmId ORDER BY c.timestamp DESC"
        ),
        @NamedQuery(
                name = "getForsetiContractByRealmAndHash",
                query = "SELECT c FROM ForsetiContractEntity c WHERE c.realmId = :realmId AND c.contractHash = :contractHash"
        ),
})

@Entity
@Table(name = "FORSETI_CONTRACT")
public class ForsetiContractEntity {

    @Id
    @Column(name = "ID", length = 36)
    @Access(AccessType.PROPERTY)
    protected String id;

    @Column(name = "REALM_ID")
    private String realmId;

    @Column(name = "CONTRACT_HASH")
    private String contractHash;

    @Column(name = "CONTRACT_CODE")
    private String contractCode;

    @Column(name = "NAME")
    private String name;

    @Column(name = "TIMESTAMP")
    protected Long timestamp = System.currentTimeMillis();

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(String realmId) {
        this.realmId = realmId;
    }

    public String getContractHash() {
        return contractHash;
    }

    public void setContractHash(String contractHash) {
        this.contractHash = contractHash;
    }

    public String getContractCode() {
        return contractCode;
    }

    public void setContractCode(String contractCode) {
        this.contractCode = contractCode;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Long timestamp) {
        this.timestamp = timestamp;
    }
}
