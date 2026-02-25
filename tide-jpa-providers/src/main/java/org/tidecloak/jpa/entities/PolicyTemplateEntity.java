package org.tidecloak.jpa.entities;

import jakarta.persistence.*;

@NamedQueries({
        @NamedQuery(
                name = "getPolicyTemplatesByRealm",
                query = "SELECT t FROM PolicyTemplateEntity t WHERE t.realmId = :realmId OR t.realmId IS NULL ORDER BY t.timestamp DESC"
        ),
        @NamedQuery(
                name = "getPolicyTemplateById",
                query = "SELECT t FROM PolicyTemplateEntity t WHERE t.id = :id"
        ),
        @NamedQuery(
                name = "deletePolicyTemplateById",
                query = "DELETE FROM PolicyTemplateEntity t WHERE t.id = :id"
        ),
})

@Entity
@Table(name = "POLICY_TEMPLATE")
public class PolicyTemplateEntity {

    @Id
    @Column(name = "ID", length = 36)
    @Access(AccessType.PROPERTY)
    protected String id;

    @Column(name = "REALM_ID")
    private String realmId;

    @Column(name = "NAME")
    private String name;

    @Column(name = "DESCRIPTION")
    private String description;

    @Column(name = "CONTRACT_CODE")
    private String contractCode;

    @Column(name = "MODEL_ID")
    private String modelId;

    @Column(name = "PARAMETERS")
    private String parameters;

    @Column(name = "CREATED_BY")
    private String createdBy;

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

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getContractCode() {
        return contractCode;
    }

    public void setContractCode(String contractCode) {
        this.contractCode = contractCode;
    }

    public String getModelId() {
        return modelId;
    }

    public void setModelId(String modelId) {
        this.modelId = modelId;
    }

    public String getParameters() {
        return parameters;
    }

    public void setParameters(String parameters) {
        this.parameters = parameters;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    public Long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Long timestamp) {
        this.timestamp = timestamp;
    }
}
