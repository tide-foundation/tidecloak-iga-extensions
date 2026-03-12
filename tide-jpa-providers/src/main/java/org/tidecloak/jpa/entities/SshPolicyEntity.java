package org.tidecloak.jpa.entities;

import jakarta.persistence.*;

@NamedQueries({
        @NamedQuery(
                name = "getSshPoliciesByRealm",
                query = "SELECT p FROM SshPolicyEntity p WHERE p.realmId = :realmId ORDER BY p.timestamp DESC"
        ),
        @NamedQuery(
                name = "getSshPolicyByRealmAndRoleId",
                query = "SELECT p FROM SshPolicyEntity p WHERE p.realmId = :realmId AND p.roleId = :roleId"
        ),
        @NamedQuery(
                name = "deleteSshPolicyByRealmAndRoleId",
                query = "DELETE FROM SshPolicyEntity p WHERE p.realmId = :realmId AND p.roleId = :roleId"
        ),
})

@Entity
@Table(name = "SSH_POLICY")
public class SshPolicyEntity {

    @Id
    @Column(name = "ID", length = 36)
    @Access(AccessType.PROPERTY)
    protected String id;

    @Column(name = "REALM_ID")
    private String realmId;

    @Column(name = "ROLE_ID")
    private String roleId;

    @Column(name = "CONTRACT_ID")
    private String contractId;

    @Column(name = "APPROVAL_TYPE")
    private String approvalType;

    @Column(name = "EXECUTION_TYPE")
    private String executionType;

    @Column(name = "THRESHOLD")
    private Integer threshold;

    @Column(name = "POLICY_DATA")
    private String policyData;

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

    public String getRoleId() {
        return roleId;
    }

    public void setRoleId(String roleId) {
        this.roleId = roleId;
    }

    public String getContractId() {
        return contractId;
    }

    public void setContractId(String contractId) {
        this.contractId = contractId;
    }

    public String getApprovalType() {
        return approvalType;
    }

    public void setApprovalType(String approvalType) {
        this.approvalType = approvalType;
    }

    public String getExecutionType() {
        return executionType;
    }

    public void setExecutionType(String executionType) {
        this.executionType = executionType;
    }

    public Integer getThreshold() {
        return threshold;
    }

    public void setThreshold(Integer threshold) {
        this.threshold = threshold;
    }

    public String getPolicyData() {
        return policyData;
    }

    public void setPolicyData(String policyData) {
        this.policyData = policyData;
    }

    public Long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Long timestamp) {
        this.timestamp = timestamp;
    }
}
