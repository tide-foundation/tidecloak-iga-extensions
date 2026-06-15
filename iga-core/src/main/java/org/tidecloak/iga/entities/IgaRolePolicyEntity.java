package org.tidecloak.iga.entities;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

/**
 * Realm-level IGA policy record. Each row is a named policy in a realm
 * (Midgard policy bytes / signature combined with Forseti contract binding).
 *
 * <p>Historically this was keyed by (REALM_ID, ROLE_ID) — a per-role record. It
 * is now keyed by (REALM_ID, NAME): policies are realm-level named records that
 * are decoupled from any specific role. The M0 admin-quorum policy uses the
 * reserved immutable name {@code tide-realm-admin}
 * ({@link org.tidecloak.iga.attestors.TideAttestor#TIDE_REALM_ADMIN_POLICY_KEY});
 * the tide-realm-admin ROLE still defines WHO approves, but the policy STORAGE
 * no longer hangs off the role id.</p>
 *
 * <p>The table is still physically named {@code IGA_ROLE_POLICY} (the ROLE_ID
 * column was dropped and a NAME column added in a migration); the FK from
 * CONTRACT_ID to IGA_FORSETI_CONTRACT is preserved.</p>
 */
@Entity
@Table(name = "IGA_ROLE_POLICY",
        uniqueConstraints = @UniqueConstraint(
                name = "UQ_IGA_REALM_POLICY_REALM_NAME",
                columnNames = {"REALM_ID", "NAME"}))
@NamedQueries({
    @NamedQuery(
        name = "IgaRolePolicy.findByRealm",
        query = "SELECT p FROM IgaRolePolicyEntity p WHERE p.realmId = :realmId ORDER BY p.createdAt DESC"
    ),
    @NamedQuery(
        name = "IgaRolePolicy.findByRealmAndName",
        query = "SELECT p FROM IgaRolePolicyEntity p WHERE p.realmId = :realmId AND p.name = :name"
    ),
    @NamedQuery(
        name = "IgaRolePolicy.findById",
        query = "SELECT p FROM IgaRolePolicyEntity p WHERE p.id = :id"
    ),
    @NamedQuery(
        name = "IgaRolePolicy.deleteByRealmAndName",
        query = "DELETE FROM IgaRolePolicyEntity p WHERE p.realmId = :realmId AND p.name = :name"
    ),
    @NamedQuery(
        name = "IgaRolePolicy.deleteByRealm",
        query = "DELETE FROM IgaRolePolicyEntity p WHERE p.realmId = :realmId"
    )
})
public class IgaRolePolicyEntity {

    @Id
    @Column(name = "ID", length = 36)
    private String id;

    @Column(name = "REALM_ID", length = 36, nullable = false)
    private String realmId;

    @Column(name = "NAME", length = 255, nullable = false)
    private String name;

    @Column(name = "POLICY", columnDefinition = "TEXT", nullable = false)
    private String policy;

    @Column(name = "POLICY_SIG", length = 512, nullable = false)
    private String policySig;

    @Column(name = "CONTRACT_ID", length = 36)
    private String contractId;

    @Column(name = "APPROVAL_TYPE", length = 64)
    private String approvalType;

    @Column(name = "EXECUTION_TYPE", length = 64)
    private String executionType;

    @Column(name = "THRESHOLD")
    private Integer threshold;

    @Column(name = "POLICY_DATA", columnDefinition = "TEXT")
    private String policyData;

    @Column(name = "CREATED_AT", nullable = false)
    private Long createdAt;

    @Column(name = "UPDATED_AT")
    private Long updatedAt;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getRealmId() { return realmId; }
    public void setRealmId(String realmId) { this.realmId = realmId; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getPolicy() { return policy; }
    public void setPolicy(String policy) { this.policy = policy; }

    public String getPolicySig() { return policySig; }
    public void setPolicySig(String policySig) { this.policySig = policySig; }

    public String getContractId() { return contractId; }
    public void setContractId(String contractId) { this.contractId = contractId; }

    public String getApprovalType() { return approvalType; }
    public void setApprovalType(String approvalType) { this.approvalType = approvalType; }

    public String getExecutionType() { return executionType; }
    public void setExecutionType(String executionType) { this.executionType = executionType; }

    public Integer getThreshold() { return threshold; }
    public void setThreshold(Integer threshold) { this.threshold = threshold; }

    public String getPolicyData() { return policyData; }
    public void setPolicyData(String policyData) { this.policyData = policyData; }

    public Long getCreatedAt() { return createdAt; }
    public void setCreatedAt(Long createdAt) { this.createdAt = createdAt; }

    public Long getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Long updatedAt) { this.updatedAt = updatedAt; }
}
