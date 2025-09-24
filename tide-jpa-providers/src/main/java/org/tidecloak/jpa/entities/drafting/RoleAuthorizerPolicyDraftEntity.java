package org.tidecloak.jpa.entities.drafting;

import jakarta.persistence.*;
import org.keycloak.models.jpa.entities.RoleEntity;

@Entity
@Table(name = "ROLE_AUTHORIZER_POLICY_DRAFT")
@NamedQueries({
    @NamedQuery(name="getRoleApDraftByRoleId",
        query="SELECT e FROM RoleAuthorizerPolicyDraftEntity e WHERE e.role.id = :roleId"),
    @NamedQuery(name="getRoleApDraftByRequestId",
        query="SELECT e FROM RoleAuthorizerPolicyDraftEntity e WHERE e.changeRequestId = :requestId")
})
public class RoleAuthorizerPolicyDraftEntity {

    @Id
    @Column(name = "ID", length = 36)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "ROLE_ID", nullable = false)
    private RoleEntity role;

    @Column(name = "CHANGE_REQUEST_ID", nullable = false, length = 64)
    private String changeRequestId;

    @Lob
    @Column(name = "AP_COMPACT")
    private String apCompact; // compact or JSON

    @Column(name = "AP_SIG", length = 4096)
    private String apSig;

    @Column(name = "CREATED_TIMESTAMP")
    private Long createdTimestamp;

    public RoleAuthorizerPolicyDraftEntity() {}

    // Getters/Setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public RoleEntity getRole() { return role; }
    public void setRole(RoleEntity role) { this.role = role; }

    public String getChangeRequestId() { return changeRequestId; }
    public void setChangeRequestId(String changeRequestId) { this.changeRequestId = changeRequestId; }

    public String getApCompact() { return apCompact; }
    public void setApCompact(String apCompact) { this.apCompact = apCompact; }

    public String getApSig() { return apSig; }
    public void setApSig(String apSig) { this.apSig = apSig; }

    public Long getCreatedTimestamp() { return createdTimestamp; }
    public void setCreatedTimestamp(Long createdTimestamp) { this.createdTimestamp = createdTimestamp; }
}
