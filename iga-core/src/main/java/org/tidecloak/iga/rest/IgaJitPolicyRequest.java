package org.tidecloak.iga.rest;

/**
 * What an application asks for when it wants a time-limited grant signed.
 *
 * <p>Intent, not bytes. The policy is built server-side by
 * {@link org.tidecloak.iga.providers.IgaJitPolicyService}, which is the only place that knows the
 * realm's access token lifespan and so the only place that can apply it as the fallback expiry.
 * An application posting pre-built bytes would have to duplicate that, and would drift from it.</p>
 *
 * <p>{@code policy} remains accepted for a caller that has already built one; when set, the fields
 * below are ignored.</p>
 */
public class IgaJitPolicyRequest {

    private String name;
    private String policy;

    private String contractId;
    private String vuid;
    private String resource;
    private String grantedRole;
    private String assessmentId;
    private String tier;
    /** Epoch seconds. Null takes the realm's access token lifespan from now. */
    private Long expiry;

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getPolicy() { return policy; }
    public void setPolicy(String policy) { this.policy = policy; }

    public String getContractId() { return contractId; }
    public void setContractId(String contractId) { this.contractId = contractId; }

    public String getVuid() { return vuid; }
    public void setVuid(String vuid) { this.vuid = vuid; }

    public String getResource() { return resource; }
    public void setResource(String resource) { this.resource = resource; }

    public String getGrantedRole() { return grantedRole; }
    public void setGrantedRole(String grantedRole) { this.grantedRole = grantedRole; }

    public String getAssessmentId() { return assessmentId; }
    public void setAssessmentId(String assessmentId) { this.assessmentId = assessmentId; }

    public String getTier() { return tier; }
    public void setTier(String tier) { this.tier = tier; }

    public Long getExpiry() { return expiry; }
    public void setExpiry(Long expiry) { this.expiry = expiry; }
}
