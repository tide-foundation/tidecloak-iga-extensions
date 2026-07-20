package org.tidecloak.iga.producer.units;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Unit 18 ({@code organization_domain_set}) — linkage set, target = org UUID.
 * Mirrors ork {@code OrganizationDomainSetAttestationUnit}. {@code domains} is the
 * complete {@code (name, verified)} ORG_DOMAIN set for the org — a linkage set so
 * deletions are detectable.
 */
public final class OrganizationDomainSetUnit extends AttestationUnit {

    private final String orgId;
    private final List<OrgDomain> domains;

    public OrganizationDomainSetUnit(String realmId, String orgId, List<OrgDomain> domains) {
        super(realmId, orgId);
        this.orgId = orgId;
        this.domains = domains;
    }

    @Override
    public AttestationUnitType type() {
        return AttestationUnitType.ORGANIZATION_DOMAIN_SET;
    }

    @Override
    public Map<String, Object> payload() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("org_id", orgId);
        p.put("domains", domains(domains));
        return p;
    }
}
