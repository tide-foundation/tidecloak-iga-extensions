package org.tidecloak.iga.producer.units;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Unit 17 ({@code organization_definition}) — definition bundle, target = org UUID.
 * Mirrors ork {@code OrganizationDefinitionAttestationUnit}. {@code alias} is the
 * literal {@code organization} claim value; {@code group_id} is the reverse FK the
 * engine walks to the backing KEYCLOAK_GROUP (type=ORGANIZATION).
 */
public final class OrganizationDefinitionUnit extends AttestationUnit {

    private final String orgId;
    private final String alias;
    private final boolean enabled;
    private final String groupId;

    public OrganizationDefinitionUnit(String realmId, String orgId, String alias,
                                      boolean enabled, String groupId) {
        super(realmId, orgId);
        this.orgId = orgId;
        this.alias = alias;
        this.enabled = enabled;
        this.groupId = groupId;
    }

    @Override
    public AttestationUnitType type() {
        return AttestationUnitType.ORGANIZATION_DEFINITION;
    }

    @Override
    public Map<String, Object> payload() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("org_id", orgId);
        p.put("alias", alias);
        p.put("enabled", enabled);
        p.put("group_id", groupId);
        return p;
    }
}
