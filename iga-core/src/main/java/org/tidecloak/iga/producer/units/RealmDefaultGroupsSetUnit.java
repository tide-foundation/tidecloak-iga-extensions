package org.tidecloak.iga.producer.units;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Unit 16 ({@code realm_default_groups_set}) — linkage set, target = realm UUID.
 * Mirrors ork {@code RealmDefaultGroupsSetAttestationUnit}. {@code group_ids} is
 * the complete REALM_DEFAULT_GROUPS set. Only load-bearing for flows that create
 * a user mid-issuance; emitted regardless to keep the closure honest.
 */
public final class RealmDefaultGroupsSetUnit extends AttestationUnit {

    private final List<String> groupIds;

    public RealmDefaultGroupsSetUnit(String realmId, List<String> groupIds) {
        // target = realm UUID = payload.realm_id (ork RequireTargetMatches(RealmId)).
        super(realmId, realmId);
        this.groupIds = groupIds;
    }

    @Override
    public String unitType() {
        return "realm_default_groups_set";
    }

    @Override
    public Map<String, Object> payload() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("realm_id", realmId);
        p.put("group_ids", groupIds);
        return p;
    }
}
