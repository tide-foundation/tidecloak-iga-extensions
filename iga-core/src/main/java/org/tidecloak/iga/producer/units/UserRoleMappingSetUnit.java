package org.tidecloak.iga.producer.units;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Unit 8 ({@code user_role_mapping_set}) — linkage set, target = user UUID.
 * Mirrors ork {@code UserRoleMappingSetAttestationUnit}. {@code role_ids} is the
 * RAW stored USER_ROLE_MAPPING child set (incl. the implicit
 * {@code default-roles-<realm>} grant).
 */
public final class UserRoleMappingSetUnit extends AttestationUnit {

    private final String userId;
    private final List<String> roleIds;

    public UserRoleMappingSetUnit(String realmId, String userId, List<String> roleIds) {
        super(realmId, userId);
        this.userId = userId;
        this.roleIds = roleIds;
    }

    @Override
    public String unitType() {
        return "user_role_mapping_set";
    }

    @Override
    public Map<String, Object> payload() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("user_id", userId);
        p.put("realm_id", realmId);
        p.put("role_ids", roleIds);
        return p;
    }
}
