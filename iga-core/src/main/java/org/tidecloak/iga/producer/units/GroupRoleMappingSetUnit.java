package org.tidecloak.iga.producer.units;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Unit 10 ({@code group_role_mapping_set}) — linkage set, target = group UUID.
 * Mirrors ork {@code GroupRoleMappingSetAttestationUnit}. {@code role_ids} is the
 * complete GROUP_ROLE_MAPPING child set for the group (RAW stored rows).
 */
public final class GroupRoleMappingSetUnit extends AttestationUnit {

    private final String groupId;
    private final List<String> roleIds;

    public GroupRoleMappingSetUnit(String realmId, String groupId, List<String> roleIds) {
        super(realmId, groupId);
        this.groupId = groupId;
        this.roleIds = roleIds;
    }

    /** The complete GROUP_ROLE_MAPPING child set (role ids) — used by the commit-time signer. */
    public List<String> roleIds() {
        return roleIds;
    }

    @Override
    public AttestationUnitType type() {
        return AttestationUnitType.GROUP_ROLE_MAPPING_SET;
    }

    @Override
    public Map<String, Object> payload() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("group_id", groupId);
        p.put("role_ids", roleIds);
        return p;
    }
}
