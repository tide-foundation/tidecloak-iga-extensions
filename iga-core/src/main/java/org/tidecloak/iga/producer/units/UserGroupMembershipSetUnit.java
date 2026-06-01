package org.tidecloak.iga.producer.units;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Unit 9 ({@code user_group_membership_set}) — linkage set, target = user UUID.
 * Mirrors ork {@code UserGroupMembershipSetAttestationUnit}. {@code group_ids} is
 * the RAW stored USER_GROUP_MEMBERSHIP child set.
 */
public final class UserGroupMembershipSetUnit extends AttestationUnit {

    private final String userId;
    private final List<String> groupIds;

    public UserGroupMembershipSetUnit(String realmId, String userId, List<String> groupIds) {
        super(realmId, userId);
        this.userId = userId;
        this.groupIds = groupIds;
    }

    @Override
    public String unitType() {
        return "user_group_membership_set";
    }

    @Override
    public Map<String, Object> payload() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("user_id", userId);
        p.put("realm_id", realmId);
        p.put("group_ids", groupIds);
        return p;
    }
}
