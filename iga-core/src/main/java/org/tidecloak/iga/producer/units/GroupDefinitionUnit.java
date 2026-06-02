package org.tidecloak.iga.producer.units;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Unit 6 ({@code group_definition}) — definition bundle, target = group UUID.
 * Mirrors ork {@code GroupDefinitionAttestationUnit}. {@code parent_group_id} is
 * {@code null} for top-level groups (KC's literal single-space sentinel is
 * folded to null by the producer; the ork {@code GetGroupParentId} folds it
 * again defensively). {@code type} is the {@link GroupType} enum wire string.
 */
public final class GroupDefinitionUnit extends AttestationUnit {

    private final String groupId;
    private final String name;
    private final String parentGroupId;
    private final GroupType type;

    public GroupDefinitionUnit(String realmId, String groupId, String name,
                               String parentGroupId, GroupType type) {
        super(realmId, groupId);
        this.groupId = groupId;
        this.name = name;
        this.parentGroupId = parentGroupId;
        this.type = type;
    }

    @Override
    public AttestationUnitType type() {
        return AttestationUnitType.GROUP_DEFINITION;
    }

    @Override
    public Map<String, Object> payload() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("group_id", groupId);
        p.put("name", name);
        p.put("parent_group_id", parentGroupId); // null for top-level
        p.put("type", type.name());
        return p;
    }
}
