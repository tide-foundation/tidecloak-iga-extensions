package org.tidecloak.iga.producer.units;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Unit 11 ({@code role_composite_children_set}) — linkage set,
 * target = composite role UUID. Mirrors ork
 * {@code RoleCompositeChildrenSetAttestationUnit}. A non-composite role still
 * gets an attestation with an empty {@code child_role_ids}.
 */
public final class RoleCompositeChildrenSetUnit extends AttestationUnit {

    private final String compositeRoleId;
    private final List<String> childRoleIds;

    public RoleCompositeChildrenSetUnit(String realmId, String compositeRoleId,
                                        List<String> childRoleIds) {
        super(realmId, compositeRoleId);
        this.compositeRoleId = compositeRoleId;
        this.childRoleIds = childRoleIds;
    }

    @Override
    public AttestationUnitType type() {
        return AttestationUnitType.ROLE_COMPOSITE_CHILDREN_SET;
    }

    @Override
    public Map<String, Object> payload() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("composite_role_id", compositeRoleId);
        p.put("child_role_ids", childRoleIds);
        return p;
    }
}
