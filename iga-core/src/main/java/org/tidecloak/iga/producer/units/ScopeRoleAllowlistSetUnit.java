package org.tidecloak.iga.producer.units;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Unit 15 ({@code scope_role_allowlist_set}) — linkage set,
 * target = client OR scope UUID (the {@code parent_id}). Mirrors ork
 * {@code ScopeRoleAllowlistSetAttestationUnit}. Source is SCOPE_MAPPING
 * ({@code parent_type=client}) or CLIENT_SCOPE_ROLE_MAPPING
 * ({@code parent_type=client_scope}). An empty {@code role_ids} is emitted
 * explicitly (the ork distinguishes "no entries" from "missing").
 */
public final class ScopeRoleAllowlistSetUnit extends AttestationUnit {

    private final ParentType parentType;
    private final String parentId;
    private final List<String> roleIds;

    public ScopeRoleAllowlistSetUnit(String realmId, ParentType parentType,
                                     String parentId, List<String> roleIds) {
        super(realmId, parentId);
        this.parentType = parentType;
        this.parentId = parentId;
        this.roleIds = roleIds;
    }

    @Override
    public AttestationUnitType type() {
        return AttestationUnitType.SCOPE_ROLE_ALLOWLIST_SET;
    }

    @Override
    public Map<String, Object> payload() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("parent_type", parentType.name());
        p.put("parent_id", parentId);
        p.put("role_ids", roleIds);
        return p;
    }
}
