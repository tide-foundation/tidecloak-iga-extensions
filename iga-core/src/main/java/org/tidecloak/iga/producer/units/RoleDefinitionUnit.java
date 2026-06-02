package org.tidecloak.iga.producer.units;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Unit 5 ({@code role_definition}) — definition bundle, target = role UUID.
 * Mirrors ork {@code RoleDefinitionAttestationUnit}. {@code container_id} is the
 * owning client's UUID for client roles, else the realm id.
 */
public final class RoleDefinitionUnit extends AttestationUnit {

    private final String roleId;
    private final String name;
    private final boolean clientRole;
    private final String containerId;

    public RoleDefinitionUnit(String realmId, String roleId, String name,
                              boolean clientRole, String containerId) {
        super(realmId, roleId);
        this.roleId = roleId;
        this.name = name;
        this.clientRole = clientRole;
        this.containerId = containerId;
    }

    @Override
    public AttestationUnitType type() {
        return AttestationUnitType.ROLE_DEFINITION;
    }

    @Override
    public Map<String, Object> payload() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("role_id", roleId);
        p.put("name", name);
        p.put("client_role", clientRole);
        p.put("container_id", containerId);
        return p;
    }
}
