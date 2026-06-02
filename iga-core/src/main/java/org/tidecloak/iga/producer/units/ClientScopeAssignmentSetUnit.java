package org.tidecloak.iga.producer.units;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Unit 12 ({@code client_scope_assignment_set}) — linkage set,
 * target = client UUID. Mirrors ork
 * {@code ClientScopeAssignmentSetAttestationUnit}. Each assignment carries
 * {@code default=true} (default scope) / {@code false} (optional scope).
 */
public final class ClientScopeAssignmentSetUnit extends AttestationUnit {

    private final String clientIdUuid;
    private final List<ScopeAssignment> assignments;

    public ClientScopeAssignmentSetUnit(String realmId, String clientIdUuid,
                                        List<ScopeAssignment> assignments) {
        super(realmId, clientIdUuid);
        this.clientIdUuid = clientIdUuid;
        this.assignments = assignments;
    }

    @Override
    public AttestationUnitType type() {
        return AttestationUnitType.CLIENT_SCOPE_ASSIGNMENT_SET;
    }

    @Override
    public Map<String, Object> payload() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("client_id_uuid", clientIdUuid);
        p.put("assignments", assignments(assignments));
        return p;
    }
}
