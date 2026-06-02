package org.tidecloak.iga.producer.units;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Unit 14 ({@code client_scope_mapper_set}) — linkage set, target = scope UUID.
 * Mirrors ork {@code ClientScopeMapperSetAttestationUnit}. Same JWT-body-irrelevant
 * factory filter as unit 13.
 */
public final class ClientScopeMapperSetUnit extends AttestationUnit {

    private final String clientScopeId;
    private final List<String> protocolMapperIds;

    public ClientScopeMapperSetUnit(String realmId, String clientScopeId,
                                    List<String> protocolMapperIds) {
        super(realmId, clientScopeId);
        this.clientScopeId = clientScopeId;
        this.protocolMapperIds = protocolMapperIds;
    }

    @Override
    public AttestationUnitType type() {
        return AttestationUnitType.CLIENT_SCOPE_MAPPER_SET;
    }

    @Override
    public Map<String, Object> payload() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("client_scope_id", clientScopeId);
        p.put("protocol_mapper_ids", protocolMapperIds);
        return p;
    }
}
