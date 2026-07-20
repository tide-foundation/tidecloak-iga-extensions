package org.tidecloak.iga.producer.units;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Unit 3 ({@code client_scope_config}) — definition bundle, target = scope UUID.
 * Mirrors ork {@code ClientScopeConfigAttestationUnit}.
 */
public final class ClientScopeConfigUnit extends AttestationUnit {

    private final String clientScopeId;
    private final String name;
    private final String protocol;
    private final List<NameValue> attributes;

    public ClientScopeConfigUnit(String realmId, String clientScopeId, String name,
                                 String protocol, List<NameValue> attributes) {
        super(realmId, clientScopeId);
        this.clientScopeId = clientScopeId;
        this.name = name;
        this.protocol = protocol;
        this.attributes = attributes;
    }

    @Override
    public AttestationUnitType type() {
        return AttestationUnitType.CLIENT_SCOPE_CONFIG;
    }

    @Override
    public Map<String, Object> payload() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("client_scope_id", clientScopeId);
        p.put("name", name);
        p.put("protocol", protocol);
        p.put("attributes", nameValues(attributes));
        return p;
    }
}
