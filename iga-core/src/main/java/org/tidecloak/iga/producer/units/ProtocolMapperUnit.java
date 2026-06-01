package org.tidecloak.iga.producer.units;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Unit 4 ({@code protocol_mapper}) — definition bundle, target = mapper UUID.
 * Mirrors ork {@code ProtocolMapperAttestationUnit}. {@code parent_type} is the
 * {@link ParentType} enum wire string; {@code protocol_mapper} is the factory id.
 */
public final class ProtocolMapperUnit extends AttestationUnit {

    private final String protocolMapperId;
    private final ParentType parentType;
    private final String parentId;
    private final String protocol;
    private final String protocolMapper;
    private final List<NameValue> config;

    public ProtocolMapperUnit(String realmId, String protocolMapperId, ParentType parentType,
                              String parentId, String protocol, String protocolMapper,
                              List<NameValue> config) {
        super(realmId, protocolMapperId);
        this.protocolMapperId = protocolMapperId;
        this.parentType = parentType;
        this.parentId = parentId;
        this.protocol = protocol;
        this.protocolMapper = protocolMapper;
        this.config = config;
    }

    @Override
    public String unitType() {
        return "protocol_mapper";
    }

    @Override
    public Map<String, Object> payload() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("protocol_mapper_id", protocolMapperId);
        p.put("realm_id", realmId);
        p.put("parent_type", parentType.name());
        p.put("parent_id", parentId);
        p.put("protocol", protocol);
        p.put("protocol_mapper", protocolMapper);
        p.put("config", nameValues(config));
        return p;
    }
}
