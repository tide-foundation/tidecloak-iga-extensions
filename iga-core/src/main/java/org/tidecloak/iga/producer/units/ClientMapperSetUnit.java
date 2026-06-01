package org.tidecloak.iga.producer.units;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Unit 13 ({@code client_mapper_set}) — linkage set, target = client UUID.
 * Mirrors ork {@code ClientMapperSetAttestationUnit}. {@code protocol_mapper_ids}
 * is the complete set of PROTOCOL_MAPPER ids attached directly to the client
 * (with the JWT-body-irrelevant factories removed by the producer, matching the
 * skipped {@code protocol_mapper} envelopes).
 */
public final class ClientMapperSetUnit extends AttestationUnit {

    private final String clientIdUuid;
    private final List<String> protocolMapperIds;

    public ClientMapperSetUnit(String realmId, String clientIdUuid,
                               List<String> protocolMapperIds) {
        super(realmId, clientIdUuid);
        this.clientIdUuid = clientIdUuid;
        this.protocolMapperIds = protocolMapperIds;
    }

    @Override
    public String unitType() {
        return "client_mapper_set";
    }

    @Override
    public Map<String, Object> payload() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("client_id_uuid", clientIdUuid);
        p.put("realm_id", realmId);
        p.put("protocol_mapper_ids", protocolMapperIds);
        return p;
    }
}
