package org.tidecloak.iga.producer.units;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Unit 2 ({@code client_config}) — definition bundle, target = client UUID.
 * Mirrors ork {@code ClientConfigAttestationUnit}.
 */
public final class ClientConfigUnit extends AttestationUnit {

    private final String clientIdUuid;
    private final String clientId;
    private final String protocol;
    private final boolean fullScopeAllowed;
    private final boolean serviceAccountsEnabled;
    private final List<String> webOrigins;
    private final List<NameValue> attributes;

    public ClientConfigUnit(String realmId, String clientIdUuid, String clientId,
                            String protocol, boolean fullScopeAllowed,
                            boolean serviceAccountsEnabled, List<String> webOrigins,
                            List<NameValue> attributes) {
        super(realmId, clientIdUuid);
        this.clientIdUuid = clientIdUuid;
        this.clientId = clientId;
        this.protocol = protocol;
        this.fullScopeAllowed = fullScopeAllowed;
        this.serviceAccountsEnabled = serviceAccountsEnabled;
        this.webOrigins = webOrigins;
        this.attributes = attributes;
    }

    @Override
    public String unitType() {
        return "client_config";
    }

    @Override
    public Map<String, Object> payload() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("client_id_uuid", clientIdUuid);
        p.put("client_id", clientId);
        p.put("realm_id", realmId);
        p.put("protocol", protocol);
        p.put("full_scope_allowed", fullScopeAllowed);
        p.put("service_accounts_enabled", serviceAccountsEnabled);
        p.put("web_origins", webOrigins);
        p.put("attributes", nameValues(attributes));
        return p;
    }
}
