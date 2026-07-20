package org.tidecloak.iga.producer.units;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Unit 1 ({@code realm_config}) — definition bundle, target = realm UUID.
 * Mirrors ork {@code RealmConfigAttestationUnit} field-for-field. Payload key
 * order + the producer's filtered {@code attributes} list (frontendUrl,
 * acr.loa.map, organizationsEnabled, each emitted as {@code ""} when null)
 * match the legacy exporter exactly.
 */
public final class RealmConfigUnit extends AttestationUnit {

    private final String name;
    private final int accessTokenLifespanSeconds;
    private final int accessTokenLifespanForImplicitFlowSeconds;
    private final int ssoSessionIdleTimeoutSeconds;
    private final int ssoSessionMaxLifespanSeconds;
    private final int clientSessionIdleTimeoutSeconds;
    private final int clientSessionMaxLifespanSeconds;
    private final int offlineSessionIdleTimeoutSeconds;
    private final boolean offlineSessionMaxLifespanEnabled;
    private final int offlineSessionMaxLifespanSeconds;
    private final List<NameValue> attributes;

    public RealmConfigUnit(String realmId, String name,
                           int accessTokenLifespanSeconds,
                           int accessTokenLifespanForImplicitFlowSeconds,
                           int ssoSessionIdleTimeoutSeconds,
                           int ssoSessionMaxLifespanSeconds,
                           int clientSessionIdleTimeoutSeconds,
                           int clientSessionMaxLifespanSeconds,
                           int offlineSessionIdleTimeoutSeconds,
                           boolean offlineSessionMaxLifespanEnabled,
                           int offlineSessionMaxLifespanSeconds,
                           List<NameValue> attributes) {
        // target = realm UUID = payload.realm_id (ork RequireTargetMatches(RealmId)).
        super(realmId, realmId);
        this.name = name;
        this.accessTokenLifespanSeconds = accessTokenLifespanSeconds;
        this.accessTokenLifespanForImplicitFlowSeconds = accessTokenLifespanForImplicitFlowSeconds;
        this.ssoSessionIdleTimeoutSeconds = ssoSessionIdleTimeoutSeconds;
        this.ssoSessionMaxLifespanSeconds = ssoSessionMaxLifespanSeconds;
        this.clientSessionIdleTimeoutSeconds = clientSessionIdleTimeoutSeconds;
        this.clientSessionMaxLifespanSeconds = clientSessionMaxLifespanSeconds;
        this.offlineSessionIdleTimeoutSeconds = offlineSessionIdleTimeoutSeconds;
        this.offlineSessionMaxLifespanEnabled = offlineSessionMaxLifespanEnabled;
        this.offlineSessionMaxLifespanSeconds = offlineSessionMaxLifespanSeconds;
        this.attributes = attributes;
    }

    @Override
    public AttestationUnitType type() {
        return AttestationUnitType.REALM_CONFIG;
    }

    @Override
    public Map<String, Object> payload() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("name", name);
        p.put("access_token_lifespan_seconds", accessTokenLifespanSeconds);
        p.put("access_token_lifespan_for_implicit_flow_seconds",
                accessTokenLifespanForImplicitFlowSeconds);
        p.put("sso_session_idle_timeout_seconds", ssoSessionIdleTimeoutSeconds);
        p.put("sso_session_max_lifespan_seconds", ssoSessionMaxLifespanSeconds);
        p.put("client_session_idle_timeout_seconds", clientSessionIdleTimeoutSeconds);
        p.put("client_session_max_lifespan_seconds", clientSessionMaxLifespanSeconds);
        p.put("offline_session_idle_timeout_seconds", offlineSessionIdleTimeoutSeconds);
        p.put("offline_session_max_lifespan_enabled", offlineSessionMaxLifespanEnabled);
        p.put("offline_session_max_lifespan_seconds", offlineSessionMaxLifespanSeconds);
        p.put("attributes", nameValues(attributes));
        return p;
    }
}
