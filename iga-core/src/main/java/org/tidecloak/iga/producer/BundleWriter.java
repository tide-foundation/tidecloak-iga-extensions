package org.tidecloak.iga.producer;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Serializes the {@code (envelopes + token + TokenRequest)} bundle into the
 * LOCKED compact wire format the ork deserializer consumes:
 *
 * <pre>
 * { "realm_id": "&lt;uuid&gt;", "schema_version": 1,
 *   "request": { "t": "access|id", "c": "&lt;clientId&gt;", "s": "&lt;raw scope&gt;", "aud": null|["..."] },
 *   "token": "&lt;compact JWS&gt;",
 *   "units": [ { "u": "&lt;unit_type&gt;", "t": "&lt;target_id&gt;", "p": { &lt;payload WITHOUT realm_id&gt; } } ] }
 * </pre>
 *
 * <p>{@code realm_id} and {@code schema_version} are HOISTED to the bundle root
 * (every unit shares them); each unit's {@code p} object therefore OMITS
 * {@code realm_id}. The ork deserializer re-expands each {@code u/t/p} back into
 * the five-key envelope ({@code unit_type, schema_version, realm_id, target_id,
 * payload}), re-injecting the hoisted {@code realm_id}/{@code schema_version}
 * AND {@code payload.realm_id}, before {@code AttestationUnitFactory.Create}.
 *
 * <p>No gzip for M1 (design §10). Output is plain Jackson JSON — the ork side
 * trusts the parsed shape and verifies no signature (design §2), so no
 * RFC-8785/JCS canonicalization is required here.
 */
public final class BundleWriter {

    private final ObjectMapper mapper;

    public BundleWriter() {
        this.mapper = new ObjectMapper();
        // Pretty for fixture readability; the ork parser is whitespace-agnostic.
        this.mapper.enable(com.fasterxml.jackson.databind.SerializationFeature.INDENT_OUTPUT);
    }

    /**
     * Build the bundle as a JSON byte[].
     *
     * @param realmId   the hoisted realm UUID.
     * @param req       the export request (supplies {@code request.t/c/s/aud}).
     * @param token     the compact JWS access/ID token.
     * @param envelopes the closure of attestation-unit envelopes.
     */
    public byte[] write(String realmId, ExportRequest req, String token,
                        List<AttestationEnvelope> envelopes) {
        try {
            return mapper.writeValueAsBytes(buildBundleMap(realmId, req, token, envelopes));
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("bundle serialization failed: " + e.getMessage(), e);
        }
    }

    /** The bundle as an ordered map (exposed for tests / direct inspection). */
    public Map<String, Object> buildBundleMap(String realmId, ExportRequest req, String token,
                                              List<AttestationEnvelope> envelopes) {
        Map<String, Object> bundle = new LinkedHashMap<>();
        bundle.put("realm_id", realmId);
        bundle.put("schema_version", AttestationEnvelope.SCHEMA_VERSION);

        Map<String, Object> request = new LinkedHashMap<>();
        request.put("t", req.tokenType().name());      // "access" | "id"
        request.put("c", req.clientId());
        request.put("s", req.scope());                  // raw requested scope (may be null)
        request.put("aud", req.requestedAudience());    // null | ["..."]
        bundle.put("request", request);

        bundle.put("token", token);

        List<Object> units = new ArrayList<>(envelopes.size());
        for (AttestationEnvelope env : envelopes) {
            Map<String, Object> u = new LinkedHashMap<>();
            u.put("u", env.unitType());
            u.put("t", env.targetId());
            u.put("p", env.payloadWithoutRealmId());
            units.add(u);
        }
        bundle.put("units", units);
        return bundle;
    }
}
