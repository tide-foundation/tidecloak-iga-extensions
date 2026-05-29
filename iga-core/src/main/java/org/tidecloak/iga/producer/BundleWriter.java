package org.tidecloak.iga.producer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;

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
 * <h2>Wire format</h2>
 * <p>The bundle data structure is unchanged regardless of encoding — only the
 * serialization differs. Two encodings are supported:
 * <ul>
 *   <li>{@link Format#CBOR} (default) — Jackson's default CBOR encoding
 *       ({@code new ObjectMapper(new CBORFactory())}). Keys are CBOR text
 *       strings, ints are CBOR uints, etc. — so the ork side can decode with
 *       {@code System.Formats.Cbor} cleanly. No gzip is applied; the bundle is
 *       not compressed at the transport or application layer.</li>
 *   <li>{@link Format#JSON} — pretty-printed Jackson JSON, byte-for-byte
 *       compatible with prior behavior; the ork parser is whitespace-agnostic.</li>
 * </ul>
 *
 * <p>The ork side trusts the parsed shape and verifies no signature (design §2),
 * so no RFC-8785/JCS canonicalization is required here.
 */
public final class BundleWriter {

    /** Output encoding for the bundle. */
    public enum Format {
        /** Jackson CBOR (default); decode-compatible with C# {@code System.Formats.Cbor}. */
        CBOR,
        /** Pretty-printed Jackson JSON (byte-identical to the prior implementation). */
        JSON
    }

    private final ObjectMapper jsonMapper;
    private final ObjectMapper cborMapper;

    public BundleWriter() {
        this.jsonMapper = new ObjectMapper();
        // Pretty for fixture readability; the ork parser is whitespace-agnostic.
        this.jsonMapper.enable(com.fasterxml.jackson.databind.SerializationFeature.INDENT_OUTPUT);
        // Default CBOR encoding — keys as CBOR text strings, ints as CBOR uints.
        this.cborMapper = new ObjectMapper(new CBORFactory());
    }

    /**
     * Build the bundle as a byte[] in the given format.
     *
     * @param realmId   the hoisted realm UUID.
     * @param req       the export request (supplies {@code request.t/c/s/aud}).
     * @param token     the compact JWS access/ID token.
     * @param envelopes the closure of attestation-unit envelopes.
     * @param format    output encoding (CBOR or JSON).
     */
    public byte[] write(String realmId, ExportRequest req, String token,
                        List<AttestationEnvelope> envelopes, Format format) {
        ObjectMapper mapper = (format == Format.JSON) ? jsonMapper : cborMapper;
        try {
            return mapper.writeValueAsBytes(buildBundleMap(realmId, req, token, envelopes));
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException(
                    "bundle serialization failed (" + format + "): " + e.getMessage(), e);
        }
    }

    /**
     * Backwards-compatible JSON shortcut — equivalent to
     * {@code write(realmId, req, token, envelopes, Format.JSON)}.
     */
    public byte[] write(String realmId, ExportRequest req, String token,
                        List<AttestationEnvelope> envelopes) {
        return write(realmId, req, token, envelopes, Format.JSON);
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
