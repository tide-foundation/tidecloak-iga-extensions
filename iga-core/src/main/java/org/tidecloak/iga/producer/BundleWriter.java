package org.tidecloak.iga.producer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import org.tidecloak.iga.producer.units.AttestationUnit;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Serializes the {@code (units + token + TokenRequest)} bundle into the wire
 * format the ork deserializer consumes. Each {@code units[]} entry is now a
 * SELF-CONTAINED FULL ENVELOPE (the unit's own {@link AttestationUnit#toEnvelopeMap()}):
 *
 * <pre>
 * { "realm_id": "&lt;uuid&gt;", "schema_version": 1,
 *   "request": { "t": "access|id", "c": "&lt;clientId&gt;", "s": "&lt;raw scope&gt;", "aud": null|["..."] },
 *   "token": "&lt;compact JWS&gt;",
 *   "units": [
 *     { "unit_type": "&lt;wire&gt;", "schema_version": 1, "realm_id": "&lt;uuid&gt;",
 *       "target_id": "&lt;pk&gt;", "payload": { ... INCLUDES realm_id ... } },
 *     ...
 *   ] }
 * </pre>
 *
 * <p><b>Full-envelope format (no more compact {@code {u,t,p}} hoisting).</b> The
 * previous wire form hoisted {@code realm_id}/{@code schema_version} to the bundle
 * root and stripped {@code realm_id} from each unit's {@code p}; the ork side then
 * re-expanded. That hoisting is GONE: every unit now carries its own
 * {@code unit_type, schema_version, realm_id, target_id, payload} (with
 * {@code payload.realm_id}), so each entry deserializes directly into the ork
 * five-key envelope and feeds {@code AttestationUnitFactory.Create} with no
 * re-injection. The bundle root still carries {@code realm_id}/{@code schema_version}
 * as bundle metadata; the per-unit copies are the self-contained design.
 *
 * <h2>Encoding</h2>
 * <p>The bundle data structure is unchanged regardless of encoding — only the
 * serialization differs. Two encodings are supported:
 * <ul>
 *   <li>{@link Format#CBOR} (default) — Jackson's default CBOR encoding
 *       ({@code new ObjectMapper(new CBORFactory())}). Keys are CBOR text
 *       strings, ints are CBOR uints, etc. — so the ork side can decode with
 *       {@code System.Formats.Cbor} cleanly. No gzip is applied.</li>
 *   <li>{@link Format#JSON} — pretty-printed Jackson JSON; the ork parser is
 *       whitespace-agnostic.</li>
 * </ul>
 *
 * <p>The ork side trusts the parsed shape and verifies no signature,
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
     * @param realmId the bundle-metadata realm UUID (each unit also carries its own).
     * @param req     the export request (supplies {@code request.t/c/s/aud}).
     * @param token   the compact JWS access/ID token.
     * @param units   the closure of typed attestation units.
     * @param format  output encoding (CBOR or JSON).
     */
    public byte[] write(String realmId, ExportRequest req, String token,
                        List<AttestationUnit> units, Format format) {
        ObjectMapper mapper = (format == Format.JSON) ? jsonMapper : cborMapper;
        try {
            return mapper.writeValueAsBytes(buildBundleMap(realmId, req, token, units));
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException(
                    "bundle serialization failed (" + format + "): " + e.getMessage(), e);
        }
    }

    /**
     * Backwards-compatible JSON shortcut — equivalent to
     * {@code write(realmId, req, token, units, Format.JSON)}.
     */
    public byte[] write(String realmId, ExportRequest req, String token,
                        List<AttestationUnit> units) {
        return write(realmId, req, token, units, Format.JSON);
    }

    /** The bundle as an ordered map (exposed for tests / direct inspection). */
    public Map<String, Object> buildBundleMap(String realmId, ExportRequest req, String token,
                                              List<AttestationUnit> units) {
        Map<String, Object> bundle = new LinkedHashMap<>();
        bundle.put("realm_id", realmId);
        bundle.put("schema_version", AttestationUnit.SCHEMA_VERSION);

        Map<String, Object> request = new LinkedHashMap<>();
        request.put("t", req.tokenType().name());      // "access" | "id"
        request.put("c", req.clientId());
        request.put("s", req.scope());                  // raw requested scope (may be null)
        request.put("aud", req.requestedAudience());    // null | ["..."]
        bundle.put("request", request);

        bundle.put("token", token);

        // Each units[] entry is the unit's FULL five-key envelope (self-contained).
        List<Object> envelopes = new ArrayList<>(units.size());
        for (AttestationUnit unit : units) {
            envelopes.add(unit.toEnvelopeMap());
        }
        bundle.put("units", envelopes);
        return bundle;
    }
}
