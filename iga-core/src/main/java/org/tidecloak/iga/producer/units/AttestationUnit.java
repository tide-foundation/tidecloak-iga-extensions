package org.tidecloak.iga.producer.units;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Base for the 18 typed attestation units. Each concrete subclass mirrors the
 * corresponding ork C# unit class field-for-field
 * ({@code Ork/.../AttestationUnits/*.cs}) and builds the SAME payload map the
 * legacy {@code RealmAttestationExporter} emitted (the existing wire-key /
 * null-vs-empty-string conventions are the contract — preserved verbatim).
 *
 * <p>A unit is self-contained: it can {@link #serialize()} itself to a full
 * four-key CBOR envelope, and it can hand the writer that same envelope as an
 * ordered map via {@link #toEnvelopeMap()} so the bundle is assembled in one
 * pass. The two are byte-equivalent:
 * {@code serialize() == cborMapper().writeValueAsBytes(toEnvelopeMap())}.
 *
 * <h2>Envelope shape (matches ork {@code BaseAttestationUnit})</h2>
 * <pre>
 * { "unit_type":      "&lt;wire string&gt;",
 *   "schema_version": 1,
 *   "target_id":      "&lt;primary key of the parent entity&gt;",
 *   "payload":        { ... INCLUDES realm_id ... } }
 * </pre>
 * The envelope-level {@code realm_id} was DROPPED (envelope is now 4 keys).
 * The realm binding is carried by {@code payload.realm_id} — the payload still
 * INCLUDES {@code realm_id} (built by each subclass's {@code payload()} /
 * {@code BuildCanonicalPayload}). The ork side asserts the realm via
 * {@code payload.realm_id} now; there is no envelope/payload {@code realm_id}
 * equality check. Unlike the old compact {@code {u,t,p}} bundle form, each unit
 * still carries its OWN {@code unit_type}/{@code schema_version} so it is a
 * self-describing envelope on the wire.
 */
public abstract class AttestationUnit {

    /** Only schema_version 1 is defined (matches ork {@code SupportedSchemaVersion}). */
    public static final int SCHEMA_VERSION = 1;

    /**
     * Shared CBOR mapper — Jackson default CBOR encoding (smallest-int default,
     * keys as CBOR text strings, explicit nulls, bools as bools). Mirrors
     * {@code BundleWriter.cborMapper} so what ork's {@code System.Formats.Cbor}
     * reader expects on the bundle units matches a standalone {@link #serialize()}.
     */
    private static final ObjectMapper CBOR_MAPPER = new ObjectMapper(new CBORFactory());

    protected final String realmId;
    protected final String targetId;

    protected AttestationUnit(String realmId, String targetId) {
        this.realmId = realmId;
        this.targetId = targetId;
    }

    /** The ork {@code unit_type} wire string (snake_case, case-sensitive). */
    public abstract String unitType();

    public final int schemaVersion() {
        return SCHEMA_VERSION;
    }

    public final String realmId() {
        return realmId;
    }

    public final String targetId() {
        return targetId;
    }

    /**
     * The full, ordered payload map INCLUDING {@code realm_id}, keyed exactly as
     * the corresponding ork unit's {@code BuildCanonicalPayload}. Each subclass
     * preserves the legacy exporter's key set + null conventions.
     */
    public abstract Map<String, Object> payload();

    /**
     * The full four-key envelope as an ordered {@link LinkedHashMap}
     * ({@code unit_type, schema_version, target_id, payload}). The
     * bundle writer drops one of these per {@code units[]} entry. The realm
     * binding lives in {@code payload.realm_id}, not at the envelope level.
     */
    public final Map<String, Object> toEnvelopeMap() {
        Map<String, Object> env = new LinkedHashMap<>();
        env.put("unit_type", unitType());
        env.put("schema_version", SCHEMA_VERSION);
        env.put("target_id", targetId);
        env.put("payload", payload());
        return env;
    }

    /** CBOR of the full envelope. Equivalent to {@code cbor(toEnvelopeMap())}. */
    public final byte[] serialize() {
        try {
            return CBOR_MAPPER.writeValueAsBytes(toEnvelopeMap());
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException(
                    "attestation-unit CBOR serialization failed (" + unitType() + "): "
                            + e.getMessage(), e);
        }
    }

    // ---- shared payload-map builders (records -> ordered maps) --------------

    /** {@code [{name,value}]} list (single-valued attribute / config / mapper config). */
    protected static java.util.List<Map<String, Object>> nameValues(
            java.util.List<NameValue> items) {
        java.util.List<Map<String, Object>> out = new java.util.ArrayList<>(items.size());
        for (NameValue nv : items) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("name", nv.name());
            m.put("value", nv.value());
            out.add(m);
        }
        return out;
    }

    /** {@code [{name,values[]}]} list (unit 7 user attributes). */
    protected static java.util.List<Map<String, Object>> nameValuesMulti(
            java.util.List<NameValues> items) {
        java.util.List<Map<String, Object>> out = new java.util.ArrayList<>(items.size());
        for (NameValues nv : items) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("name", nv.name());
            m.put("values", nv.values());
            out.add(m);
        }
        return out;
    }

    /** {@code [{client_scope_id,default}]} list (unit 12). */
    protected static java.util.List<Map<String, Object>> assignments(
            java.util.List<ScopeAssignment> items) {
        java.util.List<Map<String, Object>> out = new java.util.ArrayList<>(items.size());
        for (ScopeAssignment a : items) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("client_scope_id", a.clientScopeId());
            m.put("default", a.isDefault());
            out.add(m);
        }
        return out;
    }

    /** {@code [{name,verified}]} list (unit 18). */
    protected static java.util.List<Map<String, Object>> domains(
            java.util.List<OrgDomain> items) {
        java.util.List<Map<String, Object>> out = new java.util.ArrayList<>(items.size());
        for (OrgDomain d : items) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("name", d.name());
            m.put("verified", d.verified());
            out.add(m);
        }
        return out;
    }
}
