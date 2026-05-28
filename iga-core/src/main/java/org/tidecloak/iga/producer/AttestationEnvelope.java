package org.tidecloak.iga.producer;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One attestation-unit envelope, in the producer's internal (pre-serialization)
 * form. Mirrors the ork five-key envelope
 * ({@code unit_type, schema_version, realm_id, target_id, payload}) —
 * {@code AttestationUnit.cs:143-162}.
 *
 * <p>{@link #payload} is the FULL payload map and INCLUDES {@code realm_id}
 * (the ork base parser asserts {@code envelope.realm_id == payload.realm_id}).
 * The bundle writer hoists {@code realm_id}/{@code schema_version} to the
 * bundle root and strips {@code realm_id} out of the per-unit {@code p} object;
 * the ork deserializer re-injects both before
 * {@code AttestationUnitFactory.Create}. See the design §10 Bundle format.
 *
 * <p>Field ORDER inside the payload map is preserved (LinkedHashMap) only as a
 * convenience for readable fixtures — the ork parser reads every field by name
 * and re-sorts arrays on ingest, so order is not load-bearing.
 */
public final class AttestationEnvelope {

    /** Only schema_version 1 is defined (matches ork SupportedSchemaVersion). */
    public static final int SCHEMA_VERSION = 1;

    private final String unitType;
    private final String realmId;
    private final String targetId;
    private final Map<String, Object> payload;

    /**
     * @param unitType one of the 18 wire strings (snake_case, case-sensitive).
     * @param realmId  the realm UUID; must equal {@code payload.realm_id}.
     * @param targetId the unit's payload primary key (the ork
     *                 {@code RequireTargetMatches} contract).
     * @param payload  the full ordered payload map INCLUDING {@code realm_id}.
     */
    public AttestationEnvelope(String unitType, String realmId, String targetId,
                               Map<String, Object> payload) {
        this.unitType = unitType;
        this.realmId = realmId;
        this.targetId = targetId;
        this.payload = payload;
    }

    public String unitType() {
        return unitType;
    }

    public String realmId() {
        return realmId;
    }

    public String targetId() {
        return targetId;
    }

    /** Full payload (with realm_id). */
    public Map<String, Object> payload() {
        return payload;
    }

    /**
     * The per-unit payload with {@code realm_id} removed — the {@code p} object
     * the compact bundle carries (the ork re-injects the hoisted realm_id).
     * Returns a copy so the original (full) payload is left intact.
     */
    public Map<String, Object> payloadWithoutRealmId() {
        Map<String, Object> copy = new LinkedHashMap<>(payload);
        copy.remove("realm_id");
        return copy;
    }
}
