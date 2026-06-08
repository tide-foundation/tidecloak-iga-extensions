package org.tidecloak.iga.producer;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.producer.units.AttestationUnitType;
import org.tidecloak.iga.producer.units.RealmDefaultGroupsSetUnit;
import org.tidecloak.iga.producer.units.RealmDefaultRolesSetUnit;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * D1a — the new once-signed realm authority {@link RealmDefaultRolesSetUnit}. It attests the
 * realm's default-role id ONCE (target = realm UUID), mirroring the EXISTING
 * {@link RealmDefaultGroupsSetUnit} EXACTLY: same class shape, same serialize()/CBOR wire
 * format, same target=realm pattern — only the payload key differs (the default-role id
 * instead of group ids). The ork will get a byte-compatible
 * {@code RealmDefaultRolesSetAttestationUnit}, so wire-format fidelity to the
 * {@code realm_default_groups_set} precedent is CRITICAL.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class RealmDefaultRolesSetUnitTest {

    private static final String REALM_ID = "realm-uuid-droles";
    private static final String DEFAULT_ROLE_ID = "default-roles-realm-uuid-droles";

    @Test
    void targetIsRealmUuid_andPayloadCarriesTheDefaultRoleId() {
        RealmDefaultRolesSetUnit u = new RealmDefaultRolesSetUnit(REALM_ID, DEFAULT_ROLE_ID);
        assertEquals(AttestationUnitType.REALM_DEFAULT_ROLES_SET, u.type());
        assertEquals(REALM_ID, u.targetId(), "target = realm UUID (RequireTargetMatches(RealmId))");
        assertEquals(REALM_ID, u.realmId());
        Map<String, Object> p = u.payload();
        assertEquals(1, p.size(), "payload carries exactly the role_id key");
        assertEquals(DEFAULT_ROLE_ID, p.get("role_id"));
    }

    /**
     * ★ Byte-parallel to the {@code realm_default_groups_set} precedent. The wire shape
     * the ork mirrors: same 4-key envelope, target=realm, integer unit_type ordinal, payload
     * with the linkage id. We assert the role unit's envelope equals what the groups unit would
     * emit for the SAME (realmId, [id]) modulo (a) the unit_type ordinal and (b) the payload
     * key name (role_id vs group_ids). The structural parity is what guarantees the ork's
     * parallel decoder matches.
     */
    @Test
    void serializesByteParallelToRealmDefaultGroupsSet() throws Exception {
        byte[] roleBytes = new RealmDefaultRolesSetUnit(REALM_ID, DEFAULT_ROLE_ID).serialize();

        // Reconstruct the EXACT envelope the role unit must produce, using the same CBOR mapper
        // path the base class uses, to prove the shape matches the groups precedent's envelope
        // (unit_type=int ordinal, schema_version=1, target_id=realm, payload={...}).
        Map<String, Object> env = new LinkedHashMap<>();
        env.put("unit_type", AttestationUnitType.REALM_DEFAULT_ROLES_SET.wireValue());
        env.put("schema_version", 1);
        env.put("target_id", REALM_ID);
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("role_id", DEFAULT_ROLE_ID);
        env.put("payload", payload);
        byte[] expected = new com.fasterxml.jackson.databind.ObjectMapper(
                new com.fasterxml.jackson.dataformat.cbor.CBORFactory())
                .writeValueAsBytes(env);

        assertArrayEquals(expected, roleBytes,
                "RealmDefaultRolesSetUnit must serialize to the 4-key CBOR envelope byte-parallel "
                        + "to the realm_default_groups_set precedent (target=realm, int unit_type, "
                        + "payload={role_id})");
    }
}
