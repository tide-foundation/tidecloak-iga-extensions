package org.tidecloak.iga.producer.units;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Unit 18 ({@code realm_default_roles_set}) — linkage authority, target = realm UUID.
 * Mirrors ork {@code RealmDefaultRolesSetAttestationUnit}. {@code role_id} is the realm's
 * single default-role id ({@code realm.getDefaultRole().getId()} — the
 * {@code default-roles-<realm>} composite that every user inherits). Signed ONCE at the
 * realm level; the universal-inherit covers every user, so the per-user default-role EDGE is
 * NOT signed (see {@code RealmAttestationExporter.userRoleMappingSet} /
 * {@code TideAttestor.buildUserRoleMappingSetUnit}, both of which EXCLUDE this id).
 *
 * <p>This class is the EXACT parallel of {@link RealmDefaultGroupsSetUnit}: same class shape,
 * same {@code serialize()}/CBOR four-key envelope, same {@code target=realm} pattern — only the
 * payload differs (a single {@code role_id} string instead of the {@code group_ids} list). The
 * ork gets a byte-compatible {@code RealmDefaultRolesSetAttestationUnit}, so wire-format fidelity
 * to the {@code realm_default_groups_set} precedent is the contract.
 */
public final class RealmDefaultRolesSetUnit extends AttestationUnit {

    private final String roleId;

    public RealmDefaultRolesSetUnit(String realmId, String roleId) {
        // target = realm UUID = payload.realm_id (ork RequireTargetMatches(RealmId)).
        super(realmId, realmId);
        this.roleId = roleId;
    }

    @Override
    public AttestationUnitType type() {
        return AttestationUnitType.REALM_DEFAULT_ROLES_SET;
    }

    @Override
    public Map<String, Object> payload() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("role_id", roleId);
        return p;
    }
}
