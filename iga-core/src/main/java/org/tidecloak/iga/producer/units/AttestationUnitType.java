package org.tidecloak.iga.producer.units;

/**
 * The admin-attestable unit types, mirroring the ork enum
 * {@code Ork.Models.TideRequests.Authorization.TidecloakToken.AttestationUnitType}
 * ({@code Ork/.../TidecloakToken/AttestationUnit.cs:61-81}) field-for-field and
 * in the SAME declared order.
 *
 * <h2>Wire form — INTEGER ordinal, not the snake_case string</h2>
 * The ork CBOR decoder reads the envelope {@code unit_type} as a CBOR unsigned
 * integer enum ordinal, NOT the snake_case name:
 * <ul>
 *   <li>{@code BaseAttestationUnit} ctor — {@code GetInt(envelope, "unit_type")}
 *       then {@code (AttestationUnitType)unitTypeNum} (AttestationUnit.cs:210-217);
 *       a text-string {@code unit_type} throws {@code "property 'unit_type' must
 *       be an integer"}.</li>
 *   <li>{@code AttestationUnitFactory.Create} — {@code utv is not long utl}
 *       (AttestationUnit.cs:535); a string {@code unit_type} throws
 *       {@code "envelope missing integer 'unit_type'"}.</li>
 *   <li>The ork rebuilds its OWN canonical bytes with {@code ["unit_type"] =
 *       (int)UnitType} (AttestationUnit.cs:264), so the hash it compares is over
 *       the integer ordinal.</li>
 * </ul>
 *
 * <h2>Source of truth for the ordinal</h2>
 * The {@link #wireValue} below is the AUTHORITATIVE producer→ork mapping. It is
 * an EXPLICIT {@code int} per constant (deliberately NOT Java's implicit
 * {@link Enum#ordinal()}, which is fragile under reordering). The ork enum
 * comment is "Append new types at the end; never reorder." — the explicit value
 * + the {@link #ASSERT_ORDER_LOCKED static order guard} below enforce that here:
 * if anyone reorders or renumbers these constants out of step, class
 * initialization fails loudly instead of silently emitting a wrong ordinal.
 *
 * <pre>
 * realm_config=0  client_config=1  client_scope_config=2  protocol_mapper=3
 * role_definition=4  group_definition=5  user_identity=6  user_role_mapping_set=7
 * user_group_membership_set=8  group_role_mapping_set=9
 * role_composite_children_set=10  client_scope_assignment_set=11
 * client_mapper_set=12  client_scope_mapper_set=13  scope_role_allowlist_set=14
 * realm_default_groups_set=15  organization_definition=16  organization_domain_set=17
 * realm_default_roles_set=18
 * </pre>
 */
public enum AttestationUnitType {

    REALM_CONFIG("realm_config", 0),
    CLIENT_CONFIG("client_config", 1),
    CLIENT_SCOPE_CONFIG("client_scope_config", 2),
    PROTOCOL_MAPPER("protocol_mapper", 3),
    ROLE_DEFINITION("role_definition", 4),
    GROUP_DEFINITION("group_definition", 5),
    USER_IDENTITY("user_identity", 6),
    USER_ROLE_MAPPING_SET("user_role_mapping_set", 7),
    USER_GROUP_MEMBERSHIP_SET("user_group_membership_set", 8),
    GROUP_ROLE_MAPPING_SET("group_role_mapping_set", 9),
    ROLE_COMPOSITE_CHILDREN_SET("role_composite_children_set", 10),
    CLIENT_SCOPE_ASSIGNMENT_SET("client_scope_assignment_set", 11),
    CLIENT_MAPPER_SET("client_mapper_set", 12),
    CLIENT_SCOPE_MAPPER_SET("client_scope_mapper_set", 13),
    SCOPE_ROLE_ALLOWLIST_SET("scope_role_allowlist_set", 14),
    REALM_DEFAULT_GROUPS_SET("realm_default_groups_set", 15),
    ORGANIZATION_DEFINITION("organization_definition", 16),
    ORGANIZATION_DOMAIN_SET("organization_domain_set", 17),
    // Appended at the END (never reordered — the ork enum is "append at end; never
    // reorder", enforced by ASSERT_ORDER_LOCKED below). The realm's default-role
    // authority (D1a): signed ONCE at realm level, universal-inherit covers every user,
    // so the per-user default-role edge is dropped (RealmAttestationExporter.userRoleMappingSet
    // / TideAttestor.buildUserRoleMappingSetUnit both exclude it). The ork mirror is
    // RealmDefaultRolesSetAttestationUnit with this SAME ordinal (18).
    REALM_DEFAULT_ROLES_SET("realm_default_roles_set", 18);

    /** snake_case, case-sensitive — the ork enum constant NAME (spec / logs only). */
    private final String wireName;

    /** The CBOR-wire integer ordinal = {@code (int)} the ork enum constant. */
    private final int wireValue;

    AttestationUnitType(String wireName, int wireValue) {
        this.wireName = wireName;
        this.wireValue = wireValue;
    }

    /** snake_case wire NAME (for the {@code serialize()} error messages / logs / spec). */
    public String wireName() {
        return wireName;
    }

    /**
     * The CBOR envelope {@code unit_type} value — an {@code int} so Jackson-CBOR
     * encodes it as a CBOR unsigned integer (major type 0), matching the ork
     * {@code GetInt}/{@code (AttestationUnitType)} reader.
     */
    public int wireValue() {
        return wireValue;
    }

    // ---- order guard ---------------------------------------------------------
    // Locks the declared order to the ork enum. The explicit wireValue is the
    // source of truth; this asserts it equals the declared position so a
    // reorder/renumber that drifts from the ork enum fails class-init loudly
    // (rather than silently shipping a wrong ordinal). Append-at-end stays valid.
    // The field is read-never-but-assignment-triggers-the-check; the value is the
    // side effect of running assertOrderLocked() at class initialization.
    @SuppressWarnings("unused")
    private static final boolean ASSERT_ORDER_LOCKED = assertOrderLocked();

    private static boolean assertOrderLocked() {
        AttestationUnitType[] all = values();
        for (int i = 0; i < all.length; i++) {
            if (all[i].wireValue != i) {
                throw new ExceptionInInitializerError(
                        "AttestationUnitType wire ordinal drift: " + all[i].name()
                                + " has wireValue=" + all[i].wireValue
                                + " but is declared at position " + i
                                + " — must match ork AttestationUnit.cs enum order EXACTLY.");
            }
        }
        return true;
    }
}
