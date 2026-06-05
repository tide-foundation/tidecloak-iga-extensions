package org.tidecloak.iga.producer.spi;

import jakarta.persistence.EntityManager;
import org.tidecloak.iga.producer.units.AttestationUnit;
import org.tidecloak.iga.producer.units.AttestationUnitType;
import org.tidecloak.iga.producer.units.ParentType;
import org.tidecloak.iga.producer.units.ScopeRoleAllowlistSetUnit;

/**
 * The single source of truth mapping a producer {@link AttestationUnit} to the
 * forked KC entity column that holds its {@code TIDE-FIRSTADMIN-v1:}+b64(64-byte VVK
 * sig) attestation (the PR-A / PR-A.2 per-unit-type columns added in
 * {@code tidecloak-override}). It is the EXACT inverse of the per-CR-commit stampers
 * in {@code TideAttestor#stampProducerUnitColumns} (node / derived-set / realm units)
 * and the dispatcher's edge-set fan-out (user_role_mapping_set, user_group_membership_set,
 * group_role_mapping_set, role_composite_children_set, protocol_mapper).
 *
 * <h2>Why one resolver for read + backfill</h2>
 * Uniform Design B (PR-B) makes the login read all-or-nothing: every unit's sig is
 * replayed from its column, none re-signed. For that to be safe the toggle-on
 * full-closure backfill must stamp the EXACT same column the login reads, for every
 * unit type the login emits. Routing BOTH paths through this one resolver guarantees
 * they can never drift: a unit type the login reads is a unit type the backfill stamps,
 * by construction.
 *
 * <h2>The 18 unit types → column</h2>
 * <pre>
 *  0 realm_config                -> RealmEntity.realmConfigAttestation          (id = realmId)
 *  1 client_config               -> ClientEntity.attestation                    (id = client UUID)
 *  2 client_scope_config         -> ClientScopeEntity.attestation               (id = scope id)
 *  3 protocol_mapper             -> ProtocolMapperEntity.attestation            (id = mapper id)
 *  4 role_definition             -> RoleEntity.attestation                      (id = role id)
 *  5 group_definition            -> GroupEntity.attestation                     (id = group id)
 *  6 user_identity               -> UserEntity.attestation                      (id = user id)
 *  7 user_role_mapping_set       -> UserRoleMappingEntity.attestation           (user.id = user id; any row)
 *  8 user_group_membership_set   -> UserGroupMembershipEntity.attestation       (user.id = user id; any row)
 *  9 group_role_mapping_set      -> GroupRoleMappingEntity.attestation          (group.id = group id; any row)
 * 10 role_composite_children_set -> CompositeRoleEntity.attestation             (parentRole.id = role id; any row)
 * 11 client_scope_assignment_set -> ClientEntity.clientScopeAssignmentAttestation (id = client UUID)
 * 12 client_mapper_set           -> ClientEntity.clientMapperSetAttestation     (id = client UUID)
 * 13 client_scope_mapper_set     -> ClientScopeEntity.clientScopeMapperSetAttestation (id = scope id)
 * 14 scope_role_allowlist_set    -> {Client|ClientScope}Entity.scopeRoleAllowlistAttestation (parent_type)
 * 15 realm_default_groups_set    -> RealmEntity.realmDefaultGroupsAttestation   (id = realmId)
 * 16 organization_definition     -> OrganizationEntity.attestation              (id = org id)
 * 17 organization_domain_set     -> OrganizationEntity.orgDomainAttestation     (id = org id)
 * </pre>
 *
 * <p>The set-unit columns (7/8/9/10) are fanned across every row sharing the owner key
 * by the dispatcher, so reading any one row's column yields the per-set sig; the
 * backfill writes every such row.
 */
public final class UnitColumnMapping {

    private UnitColumnMapping() {}

    /**
     * Read the stored attestation string for a unit from its column, or {@code null}
     * if the unit has no row / no stamp yet. The read picks the FIRST non-null
     * attestation among rows sharing the owner key for the set units (they all carry
     * the same per-set sig after a fan-out).
     */
    public static String readStored(EntityManager em, AttestationUnit unit) {
        String t = unit.targetId();
        switch (unit.type()) {
            case REALM_CONFIG:
                return single(em, "SELECT e.realmConfigAttestation FROM RealmEntity e WHERE e.id = :id", t);
            case REALM_DEFAULT_GROUPS_SET:
                return single(em, "SELECT e.realmDefaultGroupsAttestation FROM RealmEntity e WHERE e.id = :id", t);
            case CLIENT_CONFIG:
                return single(em, "SELECT e.attestation FROM ClientEntity e WHERE e.id = :id", t);
            case CLIENT_SCOPE_ASSIGNMENT_SET:
                return single(em, "SELECT e.clientScopeAssignmentAttestation FROM ClientEntity e WHERE e.id = :id", t);
            case CLIENT_MAPPER_SET:
                return single(em, "SELECT e.clientMapperSetAttestation FROM ClientEntity e WHERE e.id = :id", t);
            case CLIENT_SCOPE_CONFIG:
                return single(em, "SELECT e.attestation FROM ClientScopeEntity e WHERE e.id = :id", t);
            case CLIENT_SCOPE_MAPPER_SET:
                return single(em, "SELECT e.clientScopeMapperSetAttestation FROM ClientScopeEntity e WHERE e.id = :id", t);
            case PROTOCOL_MAPPER:
                return single(em, "SELECT e.attestation FROM ProtocolMapperEntity e WHERE e.id = :id", t);
            case ROLE_DEFINITION:
                return single(em, "SELECT e.attestation FROM RoleEntity e WHERE e.id = :id", t);
            case GROUP_DEFINITION:
                return single(em, "SELECT e.attestation FROM GroupEntity e WHERE e.id = :id", t);
            case USER_IDENTITY:
                return single(em, "SELECT e.attestation FROM UserEntity e WHERE e.id = :id", t);
            case ORGANIZATION_DEFINITION:
                return single(em, "SELECT e.attestation FROM OrganizationEntity e WHERE e.id = :id", t);
            case ORGANIZATION_DOMAIN_SET:
                return single(em, "SELECT e.orgDomainAttestation FROM OrganizationEntity e WHERE e.id = :id", t);
            case USER_ROLE_MAPPING_SET:
                return firstNonNull(em, "SELECT e.attestation FROM UserRoleMappingEntity e "
                        + "WHERE e.user.id = :id AND e.attestation IS NOT NULL", t);
            case USER_GROUP_MEMBERSHIP_SET:
                return firstNonNull(em, "SELECT e.attestation FROM UserGroupMembershipEntity e "
                        + "WHERE e.user.id = :id AND e.attestation IS NOT NULL", t);
            case GROUP_ROLE_MAPPING_SET:
                return firstNonNull(em, "SELECT e.attestation FROM GroupRoleMappingEntity e "
                        + "WHERE e.group.id = :id AND e.attestation IS NOT NULL", t);
            case ROLE_COMPOSITE_CHILDREN_SET:
                return firstNonNull(em, "SELECT e.attestation FROM CompositeRoleEntity e "
                        + "WHERE e.parentRole.id = :id AND e.attestation IS NOT NULL", t);
            case SCOPE_ROLE_ALLOWLIST_SET:
                return scopeAllowlistColumn(em, (ScopeRoleAllowlistSetUnit) unit);
            default:
                throw new IllegalStateException("UnitColumnMapping: no column read for unit type "
                        + unit.type());
        }
    }

    /**
     * Stamp {@code sig} onto a unit's column. For the set units (7/8/9/10) the sig is
     * fanned across EVERY row sharing the owner key (matching the dispatcher fan-out),
     * so the per-set sig is readable from any row. Returns the number of rows updated
     * (0 means the owner entity / edge does not exist — the backfill treats that as a
     * no-op coverage hole, never an error, since the login won't emit that unit either).
     */
    public static int stamp(EntityManager em, AttestationUnit unit, String sig) {
        String t = unit.targetId();
        switch (unit.type()) {
            case REALM_CONFIG:
                return update(em, "UPDATE RealmEntity e SET e.realmConfigAttestation = :sig WHERE e.id = :id", sig, t);
            case REALM_DEFAULT_GROUPS_SET:
                return update(em, "UPDATE RealmEntity e SET e.realmDefaultGroupsAttestation = :sig WHERE e.id = :id", sig, t);
            case CLIENT_CONFIG:
                return update(em, "UPDATE ClientEntity e SET e.attestation = :sig WHERE e.id = :id", sig, t);
            case CLIENT_SCOPE_ASSIGNMENT_SET:
                return update(em, "UPDATE ClientEntity e SET e.clientScopeAssignmentAttestation = :sig WHERE e.id = :id", sig, t);
            case CLIENT_MAPPER_SET:
                return update(em, "UPDATE ClientEntity e SET e.clientMapperSetAttestation = :sig WHERE e.id = :id", sig, t);
            case CLIENT_SCOPE_CONFIG:
                return update(em, "UPDATE ClientScopeEntity e SET e.attestation = :sig WHERE e.id = :id", sig, t);
            case CLIENT_SCOPE_MAPPER_SET:
                return update(em, "UPDATE ClientScopeEntity e SET e.clientScopeMapperSetAttestation = :sig WHERE e.id = :id", sig, t);
            case PROTOCOL_MAPPER:
                return update(em, "UPDATE ProtocolMapperEntity e SET e.attestation = :sig WHERE e.id = :id", sig, t);
            case ROLE_DEFINITION:
                return update(em, "UPDATE RoleEntity e SET e.attestation = :sig WHERE e.id = :id", sig, t);
            case GROUP_DEFINITION:
                return update(em, "UPDATE GroupEntity e SET e.attestation = :sig WHERE e.id = :id", sig, t);
            case USER_IDENTITY:
                return update(em, "UPDATE UserEntity e SET e.attestation = :sig WHERE e.id = :id", sig, t);
            case ORGANIZATION_DEFINITION:
                return update(em, "UPDATE OrganizationEntity e SET e.attestation = :sig WHERE e.id = :id", sig, t);
            case ORGANIZATION_DOMAIN_SET:
                return update(em, "UPDATE OrganizationEntity e SET e.orgDomainAttestation = :sig WHERE e.id = :id", sig, t);
            case USER_ROLE_MAPPING_SET:
                return update(em, "UPDATE UserRoleMappingEntity e SET e.attestation = :sig WHERE e.user.id = :id", sig, t);
            case USER_GROUP_MEMBERSHIP_SET:
                return update(em, "UPDATE UserGroupMembershipEntity e SET e.attestation = :sig WHERE e.user.id = :id", sig, t);
            case GROUP_ROLE_MAPPING_SET:
                return update(em, "UPDATE GroupRoleMappingEntity e SET e.attestation = :sig WHERE e.group.id = :id", sig, t);
            case ROLE_COMPOSITE_CHILDREN_SET:
                return update(em, "UPDATE CompositeRoleEntity e SET e.attestation = :sig WHERE e.parentRole.id = :id", sig, t);
            case SCOPE_ROLE_ALLOWLIST_SET:
                return stampScopeAllowlist(em, (ScopeRoleAllowlistSetUnit) unit, sig);
            default:
                throw new IllegalStateException("UnitColumnMapping: no column stamp for unit type "
                        + unit.type());
        }
    }

    // ---- scope_role_allowlist_set: column depends on parent_type ----

    private static String scopeAllowlistColumn(EntityManager em, ScopeRoleAllowlistSetUnit unit) {
        if (unit.parentType() == ParentType.client_scope) {
            return single(em, "SELECT e.scopeRoleAllowlistAttestation FROM ClientScopeEntity e WHERE e.id = :id",
                    unit.targetId());
        }
        return single(em, "SELECT e.scopeRoleAllowlistAttestation FROM ClientEntity e WHERE e.id = :id",
                unit.targetId());
    }

    private static int stampScopeAllowlist(EntityManager em, ScopeRoleAllowlistSetUnit unit, String sig) {
        if (unit.parentType() == ParentType.client_scope) {
            return update(em, "UPDATE ClientScopeEntity e SET e.scopeRoleAllowlistAttestation = :sig WHERE e.id = :id",
                    sig, unit.targetId());
        }
        return update(em, "UPDATE ClientEntity e SET e.scopeRoleAllowlistAttestation = :sig WHERE e.id = :id",
                sig, unit.targetId());
    }

    // ---- small JPQL helpers ----

    private static String single(EntityManager em, String jpql, String id) {
        @SuppressWarnings("unchecked")
        java.util.List<String> r = em.createQuery(jpql).setParameter("id", id).setMaxResults(1).getResultList();
        return r.isEmpty() ? null : r.get(0);
    }

    private static String firstNonNull(EntityManager em, String jpql, String id) {
        @SuppressWarnings("unchecked")
        java.util.List<String> r = em.createQuery(jpql).setParameter("id", id).setMaxResults(1).getResultList();
        return r.isEmpty() ? null : r.get(0);
    }

    private static int update(EntityManager em, String jpql, String sig, String id) {
        return em.createQuery(jpql).setParameter("sig", sig).setParameter("id", id).executeUpdate();
    }
}
