package org.tidecloak.iga.services;

import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * Extracted in Phase 6a from {@code IgaBaselineService.collectAllUnsignedRows}
 * (deleted in the same commit). Holds the battle-tested JPQL projections that
 * find "unsigned" rows — rows whose {@code attestation} column is still NULL —
 * across every IGA-tracked entity / relationship / attribute table.
 *
 * <p>Phase 6a itself does NOT call any of these methods — they are scaffolding
 * for Phase 6b's toggle-on scan, which will iterate the five "info" tables
 * (users, roles, groups, clients, client_scopes) and create a per-entity ADOPT
 * change request for each unattested row. The relationship and attribute
 * scanners are kept (a) to avoid losing the JPQL the BASELINE codepath spent
 * Phases 1-5 perfecting, and (b) for Phase 6c / 6d quarantine cross-checks.</p>
 *
 * <p>Surface contract: every public method takes the realm id as its sole
 * scalar parameter (matching the original BASELINE collector signature) and
 * returns a tight {@link UnsignedEntityRef} record stream. The caller composes
 * the per-type streams as needed; we deliberately do NOT recreate the
 * BASELINE_APPROVAL "one giant rowsJson" snapshot — that was the BASELINE
 * shape, not the ADOPT shape.</p>
 */
public final class IgaUnsignedRowScanner {

    private static final Logger log = Logger.getLogger(IgaUnsignedRowScanner.class);

    /**
     * Tight reference to an unattested row.
     *
     * @param entityType USER | ROLE | GROUP | CLIENT | CLIENT_SCOPE |
     *                   USER_ROLE | USER_GROUP | GROUP_ROLE | COMPOSITE_ROLE |
     *                   CLIENT_SCOPE_CLIENT | CLIENT_SCOPE_ROLE |
     *                   USER_ATTRIBUTE | CLIENT_ATTRIBUTE | CLIENT_SCOPE_ATTRIBUTE |
     *                   GROUP_ATTRIBUTE | ROLE_ATTRIBUTE | REALM_ATTRIBUTE |
     *                   PROTOCOL_MAPPER
     * @param entityId   primary identifier (for "info" entities this is the
     *                   entity's own UUID; for relationship rows it is the
     *                   first half of the composite key; for attributes it is
     *                   the parent entity's UUID).
     * @param parentRef  optional secondary identifier (the second half of a
     *                   composite key, the attribute name, or the parent
     *                   client UUID for protocol mappers). {@code null} when
     *                   the entity type has no secondary identifier.
     */
    public record UnsignedEntityRef(String entityType, String entityId, String parentRef) {
    }

    private final EntityManager em;

    public IgaUnsignedRowScanner(EntityManager em) {
        this.em = em;
    }

    // -------------------------------------------------------------------------
    // "Info" entities — the five Phase 6b toggle-on scan targets.
    // Each ADOPT_X CR replays a single row update on its info table.
    // -------------------------------------------------------------------------

    /** USER_ENTITY: id where attestation IS NULL, scoped to the realm. */
    public Stream<UnsignedEntityRef> users(String realmId) {
        return idStream("USER",
                "SELECT u.id FROM UserEntity u WHERE u.realmId = ?1 AND u.attestation IS NULL",
                realmId);
    }

    /** KEYCLOAK_ROLE: id where attestation IS NULL, scoped to the realm. */
    public Stream<UnsignedEntityRef> roles(String realmId) {
        return idStream("ROLE",
                "SELECT r.id FROM RoleEntity r WHERE r.realmId = ?1 AND r.attestation IS NULL",
                realmId);
    }

    /** KEYCLOAK_GROUP: id where attestation IS NULL, scoped to the realm.
     *  Note GroupEntity's realm field is named {@code realm} (column REALM_ID). */
    public Stream<UnsignedEntityRef> groups(String realmId) {
        return idStream("GROUP",
                "SELECT g.id FROM GroupEntity g WHERE g.realm = ?1 AND g.attestation IS NULL",
                realmId);
    }

    /** CLIENT: id where attestation IS NULL, scoped to the realm. */
    public Stream<UnsignedEntityRef> clients(String realmId) {
        return idStream("CLIENT",
                "SELECT c.id FROM ClientEntity c WHERE c.realmId = ?1 AND c.attestation IS NULL",
                realmId);
    }

    /** CLIENT_SCOPE: id where attestation IS NULL, scoped to the realm. */
    public Stream<UnsignedEntityRef> clientScopes(String realmId) {
        return idStream("CLIENT_SCOPE",
                "SELECT cs.id FROM ClientScopeEntity cs WHERE cs.realmId = ?1 AND cs.attestation IS NULL",
                realmId);
    }

    /**
     * Aggregate the five info-table streams into one. Convenience for Phase 6b
     * — preserves the same insertion order BASELINE used (users → roles →
     * groups → clients → client_scopes) so existing snapshots remain
     * comparable.
     */
    public Stream<UnsignedEntityRef> allInfoEntities(String realmId) {
        return Stream.of(
                        users(realmId),
                        roles(realmId),
                        groups(realmId),
                        clients(realmId),
                        clientScopes(realmId))
                .flatMap(s -> s);
    }

    // -------------------------------------------------------------------------
    // Phase 6b — projection variants that surface the columns needed by
    // {@link IgaSystemEntityFilter} to identify built-in clients (by clientId
    // string) and client-roles whose parent is a built-in client. These are
    // ADDITIVE: the existing id-only methods above remain byte-unchanged in
    // their JPQL, so callers that don't need the system-filter projection are
    // unaffected.
    //
    // Each row carries the entity's UUID plus the name(s) the filter needs.
    // -------------------------------------------------------------------------

    /**
     * (entityId, entityName) for unattested USERs in the realm. Name is the
     * KC USERNAME column — the filter does not currently key on it but it is
     * surfaced for symmetry / future rules and for the audit log line.
     */
    public record InfoRow(String entityId, String entityName, String parentClientId) { }

    public List<InfoRow> usersWithNames(String realmId) {
        @SuppressWarnings("unchecked")
        List<Object[]> rows = (List<Object[]>) em.createQuery(
                "SELECT u.id, u.username FROM UserEntity u " +
                        "WHERE u.realmId = ?1 AND u.attestation IS NULL")
                .setParameter(1, realmId).getResultList();
        List<InfoRow> out = new ArrayList<>(rows.size());
        for (Object[] r : rows) out.add(new InfoRow(asStr(r, 0), asStr(r, 1), null));
        log.debugf("scanner: USER (with-name) — %d unsigned row(s) in realm %s", out.size(), realmId);
        return out;
    }

    /**
     * (entityId, roleName, parentClientId) for unattested ROLEs.
     *
     * <p>{@code parentClientId} is the parent client's {@code clientId} STRING
     * (e.g. "realm-management"), not its UUID — that's what the system-filter
     * compares against. For realm roles the field is {@code null}. The JPQL
     * left-joins the parent client to keep realm roles in the result set and
     * avoid running a second query.</p>
     */
    public List<InfoRow> rolesWithNames(String realmId) {
        @SuppressWarnings("unchecked")
        List<Object[]> rows = (List<Object[]>) em.createQuery(
                "SELECT r.id, r.name, parent.clientId FROM RoleEntity r " +
                        "LEFT JOIN ClientEntity parent ON parent.id = r.clientId " +
                        "WHERE r.realmId = ?1 AND r.attestation IS NULL")
                .setParameter(1, realmId).getResultList();
        List<InfoRow> out = new ArrayList<>(rows.size());
        for (Object[] r : rows) out.add(new InfoRow(asStr(r, 0), asStr(r, 1), asStr(r, 2)));
        log.debugf("scanner: ROLE (with-name) — %d unsigned row(s) in realm %s", out.size(), realmId);
        return out;
    }

    public List<InfoRow> groupsWithNames(String realmId) {
        @SuppressWarnings("unchecked")
        List<Object[]> rows = (List<Object[]>) em.createQuery(
                "SELECT g.id, g.name FROM GroupEntity g " +
                        "WHERE g.realm = ?1 AND g.attestation IS NULL")
                .setParameter(1, realmId).getResultList();
        List<InfoRow> out = new ArrayList<>(rows.size());
        for (Object[] r : rows) out.add(new InfoRow(asStr(r, 0), asStr(r, 1), null));
        log.debugf("scanner: GROUP (with-name) — %d unsigned row(s) in realm %s", out.size(), realmId);
        return out;
    }

    /**
     * (entityId, clientId-string) for unattested CLIENTs. The string clientId
     * is what {@link IgaSystemEntityFilter#BUILTIN_CLIENT_IDS} matches on.
     */
    public List<InfoRow> clientsWithNames(String realmId) {
        @SuppressWarnings("unchecked")
        List<Object[]> rows = (List<Object[]>) em.createQuery(
                "SELECT c.id, c.clientId FROM ClientEntity c " +
                        "WHERE c.realmId = ?1 AND c.attestation IS NULL")
                .setParameter(1, realmId).getResultList();
        List<InfoRow> out = new ArrayList<>(rows.size());
        for (Object[] r : rows) out.add(new InfoRow(asStr(r, 0), asStr(r, 1), null));
        log.debugf("scanner: CLIENT (with-name) — %d unsigned row(s) in realm %s", out.size(), realmId);
        return out;
    }

    public List<InfoRow> clientScopesWithNames(String realmId) {
        @SuppressWarnings("unchecked")
        List<Object[]> rows = (List<Object[]>) em.createQuery(
                "SELECT cs.id, cs.name FROM ClientScopeEntity cs " +
                        "WHERE cs.realmId = ?1 AND cs.attestation IS NULL")
                .setParameter(1, realmId).getResultList();
        List<InfoRow> out = new ArrayList<>(rows.size());
        for (Object[] r : rows) out.add(new InfoRow(asStr(r, 0), asStr(r, 1), null));
        log.debugf("scanner: CLIENT_SCOPE (with-name) — %d unsigned row(s) in realm %s", out.size(), realmId);
        return out;
    }

    /**
     * (entityId, orgName) for ORGANIZATIONs in the realm. Phase 7b — orgs
     * have NO {@code attestation} column on {@code OrganizationEntity} (see
     * {@link org.tidecloak.iga.replay.IgaReplayDispatcher} line 496-497 for
     * the design choice), so this query enumerates EVERY org in the realm
     * without an {@code attestation IS NULL} filter. The "unsigned" filter
     * happens at the scan level via the existing committed-ADOPT skip-set
     * (an org with an APPROVED ADOPT_ORGANIZATION CR is "governed" and is
     * filtered by {@link IgaAdoptScan} at the per-entity stage). Pending
     * CREATE_ORGANIZATION CRs filter the same way.
     *
     * <p>{@code parentClientId} is always {@code null} for orgs — they have
     * no client parent (the field is reused unchanged from the other
     * info-type helpers for record symmetry).</p>
     */
    public List<InfoRow> organizationsWithNames(String realmId) {
        @SuppressWarnings("unchecked")
        List<Object[]> rows = (List<Object[]>) em.createQuery(
                "SELECT o.id, o.name FROM OrganizationEntity o " +
                        "WHERE o.realmId = ?1")
                .setParameter(1, realmId).getResultList();
        List<InfoRow> out = new ArrayList<>(rows.size());
        for (Object[] r : rows) out.add(new InfoRow(asStr(r, 0), asStr(r, 1), null));
        log.debugf("scanner: ORGANIZATION (with-name) — %d row(s) in realm %s", out.size(), realmId);
        return out;
    }

    private static String asStr(Object[] r, int i) {
        return r.length > i && r[i] != null ? r[i].toString() : null;
    }

    // -------------------------------------------------------------------------
    // Protocol mappers (scoped to clients in the realm). Phase 6b/6c may treat
    // these alongside their parent client; surfaced separately so the caller
    // can decide.
    // -------------------------------------------------------------------------

    /**
     * PROTOCOL_MAPPER: (mapper id, owning client id) pairs where
     * {@code attestation IS NULL}, scoped via the parent client's realm.
     */
    public Stream<UnsignedEntityRef> protocolMappers(String realmId) {
        return pairStream("PROTOCOL_MAPPER",
                "SELECT pm.id, pm.client.id FROM ProtocolMapperEntity pm " +
                        "WHERE pm.client.realmId = ?1 AND pm.attestation IS NULL",
                realmId);
    }

    // -------------------------------------------------------------------------
    // Relationship tables — composite key rows. Phase 6b/6c quarantine.
    // entityId = key1, parentRef = key2.
    // -------------------------------------------------------------------------

    /** USER_ROLE_MAPPING — (user id, role id). */
    public Stream<UnsignedEntityRef> userRoleMappings(String realmId) {
        return pairStream("USER_ROLE",
                "SELECT urm.user.id, urm.roleId FROM UserRoleMappingEntity urm " +
                        "WHERE urm.user.realmId = ?1 AND urm.attestation IS NULL",
                realmId);
    }

    /** USER_GROUP_MEMBERSHIP — (user id, group id). */
    public Stream<UnsignedEntityRef> userGroupMemberships(String realmId) {
        return pairStream("USER_GROUP",
                "SELECT ugm.user.id, ugm.groupId FROM UserGroupMembershipEntity ugm " +
                        "WHERE ugm.user.realmId = ?1 AND ugm.attestation IS NULL",
                realmId);
    }

    /** GROUP_ROLE_MAPPING — (group id, role id). */
    public Stream<UnsignedEntityRef> groupRoleMappings(String realmId) {
        return pairStream("GROUP_ROLE",
                "SELECT grm.group.id, grm.roleId FROM GroupRoleMappingEntity grm " +
                        "WHERE grm.group.realm = ?1 AND grm.attestation IS NULL",
                realmId);
    }

    /** COMPOSITE_ROLE — (parent role id, child role id). */
    public Stream<UnsignedEntityRef> compositeRoles(String realmId) {
        return pairStream("COMPOSITE_ROLE",
                "SELECT cr.parentRole.id, cr.childRole.id FROM CompositeRoleEntity cr " +
                        "WHERE cr.parentRole.realmId = ?1 AND cr.attestation IS NULL",
                realmId);
    }

    /** CLIENT_SCOPE_CLIENT — (client id, scope id). */
    public Stream<UnsignedEntityRef> clientScopeClients(String realmId) {
        return pairStream("CLIENT_SCOPE_CLIENT",
                "SELECT csc.clientId, csc.clientScopeId " +
                        "FROM ClientScopeClientMappingEntity csc " +
                        "JOIN ClientEntity c ON c.id = csc.clientId " +
                        "WHERE c.realmId = ?1 AND csc.attestation IS NULL",
                realmId);
    }

    /** CLIENT_SCOPE_ROLE_MAPPING — (scope id, role id). */
    public Stream<UnsignedEntityRef> clientScopeRoleMappings(String realmId) {
        return pairStream("CLIENT_SCOPE_ROLE",
                "SELECT csrm.clientScope.id, csrm.role.id " +
                        "FROM ClientScopeRoleMappingEntity csrm " +
                        "WHERE csrm.clientScope.realmId = ?1 AND csrm.attestation IS NULL",
                realmId);
    }

    // -------------------------------------------------------------------------
    // Attribute tables — (parent entity id, attribute name) pairs.
    // -------------------------------------------------------------------------

    /** USER_ATTRIBUTE — (user id, name). */
    public Stream<UnsignedEntityRef> userAttributes(String realmId) {
        return pairStream("USER_ATTRIBUTE",
                "SELECT ua.user.id, ua.name FROM UserAttributeEntity ua " +
                        "WHERE ua.user.realmId = ?1 AND ua.attestation IS NULL",
                realmId);
    }

    /** CLIENT_ATTRIBUTES — (client id, name). */
    public Stream<UnsignedEntityRef> clientAttributes(String realmId) {
        return pairStream("CLIENT_ATTRIBUTE",
                "SELECT ca.client.id, ca.name FROM ClientAttributeEntity ca " +
                        "WHERE ca.client.realmId = ?1 AND ca.attestation IS NULL",
                realmId);
    }

    /** CLIENT_SCOPE_ATTRIBUTES — (scope id, name). */
    public Stream<UnsignedEntityRef> clientScopeAttributes(String realmId) {
        return pairStream("CLIENT_SCOPE_ATTRIBUTE",
                "SELECT csa.clientScope.id, csa.name " +
                        "FROM ClientScopeAttributeEntity csa " +
                        "WHERE csa.clientScope.realmId = ?1 AND csa.attestation IS NULL",
                realmId);
    }

    /** GROUP_ATTRIBUTE — (group id, name). */
    public Stream<UnsignedEntityRef> groupAttributes(String realmId) {
        return pairStream("GROUP_ATTRIBUTE",
                "SELECT ga.group.id, ga.name FROM GroupAttributeEntity ga " +
                        "WHERE ga.group.realm = ?1 AND ga.attestation IS NULL",
                realmId);
    }

    /** ROLE_ATTRIBUTE — (role id, name). */
    public Stream<UnsignedEntityRef> roleAttributes(String realmId) {
        return pairStream("ROLE_ATTRIBUTE",
                "SELECT ra.role.id, ra.name FROM RoleAttributeEntity ra " +
                        "WHERE ra.role.realmId = ?1 AND ra.attestation IS NULL",
                realmId);
    }

    /** REALM_ATTRIBUTE — (realm id, name). */
    public Stream<UnsignedEntityRef> realmAttributes(String realmId) {
        return pairStream("REALM_ATTRIBUTE",
                "SELECT rea.realm.id, rea.name FROM RealmAttributeEntity rea " +
                        "WHERE rea.realm.id = ?1 AND rea.attestation IS NULL",
                realmId);
    }

    // -------------------------------------------------------------------------
    // Plumbing — JPQL execution / row → record adaptation.
    // -------------------------------------------------------------------------

    private Stream<UnsignedEntityRef> idStream(String entityType, String jpql, String realmId) {
        List<String> ids = em.createQuery(jpql, String.class).setParameter(1, realmId).getResultList();
        log.debugf("scanner: %s — %d unsigned row(s) in realm %s", entityType, ids.size(), realmId);
        List<UnsignedEntityRef> out = new ArrayList<>(ids.size());
        for (String id : ids) out.add(new UnsignedEntityRef(entityType, id, null));
        return out.stream();
    }

    @SuppressWarnings("unchecked")
    private Stream<UnsignedEntityRef> pairStream(String entityType, String jpql, String realmId) {
        List<Object[]> rows = (List<Object[]>) em.createQuery(jpql).setParameter(1, realmId).getResultList();
        log.debugf("scanner: %s — %d unsigned row(s) in realm %s", entityType, rows.size(), realmId);
        List<UnsignedEntityRef> out = new ArrayList<>(rows.size());
        for (Object[] r : rows) {
            String a = r.length > 0 && r[0] != null ? r[0].toString() : null;
            String b = r.length > 1 && r[1] != null ? r[1].toString() : null;
            out.add(new UnsignedEntityRef(entityType, a, b));
        }
        return out.stream();
    }
}
