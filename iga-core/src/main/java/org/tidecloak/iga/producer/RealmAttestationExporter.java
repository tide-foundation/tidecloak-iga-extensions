package org.tidecloak.iga.producer;

import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OrganizationDomainModel;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.organization.OrganizationProvider;
import org.tidecloak.iga.producer.units.AttestationUnit;
import org.tidecloak.iga.producer.units.ClientConfigUnit;
import org.tidecloak.iga.producer.units.ClientMapperSetUnit;
import org.tidecloak.iga.producer.units.ClientScopeAssignmentSetUnit;
import org.tidecloak.iga.producer.units.ClientScopeConfigUnit;
import org.tidecloak.iga.producer.units.ClientScopeMapperSetUnit;
import org.tidecloak.iga.producer.units.GroupDefinitionUnit;
import org.tidecloak.iga.producer.units.GroupRoleMappingSetUnit;
import org.tidecloak.iga.producer.units.GroupType;
import org.tidecloak.iga.producer.units.NameValue;
import org.tidecloak.iga.producer.units.NameValues;
import org.tidecloak.iga.producer.units.OrgDomain;
import org.tidecloak.iga.producer.units.OrganizationDefinitionUnit;
import org.tidecloak.iga.producer.units.OrganizationDomainSetUnit;
import org.tidecloak.iga.producer.units.ParentType;
import org.tidecloak.iga.producer.units.ProtocolMapperUnit;
import org.tidecloak.iga.producer.units.RealmConfigUnit;
import org.tidecloak.iga.producer.units.RealmDefaultGroupsSetUnit;
import org.tidecloak.iga.producer.units.RoleCompositeChildrenSetUnit;
import org.tidecloak.iga.producer.units.RoleDefinitionUnit;
import org.tidecloak.iga.producer.units.ScopeAssignment;
import org.tidecloak.iga.producer.units.ScopeRoleAllowlistSetUnit;
import org.tidecloak.iga.producer.units.UserGroupMembershipSetUnit;
import org.tidecloak.iga.producer.units.UserIdentityUnit;
import org.tidecloak.iga.producer.units.UserRoleMappingSetUnit;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Emits the closure of typed {@link AttestationUnit} instances (plain CBOR/JSON,
 * no JCS / no signature) for a {@code (realm, client, user, scope)},
 * so the ork {@code TokenValidationEngine} can validate a real issued token
 * against current attested realm state. Each unit mirrors its ork C# counterpart
 * field-for-field and can {@code serialize()} itself to a self-contained
 * full-envelope CBOR ({@code unit_type, schema_version, realm_id, target_id,
 * payload}).
 *
 * <p><b>Full claim closure.</b> A real Keycloak access token (even
 * {@code scope=openid}) carries the claims of every DEFAULT client scope (and
 * any REQUESTED optional scope): the profile/email property+attribute mappers
 * ({@code preferred_username}, {@code given_name}, {@code family_name},
 * {@code email}, {@code email_verified}, …), {@code realm_access.roles} /
 * {@code resource_access.*.roles} (the roles scope), and — via the implicit
 * {@code default-roles-<realm>} composite — the built-in roles
 * {@code offline_access} / {@code uma_authorization} and the {@code account}
 * client roles. The engine validates the EXACT token: it rejects any claim with
 * no attested source AND any attested-but-suppressed claim. So the producer must
 * emit precisely the closure the requested {@code (client, user, scope)} would
 * issue — no more, no less.
 *
 * <p><b>Role-closure rule (built-ins included).</b> {@code includeSystem=false}
 * skips built-in CLIENTS / SCOPES from <i>independent</i> governance, but it must
 * NOT drop a {@code role_definition} for any role that surfaces in the token via
 * the {@code default-roles} composite expansion. The transitive walk therefore
 * ignores the system filter entirely.
 *
 * <p>Payload field names / types mirror the ork unit schemas field-for-field
 * ({@code Ork/.../AttestationUnits/*.cs}). Every declared field is present;
 * optional strings are explicit {@code null}, booleans are JSON booleans, ints
 * are JSON numbers.
 *
 * <p><b>Fixture-honesty note:</b> the engine does not check the IGA
 * {@code attestation} column today, and a stock (non-IGA) realm has every
 * {@code attestation} NULL. To keep the claim-closure EXACT (a referenced row
 * that is omitted makes the engine reject), the producer includes the required
 * rows regardless of attestation state. The {@code attestation IS NOT NULL}
 * discriminator is wired as {@link #onlyAttested} for a future
 * trust-loop pass but defaults to off.
 */
public final class RealmAttestationExporter {

    private static final Logger log = Logger.getLogger(RealmAttestationExporter.class);

    // realm_config attributes the ork preset carries (the RealmConfig preset).
    private static final List<String> REALM_CONFIG_ATTR_KEYS = List.of(
            "frontendUrl", "acr.loa.map", "organizationsEnabled");

    /**
     * Protocol-mapper factory ids whose mappers do NOT contribute to the JWT body
     * and must therefore be filtered out of the producer's emit closure.
     *
     * <p><b>Engine contract.</b> The ork TVE {@code ClaimMapperRegistry} no longer
     * registers {@code NoOpClaimMapper} for these factories — it deliberately
     * REJECTS any {@code protocol_mapper} unit whose factory is session-note-only
     * or base-claim-handled. Emitting them would cause the engine to fail the unit
     * lookup; emitting them but referencing them from
     * {@code client_mapper_set} / {@code client_scope_mapper_set} would dangle a
     * member id without a matching unit. So the producer must:
     * (1) skip emission of the {@code protocol_mapper} envelope for these factories,
     * AND (2) remove the same id from the corresponding mapper-set membership list,
     * so the set stays consistent with what's emitted.</p>
     *
     * <p>The six filtered factories and why each is JWT-body-irrelevant:
     * <ul>
     *   <li>{@code oidc-allowed-origins-mapper} — emits a SESSION NOTE
     *       ({@code allowed-origins}), not a JWT claim;</li>
     *   <li>{@code oidc-acr-mapper} — the {@code acr} claim is set by KC's
     *       {@code initToken}, not by this mapper;</li>
     *   <li>{@code oidc-sub-mapper} — {@code sub} is base-bound from
     *       {@code user_identity}, not by this mapper;</li>
     *   <li>{@code oidc-session-state-mapper} — {@code session_state} is runtime
     *       (same family as {@code sid});</li>
     *   <li>{@code oidc-amr-mapper} — {@code amr} is the runtime auth-method,
     *       not reproducible from attested state;</li>
     *   <li>{@code oidc-nonce-backwards-compatible-mapper} — {@code nonce} is
     *       presence-accepted as a base claim.</li>
     * </ul>
     */
    private static final Set<String> JWT_BODY_IRRELEVANT_FACTORIES = Set.of(
            "oidc-allowed-origins-mapper",
            "oidc-acr-mapper",
            "oidc-sub-mapper",
            "oidc-session-state-mapper",
            "oidc-amr-mapper",
            "oidc-nonce-backwards-compatible-mapper");

    /**
     * When true, only rows whose IGA {@code attestation} column is non-null are
     * emitted (the "governed/committed" discriminator). Leaves this
     * false so the closure stays exact on a stock realm; flip on for the future
     * trust-loop pass. NOTE: never narrows the transitive role closure — a role
     * that surfaces in the token must always get a definition.
     *
     * <p>WARNING: the firstAdmin signer ({@code TideAttestor#buildUserRoleMappingSetUnitCbor})
     * hard-codes the UNFILTERED user_role_mapping_set (no {@code attestation IS NOT NULL}
     * predicate). Flipping {@code onlyAttested=true} would narrow the producer's
     * emitted membership below the signed set and silently break firstAdmin VVK
     * signature verification on the ork (membership divergence over literal bytes).
     */
    private boolean onlyAttested = false;

    public RealmAttestationExporter onlyAttested(boolean v) {
        this.onlyAttested = v;
        return this;
    }

    /**
     * Emit the full-closure set of typed attestation units for the request.
     * Caller is responsible for binding the realm onto the session context if the
     * session is fresh (see {@code IgaAdoptScan}).
     */
    public List<AttestationUnit> export(KeycloakSession session, RealmModel realm,
                                        ExportRequest req) {
        session.getContext().setRealm(realm);
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        String realmId = realm.getId();

        ClientModel client = realm.getClientByClientId(req.clientId());
        if (client == null) {
            throw new IllegalArgumentException("client '" + req.clientId()
                    + "' not found in realm " + realm.getName());
        }
        UserModel user = session.users().getUserById(realm, req.userId());
        if (user == null) {
            throw new IllegalArgumentException("user '" + req.userId()
                    + "' not found in realm " + realm.getName());
        }

        List<AttestationUnit> out = new ArrayList<>();

        // 1) realm_config (target = realm UUID).
        out.add(realmConfig(realm, realmId));

        // 2) client_config (the request client).
        out.add(clientConfig(client, realmId));

        // 3) client_scope_assignment_set + 4) a client_scope_config per assigned scope.
        Map<String, ClientScopeModel> assigned = collectAssignedScopes(client);
        out.add(clientScopeAssignmentSet(client, assigned, realmId));
        for (ClientScopeModel scope : assigned.values()) {
            out.add(clientScopeConfig(scope, realmId));
        }

        // 5) user_identity (the 4-unit floor) — carries every property/attribute the
        //    profile/email mappers read.
        out.add(userIdentity(user, realmId));

        // 6) user_role_mapping_set — the RAW stored USER_ROLE_MAPPING child set
        //    (JPQL, not the effective set) so the hash matches the stored rows.
        List<String> seedRoleIds = userRoleMappingSet(em, req.userId());
        out.add(new UserRoleMappingSetUnit(realmId, req.userId(), seedRoleIds));

        // 7) role_definition + 8) role_composite_children_set for the FULL TRANSITIVE
        //    role-METADATA closure (mirrors the engine's GrantedRoles composite
        //    expansion). Built-ins are INCLUDED — a role surfacing in the token via the
        //    default-roles composite must have a definition regardless of onlyAttested
        //    / includeSystem (the role-closure rule).
        //
        //    GUARDRAIL: this closure drives ONLY role-metadata emission (role_definition
        //    + role_composite_children_set) and the owning-client_config fan-out. It does
        //    NOT feed the user's effective-membership units (U8 user_role_mapping_set is
        //    `seedRoleIds` above; U9/U10 group sets are emitted in emitOrganizationClosure
        //    from raw JPQL). So widening it adds metadata units ONLY and cannot add roles
        //    to the user's held set.
        //
        //    The metadata seed is widened beyond the user's grant closure to the union of:
        //      (i)  the user's direct grants (seedRoleIds),
        //      (ii) every role mapped to a group the user belongs to (group roles the ORK
        //           folds into its closure — fixes (a2) group-inherited composites),
        //      (iii) the request client's own scope→role allowlist (SCOPE_MAPPING),
        //      (iv) every assigned client_scope's allowlist (CLIENT_SCOPE_ROLE_MAPPING),
        //    each then composite-expanded. This lets the ORK expand allowlist/group
        //    composites it walks even when the user does not transitively hold them
        //    (fixes (a)). U15 allowlist sets stay RAW (unexpanded) — the ORK expands.
        Set<String> metadataRoleSeed = metadataRoleSeed(seedRoleIds, user,
                scopeMappingRoleIds(client), assigned.values());
        Set<RoleModel> roleClosure = transitiveRoleClosure(realm, new ArrayList<>(metadataRoleSeed),
                req.userId());
        Set<String> ownerClientUuids = new LinkedHashSet<>();
        for (RoleModel role : roleClosure) {
            out.add(roleDefinition(role, realmId));
            out.add(roleCompositeChildrenSet(role, realmId));
            // The engine's client-role mapper walks role_definition.container_id ->
            // client_config to name resource_access.<clientId>. Collect every owning
            // client of a client-role so we can emit its client_config below.
            if (role.isClientRole()) {
                ownerClientUuids.add(role.getContainerId());
            }
        }

        // 9) client_config for every OWNING client of a client-role in the closure
        //    (e.g. the built-in `account` client, owner of manage-account/...).
        //    Skip the request client (already emitted above). Emitted regardless of
        //    the system filter: an unattested owner would drop a real token claim.
        for (String ownerUuid : ownerClientUuids) {
            if (ownerUuid.equals(client.getId())) {
                continue;
            }
            ClientModel owner = realm.getClientById(ownerUuid);
            if (owner == null) {
                log.warnf("producer: client-role owner client %s not resolvable; "
                        + "resource_access for it will be dropped (closure incomplete)", ownerUuid);
                continue;
            }
            out.add(clientConfig(owner, realmId));
        }

        // 10) scope_role_allowlist_set — the client's scope→role allowlist
        //     (parent_type=client, from SCOPE_MAPPING). Emitted explicitly even when
        //     empty (the ork distinguishes "no entries" from "missing"); only the
        //     parent_type=client one is consulted by the full-scope filter, but emitting
        //     it always keeps the closure honest.
        out.add(new ScopeRoleAllowlistSetUnit(realmId, ParentType.client, client.getId(),
                scopeMappingRoleIds(client)));
        // Per assigned scope that carries its own scope→role mapping.
        for (ClientScopeModel scope : assigned.values()) {
            List<String> scopeAllow = scopeMappingRoleIds(scope);
            if (!scopeAllow.isEmpty()) {
                out.add(new ScopeRoleAllowlistSetUnit(realmId, ParentType.client_scope,
                        scope.getId(), scopeAllow));
            }
        }

        // 11) protocol_mapper + 12) client_mapper_set / client_scope_mapper_set for
        //     ALL mappers of the active scopes (client-owned + each active scope's),
        //     so every claim the token carries (profile/email/roles/...) has an
        //     attested source.
        emitAllActiveMappers(client, assigned, req, realmId, out);

        // 13) realm_default_groups_set (unit 16) — the realm's REALM_DEFAULT_GROUPS
        //     set, target = realm UUID. Load-bearing only for user-creation flows but
        //     emitted always to keep the closure honest. Empty group list still emits
        //     (the ork distinguishes "no entries" from "missing").
        out.add(realmDefaultGroupsSet(realm, realmId));

        // 14) Organization closure for the org-membership claim mapper
        //     (OrganizationMembershipClaimMapper). The mapper walks:
        //     user_identity → user_group_membership_set → (per group_id)
        //     group_definition (type=ORGANIZATION) + group_role_mapping_set (unit 10)
        //     → reverse FK organization_definition.group_id → alias, plus the org's
        //     organization_domain_set (unit 18). Emitting these unit families gives
        //     the engine an attested source for the `organization` claim. No-ops on a
        //     realm without organizations.
        int orgUnitsEmitted = emitOrganizationClosure(session, em, realm, user, realmId, out);

        log.infof("producer: full-closure export realm=%s client=%s user=%s scope=%s -> "
                        + "%d unit(s); roles=%d ownerClients=%d orgUnits=%d",
                realm.getName(), req.clientId(), req.userId(), req.scope(),
                out.size(), roleClosure.size(), ownerClientUuids.size(), orgUnitsEmitted);
        return out;
    }

    // -------------------------------------------------------------------------
    // Organization closure (units 6 group_definition, 9 user_group_membership_set,
    // 10 group_role_mapping_set, 17 organization_definition, 18 organization_domain_set)
    // -------------------------------------------------------------------------

    /**
     * Emit the org-closure family backing the {@code organization} claim mapper:
     * <ol>
     *   <li>{@code user_group_membership_set} (unit 9) — the user's RAW stored
     *       USER_GROUP_MEMBERSHIP child set, one unit, target = user id. Skipped
     *       when empty (the engine's {@code ResolveMemberAliases} then yields no
     *       aliases, dropping the claim — matches KC runtime).</li>
     *   <li>{@code group_definition} (unit 6) — one unit per ORGANIZATION-type
     *       backing group the user is in. {@code type=ORGANIZATION} gates the org
     *       membership in the engine's WALK.group_to_org.</li>
     *   <li>{@code group_role_mapping_set} (unit 10) — the RAW stored
     *       GROUP_ROLE_MAPPING child set for each visited backing group, so any
     *       role inherited through the org group has an attested source.</li>
     *   <li>{@code organization_definition} (unit 17) — one unit per org the user
     *       is a MEMBER of, target = org id ({@code org_id, alias, enabled,
     *       group_id}).</li>
     *   <li>{@code organization_domain_set} (unit 18) — one unit per such org, the
     *       complete {@code (name, verified)} ORG_DOMAIN set, target = org id.</li>
     * </ol>
     *
     * <p>Uses {@link OrganizationProvider#getByMember(UserModel)} to enumerate the
     * orgs, then derives the backing-group id via JPQL against
     * {@code OrganizationEntity.groupId} (the public {@code OrganizationModel}
     * interface does not expose {@code getGroupId()}; JPQL keeps us interface-clean).
     *
     * <p>Returns the count of units added (for the producer log).</p>
     */
    private int emitOrganizationClosure(KeycloakSession session, EntityManager em,
                                        RealmModel realm, UserModel user, String realmId,
                                        List<AttestationUnit> out) {
        OrganizationProvider orgProvider;
        try {
            orgProvider = session.getProvider(OrganizationProvider.class);
        } catch (RuntimeException re) {
            log.debugf("producer: OrganizationProvider not available (%s); skipping org closure",
                    re.getMessage());
            return 0;
        }
        if (orgProvider == null) {
            return 0;
        }

        // 1) user's full group-membership set (the RAW stored child set). One unit
        //    per user. Mirrors the user_role_mapping_set JPQL shape.
        List<String> groupIds = userGroupMembershipSet(em, user.getId());
        int added = 0;
        if (!groupIds.isEmpty()) {
            out.add(new UserGroupMembershipSetUnit(realmId, user.getId(), groupIds));
            added++;
        }

        // 2) per-org closure: organization_definition + organization_domain_set + the
        //    ORGANIZATION-type backing group_definition + its group_role_mapping_set.
        //    Driven by the orgs the user is a MEMBER of (the engine walks membership
        //    first, so this set is exact). Dedup group ids.
        Set<String> emittedGroupIds = new LinkedHashSet<>();
        List<OrganizationModel> memberOrgs = orgProvider.getByMember(user)
                .collect(java.util.stream.Collectors.toList());
        for (OrganizationModel org : memberOrgs) {
            String orgId = org.getId();
            String groupId = organizationBackingGroupId(em, orgId);
            if (groupId == null) {
                log.warnf("producer: organization %s has no backing group id; "
                        + "skipping org closure for it (closure incomplete)", orgId);
                continue;
            }
            // organization_definition (unit 17).
            out.add(organizationDefinition(org, groupId, realmId));
            added++;

            // organization_domain_set (unit 18) — the complete (name, verified) set
            // from ORG_DOMAIN via the public OrganizationModel.getDomains() surface.
            out.add(organizationDomainSet(org, realmId));
            added++;

            // group_definition (unit 6) + group_role_mapping_set (unit 10) for the
            // ORGANIZATION-type backing group (dedup across orgs).
            if (emittedGroupIds.add(groupId)) {
                GroupModel backing = realm.getGroupById(groupId);
                if (backing == null) {
                    log.warnf("producer: org %s backing group %s not resolvable; "
                            + "skipping group_definition (may drop the claim)",
                            orgId, groupId);
                    continue;
                }
                out.add(groupDefinition(backing, realmId));
                added++;
                out.add(groupRoleMappingSet(em, groupId, realmId));
                added++;
            }
        }
        return added;
    }

    /** Per-user RAW USER_GROUP_MEMBERSHIP child set (group ids). Mirrors userRoleMappingSet JPQL. */
    private List<String> userGroupMembershipSet(EntityManager em, String userId) {
        return userGroupMembershipSet(em, userId, onlyAttested);
    }

    /**
     * Shared, single-source per-user RAW USER_GROUP_MEMBERSHIP child set (group ids).
     * The commit-time signer ({@code TideAttestor}) calls this with
     * {@code onlyAttested=false} so it signs the same unfiltered post-change set the
     * producer's default export emits — guaranteeing byte-identical
     * {@link UserGroupMembershipSetUnit#serialize()} output at commit and at login.
     */
    public static List<String> userGroupMembershipSet(EntityManager em, String userId,
                                                      boolean onlyAttested) {
        String jpql = "SELECT m.groupId FROM UserGroupMembershipEntity m WHERE m.user.id = :owner";
        if (onlyAttested) {
            // UserGroupMembershipEntity does not currently carry an attestation column
            // in the IGA model, so this discriminator is inert here — left in place to
            // mirror the userRoleMappingSet pattern in case the column is added.
            jpql += " AND m.attestation IS NOT NULL";
        }
        // Deterministic group-id ordering: the VVK sig is verified over the LITERAL
        // envelope bytes (no re-canonicalization), so the set ORDER is load-bearing.
        // Must mirror the commit-time signer's final sort
        // (TideAttestor#buildUserGroupMembershipSetUnitCbor) so commit and login emit
        // an identical set. (See the user_role_mapping_set precedent.)
        jpql += " ORDER BY m.groupId";
        @SuppressWarnings("unchecked")
        List<String> ids = em.createQuery(jpql).setParameter("owner", userId).getResultList();
        return new ArrayList<>(ids);
    }

    /** Per-group RAW GROUP_ROLE_MAPPING child set (role ids). Mirrors userRoleMappingSet JPQL. */
    public static GroupRoleMappingSetUnit groupRoleMappingSet(EntityManager em, String groupId,
                                                        String realmId) {
        // Deterministic role-id ordering (ORDER BY) — load-bearing for the literal-bytes
        // VVK verification; mirrors the commit-time signer's sort.
        String jpql = "SELECT m.roleId FROM GroupRoleMappingEntity m WHERE m.group.id = :gid"
                + " ORDER BY m.roleId";
        @SuppressWarnings("unchecked")
        List<String> ids = em.createQuery(jpql).setParameter("gid", groupId).getResultList();
        return new GroupRoleMappingSetUnit(realmId, groupId, new ArrayList<>(ids));
    }

    /**
     * The ORGANIZATION-type backing group's id for the given organization, looked
     * up via {@code OrganizationEntity.groupId} (a column not exposed on the public
     * {@code OrganizationModel} interface — only on the JPA adapter). JPQL keeps the
     * producer interface-clean.
     */
    private String organizationBackingGroupId(EntityManager em, String orgId) {
        @SuppressWarnings("unchecked")
        List<String> rows = em.createQuery(
                "SELECT o.groupId FROM OrganizationEntity o WHERE o.id = :oid")
                .setParameter("oid", orgId).getResultList();
        return rows.isEmpty() ? null : rows.get(0);
    }

    /**
     * Build the {@code organization_domain_set} (unit 18) from the public
     * {@code OrganizationModel.getDomains()} surface — the complete
     * {@code (name, verified)} ORG_DOMAIN set for the org, target = org id.
     */
    /**
     * Build an {@code organization_definition} NODE unit (unit 16). The backing
     * ORGANIZATION-type group id is resolved by the caller (it lives on the JPA
     * adapter, not the public {@code OrganizationModel} surface). Shared so the
     * commit-time signer emits byte-identical bytes to this export path.
     */
    public static OrganizationDefinitionUnit organizationDefinition(OrganizationModel org,
                                                                    String backingGroupId,
                                                                    String realmId) {
        return new OrganizationDefinitionUnit(realmId, org.getId(), org.getAlias(),
                org.isEnabled(), backingGroupId);
    }

    private OrganizationDomainSetUnit organizationDomainSet(OrganizationModel org, String realmId) {
        List<OrgDomain> domains = new ArrayList<>();
        org.getDomains().forEach((OrganizationDomainModel d) ->
                domains.add(new OrgDomain(d.getName(), d.isVerified())));
        return new OrganizationDomainSetUnit(realmId, org.getId(), domains);
    }

    /**
     * Build a {@code group_definition} unit for a backing group. {@code type} is the
     * literal {@code REALM}/{@code ORGANIZATION} enum name. KC's {@code getParentId()}
     * returns null for top-level groups; ORGANIZATION-type backing groups are always
     * top-level, so {@code parent_group_id} is null in practice.
     */
    public static GroupDefinitionUnit groupDefinition(GroupModel group, String realmId) {
        GroupModel.Type t = group.getType();
        GroupType type = (t == GroupModel.Type.ORGANIZATION) ? GroupType.ORGANIZATION : GroupType.REALM;
        return new GroupDefinitionUnit(realmId, group.getId(), group.getName(),
                group.getParentId(), type);
    }

    // -------------------------------------------------------------------------
    // Transitive role closure (reverse of the engine's GrantedRoles walk)
    // -------------------------------------------------------------------------

    /**
     * Build the widened ROLE-METADATA seed (pre composite-expansion) whose
     * {@link #transitiveRoleClosure} drives {@code role_definition} (unit 5) +
     * {@code role_composite_children_set} (unit 11) emission, so the ORK can expand
     * every composite it walks. The seed is the UNION of:
     * <ol>
     *   <li>{@code userGrantRoleIds} — the user's direct USER_ROLE_MAPPING grants
     *       (same ids as the U8 {@code user_role_mapping_set} payload);</li>
     *   <li>group-role ids — every role mapped to a group the user is a member of
     *       AND to every ancestor group on that group's {@code parent_group_id} chain
     *       (via {@code user.getGroupsStream()} → ascend {@code GroupModel.getParent()}
     *       → {@code group.getRoleMappingsStream()}). The ORK enumerates group roles
     *       ancestor-inclusively (a role on a parent reaches a child member), so the
     *       seed walks the same parent chain — fixes (a2) incl. ancestor composites;</li>
     *   <li>{@code clientAllowlistRoleIds} — the request client's own SCOPE_MAPPING
     *       allowlist (used by {@code getAccess} when {@code full_scope_allowed=false});</li>
     *   <li>per assigned {@code client_scope} — its CLIENT_SCOPE_ROLE_MAPPING
     *       allowlist — fixes (a).</li>
     * </ol>
     *
     * <p><b>GUARDRAIL:</b> this is a METADATA seed only. It is NOT emitted as, and does
     * not feed, any user-effective-membership unit (U8/U9/U10). Widening it adds only
     * which {@code role_definition}/{@code role_composite_children_set} units appear —
     * never which roles the user holds. Package-private + static for direct unit testing.
     */
    static Set<String> metadataRoleSeed(List<String> userGrantRoleIds, UserModel user,
                                        List<String> clientAllowlistRoleIds,
                                        java.util.Collection<ClientScopeModel> assignedScopes) {
        Set<String> seed = new LinkedHashSet<>();
        if (userGrantRoleIds != null) {
            seed.addAll(userGrantRoleIds);
        }
        // (ii) group-role ids — every role mapped to a group the user belongs to, AND
        //      every ANCESTOR group reached by ascending the parent_group_id chain. The
        //      ORK enumerates group roles ancestor-inclusively (MapperContext.GrantedRoles
        //      → GroupAndAncestors walks parent_group_id until a top-level group), folding
        //      roles on a PARENT of a joined group into a child member's GrantedRoles
        //      closure. So a COMPOSITE role sitting on an ancestor group must have its
        //      definition/composite-children attested too, or the ORK can't expand it and
        //      resource_access/realm_access under-reports (false reject). Mirror that
        //      ascent here. Membership itself is untouched (U9/U10 emission is unchanged):
        //      this only widens which role_definition/role_composite_children_set units are
        //      emitted, never which roles the user holds.
        if (user != null) {
            user.getGroupsStream().forEach(g -> {
                for (GroupModel grp = g; grp != null; grp = grp.getParent()) {
                    grp.getRoleMappingsStream().forEach(r -> seed.add(r.getId()));
                }
            });
        }
        // (iii) request client's own SCOPE_MAPPING allowlist.
        if (clientAllowlistRoleIds != null) {
            seed.addAll(clientAllowlistRoleIds);
        }
        // (iv) every assigned client_scope's CLIENT_SCOPE_ROLE_MAPPING allowlist.
        if (assignedScopes != null) {
            for (ClientScopeModel scope : assignedScopes) {
                scope.getScopeMappingsStream().forEach(r -> seed.add(r.getId()));
            }
        }
        return seed;
    }

    /**
     * The full transitive role closure of the seed role ids, each COMPOSITE-EXPANDED
     * via {@link RoleModel#getCompositesStream()}
     * recursively, with a {@code seen} set guarding cycles/diamonds. Built-in /
     * system roles are INCLUDED — every role id that can surface in the token must
     * have a definition. Mirrors, in reverse, the engine's GrantedRoles.
     */
    private Set<RoleModel> transitiveRoleClosure(RealmModel realm, List<String> seedRoleIds,
                                                 String userId) {
        Set<RoleModel> closure = new LinkedHashSet<>();
        Set<String> seen = new LinkedHashSet<>();
        Deque<String> pending = new ArrayDeque<>(seedRoleIds);
        while (!pending.isEmpty()) {
            String id = pending.pop();
            if (!seen.add(id)) {
                continue; // already expanded — cycle / diamond guard
            }
            RoleModel role = realm.getRoleById(id);
            if (role == null) {
                log.warnf("producer: role %s referenced by user %s not resolvable; "
                        + "emitting nothing for it (closure may be incomplete)", id, userId);
                continue;
            }
            closure.add(role);
            if (role.isComposite()) {
                role.getCompositesStream().forEach(child -> pending.push(child.getId()));
            }
        }
        return closure;
    }

    // -------------------------------------------------------------------------
    // Node units (definition bundles)
    // -------------------------------------------------------------------------

    private RealmConfigUnit realmConfig(RealmModel realm, String realmId) {
        return new RealmConfigUnit(realmId,
                realm.getName(),
                realm.getAccessTokenLifespan(),
                realm.getAccessTokenLifespanForImplicitFlow(),
                realm.getSsoSessionIdleTimeout(),
                realm.getSsoSessionMaxLifespan(),
                realm.getClientSessionIdleTimeout(),
                realm.getClientSessionMaxLifespan(),
                realm.getOfflineSessionIdleTimeout(),
                realm.isOfflineSessionMaxLifespanEnabled(),
                realm.getOfflineSessionMaxLifespan(),
                realmConfigAttributes(realm));
    }

    /** The producer-filtered realm attributes ({name,value} list; null → ""). */
    private List<NameValue> realmConfigAttributes(RealmModel realm) {
        List<NameValue> attrs = new ArrayList<>();
        for (String key : REALM_CONFIG_ATTR_KEYS) {
            String val = realm.getAttribute(key);
            attrs.add(new NameValue(key, val == null ? "" : val));
        }
        return attrs;
    }

    public static ClientConfigUnit clientConfig(ClientModel client, String realmId) {
        return new ClientConfigUnit(realmId,
                client.getId(),
                client.getClientId(),
                nullToEmpty(client.getProtocol()),
                client.isFullScopeAllowed(),
                client.isServiceAccountsEnabled(),
                new ArrayList<>(orEmptySet(client.getWebOrigins())),
                attributeNameValues(client.getAttributes()));
    }

    public static ClientScopeConfigUnit clientScopeConfig(ClientScopeModel scope, String realmId) {
        return new ClientScopeConfigUnit(realmId,
                scope.getId(),
                scope.getName(),
                nullToEmpty(scope.getProtocol()),
                attributeNameValues(scope.getAttributes()));
    }

    public static UserIdentityUnit userIdentity(UserModel user, String realmId) {
        return new UserIdentityUnit(realmId,
                user.getId(),
                user.getUsername(),
                user.getEmail(),            // explicit null if absent
                user.isEmailVerified(),
                user.getFirstName(),        // explicit null if absent
                user.getLastName(),         // explicit null if absent
                userAttributeNameValues(user.getAttributes()));
    }

    public static RoleDefinitionUnit roleDefinition(RoleModel role, String realmId) {
        // container_id = owning client UUID for client roles, else the realm id.
        return new RoleDefinitionUnit(realmId, role.getId(), role.getName(),
                role.isClientRole(), role.getContainerId());
    }

    public static RoleCompositeChildrenSetUnit roleCompositeChildrenSet(RoleModel role, String realmId) {
        List<String> childIds = new ArrayList<>();
        if (role.isComposite()) {
            role.getCompositesStream().forEach(c -> childIds.add(c.getId()));
        }
        // Deterministic child-id ordering: getCompositesStream() has no defined order,
        // so the literal-bytes VVK verification would be non-reproducible without a sort.
        // The commit-time signer (TideAttestor#buildRoleCompositeChildrenSetUnitCbor)
        // applies the SAME ascending sort so commit and login emit identical bytes.
        childIds.sort(java.util.Comparator.naturalOrder());
        return new RoleCompositeChildrenSetUnit(realmId, role.getId(), childIds);
    }

    // -------------------------------------------------------------------------
    // Set units
    // -------------------------------------------------------------------------

    private ClientScopeAssignmentSetUnit clientScopeAssignmentSet(
            ClientModel client, Map<String, ClientScopeModel> assigned, String realmId) {
        // default=true for default scopes, false for optional.
        Set<String> defaultIds = client.getClientScopes(true).values().stream()
                .map(ClientScopeModel::getId).collect(java.util.stream.Collectors.toSet());
        List<ScopeAssignment> assignments = new ArrayList<>();
        for (ClientScopeModel scope : assigned.values()) {
            assignments.add(new ScopeAssignment(scope.getId(), defaultIds.contains(scope.getId())));
        }
        return new ClientScopeAssignmentSetUnit(realmId, client.getId(), assignments);
    }

    /** The realm's REALM_DEFAULT_GROUPS set (unit 16), target = realm UUID. */
    private RealmDefaultGroupsSetUnit realmDefaultGroupsSet(RealmModel realm, String realmId) {
        List<String> groupIds = new ArrayList<>();
        realm.getDefaultGroupsStream().forEach(g -> groupIds.add(g.getId()));
        return new RealmDefaultGroupsSetUnit(realmId, groupIds);
    }

    /**
     * The set of scopes whose mappers the token actually applies — mirrors the
     * engine's Stage 3 scope resolution: every DEFAULT scope (always applied) plus
     * every OPTIONAL scope whose name appears as a whitespace token in the request
     * {@code scope} param.
     */
    private Map<String, ClientScopeModel> resolveActiveScopes(ClientModel client,
                                                              ExportRequest req) {
        Map<String, ClientScopeModel> active = new LinkedHashMap<>();
        for (ClientScopeModel s : client.getClientScopes(true).values()) {
            active.put(s.getId(), s); // default scopes always active
        }
        Set<String> requested = requestedScopeNames(req);
        for (ClientScopeModel s : client.getClientScopes(false).values()) {
            if (requested.contains(s.getName())) {
                active.put(s.getId(), s);
            }
        }
        return active;
    }

    private Set<String> requestedScopeNames(ExportRequest req) {
        Set<String> names = new LinkedHashSet<>();
        if (req.scope() != null) {
            for (String tok : req.scope().trim().split("\\s+")) {
                if (!tok.isEmpty()) {
                    names.add(tok);
                }
            }
        }
        return names;
    }

    /**
     * Emit a {@code protocol_mapper} for EVERY mapper on the client and on each
     * ACTIVE scope, plus the {@code client_mapper_set} / {@code client_scope_mapper_set}
     * membership unit listing those ids. The profile/email/roles/web-origins/etc.
     * mappers are all emitted so each token claim has an attested source. (The engine
     * resolves every id in a mapper-set to a protocol_mapper unit, so the set and the
     * units stay in lockstep.)
     */
    private void emitAllActiveMappers(ClientModel client, Map<String, ClientScopeModel> assigned,
                                      ExportRequest req, String realmId,
                                      List<AttestationUnit> out) {
        // Client-owned (dedicated) mappers — the client-as-scope participant.
        // Filter out JWT-body-irrelevant factories (engine contract: the TVE
        // ClaimMapperRegistry REJECTS these as session-note-only / base-claim-handled;
        // see JWT_BODY_IRRELEVANT_FACTORIES). Skip emission AND set membership.
        List<String> clientMapperIds = new ArrayList<>();
        client.getProtocolMappersStream().forEach(pm -> {
            if (JWT_BODY_IRRELEVANT_FACTORIES.contains(pm.getProtocolMapper())) {
                log.debugf("producer: skipping JWT-body-irrelevant client mapper %s (factory=%s)",
                        pm.getId(), pm.getProtocolMapper());
                return;
            }
            out.add(protocolMapper(pm, ParentType.client, client.getId(), realmId));
            clientMapperIds.add(pm.getId());
        });
        if (!clientMapperIds.isEmpty()) {
            out.add(new ClientMapperSetUnit(realmId, client.getId(), clientMapperIds));
        }
        // Active scope mappers (default + requested-optional only — the engine never
        // visits an unresolved optional scope's mapper set). Same factory filter.
        Map<String, ClientScopeModel> active = resolveActiveScopes(client, req);
        for (ClientScopeModel scope : active.values()) {
            List<String> scopeMapperIds = new ArrayList<>();
            scope.getProtocolMappersStream().forEach(pm -> {
                if (JWT_BODY_IRRELEVANT_FACTORIES.contains(pm.getProtocolMapper())) {
                    log.debugf("producer: skipping JWT-body-irrelevant scope mapper %s "
                            + "(scope=%s, factory=%s)", pm.getId(), scope.getName(),
                            pm.getProtocolMapper());
                    return;
                }
                out.add(protocolMapper(pm, ParentType.client_scope, scope.getId(), realmId));
                scopeMapperIds.add(pm.getId());
            });
            if (!scopeMapperIds.isEmpty()) {
                out.add(new ClientScopeMapperSetUnit(realmId, scope.getId(), scopeMapperIds));
            }
        }
    }

    private ProtocolMapperUnit protocolMapper(ProtocolMapperModel pm, ParentType parentType,
                                              String parentId, String realmId) {
        return new ProtocolMapperUnit(realmId,
                pm.getId(),
                parentType,
                parentId,
                nullToEmpty(pm.getProtocol()),
                pm.getProtocolMapper(),
                attributeNameValues(pm.getConfig()));
    }

    // -------------------------------------------------------------------------
    // JPQL helpers (raw stored linkage rows)
    // -------------------------------------------------------------------------

    /**
     * The RAW stored USER_ROLE_MAPPING role-id set for a user (the complete child
     * set, incl. the implicit {@code default-roles-<realm>} grant). Uses the same
     * JPQL shape as {@link org.tidecloak.iga.services.IgaUnsignedRowScanner}.
     */
    private List<String> userRoleMappingSet(EntityManager em, String userId) {
        String jpql = "SELECT urm.roleId FROM UserRoleMappingEntity urm WHERE urm.user.id = :owner";
        if (onlyAttested) {
            jpql += " AND urm.attestation IS NOT NULL";
        }
        // Deterministic role-id ordering: the VVK sig is verified over the LITERAL
        // envelope bytes (no re-canonicalization), so role_ids order is load-bearing.
        // Must stay the LAST clause and mirror the firstAdmin signer's final sort
        // (TideAttestor#buildUserRoleMappingSetUnitCbor) so both emit an identical set.
        jpql += " ORDER BY urm.roleId";
        @SuppressWarnings("unchecked")
        List<String> ids = em.createQuery(jpql).setParameter("owner", userId).getResultList();
        return new ArrayList<>(ids);
    }

    // -------------------------------------------------------------------------
    // Scope resolution + small builders
    // -------------------------------------------------------------------------

    /** Default + optional client-scope assignments (the assignment-set closure). */
    private Map<String, ClientScopeModel> collectAssignedScopes(ClientModel client) {
        Map<String, ClientScopeModel> all = new LinkedHashMap<>();
        // KC keys these maps by scope NAME; we re-key by id for stable lookup.
        for (ClientScopeModel s : client.getClientScopes(true).values()) {
            all.put(s.getId(), s);
        }
        for (ClientScopeModel s : client.getClientScopes(false).values()) {
            all.put(s.getId(), s);
        }
        return all;
    }

    /** scope→role allowlist (SCOPE_MAPPING / CLIENT_SCOPE_ROLE_MAPPING) role ids. */
    private List<String> scopeMappingRoleIds(org.keycloak.models.ScopeContainerModel container) {
        List<String> ids = new ArrayList<>();
        container.getScopeMappingsStream().forEach(r -> ids.add(r.getId()));
        return ids;
    }

    // ---- name/value list helpers (ork {name,value} / {name,values}) ----

    /** Single-valued attribute map -> [NameValue] (null value -> ""). */
    private static List<NameValue> attributeNameValues(Map<String, String> attrs) {
        List<NameValue> out = new ArrayList<>();
        if (attrs != null) {
            for (Map.Entry<String, String> e : attrs.entrySet()) {
                out.add(new NameValue(e.getKey(), e.getValue() == null ? "" : e.getValue()));
            }
        }
        return out;
    }

    /** Multi-valued user attribute map -> [NameValues] (ork unit 7). */
    private static List<NameValues> userAttributeNameValues(Map<String, List<String>> attrs) {
        List<NameValues> out = new ArrayList<>();
        if (attrs != null) {
            for (Map.Entry<String, List<String>> e : attrs.entrySet()) {
                out.add(new NameValues(e.getKey(),
                        e.getValue() == null ? new ArrayList<>() : new ArrayList<>(e.getValue())));
            }
        }
        return out;
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    private static Set<String> orEmptySet(Set<String> s) {
        return s == null ? new LinkedHashSet<>() : s;
    }
}
