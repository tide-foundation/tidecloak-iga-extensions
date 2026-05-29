package org.tidecloak.iga.producer;

import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.organization.OrganizationProvider;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Emits the closure of attestation-unit envelopes (plain JSON, no JCS / no
 * signature — design §2) for a {@code (realm, client, user, scope)}, so the ork
 * {@code TokenValidationEngine} can validate a real issued token against current
 * attested realm state.
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
 * issue — no more, no less:
 * <ul>
 *   <li>the 4-unit floor: {@code realm_config}, {@code client_config} (the
 *       request client), {@code client_scope_assignment_set}, {@code user_identity};</li>
 *   <li>a {@code client_scope_config} per assigned scope;</li>
 *   <li>the {@code protocol_mapper}s of EVERY active scope (the client's own
 *       dedicated mappers + each resolved scope's mappers) plus their
 *       {@code client_mapper_set} / {@code client_scope_mapper_set} membership
 *       — not just the role mappers, so the profile/email/roles/etc. claims all
 *       have an attested source;</li>
 *   <li>a {@code role_definition} + {@code role_composite_children_set} for the
 *       FULL TRANSITIVE role closure of the user's grants — INCLUDING built-ins
 *       ({@code offline_access}, {@code uma_authorization}, the
 *       {@code default-roles-<realm>} composite and its children). Every role id
 *       that can surface in the token gets a definition, even system roles;</li>
 *   <li>a {@code client_config} for every OWNING client of a client-role in that
 *       closure (e.g. {@code account}) — the engine's client-role mapper walks
 *       {@code role_definition.container_id → client_config} to name
 *       {@code resource_access.<clientId>}, so an unattested owner would drop the
 *       claim;</li>
 *   <li>{@code user_role_mapping_set} (the RAW stored child set) and the
 *       {@code scope_role_allowlist_set} for the client and any scope carrying a
 *       scope→role allowlist.</li>
 * </ul>
 *
 * <p><b>Role-closure rule (built-ins included).</b> {@code includeSystem=false}
 * skips built-in CLIENTS / SCOPES from <i>independent</i> governance, but it must
 * NOT drop a {@code role_definition} for any role that surfaces in the token via
 * the {@code default-roles} composite expansion. The transitive walk therefore
 * ignores the system filter entirely — it mirrors, in reverse, the engine's
 * {@code MapperContext.GrantedRoles()} composite expansion
 * ({@code role_composite_children_set} recursion with a cycle/diamond guard).
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
 * discriminator (design §7) is wired as {@link #onlyAttested} for a future
 * trust-loop pass but defaults to off.
 */
public final class RealmAttestationExporter {

    private static final Logger log = Logger.getLogger(RealmAttestationExporter.class);

    // ---- ork unit_type wire strings (snake_case, case-sensitive) ----
    private static final String U_REALM_CONFIG = "realm_config";
    private static final String U_CLIENT_CONFIG = "client_config";
    private static final String U_CLIENT_SCOPE_CONFIG = "client_scope_config";
    private static final String U_PROTOCOL_MAPPER = "protocol_mapper";
    private static final String U_ROLE_DEFINITION = "role_definition";
    private static final String U_USER_IDENTITY = "user_identity";
    private static final String U_USER_ROLE_MAPPING_SET = "user_role_mapping_set";
    private static final String U_ROLE_COMPOSITE_CHILDREN_SET = "role_composite_children_set";
    private static final String U_CLIENT_SCOPE_ASSIGNMENT_SET = "client_scope_assignment_set";
    private static final String U_CLIENT_MAPPER_SET = "client_mapper_set";
    private static final String U_CLIENT_SCOPE_MAPPER_SET = "client_scope_mapper_set";
    private static final String U_SCOPE_ROLE_ALLOWLIST_SET = "scope_role_allowlist_set";
    private static final String U_ORGANIZATION_DEFINITION = "organization_definition";
    private static final String U_GROUP_DEFINITION = "group_definition";
    private static final String U_USER_GROUP_MEMBERSHIP_SET = "user_group_membership_set";

    // realm_config attributes the ork preset carries (design §5 / RealmConfig preset).
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
     * emitted (the design §7 "governed/committed" discriminator). Leaves this
     * false so the closure stays exact on a stock realm; flip on for the future
     * trust-loop pass. NOTE: never narrows the transitive role closure — a role
     * that surfaces in the token must always get a definition.
     */
    private boolean onlyAttested = false;

    public RealmAttestationExporter onlyAttested(boolean v) {
        this.onlyAttested = v;
        return this;
    }

    /**
     * Emit the full-closure set of attestation-unit envelopes for the request.
     * Caller is responsible for binding the realm onto the session context if the
     * session is fresh (see {@code IgaAdoptScan}).
     */
    public List<AttestationEnvelope> export(KeycloakSession session, RealmModel realm,
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

        List<AttestationEnvelope> out = new ArrayList<>();

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
        out.add(setUnit(U_USER_ROLE_MAPPING_SET, realmId, req.userId(), payload -> {
            payload.put("user_id", req.userId());
            payload.put("realm_id", realmId);
            payload.put("role_ids", seedRoleIds);
        }));

        // 7) role_definition + 8) role_composite_children_set for the FULL TRANSITIVE
        //    role closure (mirrors the engine's GrantedRoles composite expansion).
        //    Built-ins are INCLUDED — a role surfacing in the token via the
        //    default-roles composite must have a definition regardless of onlyAttested
        //    / includeSystem (the role-closure rule).
        Set<RoleModel> roleClosure = transitiveRoleClosure(realm, seedRoleIds, req.userId());
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
        out.add(scopeRoleAllowlistSet("client", client.getId(), realmId,
                scopeMappingRoleIds(client)));
        // Per assigned scope that carries its own scope→role mapping.
        for (ClientScopeModel scope : assigned.values()) {
            List<String> scopeAllow = scopeMappingRoleIds(scope);
            if (!scopeAllow.isEmpty()) {
                out.add(scopeRoleAllowlistSet("client_scope", scope.getId(), realmId, scopeAllow));
            }
        }

        // 11) protocol_mapper + 12) client_mapper_set / client_scope_mapper_set for
        //     ALL mappers of the active scopes (client-owned + each active scope's),
        //     so every claim the token carries (profile/email/roles/...) has an
        //     attested source.
        emitAllActiveMappers(client, assigned, req, realmId, out);

        // 13) Organization closure for the org-membership claim mapper
        //     (OrganizationMembershipClaimMapper). The mapper walks:
        //     user_identity → user_group_membership_set → (per group_id)
        //     group_definition (type=ORGANIZATION) → reverse FK
        //     organization_definition.group_id → alias. Emitting these three unit
        //     families gives the engine an attested source for the `organization`
        //     claim. No-ops on a realm without organizations (and on a user with
        //     zero memberships, no user_group_membership_set is emitted — the
        //     mapper then returns an empty alias set and drops the claim, matching
        //     KC's runtime behaviour).
        int orgUnitsEmitted = emitOrganizationClosure(session, em, realm, user, realmId, out);

        log.infof("producer: full-closure export realm=%s client=%s user=%s scope=%s -> "
                        + "%d envelope(s); roles=%d ownerClients=%d orgUnits=%d",
                realm.getName(), req.clientId(), req.userId(), req.scope(),
                out.size(), roleClosure.size(), ownerClientUuids.size(), orgUnitsEmitted);
        return out;
    }

    // -------------------------------------------------------------------------
    // Organization closure (units 6 group_definition, 9 user_group_membership_set,
    // 17 organization_definition) — backs the org-membership claim mapper.
    // -------------------------------------------------------------------------

    /**
     * Emit the org-closure trio backing the {@code organization} claim mapper:
     * <ol>
     *   <li>{@link #U_USER_GROUP_MEMBERSHIP_SET} (unit 9) — the user's RAW stored
     *       USER_GROUP_MEMBERSHIP child set (group ids), exactly one envelope, target
     *       = user id. Skipped when empty (and the engine's
     *       {@code ResolveMemberAliases} then yields no aliases, dropping the
     *       claim — matches KC runtime).</li>
     *   <li>{@link #U_GROUP_DEFINITION} (unit 6) — one envelope per
     *       ORGANIZATION-type backing group the user is in. {@code type=ORGANIZATION}
     *       gates the org membership in the engine's WALK.group_to_org; without it
     *       a joined regular (REALM-type) group would never resolve an org.
     *       Top-level groups serialize {@code parent_group_id=null} (KC's literal
     *       single-space sentinel is folded to null per the unit-6 spec gotcha).</li>
     *   <li>{@link #U_ORGANIZATION_DEFINITION} (unit 17) — one envelope per org the
     *       user is a MEMBER of, target = org id. Wire fields: {@code org_id},
     *       {@code alias}, {@code enabled}, {@code group_id} (the reverse FK the
     *       engine walks: {@code organization_definition.group_id == group.group_id}).</li>
     * </ol>
     *
     * <p>Uses {@link OrganizationProvider#getByMember(UserModel)} to enumerate the
     * orgs (the same surface the KC OrganizationMembershipMapper uses), then derives
     * the backing-group id via JPQL against {@code OrganizationEntity.groupId} (the
     * public {@code OrganizationModel} interface does not expose {@code getGroupId()}
     * — only the JPA adapter does; JPQL keeps us interface-clean).</p>
     *
     * <p>Returns the count of envelopes added (for the producer log).</p>
     */
    private int emitOrganizationClosure(KeycloakSession session, EntityManager em,
                                        RealmModel realm, UserModel user, String realmId,
                                        List<AttestationEnvelope> out) {
        // Resolve OrganizationProvider only when the realm has organizations enabled
        // (and when the provider is registered at all). Failing soft keeps the
        // producer working on a non-org realm — a regression-safe pre-check.
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

        // 1) user's full group-membership set (the RAW stored child set). One envelope
        //    per user. Mirrors the user_role_mapping_set JPQL shape (and the
        //    ResolveMemberAliases walk: U9 -> U6 -> U17).
        List<String> groupIds = userGroupMembershipSet(em, user.getId());
        int added = 0;
        if (!groupIds.isEmpty()) {
            out.add(setUnit(U_USER_GROUP_MEMBERSHIP_SET, realmId, user.getId(), p -> {
                p.put("user_id", user.getId());
                p.put("realm_id", realmId);
                p.put("group_ids", groupIds);
            }));
            added++;
        }

        // 2) per-org closure: organization_definition + the ORGANIZATION-type backing
        //    group_definition. Driven by the orgs the user is a MEMBER of (the engine
        //    walks membership first, so this set is exact). Dedup the group ids so a
        //    user in two orgs that (theoretically) share a backing group doesn't emit
        //    twice — KC's data model is one-group-per-org but the guard costs nothing.
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
            // organization_definition (unit 17). Wire fields per
            // OrganizationDefinitionAttestationUnit: org_id, realm_id, alias, enabled,
            // group_id. realm_id hoisted from the envelope; payload mirrors the unit's
            // BuildCanonicalPayload key-for-key.
            final String alias = org.getAlias();
            final boolean enabled = org.isEnabled();
            out.add(setUnit(U_ORGANIZATION_DEFINITION, realmId, orgId, p -> {
                p.put("org_id", orgId);
                p.put("realm_id", realmId);
                p.put("alias", alias);
                p.put("enabled", enabled);
                p.put("group_id", groupId);
            }));
            added++;

            // group_definition (unit 6) for the ORGANIZATION-type backing group.
            // Dedup (same group can theoretically back multiple orgs in a malformed
            // data set; KC normally maintains a 1:1).
            if (emittedGroupIds.add(groupId)) {
                GroupModel backing = realm.getGroupById(groupId);
                if (backing == null) {
                    log.warnf("producer: org %s backing group %s not resolvable; "
                            + "emitting group_definition with minimal payload may drop the claim",
                            orgId, groupId);
                    continue;
                }
                out.add(groupDefinition(backing, realmId));
                added++;
            }
        }
        return added;
    }

    /** Per-user RAW USER_GROUP_MEMBERSHIP child set (group ids). Mirrors the user_role_mapping_set JPQL. */
    private List<String> userGroupMembershipSet(EntityManager em, String userId) {
        String jpql = "SELECT m.groupId FROM UserGroupMembershipEntity m WHERE m.user.id = :owner";
        if (onlyAttested) {
            // UserGroupMembershipEntity does not currently carry an attestation column
            // in the IGA model, so this discriminator is inert here — left in place to
            // mirror the userRoleMappingSet pattern in case the column is added.
            jpql += " AND m.attestation IS NOT NULL";
        }
        @SuppressWarnings("unchecked")
        List<String> ids = em.createQuery(jpql).setParameter("owner", userId).getResultList();
        return new ArrayList<>(ids);
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
     * Build a {@code group_definition} envelope for a backing group. Wire fields per
     * {@code GroupDefinitionAttestationUnit}: {@code group_id}, {@code name},
     * {@code realm_id}, {@code parent_group_id}, {@code type}. {@code type} is the
     * literal {@code "REALM"} or {@code "ORGANIZATION"} enum name (Type.toString()
     * round-trips the wire value, per AttestationUnit.cs). KC's literal single-space
     * sentinel for a top-level group's parent is NOT applied here: {@code getParentId()}
     * already returns null for top-level groups; the engine's GetGroupParentId folds
     * a literal {@code " "} to null defensively. ORGANIZATION-type backing groups are
     * always top-level (the org schema does not nest them), so this is null in practice.
     */
    private AttestationEnvelope groupDefinition(GroupModel group, String realmId) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("group_id", group.getId());
        p.put("name", group.getName());
        p.put("realm_id", realmId);
        p.put("parent_group_id", group.getParentId()); // null for top-level (org backing)
        GroupModel.Type t = group.getType();
        p.put("type", (t == null ? GroupModel.Type.REALM : t).name());
        return new AttestationEnvelope(U_GROUP_DEFINITION, realmId, group.getId(), p);
    }

    // -------------------------------------------------------------------------
    // Transitive role closure (reverse of the engine's GrantedRoles walk)
    // -------------------------------------------------------------------------

    /**
     * The full transitive role closure of the user's stored grants: the seed role
     * ids, each COMPOSITE-EXPANDED via {@link RoleModel#getCompositesStream()}
     * recursively, with a {@code seen} set guarding cycles/diamonds. Built-in /
     * system roles ({@code offline_access}, {@code uma_authorization}, the
     * {@code default-roles-<realm>} composite and its children, the {@code account}
     * client roles) are INCLUDED — every role id that can surface in the token must
     * have a definition. This mirrors, in reverse, the engine's
     * {@code MapperContext.GrantedRoles()} ({@code RoleUtils.expandCompositeRoles}).
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
    // Node units
    // -------------------------------------------------------------------------

    private AttestationEnvelope realmConfig(RealmModel realm, String realmId) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("realm_id", realmId);
        p.put("name", realm.getName());
        p.put("access_token_lifespan_seconds", realm.getAccessTokenLifespan());
        p.put("access_token_lifespan_for_implicit_flow_seconds",
                realm.getAccessTokenLifespanForImplicitFlow());
        p.put("sso_session_idle_timeout_seconds", realm.getSsoSessionIdleTimeout());
        p.put("sso_session_max_lifespan_seconds", realm.getSsoSessionMaxLifespan());
        p.put("client_session_idle_timeout_seconds", realm.getClientSessionIdleTimeout());
        p.put("client_session_max_lifespan_seconds", realm.getClientSessionMaxLifespan());
        p.put("offline_session_idle_timeout_seconds", realm.getOfflineSessionIdleTimeout());
        p.put("offline_session_max_lifespan_enabled", realm.isOfflineSessionMaxLifespanEnabled());
        p.put("offline_session_max_lifespan_seconds", realm.getOfflineSessionMaxLifespan());
        p.put("attributes", realmConfigAttributes(realm));
        return new AttestationEnvelope(U_REALM_CONFIG, realmId, realmId, p);
    }

    /** The producer-filtered realm attributes ({name,value} list). */
    private List<Map<String, Object>> realmConfigAttributes(RealmModel realm) {
        List<Map<String, Object>> attrs = new ArrayList<>();
        for (String key : REALM_CONFIG_ATTR_KEYS) {
            String val = realm.getAttribute(key);
            attrs.add(nameValue(key, val == null ? "" : val));
        }
        return attrs;
    }

    private AttestationEnvelope clientConfig(ClientModel client, String realmId) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("client_id_uuid", client.getId());
        p.put("client_id", client.getClientId());
        p.put("realm_id", realmId);
        p.put("protocol", nullToEmpty(client.getProtocol()));
        p.put("full_scope_allowed", client.isFullScopeAllowed());
        p.put("service_accounts_enabled", client.isServiceAccountsEnabled());
        p.put("web_origins", new ArrayList<>(orEmptySet(client.getWebOrigins())));
        p.put("attributes", attributeNameValues(client.getAttributes()));
        return new AttestationEnvelope(U_CLIENT_CONFIG, realmId, client.getId(), p);
    }

    private AttestationEnvelope clientScopeConfig(ClientScopeModel scope, String realmId) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("client_scope_id", scope.getId());
        p.put("name", scope.getName());
        p.put("realm_id", realmId);
        p.put("protocol", nullToEmpty(scope.getProtocol()));
        p.put("attributes", attributeNameValues(scope.getAttributes()));
        return new AttestationEnvelope(U_CLIENT_SCOPE_CONFIG, realmId, scope.getId(), p);
    }

    private AttestationEnvelope userIdentity(UserModel user, String realmId) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("user_id", user.getId());
        p.put("username", user.getUsername());
        p.put("realm_id", realmId);
        p.put("email", user.getEmail());           // explicit null if absent
        p.put("email_verified", user.isEmailVerified());
        p.put("first_name", user.getFirstName());   // explicit null if absent
        p.put("last_name", user.getLastName());     // explicit null if absent
        p.put("attributes", userAttributeNameValues(user.getAttributes()));
        return new AttestationEnvelope(U_USER_IDENTITY, realmId, user.getId(), p);
    }

    private AttestationEnvelope roleDefinition(RoleModel role, String realmId) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("role_id", role.getId());
        p.put("name", role.getName());
        p.put("realm_id", realmId);
        p.put("client_role", role.isClientRole());
        // container_id = owning client UUID for client roles, else the realm id.
        p.put("container_id", role.getContainerId());
        return new AttestationEnvelope(U_ROLE_DEFINITION, realmId, role.getId(), p);
    }

    private AttestationEnvelope roleCompositeChildrenSet(RoleModel role, String realmId) {
        List<String> childIds = new ArrayList<>();
        if (role.isComposite()) {
            role.getCompositesStream().forEach(c -> childIds.add(c.getId()));
        }
        return setUnit(U_ROLE_COMPOSITE_CHILDREN_SET, realmId, role.getId(), p -> {
            p.put("composite_role_id", role.getId());
            p.put("realm_id", realmId);
            p.put("child_role_ids", childIds);
        });
    }

    // -------------------------------------------------------------------------
    // Set units
    // -------------------------------------------------------------------------

    private AttestationEnvelope clientScopeAssignmentSet(ClientModel client,
                                                         Map<String, ClientScopeModel> assigned,
                                                         String realmId) {
        // default=true for default scopes, false for optional. Build the
        // assignments list from the two KC scope maps.
        Set<String> defaultIds = client.getClientScopes(true).values().stream()
                .map(ClientScopeModel::getId).collect(java.util.stream.Collectors.toSet());
        List<Map<String, Object>> assignments = new ArrayList<>();
        for (ClientScopeModel scope : assigned.values()) {
            Map<String, Object> a = new LinkedHashMap<>();
            a.put("client_scope_id", scope.getId());
            a.put("default", defaultIds.contains(scope.getId()));
            assignments.add(a);
        }
        return setUnit(U_CLIENT_SCOPE_ASSIGNMENT_SET, realmId, client.getId(), p -> {
            p.put("client_id_uuid", client.getId());
            p.put("realm_id", realmId);
            p.put("assignments", assignments);
        });
    }

    private AttestationEnvelope scopeRoleAllowlistSet(String parentType, String parentId,
                                                      String realmId, List<String> roleIds) {
        return setUnit(U_SCOPE_ROLE_ALLOWLIST_SET, realmId, parentId, p -> {
            p.put("parent_type", parentType);
            p.put("parent_id", parentId);
            p.put("realm_id", realmId);
            p.put("role_ids", roleIds);
        });
    }

    /**
     * The set of scopes whose mappers the token actually applies — mirrors the
     * engine's Stage 3 scope resolution: every DEFAULT scope (always applied) plus
     * every OPTIONAL scope whose name appears as a whitespace token in the request
     * {@code scope} param. The engine only visits these scopes' mapper sets, so
     * emitting mappers for an UNRESOLVED optional scope would be inert; emitting a
     * mapper for a resolved scope is required to back its claims.
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
     * membership unit listing those ids. Generalizes the former role-only emit:
     * the profile/email/roles/web-origins/etc. mappers are all emitted so each
     * token claim has an attested source. (The engine resolves every id in a
     * mapper-set to a protocol_mapper unit, so the set and the units stay in lockstep.)
     */
    private void emitAllActiveMappers(ClientModel client, Map<String, ClientScopeModel> assigned,
                                      ExportRequest req, String realmId,
                                      List<AttestationEnvelope> out) {
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
            out.add(protocolMapper(pm, "client", client.getId(), realmId));
            clientMapperIds.add(pm.getId());
        });
        if (!clientMapperIds.isEmpty()) {
            out.add(setUnit(U_CLIENT_MAPPER_SET, realmId, client.getId(), p -> {
                p.put("client_id_uuid", client.getId());
                p.put("realm_id", realmId);
                p.put("protocol_mapper_ids", clientMapperIds);
            }));
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
                out.add(protocolMapper(pm, "client_scope", scope.getId(), realmId));
                scopeMapperIds.add(pm.getId());
            });
            if (!scopeMapperIds.isEmpty()) {
                out.add(setUnit(U_CLIENT_SCOPE_MAPPER_SET, realmId, scope.getId(), p -> {
                    p.put("client_scope_id", scope.getId());
                    p.put("realm_id", realmId);
                    p.put("protocol_mapper_ids", scopeMapperIds);
                }));
            }
        }
    }

    private AttestationEnvelope protocolMapper(ProtocolMapperModel pm, String parentType,
                                               String parentId, String realmId) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("protocol_mapper_id", pm.getId());
        p.put("realm_id", realmId);
        p.put("parent_type", parentType);
        p.put("parent_id", parentId);
        p.put("protocol", nullToEmpty(pm.getProtocol()));
        p.put("protocol_mapper", pm.getProtocolMapper());
        p.put("config", attributeNameValues(pm.getConfig()));
        return new AttestationEnvelope(U_PROTOCOL_MAPPER, realmId, pm.getId(), p);
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

    private static Map<String, Object> nameValue(String name, String value) {
        Map<String, Object> nv = new LinkedHashMap<>();
        nv.put("name", name);
        nv.put("value", value);
        return nv;
    }

    /** Single-valued attribute map -> [{name,value}]. */
    private static List<Map<String, Object>> attributeNameValues(Map<String, String> attrs) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (attrs != null) {
            for (Map.Entry<String, String> e : attrs.entrySet()) {
                out.add(nameValue(e.getKey(), e.getValue() == null ? "" : e.getValue()));
            }
        }
        return out;
    }

    /** Multi-valued user attribute map -> [{name,values[]}] (ork unit 7). */
    private static List<Map<String, Object>> userAttributeNameValues(Map<String, List<String>> attrs) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (attrs != null) {
            for (Map.Entry<String, List<String>> e : attrs.entrySet()) {
                Map<String, Object> nv = new LinkedHashMap<>();
                nv.put("name", e.getKey());
                nv.put("values", e.getValue() == null ? new ArrayList<>() : new ArrayList<>(e.getValue()));
                out.add(nv);
            }
        }
        return out;
    }

    private interface PayloadBuilder {
        void build(Map<String, Object> payload);
    }

    private static AttestationEnvelope setUnit(String unitType, String realmId, String targetId,
                                               PayloadBuilder b) {
        Map<String, Object> p = new LinkedHashMap<>();
        b.build(p);
        return new AttestationEnvelope(unitType, realmId, targetId, p);
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    private static Set<String> orEmptySet(Set<String> s) {
        return s == null ? new LinkedHashSet<>() : s;
    }
}
