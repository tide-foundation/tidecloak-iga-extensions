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
import org.tidecloak.iga.producer.units.RealmDefaultRolesSetUnit;
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
import java.util.stream.Stream;

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
     * <p><b>NOTE on {@code oidc-allowed-origins-mapper}.</b> This factory is NOT in
     * the filter set. The ork TVE registers a dedicated value-verifying handler for it
     * ({@code Mappers/AllowedWebOriginsClaimMapper.cs}, factory
     * {@code oidc-allowed-origins-mapper}) that DERIVES the {@code allowed-origins}
     * claim from the requesting client's attested {@code web_origins}
     * ({@code client_config.web_origins}, unit 1). On a NON-lightweight access token
     * (KC default {@code access.token.claim} ⇒ included) the token carries
     * {@code allowed-origins}, so the engine MUST collect this mapper (via the
     * per-scope {@code client_scope_mapper_set}, unit 13) and run the handler, else
     * Stage 8 rejects {@code allowed-origins} as "no attested source". So the producer
     * emits the {@code protocol_mapper} envelope for it AND keeps its id in the
     * web-origins scope's mapper-set membership. (The {@code web_origins} value the
     * handler reads is RESOLVED in {@link #clientConfig} — KC's {@code +} wildcard is
     * expanded to the client's redirect-URI origins so the attested-derived value
     * MATCHES the token's resolved {@code allowed-origins}.)
     *
     * <p>The five filtered factories and why each is JWT-body-irrelevant:
     * <ul>
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

        // Fail closed with a clear, named error instead of letting a null userId fall
        // through to session.users().getUserById(realm, null), which NPEs deep in the
        // Infinispan key codec ("Null keys are not supported!") with no actionable
        // context. The DTM caller now sources userId from the userSession; this guard
        // catches any future caller that supplies a null id (e.g. a lightweight access
        // token whose `sub` claim was skipped) before it reaches the cache.
        if (req.userId() == null) {
            throw new IllegalStateException(
                    "IGA producer export: null userId for realm '" + realm.getName()
                            + "' client '" + req.clientId() + "' (scope '" + req.scope()
                            + "'). The caller must supply the authenticated user id "
                            + "(source it from the userSession, not the token `sub` "
                            + "claim, which is absent on lightweight access tokens).");
        }
        if (req.clientId() == null) {
            throw new IllegalStateException(
                    "IGA producer export: null clientId for realm '" + realm.getName()
                            + "' user '" + req.userId() + "'.");
        }

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
        out.add(clientConfig(session, client, realmId));

        // 3) client_scope_assignment_set + 4) a client_scope_config per assigned scope.
        Map<String, ClientScopeModel> assigned = collectAssignedScopes(client);
        out.add(clientScopeAssignmentSet(client, assigned, realmId));
        for (ClientScopeModel scope : assigned.values()) {
            out.add(clientScopeConfig(scope, realmId));
        }

        // 5) user_identity (the 4-unit floor) + 6) user_role_mapping_set + (when
        //    non-empty) user_group_membership_set — the user's OWN per-user closure,
        //    single-sourced from perUserUnits so the commit-time CREATE_USER carrier
        //    (TideAttestor.enumerateLiveCrUnits) derives the SAME set this login emits.
        //    user_group_membership_set is emitted HERE (not only in
        //    emitOrganizationClosure) so the per-user closure is complete in one place.
        out.addAll(perUserUnits(em, user, realmId));

        // Emit the group→role BINDING edge for the user's plain (non-organization) realm groups.
        // perUserUnits (above) emits the membership edge "user ∈ admins"; this emits "admins → realm-admin".
        // Without it the ORK has the membership and the role composition but never binds the role to the
        // user, collapsing `aud`. Ancestor-inclusive (a parent group's roles reach child members); deduped;
        // leaf-gated so a role-less group never dangles a column-less unit that fail-closes the login.
        // Org-backing groups are handled by emitOrganizationClosure — skip them here so the split is explicit.
        Set<String> emittedGroupRoleMapGroupIds = new LinkedHashSet<>();
        user.getGroupsStream().forEach(g -> {
            for (GroupModel grp = g; grp != null; grp = grp.getParent()) {
                if (grp.getType() == GroupModel.Type.ORGANIZATION) continue;
                if (!emittedGroupRoleMapGroupIds.add(grp.getId())) continue;
                GroupRoleMappingSetUnit unit = groupRoleMappingSet(em, grp.getId(), realmId);
                if (!unit.roleIds().isEmpty()) out.add(unit);
            }
        });

        // The metadata seed needs the RAW stored USER_ROLE_MAPPING child set (JPQL,
        // not the effective set). Recompute it here for the role-closure seed; this is
        // the SAME query perUserUnits used for the emitted unit (byte-identical).
        // The realm default-role id is the U8 EXCLUSION (D1b) AND the metadata-seed
        // INCLUSION (the aud fix) — captured once so getDefaultRole() is called once.
        String realmDefaultRoleId =
                realm.getDefaultRole() == null ? null : realm.getDefaultRole().getId();
        List<String> seedRoleIds = userRoleMappingSet(em, req.userId(), realmDefaultRoleId);

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
        //      (v)  the realm default-role id (default-roles-<realm> composite) — EXCLUDED
        //           from the per-user U8 edge (seedRoleIds) but seeded HERE so the closure
        //           expands the default-roles composite and emits the owning `account`
        //           client_config (the aud fix). The ORK universal-inherits the grant.
        //    each then composite-expanded. This lets the ORK expand allowlist/group
        //    composites it walks even when the user does not transitively hold them
        //    (fixes (a)). U15 allowlist sets stay RAW (unexpanded) — the ORK expands.
        Set<String> metadataRoleSeed = metadataRoleSeed(seedRoleIds, user,
                scopeMappingRoleIds(client), assigned.values(), realmDefaultRoleId);
        Set<RoleModel> roleClosure = transitiveRoleClosure(realm, new ArrayList<>(metadataRoleSeed),
                req.userId());
        Set<String> ownerClientUuids = new LinkedHashSet<>();
        for (RoleModel role : roleClosure) {
            out.add(roleDefinition(role, realmId));
            emitRoleCompositeChildrenSet(role, realmId, out);
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
            out.add(clientConfig(session, owner, realmId));
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

        // 13b) realm_default_roles_set (unit 18) — the realm's default-role authority,
        //     target = realm UUID. Signed ONCE here; the universal-inherit covers every
        //     user, so the per-user default-role edge is NOT signed (userRoleMappingSet
        //     excludes it). Mirrors realm_default_groups_set exactly.
        out.add(realmDefaultRolesSet(realm, realmId));

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

    /**
     * The producer's per-user closure: EXACTLY the units the {@link #export} login
     * emits whose {@code target_id == user.getId()} — i.e. the units that would be
     * NULL for a freshly-created user and that the user's LOGIN replay demands.
     *
     * <p><b>Single source of truth.</b> This is the ONLY place that enumerates a
     * user's own units. {@link #export} calls it (so the login closure and this
     * method can never drift), {@code emitOrganizationClosure} reuses its
     * {@code user_group_membership_set} emission, and the commit-time signer
     * ({@code TideAttestor.enumerateLiveCrUnits} CREATE_USER carrier /
     * {@code stampAdoptUser}) calls it to frame the quorum-signed set. Because the
     * carrier is DERIVED from this method rather than a hand-listed subset, adding a
     * new per-user unit type here is COMPLETE BY CONSTRUCTION: every consumer — the
     * login replay AND the commit-time carrier — picks it up automatically.
     *
     * <p><b>Byte-identity.</b> Built with the SAME builders + JPQL/order the login
     * uses ({@link #userIdentity}, {@link #userRoleMappingSet} ORDER BY urm.roleId,
     * {@link #userGroupMembershipSet}), so the quorum-signed CBOR is byte-identical
     * to the login-emitted unit and the VVK signature verifies over the literal
     * envelope bytes.
     *
     * <p><b>Emission shape (mirrors {@code export} exactly):</b>
     * <ul>
     *   <li>{@code user_identity} — always.</li>
     *   <li>{@code user_role_mapping_set} — ONLY when the user holds at least one direct
     *       role row. The set's sig lives ON the user_role_mapping rows (any row), so a
     *       roleless user has no row to carry it; emitting it empty would dangle a
     *       column-less unit that fail-closes the login (commit stamps 0 rows, login read
     *       sees a NULL column). Same rule as {@code user_group_membership_set} below and
     *       the {@code role_composite_children_set} leaf-role precedent.</li>
     *   <li>{@code user_group_membership_set} — ONLY when non-empty, matching
     *       {@code emitOrganizationClosure} (an empty set is not emitted by the login
     *       and would dangle a column-less unit).</li>
     * </ul>
     *
     * <p>Honors {@link #onlyAttested} on the membership JPQL (off by default) exactly
     * as {@code export} does, so this method and the login agree under either setting.
     */
    public List<AttestationUnit> perUserUnits(EntityManager em, UserModel user, String realmId) {
        List<AttestationUnit> out = new ArrayList<>();
        out.add(userIdentity(user, realmId));
        // user_role_mapping_set: emitted ONLY when the user actually holds at least one
        // direct role row. The set unit's sig lives ON the user_role_mapping rows (see
        // UnitColumnMapping: "user.id = :id; any row"), so a roleless user has NO row to
        // carry it — the commit-time stamp would write 0 rows and the login read would
        // find a NULL column → replayOrFailClosed fail-closes the login. A roleless user with
        // 0 role rows would otherwise have the phase-1 carrier frame an empty unit the quorum
        // signs but has nowhere to stamp. This mirrors the existing
        // user_group_membership_set rule directly below ("an empty set is not emitted by
        // the login and would dangle a column-less unit") and the role_composite_children_set
        // precedent (a leaf role with no composite_role row must not emit the
        // set unit). Because perUserUnits is the SINGLE source for BOTH the login export and
        // the commit-time CREATE_USER carrier, gating here keeps them byte-identical: the
        // carrier frames (and the quorum signs) exactly the set the login replays.
        // Exclude the realm default-role id (D1b): a user holding ONLY default-roles → empty
        // set → no user_role_mapping_set emitted (the existing empty-skip below). The id is
        // resolved from RealmEntity by realmId so this method's public signature is unchanged
        // (it is called by TideAttestor too).
        List<String> roleIds = userRoleMappingSet(em, user.getId(), defaultRoleIdForRealm(em, realmId));
        if (!roleIds.isEmpty()) {
            out.add(new UserRoleMappingSetUnit(realmId, user.getId(), roleIds));
        }
        List<String> groupIds = userGroupMembershipSet(em, user.getId());
        if (!groupIds.isEmpty()) {
            out.add(new UserGroupMembershipSetUnit(realmId, user.getId(), groupIds));
        }
        return out;
    }

    /**
     * Emit the FULL realm-METADATA unit closure — every membership-INDEPENDENT unit
     * the realm owns, regardless of which (if any) current user holds the role / scope /
     * group. This is the convergence / toggle-on counterpart of {@link #export}: where
     * {@code export} emits only the metadata a SPECIFIC {@code (client, user, scope)} login
     * would surface (seeded from that user's grants / groups / allowlists), this enumerates
     * EVERY role, client-scope, client, group and organization in the realm so a role NO
     * current user holds (e.g. {@code tide-realm-admin → realm-admin} and the
     * {@code realm-management} system composites) still gets its
     * {@code role_definition} + {@code role_composite_children_set} signed.
     *
     * <p><b>What is emitted (all membership-INDEPENDENT, all 18 metadata-class types):</b>
     * <ul>
     *   <li><b>Realm</b> — {@code realm_config} + {@code realm_default_groups_set}.</li>
     *   <li><b>All roles</b> — realm roles ({@code session.roles().getRealmRolesStream})
     *       AND every client's roles ({@code client.getRolesStream()}), INCLUDING the
     *       built-in {@code realm-management} / {@code account} / system clients and
     *       {@code tide-realm-admin}: {@code role_definition} (unit 4) +
     *       {@code role_composite_children_set} (unit 10, for composites).</li>
     *   <li><b>All client scopes</b> — every {@code realm.getClientScopesStream()} (incl.
     *       built-ins): {@code client_scope_config} (unit 2) +
     *       {@code client_scope_mapper_set} (unit 13) + {@code scope_role_allowlist_set}
     *       (unit 14, {@code parent_type=client_scope}) + a {@code protocol_mapper}
     *       (unit 3) per JWT-relevant mapper the scope owns.</li>
     *   <li><b>All clients</b> — every {@code realm.getClientsStream()}:
     *       {@code client_config} (unit 1) + {@code client_mapper_set} (unit 12) +
     *       {@code client_scope_assignment_set} (unit 11) + {@code scope_role_allowlist_set}
     *       (unit 14, {@code parent_type=client}) + a {@code protocol_mapper} (unit 3) per
     *       JWT-relevant mapper the client owns.</li>
     *   <li><b>All groups</b> — every {@code realm.getGroupsStream()} (flat, incl.
     *       sub-groups): {@code group_definition} (unit 5) + {@code group_role_mapping_set}
     *       (unit 9).</li>
     *   <li><b>All organizations</b> — every org via {@code OrganizationProvider.getAllStream}:
     *       {@code organization_definition} (unit 16) + {@code organization_domain_set}
     *       (unit 17). (The org's backing group is already covered by the all-groups walk.)</li>
     * </ul>
     *
     * <p><b>What is NOT emitted here — the per-USER membership units stay per-user:</b>
     * {@code user_identity} (unit 6), {@code user_role_mapping_set} (unit 7) and
     * {@code user_group_membership_set} (unit 8) are membership-DEPENDENT and are produced
     * by {@link #export} from each ENABLED user's own state. The convergence caller stamps
     * those from the per-user export loop; this method emits ONLY the metadata closure.
     *
     * <p><b>Byte-identity.</b> Every unit here is built with the SAME {@code public static}
     * builders {@link #export} uses ({@link #roleDefinition}, {@link #roleCompositeChildrenSet},
     * {@link #clientConfig}, {@link #clientScopeConfig}, {@link #clientMapperSet},
     * {@link #clientScopeMapperSet}, {@link #clientScopeAssignmentSet},
     * {@link #scopeRoleAllowlistSet}, {@link #realmConfig}, {@link #realmDefaultGroupsSetStatic},
     * {@link #groupDefinition}, {@link #groupRoleMappingSet}, {@link #protocolMapperUnit},
     * {@link #organizationDefinition}, {@link #organizationDomainSet}). A unit a login emits
     * is byte-identical to the same unit emitted here (same target id, same payload), so the
     * convergence-stamped column the uniform login read replays cannot drift from what the
     * login would itself emit.
     *
     * <p>The list may contain DUPLICATE logical units (e.g. the same role enumerated under a
     * client and surfaced by {@code export} for a user too) — the convergence caller dedups
     * by {@code (type, targetId)} before signing, so duplicates are harmless.
     *
     * @return every membership-independent metadata {@link AttestationUnit} in the realm
     */
    public List<AttestationUnit> exportRealmMetadata(KeycloakSession session, RealmModel realm) {
        session.getContext().setRealm(realm);
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        String realmId = realm.getId();

        List<AttestationUnit> out = new ArrayList<>();

        // 1) Realm-level units.
        out.add(realmConfig(realm, realmId));
        out.add(realmDefaultGroupsSetStatic(realm, realmId));
        out.add(realmDefaultRolesSetStatic(realm, realmId));

        // 2) All roles — realm roles + every client's roles (built-ins INCLUDED). The
        //    role_definition + role_composite_children_set for tide-realm-admin / realm-admin
        //    / the realm-management system composites are signed here even though NO current
        //    user holds them, so the moment a user is granted tide-realm-admin and logs in,
        //    every composite the token emits already carries a real column sig.
        session.roles().getRealmRolesStream(realm)
                .forEach(role -> emitRoleMetadata(role, realmId, out));

        // 3) All client scopes (built-ins INCLUDED) — config + mapper-set + scope→role
        //    allowlist + a protocol_mapper per JWT-relevant mapper the scope owns.
        realm.getClientScopesStream().forEach(scope -> {
            out.add(clientScopeConfig(scope, realmId));
            out.add(clientScopeMapperSet(scope, realmId));
            out.add(scopeRoleAllowlistSet(ParentType.client_scope, scope.getId(), scope, realmId));
            emitContainerProtocolMappers(scope.getProtocolMappersStream(),
                    ParentType.client_scope, scope.getId(), realmId, out);
        });

        // 4) All clients — config + mapper-set + scope-assignment-set + scope→role allowlist
        //    + a protocol_mapper per JWT-relevant mapper the client owns + the client's own
        //    roles (client roles are owned by the client, not surfaced by getRealmRolesStream).
        realm.getClientsStream().forEach(client -> {
            out.add(clientConfig(session, client, realmId));
            out.add(clientMapperSet(client, realmId));
            out.add(clientScopeAssignmentSet(client, realmId));
            out.add(scopeRoleAllowlistSet(ParentType.client, client.getId(), client, realmId));
            emitContainerProtocolMappers(client.getProtocolMappersStream(),
                    ParentType.client, client.getId(), realmId, out);
            client.getRolesStream().forEach(role -> emitRoleMetadata(role, realmId, out));
        });

        // 5) All groups (flat stream, incl. sub-groups) — definition + role-mapping set.
        realm.getGroupsStream().forEach(group -> {
            out.add(groupDefinition(group, realmId));
            out.add(groupRoleMappingSet(em, group.getId(), realmId));
        });

        // 6) All organizations — definition + domain set (the backing group is already
        //    covered by the all-groups walk above; no separate group emission needed).
        emitAllOrganizations(session, em, realm, realmId, out);

        log.infof("producer: realm-METADATA export realm=%s -> %d unit(s) (membership-independent; "
                + "all roles incl tide-realm-admin/realm-management, all scopes, all clients, "
                + "all groups, all orgs)", realm.getName(), out.size());
        return out;
    }

    /** {@code role_definition} (unit 4) + {@code role_composite_children_set} (unit 10) for a role. */
    private void emitRoleMetadata(RoleModel role, String realmId, List<AttestationUnit> out) {
        out.add(roleDefinition(role, realmId));
        emitRoleCompositeChildrenSet(role, realmId, out);
    }

    /**
     * Gated emission of {@code role_composite_children_set} (unit 10): emit ONLY for roles
     * that are REAL composites with at least one composite child (i.e. they own
     * {@code composite_role} rows). A LEAF role (e.g. {@code offline_access},
     * {@code view-profile}, {@code manage-account-links}) has NO {@code composite_role} row,
     * so {@code CompositeRoleEntity.attestation WHERE parentRole.id=:id} is structurally
     * NULL — there is no column for the convergence stamper to write a signature into, and
     * {@code IgaAttestationExporterProvider.replayOrFailClosed} would fail-close on the NULL
     * at EVERY login (all users hold these default leaf roles via {@code default-roles}).
     *
     * <p>The convergence only signs existing {@code composite_role} rows, so emitting fewer
     * units here keeps the login-emitted set and the convergence-signed set byte-identical
     * and in lockstep. {@code role_definition} (unit 4) is STILL emitted for leaf roles by
     * the callers (keyed on {@code keycloak_role.attestation}, which always exists) — only
     * unit 10 is gated. Used by BOTH the login {@link #export} closure and the
     * {@code exportRealmMetadata} convergence path (via {@link #emitRoleMetadata}).
     */
    private void emitRoleCompositeChildrenSet(RoleModel role, String realmId,
                                              List<AttestationUnit> out) {
        RoleCompositeChildrenSetUnit unit = roleCompositeChildrenSet(role, realmId);
        if (unit.childRoleIds().isEmpty()) {
            // Leaf role (no composite children) — no composite_role row to sign. Do NOT
            // emit; emitting it would orphan a unit with no signable column → fail-close.
            return;
        }
        out.add(unit);
    }

    /**
     * Emit a {@code protocol_mapper} (unit 3) for every JWT-relevant mapper a container
     * (client OR client-scope) owns — the SAME {@link #JWT_BODY_IRRELEVANT_FACTORIES}
     * filter the login path applies, so the realm-metadata set never emits a mapper unit
     * the login would suppress (which would dangle an un-referenced column with no harm,
     * but emitting only JWT-relevant mappers keeps the closure exactly the login's).
     */
    private void emitContainerProtocolMappers(Stream<ProtocolMapperModel> mappers,
                                              ParentType parentType, String parentId,
                                              String realmId, List<AttestationUnit> out) {
        mappers.forEach(pm -> {
            if (JWT_BODY_IRRELEVANT_FACTORIES.contains(pm.getProtocolMapper())) {
                return;
            }
            out.add(protocolMapperUnit(pm, parentType, parentId, realmId));
        });
    }

    /**
     * Emit {@code organization_definition} (unit 16) + {@code organization_domain_set}
     * (unit 17) for EVERY organization in the realm (membership-independent), reusing the
     * shared {@link #organizationDefinition} / {@link #organizationDomainSet} builders so the
     * bytes match the per-user org closure. No-op when the realm has no organizations or the
     * provider is unavailable.
     */
    private void emitAllOrganizations(KeycloakSession session, EntityManager em,
                                      RealmModel realm, String realmId, List<AttestationUnit> out) {
        OrganizationProvider orgProvider;
        try {
            orgProvider = session.getProvider(OrganizationProvider.class);
        } catch (RuntimeException re) {
            log.debugf("producer: OrganizationProvider not available (%s); skipping realm-metadata "
                    + "org closure", re.getMessage());
            return;
        }
        if (orgProvider == null) {
            return;
        }
        orgProvider.getAllStream().forEach(org -> {
            String groupId = organizationBackingGroupId(em, org.getId());
            if (groupId == null) {
                log.warnf("producer: organization %s has no backing group id; emitting "
                        + "organization_definition with null group_id (realm-metadata closure)",
                        org.getId());
            }
            out.add(organizationDefinition(org, groupId, realmId));
            out.add(organizationDomainSet(org, realmId));
        });
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

        // 1) user's full group-membership set (the RAW stored child set) is now
        //    emitted by perUserUnits (the single per-user closure source), called from
        //    export() above — NOT here — so the login closure carries exactly one
        //    user_group_membership_set unit and the commit-time CREATE_USER carrier can
        //    derive the same per-user set. This method emits ONLY the org/group units.
        int added = 0;

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
    public static String organizationBackingGroupId(EntityManager em, String orgId) {
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

    /**
     * The {@code organization_domain_set} (unit 17) from the public
     * {@code OrganizationModel.getDomains()} surface — the complete
     * {@code (name, verified)} ORG_DOMAIN set for the org, target = org id. Shared
     * {@code public static} so the commit-time signer emits byte-identical bytes.
     *
     * <p><b>Deterministic ordering.</b> {@code getDomains()} has no defined order;
     * the domains are sorted ascending by name so the literal-bytes VVK verification
     * is reproducible.
     */
    public static OrganizationDomainSetUnit organizationDomainSet(OrganizationModel org, String realmId) {
        List<OrgDomain> domains = new ArrayList<>();
        org.getDomains().forEach((OrganizationDomainModel d) ->
                domains.add(new OrgDomain(d.getName(), d.isVerified())));
        domains.sort(java.util.Comparator.comparing(OrgDomain::name,
                java.util.Comparator.nullsFirst(java.util.Comparator.naturalOrder())));
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
     *       allowlist — fixes (a);</li>
     *   <li>{@code defaultRoleId} — the realm {@code default-roles-<realm>} composite id
     *       (nullable). The per-user U8 edge EXCLUDES it (D1b), so it is NOT in
     *       {@code userGrantRoleIds}; seeding it HERE lets the closure expand the
     *       default-roles composite and emit its children's {@code role_definition} +
     *       the owning {@code account} {@code client_config} (the aud fix). Metadata-seed
     *       ONLY — never folded into the U8 held set (the ORK universal-inherits it).</li>
     * </ol>
     *
     * <p><b>GUARDRAIL:</b> this is a METADATA seed only. It is NOT emitted as, and does
     * not feed, any user-effective-membership unit (U8/U9/U10). Widening it adds only
     * which {@code role_definition}/{@code role_composite_children_set} units appear —
     * never which roles the user holds. Package-private + static for direct unit testing.
     */
    static Set<String> metadataRoleSeed(List<String> userGrantRoleIds, UserModel user,
                                        List<String> clientAllowlistRoleIds,
                                        java.util.Collection<ClientScopeModel> assignedScopes,
                                        String defaultRoleId) {
        Set<String> seed = new LinkedHashSet<>();
        if (userGrantRoleIds != null) {
            seed.addAll(userGrantRoleIds);
        }
        // (v) the realm default-role id (default-roles-<realm> composite). The per-user U8
        //     edge EXCLUDES it (D1b) so it is absent from userGrantRoleIds above — but the
        //     METADATA closure still needs it: transitiveRoleClosure must expand the
        //     default-roles composite to emit role_definition for its account/realm-management
        //     children, role_composite_children_set for the composite, and (via ownerClientUuids)
        //     the client_config for the owning `account` client. Without this, the ORK
        //     AudienceResolveClaimMapper finds account's client_config ABSENT from the login
        //     closure → "aud has no attested source". This is METADATA-seed only: it never
        //     enters userGrantRoleIds/the U8 held set (the universal-inherit grants it on the
        //     ORK). Mirrors how group/allowlist composites are seeded without touching membership.
        if (defaultRoleId != null) {
            seed.add(defaultRoleId);
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

    /**
     * The {@code realm_config} NODE unit (unit 0), target = realm UUID. Shared
     * {@code public static} so the commit-time signer ({@code TideAttestor}) emits
     * byte-identical bytes to this export path (commit bytes == login bytes by
     * construction).
     */
    public static RealmConfigUnit realmConfig(RealmModel realm, String realmId) {
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

    /**
     * The producer-filtered realm attributes ({name,value} list; null → "").
     *
     * <p><b>Ordinal-sorted by name (load-bearing).</b> The ork verifies the
     * attested-unit Ed25519 signature over the LITERAL emitted CBOR bytes
     * ({@code TidecloakSessionStartTokenSignRequest.Validate} →
     * {@code vvk.VerifyWithThrow(envelope, sig)}), and its own canonicalizer
     * ({@code AttestationUnit.GetNameValueList}) sorts {name,value} entries by name
     * with {@code CompareOrdinal} ascending. So the canonical wire order is
     * ordinal-by-name. {@code REALM_CONFIG_ATTR_KEYS} is a hand-ordered list, not
     * ordinal — sort it here so the realm_config bytes the convergence/commit signer
     * stamps and the login {@link #realmConfig} emits are byte-identical (and match
     * the ork canonical).
     */
    private static List<NameValue> realmConfigAttributes(RealmModel realm) {
        List<NameValue> attrs = new ArrayList<>();
        for (String key : REALM_CONFIG_ATTR_KEYS) {
            String val = realm.getAttribute(key);
            attrs.add(new NameValue(key, val == null ? "" : val));
        }
        attrs.sort(java.util.Comparator.comparing(NameValue::name));
        return attrs;
    }

    public static ClientConfigUnit clientConfig(KeycloakSession session, ClientModel client,
                                                String realmId) {
        // web_origins is a Set with no stable iteration order across sessions; the ork
        // canonicalizes it with GetStringList -> StringComparer.Ordinal sort, and verifies
        // the sig over the literal emitted bytes, so emit it ordinal-sorted to keep the
        // sign-time stamp byte-identical to the login emit (and aligned with the ork canonical).
        //
        // WILDCARD RESOLUTION (allowed-origins value-verification). The ork TVE's
        // AllowedWebOriginsClaimMapper writes this client_config.web_origins set VERBATIM
        // into the `allowed-origins` claim (Mappers/AllowedWebOriginsClaimMapper.cs:43-49:
        // `var origins = ctx.Client.WebOrigins; ... PlaceClaim("allowed-origins", arr)`) and
        // does NOT itself resolve KC's `+`/`*` wildcards (its ClientConfigAttestationUnit has
        // no redirect_uris field). The REAL token's allowed-origins is
        // WebOriginsUtils.resolveValidWebOrigins(session, client) — KC's
        // AllowedWebOriginsProtocolMapper.setWebOrigin resolves `+` to the origins
        // of the client's redirect URIs. So for the attested-derived value to MATCH the
        // token, the producer must attest the RESOLVED origins here, not the raw `+`. We
        // call the exact KC util the mapper uses, keyed off the same session, so the
        // attested web_origins == the token's allowed-origins (e.g. `["+"]` on
        // security-admin-console -> `["http://localhost:8080"]`). For a client with no `+`
        // this is an identity transform over the raw set (modulo the ordinal sort).
        Set<String> resolved = (session == null || client.getWebOrigins() == null)
                ? orEmptySet(client.getWebOrigins())
                : org.keycloak.protocol.oidc.utils.WebOriginsUtils.resolveValidWebOrigins(session, client);
        List<String> webOrigins = new ArrayList<>(resolved);
        webOrigins.sort(java.util.Comparator.naturalOrder());
        return new ClientConfigUnit(realmId,
                client.getId(),
                client.getClientId(),
                nullToEmpty(client.getProtocol()),
                client.isFullScopeAllowed(),
                client.isServiceAccountsEnabled(),
                webOrigins,
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
        return clientScopeAssignmentSet(client, realmId);
    }

    /**
     * The {@code client_scope_assignment_set} (unit 11) for a client, target =
     * client UUID. Shared {@code public static} so the commit-time signer
     * ({@code TideAttestor}) emits byte-identical bytes to this export path.
     *
     * <p><b>Deterministic ordering.</b> The VVK sig is verified over the LITERAL
     * envelope bytes, so the assignment ORDER is load-bearing. The assignments are
     * sorted ascending by {@code clientScopeId} so commit and login emit an identical
     * set regardless of {@code getClientScopes()} iteration order. (Mirrors the URM
     * precedent's {@code ORDER BY}.)
     */
    public static ClientScopeAssignmentSetUnit clientScopeAssignmentSet(
            ClientModel client, String realmId) {
        // default=true for default scopes, false for optional.
        Set<String> defaultIds = client.getClientScopes(true).values().stream()
                .map(ClientScopeModel::getId).collect(java.util.stream.Collectors.toSet());
        // Union of default + optional assignments, keyed + sorted by scope id for a
        // deterministic, byte-stable emission.
        Map<String, ClientScopeModel> assigned = new java.util.TreeMap<>();
        for (ClientScopeModel s : client.getClientScopes(true).values()) {
            assigned.put(s.getId(), s);
        }
        for (ClientScopeModel s : client.getClientScopes(false).values()) {
            assigned.put(s.getId(), s);
        }
        List<ScopeAssignment> assignments = new ArrayList<>();
        for (ClientScopeModel scope : assigned.values()) {
            assignments.add(new ScopeAssignment(scope.getId(), defaultIds.contains(scope.getId())));
        }
        return new ClientScopeAssignmentSetUnit(realmId, client.getId(), assignments);
    }

    /** The realm's REALM_DEFAULT_GROUPS set (unit 16), target = realm UUID. */
    private RealmDefaultGroupsSetUnit realmDefaultGroupsSet(RealmModel realm, String realmId) {
        return realmDefaultGroupsSetStatic(realm, realmId);
    }

    /**
     * The realm's REALM_DEFAULT_GROUPS set (unit 15), target = realm UUID. Shared
     * {@code public static} so the commit-time signer emits byte-identical bytes.
     *
     * <p><b>Deterministic ordering.</b> {@code getDefaultGroupsStream()} has no
     * defined order; the group ids are sorted ascending so the literal-bytes VVK
     * verification is reproducible and the commit-time signer can mirror the sort.
     */
    public static RealmDefaultGroupsSetUnit realmDefaultGroupsSetStatic(RealmModel realm, String realmId) {
        List<String> groupIds = new ArrayList<>();
        realm.getDefaultGroupsStream().forEach(g -> groupIds.add(g.getId()));
        groupIds.sort(java.util.Comparator.naturalOrder());
        return new RealmDefaultGroupsSetUnit(realmId, groupIds);
    }

    /** The realm's default-role authority (unit 18), target = realm UUID. */
    private RealmDefaultRolesSetUnit realmDefaultRolesSet(RealmModel realm, String realmId) {
        return realmDefaultRolesSetStatic(realm, realmId);
    }

    /**
     * The realm's default-role authority (unit 18), target = realm UUID. Shared
     * {@code public static} so the commit-time signer / convergence emits byte-identical
     * bytes. Mirrors {@link #realmDefaultGroupsSetStatic} EXACTLY (same target=realm
     * pattern, same envelope shape) — the payload is the single
     * {@code realm.getDefaultRole().getId()} (the {@code default-roles-<realm>} composite
     * every user inherits) instead of the group-id list.
     *
     * <p>Because this realm authority is signed ONCE and the universal-inherit covers every
     * user, the per-user default-role EDGE is NOT signed (see {@link #userRoleMappingSet} and
     * {@code TideAttestor.buildUserRoleMappingSetUnit}, both of which exclude this id). The
     * id is emitted verbatim ({@code getDefaultRole()} returns the single composite; there is
     * no set to sort).
     */
    public static RealmDefaultRolesSetUnit realmDefaultRolesSetStatic(RealmModel realm, String realmId) {
        RoleModel defaultRole = realm.getDefaultRole();
        String roleId = (defaultRole == null) ? null : defaultRole.getId();
        return new RealmDefaultRolesSetUnit(realmId, roleId);
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
        List<String> clientMapperIds = jwtRelevantMapperIds(client.getProtocolMappersStream());
        client.getProtocolMappersStream().forEach(pm -> {
            if (JWT_BODY_IRRELEVANT_FACTORIES.contains(pm.getProtocolMapper())) {
                log.debugf("producer: skipping JWT-body-irrelevant client mapper %s (factory=%s)",
                        pm.getId(), pm.getProtocolMapper());
                return;
            }
            out.add(protocolMapper(pm, ParentType.client, client.getId(), realmId));
        });
        if (!clientMapperIds.isEmpty()) {
            out.add(new ClientMapperSetUnit(realmId, client.getId(), clientMapperIds));
        }
        // Active scope mappers (default + requested-optional only — the engine never
        // visits an unresolved optional scope's mapper set). Same factory filter.
        Map<String, ClientScopeModel> active = resolveActiveScopes(client, req);
        for (ClientScopeModel scope : active.values()) {
            List<String> scopeMapperIds = jwtRelevantMapperIds(scope.getProtocolMappersStream());
            scope.getProtocolMappersStream().forEach(pm -> {
                if (JWT_BODY_IRRELEVANT_FACTORIES.contains(pm.getProtocolMapper())) {
                    log.debugf("producer: skipping JWT-body-irrelevant scope mapper %s "
                            + "(scope=%s, factory=%s)", pm.getId(), scope.getName(),
                            pm.getProtocolMapper());
                    return;
                }
                out.add(protocolMapper(pm, ParentType.client_scope, scope.getId(), realmId));
            });
            if (!scopeMapperIds.isEmpty()) {
                out.add(new ClientScopeMapperSetUnit(realmId, scope.getId(), scopeMapperIds));
            }
        }
    }

    /**
     * The JWT-relevant protocol-mapper ids of a container (client OR client-scope),
     * with the {@link #JWT_BODY_IRRELEVANT_FACTORIES} filtered out and the surviving
     * ids sorted ascending. Shared so the {@code client_mapper_set} /
     * {@code client_scope_mapper_set} membership lists are deterministic + byte-stable
     * for the literal-bytes VVK verification, and the commit-time signer mirrors the
     * exact same filter + sort.
     */
    public static List<String> jwtRelevantMapperIds(
            Stream<ProtocolMapperModel> mappers) {
        List<String> ids = new ArrayList<>();
        mappers.forEach(pm -> {
            if (!JWT_BODY_IRRELEVANT_FACTORIES.contains(pm.getProtocolMapper())) {
                ids.add(pm.getId());
            }
        });
        ids.sort(java.util.Comparator.naturalOrder());
        return ids;
    }

    /** Build a {@code client_mapper_set} (unit 12) for a client, deterministic + shared. */
    public static ClientMapperSetUnit clientMapperSet(ClientModel client, String realmId) {
        return new ClientMapperSetUnit(realmId, client.getId(),
                jwtRelevantMapperIds(client.getProtocolMappersStream()));
    }

    /** Build a {@code client_scope_mapper_set} (unit 13) for a scope, deterministic + shared. */
    public static ClientScopeMapperSetUnit clientScopeMapperSet(ClientScopeModel scope, String realmId) {
        return new ClientScopeMapperSetUnit(realmId, scope.getId(),
                jwtRelevantMapperIds(scope.getProtocolMappersStream()));
    }

    /** Build a {@code scope_role_allowlist_set} (unit 14) for a scope container, deterministic + shared. */
    public static ScopeRoleAllowlistSetUnit scopeRoleAllowlistSet(
            ParentType parentType, String parentId,
            org.keycloak.models.ScopeContainerModel container, String realmId) {
        return new ScopeRoleAllowlistSetUnit(realmId, parentType, parentId,
                scopeMappingRoleIds(container));
    }

    private ProtocolMapperUnit protocolMapper(ProtocolMapperModel pm, ParentType parentType,
                                              String parentId, String realmId) {
        return protocolMapperUnit(pm, parentType, parentId, realmId);
    }

    /**
     * Build a {@code protocol_mapper} (unit 3) for a mapper whose parent is already
     * resolved. {@code public static} so the commit-time ADOPT_PROTOCOL_MAPPER stamper
     * (TideAttestor) can build the SAME unit-envelope the login/export path emits.
     */
    public static ProtocolMapperUnit protocolMapperUnit(ProtocolMapperModel pm, ParentType parentType,
                                                        String parentId, String realmId) {
        return new ProtocolMapperUnit(realmId,
                pm.getId(),
                parentType,
                parentId,
                nullToEmpty(pm.getProtocol()),
                pm.getProtocolMapper(),
                attributeNameValues(pm.getConfig()));
    }

    /**
     * Resolve a {@code protocol_mapper} (unit 3) from just the mapper id (the key an
     * ADOPT_PROTOCOL_MAPPER CR carries), or {@code null} if the mapper / its parent are
     * not resolvable. Looks up the owning client or client-scope via the
     * ProtocolMapperEntity FK columns, then rebuilds via the model API so the unit bytes
     * match the login/export emission byte-for-byte.
     */
    public static ProtocolMapperUnit protocolMapperUnitById(KeycloakSession session,
                                                            RealmModel realm, String mapperId) {
        if (mapperId == null) {
            return null;
        }
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        // ProtocolMapperEntity has a client FK and a clientScope FK (one is set).
        @SuppressWarnings("unchecked")
        List<String> clientUuids = em.createQuery(
                        "SELECT e.client.id FROM ProtocolMapperEntity e WHERE e.id = :id AND e.client IS NOT NULL")
                .setParameter("id", mapperId).getResultList();
        if (!clientUuids.isEmpty()) {
            ClientModel client = realm.getClientById(clientUuids.get(0));
            if (client == null) {
                return null;
            }
            ProtocolMapperModel pm = client.getProtocolMapperById(mapperId);
            return pm == null ? null
                    : protocolMapperUnit(pm, ParentType.client, client.getId(), realm.getId());
        }
        @SuppressWarnings("unchecked")
        List<String> scopeIds = em.createQuery(
                        "SELECT e.clientScope.id FROM ProtocolMapperEntity e WHERE e.id = :id AND e.clientScope IS NOT NULL")
                .setParameter("id", mapperId).getResultList();
        if (!scopeIds.isEmpty()) {
            ClientScopeModel scope = realm.getClientScopeById(scopeIds.get(0));
            if (scope == null) {
                return null;
            }
            ProtocolMapperModel pm = scope.getProtocolMapperById(mapperId);
            return pm == null ? null
                    : protocolMapperUnit(pm, ParentType.client_scope, scope.getId(), realm.getId());
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // JPQL helpers (raw stored linkage rows)
    // -------------------------------------------------------------------------

    /**
     * The RAW stored USER_ROLE_MAPPING role-id set for a user (the complete child
     * set, incl. the implicit {@code default-roles-<realm>} grant). Uses the same
     * JPQL shape as {@link org.tidecloak.iga.services.IgaUnsignedRowScanner}.
     */
    /**
     * The user's RAW stored USER_ROLE_MAPPING child set (role ids), EXCLUDING the realm
     * default-role id (D1b). Default roles are realm-level + identical for every user; the
     * realm authority {@code realm_default_roles_set} (unit 18) + universal-inherit covers
     * them, so signing the default-role EDGE per-user is redundant. A user holding ONLY
     * default-roles therefore returns an EMPTY set → {@link #perUserUnits} emits no
     * {@code user_role_mapping_set} (the existing empty-skip); a user with an explicit grant
     * returns ONLY that grant.
     *
     * <p>The EXCLUSION here MUST be byte-identical to the firstAdmin GRANT_ROLES signer's
     * inline query ({@code TideAttestor.buildUserRoleMappingSetUnit}) — the two MUST produce
     * the same set or the VVK verify breaks. Both add
     * {@code AND urm.roleId <> :defaultRoleId} and end with {@code ORDER BY urm.roleId}.
     */
    private List<String> userRoleMappingSet(EntityManager em, String userId, String defaultRoleId) {
        String jpql = "SELECT urm.roleId FROM UserRoleMappingEntity urm WHERE urm.user.id = :owner";
        if (defaultRoleId != null) {
            jpql += " AND urm.roleId <> :defaultRoleId";
        }
        if (onlyAttested) {
            jpql += " AND urm.attestation IS NOT NULL";
        }
        // Deterministic role-id ordering: the VVK sig is verified over the LITERAL
        // envelope bytes (no re-canonicalization), so role_ids order is load-bearing.
        // Must stay the LAST clause and mirror the firstAdmin signer's final sort
        // (TideAttestor#buildUserRoleMappingSetUnitCbor) so both emit an identical set.
        jpql += " ORDER BY urm.roleId";
        var q = em.createQuery(jpql).setParameter("owner", userId);
        if (defaultRoleId != null) {
            q.setParameter("defaultRoleId", defaultRoleId);
        }
        @SuppressWarnings("unchecked")
        List<String> ids = q.getResultList();
        return new ArrayList<>(ids);
    }

    /**
     * The realm's default-role id ({@code realm.getDefaultRole().getId()}) resolved from the
     * RealmEntity by realm id, so {@link #perUserUnits} (which holds only {@code realmId}) can
     * pass the exclusion id into {@link #userRoleMappingSet} without changing its public
     * signature. Returns {@code null} if the realm or its default role is not resolvable (the
     * exclusion clause is then a no-op — the back-compat behaviour).
     */
    private String defaultRoleIdForRealm(EntityManager em, String realmId) {
        try {
            return em.createQuery(
                            "SELECT r.defaultRoleId FROM RealmEntity r WHERE r.id = :realmId", String.class)
                    .setParameter("realmId", realmId)
                    .getSingleResult();
        } catch (RuntimeException e) {
            // NoResultException (realm gone) → null = no-op exclusion (back-compat). Also
            // degrades safely under unit-test mocks that do not stub the typed RealmEntity
            // query: the exclusion is then a no-op, exactly as before D1b.
            return null;
        }
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

    /**
     * scope→role allowlist (SCOPE_MAPPING / CLIENT_SCOPE_ROLE_MAPPING) role ids.
     * Shared {@code public static} so the commit-time signer emits byte-identical
     * bytes to this export path.
     *
     * <p><b>Deterministic ordering.</b> {@code getScopeMappingsStream()} has no
     * defined order; the ids are sorted ascending so the literal-bytes VVK
     * verification is reproducible (load-bearing for the {@code scope_role_allowlist_set}
     * unit). The metadata-seed callers (which union the ids into a Set) are order-
     * insensitive, so the sort is harmless there.
     */
    public static List<String> scopeMappingRoleIds(org.keycloak.models.ScopeContainerModel container) {
        List<String> ids = new ArrayList<>();
        container.getScopeMappingsStream().forEach(r -> ids.add(r.getId()));
        ids.sort(java.util.Comparator.naturalOrder());
        return ids;
    }

    // ---- name/value list helpers (ork {name,value} / {name,values}) ----

    /**
     * Single-valued attribute / config / mapper-config map -> [NameValue] (null value -> "").
     *
     * <p><b>Ordinal-sorted by name (load-bearing byte-identity).</b> The source map is a
     * JPA {@code @ElementCollection} (Hibernate {@code PersistentMap} over a HashMap for
     * {@code ProtocolMapperEntity.config}, {@code ClientEntity}/{@code ClientScopeEntity}
     * attributes), whose iteration order is NOT stable across sessions — the convergence /
     * commit-time signer ({@code TideAttestor.stampProducerUnitColumns}) and the login
     * {@link #export} read the entity in DIFFERENT sessions, so an unsorted emission can
     * stamp one key order and emit another, diverging the LITERAL CBOR bytes the ork
     * Ed25519-verifies ({@code TidecloakSessionStartTokenSignRequest.Validate} verifies the
     * signature over the verbatim envelope, no re-canonicalization). The ork's own
     * canonicalizer ({@code AttestationUnit.GetNameValueList}) sorts {name,value} by name
     * with {@code CompareOrdinal} — so ordinal-by-name IS the canonical wire order. Sorting
     * here (the SOLE construction site for client_config #1, client_scope_config #2,
     * protocol_mapper #3 config) makes sign-time == login-emit byte-identical, fixing the
     * "Attested unit signature validation failed" on the attribute-bearing units (the
     * protocol_mapper / *_config family were the bulk of the 44 re-signed types).
     */
    private static List<NameValue> attributeNameValues(Map<String, String> attrs) {
        List<NameValue> out = new ArrayList<>();
        if (attrs != null) {
            for (Map.Entry<String, String> e : attrs.entrySet()) {
                out.add(new NameValue(e.getKey(), e.getValue() == null ? "" : e.getValue()));
            }
        }
        // Deterministic ordinal-by-name order (matches the ork canonical + makes the
        // sign-time stamp byte-identical to the login emit regardless of map iteration).
        out.sort(java.util.Comparator.comparing(NameValue::name));
        return out;
    }

    /**
     * Multi-valued user attribute map -> [NameValues] (ork unit 7).
     *
     * <p>The ork {@code user_identity} validator ({@code AttestationUnit.cs}
     * {@code GetNameValuesList}) requires every element of each {@code values[]}
     * to be a CBOR text string — a {@code null} element fails the unit with
     * {@code 'attributes'.values must contain only strings}, which aborts ORK
     * signing of the whole bundle ({@code Midgard.SignModel} → "Not enough orks").
     *
     * <p>Keycloak's {@code UserAdapter.getAttributes()} merges the standard
     * profile fields into this map via {@code MultivaluedHashMap.add}, which
     * stores the raw getter result even when it is {@code null}: an absent
     * {@code firstName}/{@code lastName}/{@code email} yields a single-element
     * list {@code [null]}. We coerce to all-string by dropping {@code null}
     * elements (an absent standard field → empty {@code values[]}); the ork reads
     * those standard fields from the dedicated nullable payload keys
     * ({@code first_name}/{@code last_name}/{@code email}), not from
     * {@code attributes}, so dropping the {@code null} placeholder loses no
     * verified state. Any genuine {@code null} inside a custom multi-valued
     * attribute is likewise dropped (the ork has no representation for a null
     * member of a string set).
     *
     * <p>This is the ONLY place the {@code attributes} {@code values[]} is built,
     * and it serves BOTH the toggle-on backfill/commit signer and the login/export
     * read ({@link #userIdentity}). A single coercion therefore keeps the two
     * byte-identical: the same {@code null}-stripped list is emitted at sign time
     * and at verify time.
     */
    private static List<NameValues> userAttributeNameValues(Map<String, List<String>> attrs) {
        List<NameValues> out = new ArrayList<>();
        if (attrs != null) {
            for (Map.Entry<String, List<String>> e : attrs.entrySet()) {
                List<String> values = new ArrayList<>();
                if (e.getValue() != null) {
                    for (String v : e.getValue()) {
                        if (v != null) {
                            values.add(v);
                        }
                    }
                }
                out.add(new NameValues(e.getKey(), values));
            }
        }
        // Sort the entries by NAME ordinal (load-bearing byte-identity): the user-attribute
        // map (UserEntity attributes, a JPA element collection) has no stable iteration order
        // across the sign-time (stampUserIdentity / ADOPT_USER) vs login (export) sessions, so
        // an unsorted user_identity #6 emission diverges the LITERAL CBOR bytes the ork
        // Ed25519-verifies. The ork canonicalizer (AttestationUnit.GetNameValuesList) sorts the
        // {name,values} entries by name with CompareOrdinal but keeps each values[] in STORED
        // order (KC getFirstAttribute reads values[0] = stored-first), so we mirror exactly:
        // sort by name only, never reorder the per-attribute values[].
        out.sort(java.util.Comparator.comparing(NameValues::name));
        return out;
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    private static Set<String> orEmptySet(Set<String> s) {
        return s == null ? new LinkedHashSet<>() : s;
    }
}
